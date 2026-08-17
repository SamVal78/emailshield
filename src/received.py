"""
Received chain analysis.

Closes a gap the threat model called out. Until now the tool inferred forwarding
indirectly, from DKIM surviving while SPF failed. That inference is usually right
and occasionally wrong, and it cannot say *who* forwarded the message.

A Received header is added by each server that handles a message, and they are
prepended, so the file order is newest first and the chain reads backwards through
the message's journey. Only the hops at or above our own boundary are trustworthy:
everything below was supplied by whoever sent the message and can be fabricated
wholesale to invent a plausible history.

That asymmetry is the whole reason this module is careful about where it stops
believing what it reads.

Standard library only. No DNS, no reverse lookups.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .domains import registrable_domain

# "from mail.example.com (mail.example.com [203.0.113.9]) by mx1.northgate.co.uk"
_FROM_RE = re.compile(r"(?is)\bfrom\s+([A-Za-z0-9._\-]+)")
_BY_RE = re.compile(r"(?is)\bby\s+([A-Za-z0-9._\-]+)")
_FOR_RE = re.compile(r"(?is)\bfor\s+<?([^\s;>]+@[^\s;>]+)>?")
_WITH_RE = re.compile(r"(?is)\bwith\s+([A-Za-z0-9]+)")
_IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{6,})\]?")


@dataclass
class Hop:
    index: int                    # 0 is topmost, added last
    raw: str
    from_host: str = ""
    by_host: str = ""
    ip: str = ""
    is_private_ip: bool = False
    protocol: str = ""
    timestamp: datetime | None = None
    trusted: bool = False
    """
    True when `by_host` is one of our own servers.

    A hop is trusted because *we* wrote it, not because it looks plausible.
    """


@dataclass
class ChainAssessment:
    hops: list[Hop]
    boundary_index: int | None = None      # lowest trusted hop: where our estate ends
    external_hop_count: int = 0
    forwarded: bool = False
    forwarding_host: str = ""
    delivered_to_intermediate: str = ""
    time_anomalies: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def untrusted_hops(self) -> list[Hop]:
        if self.boundary_index is None:
            return self.hops
        return self.hops[self.boundary_index + 1:]


def parse_hop(raw: str, index: int, trusted_hosts: set[str]) -> Hop:
    hop = Hop(index=index, raw=raw)

    from_match = _FROM_RE.search(raw)
    if from_match:
        hop.from_host = from_match.group(1).lower().rstrip(".")

    by_match = _BY_RE.search(raw)
    if by_match:
        hop.by_host = by_match.group(1).lower().rstrip(".")

    with_match = _WITH_RE.search(raw)
    if with_match:
        hop.protocol = with_match.group(1).upper()

    # Take the first bracketed or bare address in the header. Several may appear;
    # the first is conventionally the connecting client.
    for candidate in _IP_RE.findall(raw):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        hop.ip = str(address)
        hop.is_private_ip = address.is_private or address.is_loopback
        break

    # The date follows the final semicolon.
    if ";" in raw:
        tail = raw.rsplit(";", 1)[1].strip()
        try:
            parsed = parsedate_to_datetime(tail)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            hop.timestamp = parsed
        except (TypeError, ValueError, IndexError):
            pass

    hop.trusted = bool(hop.by_host) and hop.by_host in trusted_hosts
    return hop


def assess_chain(
    received_headers: list[str],
    from_address: str,
    trusted_hosts: set[str],
    envelope_to: str = "",
) -> ChainAssessment:
    """
    Describe a message's path, and say where the description stops being evidence.

    trusted_hosts are hostnames of mail servers under your control, matched against
    the `by` clause. Without them every hop is sender-supplied and nothing in the
    chain can be relied on, which the assessment reports rather than glossing over.
    """
    hops = [
        parse_hop(raw, i, trusted_hosts)
        for i, raw in enumerate(received_headers)
    ]
    assessment = ChainAssessment(hops=hops)

    if not hops:
        assessment.notes.append(
            "no Received headers present, so the message path cannot be examined"
        )
        return assessment

    trusted_indices = [h.index for h in hops if h.trusted]
    if not trusted_indices:
        assessment.notes.append(
            "no Received header names one of our own servers in its 'by' clause. "
            "Every hop shown was supplied by the sender and none of it is evidence."
        )
    else:
        # The boundary is the lowest trusted hop: below it we are reading the
        # sender's account of the journey.
        assessment.boundary_index = max(trusted_indices)

    untrusted = assessment.untrusted_hops
    assessment.external_hop_count = len(untrusted)

    # Forwarding evidence. A message that reached us via an intermediate mail
    # system shows a hop below our boundary whose 'by' host sits on a different
    # registrable domain from both us and the sender.
    from_domain = registrable_domain(
        from_address.rpartition("@")[2]
    ).registrable if from_address else ""

    for hop in untrusted:
        if not hop.by_host:
            continue
        by_domain = registrable_domain(hop.by_host).registrable
        if not by_domain or by_domain == from_domain:
            continue
        if any(by_domain == registrable_domain(t).registrable for t in trusted_hosts):
            continue
        assessment.forwarded = True
        assessment.forwarding_host = hop.by_host
        assessment.notes.append(
            f"message passed through '{hop.by_host}', which belongs to neither the "
            f"sender's domain nor ours. Consistent with a mailing list or forwarder, "
            "which is the ordinary explanation for an SPF alignment failure."
        )
        break

    # A 'for' clause naming a different recipient than the envelope is another
    # forwarding tell, and one the sender cannot easily fake below our boundary
    # without also faking our own header.
    if envelope_to:
        for hop in hops:
            for_match = _FOR_RE.search(hop.raw)
            if not for_match:
                continue
            recipient = for_match.group(1).lower()
            if recipient != envelope_to.lower():
                assessment.delivered_to_intermediate = recipient
                assessment.notes.append(
                    "an intermediate hop recorded delivery to a different address, "
                    "which indicates the message was redirected rather than sent "
                    "directly"
                )
                break

    # Timestamps should decrease as the list is read downwards, because the top
    # header is the most recent. Anything else is clock skew or fabrication, and
    # only anomalies at or above our boundary are worth taking seriously.
    timestamps = [(h.index, h.timestamp) for h in hops if h.timestamp]
    for (upper_index, upper), (lower_index, lower) in zip(timestamps, timestamps[1:]):
        if upper < lower:
            drift = (lower - upper).total_seconds()
            location = (
                "at or above our boundary"
                if assessment.boundary_index is not None
                and lower_index <= assessment.boundary_index
                else "below our boundary, where the sender controls the text"
            )
            assessment.time_anomalies.append(
                f"hop {upper_index} is timestamped {drift:.0f}s earlier than hop "
                f"{lower_index} beneath it ({location})"
            )

    if len(untrusted) > 6:
        assessment.notes.append(
            f"{len(untrusted)} sender-supplied hops. A long invented chain is a "
            "cheap way to make a message look well travelled."
        )

    return assessment
