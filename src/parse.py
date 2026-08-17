"""
Email parsing for EmailShield.

Turns a raw .eml file into a normalised ParsedEmail. Nothing in this module makes
a judgement about whether the message is malicious. It only extracts, decodes and
records what is actually present, so that every downstream signal reads from the
same structure and cannot disagree about what the email said.

Standard library only. No network access anywhere in this project.
"""

from __future__ import annotations

import email
import email.policy
import re
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #

@dataclass
class Attachment:
    """One attachment or inline part with a filename."""
    filename: str
    declared_content_type: str
    size_bytes: int
    payload: bytes = field(repr=False, default=b"")


@dataclass
class Link:
    """
    A hyperlink found in the message.

    href is the actual destination. anchor_text is what the reader sees. The gap
    between the two is one of the most useful signals in phishing triage, so they
    are recorded separately and never collapsed together.
    """
    href: str
    anchor_text: str = ""
    source: str = "html"          # "html", "text", or "header"


@dataclass
class ReceivedHop:
    """One Received: header, in the order it appeared in the file."""
    index: int                    # 0 is the topmost header, added last in transit
    raw: str


@dataclass
class ParsedEmail:
    path: str
    subject: str
    from_display_name: str
    from_address: str
    reply_to: list[str]
    return_path: str
    to: list[str]
    cc: list[str]
    date: str
    message_id: str
    headers: list[tuple[str, str]]            # all headers, order preserved
    received_hops: list[ReceivedHop]
    authentication_results: list[str]         # topmost first
    body_text: str
    body_html: str
    links: list[Link]
    attachments: list[Attachment]
    parse_warnings: list[str]

    def header_values(self, name: str) -> list[str]:
        """All values for a header name, in file order. Case-insensitive."""
        lowered = name.lower()
        return [v for k, v in self.headers if k.lower() == lowered]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _decode_header_value(raw: str | None) -> str:
    """
    Decode an RFC 2047 encoded header into plain text.

    Subject lines are routinely encoded, for example
    =?utf-8?B?VXJnZW50?= which decodes to "Urgent". A signal that greps the raw
    header for keywords would miss every encoded message, so decoding has to
    happen here rather than in the signals.
    """
    if raw is None:
        return ""
    try:
        return str(make_header(decode_header(raw)))
    except Exception:
        # Malformed encoding is common in real mail and in evasion attempts.
        # Fall back to the raw value rather than losing the header entirely.
        return raw


class _LinkExtractor(HTMLParser):
    """Pulls href values and their visible anchor text out of an HTML body."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self._current_href = value
                self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or self._current_href is None:
            return
        self.links.append(
            Link(
                href=self._current_href,
                anchor_text="".join(self._current_text).strip(),
                source="html",
            )
        )
        self._current_href = None
        self._current_text = []


_TEXT_URL_RE = re.compile(r"""(?ix)
    \b
    (?:https?://|www\.)          # scheme, or a bare www host
    [^\s<>"')\]]+                # run to the first delimiter
""")

# Trailing punctuation that is almost always sentence punctuation, not URL.
_TRAILING_JUNK = ".,;:!?)]}>'\""


def _extract_text_links(text: str) -> list[Link]:
    out: list[Link] = []
    for match in _TEXT_URL_RE.finditer(text):
        url = match.group(0).rstrip(_TRAILING_JUNK)
        out.append(Link(href=url, anchor_text=url, source="text"))
    return out


def _decode_part(part: Message) -> str:
    """
    Decode one message part to text, handling base64 and quoted-printable.

    get_payload(decode=True) reverses the transfer encoding. The charset then has
    to be applied separately, and a wrong or missing charset must not raise,
    because a crash here would let a malformed message bypass analysis entirely.
    """
    raw = part.get_payload(decode=True)
    if raw is None:
        payload = part.get_payload()
        return payload if isinstance(payload, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #

def parse_email_bytes(data: bytes, path: str = "<bytes>") -> ParsedEmail:
    warnings: list[str] = []

    # policy=default gives the modern header API. compat32 would silently mangle
    # some structured headers.
    try:
        msg = email.message_from_bytes(data, policy=email.policy.default)
    except Exception as exc:
        warnings.append(f"strict parse failed ({exc}); retried in compatibility mode")
        msg = email.message_from_bytes(data, policy=email.policy.compat32)

    headers: list[tuple[str, str]] = []
    for key, value in msg.items():
        headers.append((str(key), _decode_header_value(str(value))))

    subject = _decode_header_value(msg.get("Subject"))

    from_raw = _decode_header_value(msg.get("From"))
    from_display_name, from_address = parseaddr(from_raw)

    reply_to = [addr for _, addr in getaddresses(
        [_decode_header_value(v) for v in msg.get_all("Reply-To", [])]
    ) if addr]

    # Return-Path is stamped by the receiving MTA from the SMTP MAIL FROM
    # (the envelope sender). It can legitimately differ from the From header,
    # for example for mailing lists, so a mismatch is a signal and not a verdict.
    return_path_raw = _decode_header_value(msg.get("Return-Path"))
    _, return_path = parseaddr(return_path_raw)

    to = [addr for _, addr in getaddresses(
        [_decode_header_value(v) for v in msg.get_all("To", [])]
    ) if addr]
    cc = [addr for _, addr in getaddresses(
        [_decode_header_value(v) for v in msg.get_all("Cc", [])]
    ) if addr]

    received_hops = [
        ReceivedHop(index=i, raw=v)
        for i, v in enumerate(_decode_header_value(h) for h in msg.get_all("Received", []))
    ]

    # Order matters enormously here and is handled in auth.py. Preserved as-is.
    authentication_results = [
        _decode_header_value(v) for v in msg.get_all("Authentication-Results", [])
    ]

    body_text_parts: list[str] = []
    body_html_parts: list[str] = []
    attachments: list[Attachment] = []

    if msg.is_multipart():
        walker = msg.walk()
    else:
        walker = iter([msg])

    for part in walker:
        if part.get_content_maintype() == "multipart":
            continue

        filename = part.get_filename()
        if filename:
            filename = _decode_header_value(filename)

        disposition = (part.get("Content-Disposition") or "").lower()

        if filename or "attachment" in disposition:
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    declared_content_type=part.get_content_type(),
                    size_bytes=len(payload),
                    payload=payload,
                )
            )
            continue

        content_type = part.get_content_type()
        if content_type == "text/plain":
            body_text_parts.append(_decode_part(part))
        elif content_type == "text/html":
            body_html_parts.append(_decode_part(part))
        else:
            warnings.append(f"unhandled inline part type: {content_type}")

    body_text = "\n".join(body_text_parts)
    body_html = "\n".join(body_html_parts)

    links: list[Link] = []
    if body_html:
        extractor = _LinkExtractor()
        try:
            extractor.feed(body_html)
            extractor.close()
        except Exception as exc:
            warnings.append(f"HTML link extraction failed: {exc}")
        links.extend(extractor.links)
    links.extend(_extract_text_links(body_text))

    if not from_address:
        warnings.append("no parseable From address")
    if not body_text and not body_html:
        warnings.append("message has no text or HTML body")

    return ParsedEmail(
        path=path,
        subject=subject,
        from_display_name=from_display_name,
        from_address=from_address,
        reply_to=reply_to,
        return_path=return_path,
        to=to,
        cc=cc,
        date=_decode_header_value(msg.get("Date")),
        message_id=_decode_header_value(msg.get("Message-ID")),
        headers=headers,
        received_hops=received_hops,
        authentication_results=authentication_results,
        body_text=body_text,
        body_html=body_html,
        links=links,
        attachments=attachments,
        parse_warnings=warnings,
    )


def parse_email_file(path: str | Path) -> ParsedEmail:
    p = Path(path)
    return parse_email_bytes(p.read_bytes(), path=str(p))
