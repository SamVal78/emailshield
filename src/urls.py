"""
URL deobfuscation for EmailShield.

The destination a reader believes they are visiting and the destination the
browser actually resolves are frequently different, and the gap is deliberate.
This module unwraps the common tricks so that later signals reason about the real
host rather than the decorated string.

Nothing here contacts the network. Resolving a URL from an email would confirm to
the sender that the message was opened and would leak the analyst's egress
address, so it is a deliberate design constraint that this tool never fetches.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit


SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id",
    "lnkd.in", "trib.al", "shorte.st", "bl.ink", "snip.ly",
}

# Parameters commonly used to carry a nested destination.
REDIRECT_PARAMS = (
    "url", "u", "target", "dest", "destination", "redirect", "redirect_uri",
    "redir", "next", "continue", "return", "returnurl", "return_to", "r", "q",
    "link", "goto", "out",
)


@dataclass
class AnalysedURL:
    original: str
    normalised: str
    scheme: str = ""
    host: str = ""                       # lowercased, punycode left as-is
    port: int | None = None
    path: str = ""
    userinfo: str = ""                   # the part before @ in the authority
    is_ip_literal: bool = False
    ip_literal_form: str = ""            # "dotted", "decimal", "hex", "octal", "ipv6"
    is_private_ip: bool = False
    is_shortener: bool = False
    redirect_chain: list[str] = field(default_factory=list)
    unwrap_depth: int = 0
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Host normalisation
# --------------------------------------------------------------------------- #

def _parse_numeric_host(host: str) -> tuple[str, str] | None:
    """
    Recognise an IP address written in a non-obvious base.

    http://3232235777/ and http://0xC0A80101/ both resolve to 192.168.1.1 in most
    browsers. Attackers use these forms because a reader scanning for a hostname
    sees digits and moves on, and because naive detections only look for the
    dotted-quad pattern.

    Returns (dotted_form, form_name) or None.
    """
    h = host.strip("[]")

    # IPv6
    if ":" in h:
        try:
            return str(ipaddress.IPv6Address(h)), "ipv6"
        except ValueError:
            return None

    # Dotted quad
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h):
        try:
            return str(ipaddress.IPv4Address(h)), "dotted"
        except ValueError:
            return None

    # Hexadecimal, e.g. 0xC0A80101
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", h):
        try:
            return str(ipaddress.IPv4Address(int(h, 16))), "hex"
        except (ValueError, ipaddress.AddressValueError):
            return None

    # Octal, e.g. 0300.0250.0001.0001 or a single leading-zero integer
    if re.fullmatch(r"0[0-7]+", h):
        try:
            return str(ipaddress.IPv4Address(int(h, 8))), "octal"
        except (ValueError, ipaddress.AddressValueError):
            return None

    # Bare decimal integer, e.g. 3232235777
    if re.fullmatch(r"\d+", h):
        try:
            return str(ipaddress.IPv4Address(int(h))), "decimal"
        except (ValueError, ipaddress.AddressValueError):
            return None

    return None


def _split_authority(authority: str) -> tuple[str, str, int | None]:
    """
    Split an authority into userinfo, host and port.

    The userinfo trick matters here. In https://www.bank.com@evil.net/login the
    authority is www.bank.com@evil.net, the userinfo is www.bank.com and the real
    host is evil.net. urlsplit().hostname handles this correctly, but the userinfo
    is exactly what the reader's eye latches onto, so it is captured rather than
    discarded.
    """
    userinfo = ""
    rest = authority
    if "@" in authority:
        userinfo, _, rest = authority.rpartition("@")

    port: int | None = None
    host = rest
    if rest.startswith("["):                     # IPv6 literal
        closing = rest.find("]")
        if closing != -1:
            host = rest[: closing + 1]
            if rest[closing + 1:].startswith(":"):
                try:
                    port = int(rest[closing + 2:])
                except ValueError:
                    port = None
    elif ":" in rest:
        host, _, port_str = rest.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            host = rest
            port = None

    return userinfo, host.lower(), port


# --------------------------------------------------------------------------- #
# Redirect unwrapping
# --------------------------------------------------------------------------- #

def _find_nested_url(url: str) -> str | None:
    """
    Look for another URL carried inside this one's query string.

    Legitimate services do this constantly, for click tracking and for SSO
    returns, which is why finding a nested URL is not by itself suspicious. What
    matters is where the innermost URL actually points.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.query:
        return None

    params = parse_qs(parts.query, keep_blank_values=False)
    for name in REDIRECT_PARAMS:
        for key in params:
            if key.lower() != name:
                continue
            for raw in params[key]:
                candidate = unquote(raw)
                if re.match(r"(?i)^https?://", candidate):
                    return candidate
    return None


def analyse_url(raw: str, max_unwrap: int = 5) -> AnalysedURL:
    """Normalise one URL and describe how it was obfuscated, if it was."""
    original = raw.strip()
    result = AnalysedURL(original=original, normalised=original)

    working = original

    # A bare www.example.com has no scheme. Assume http so it parses, and record
    # the assumption rather than hiding it.
    if not re.match(r"(?i)^[a-z][a-z0-9+.\-]*:", working):
        working = "http://" + working
        result.notes.append("no scheme in source; assumed http for parsing")

    # Unwrap nested redirects, bounded to avoid a crafted infinite chain.
    chain = [working]
    depth = 0
    while depth < max_unwrap:
        nested = _find_nested_url(chain[-1])
        if nested is None or nested in chain:
            break
        chain.append(nested)
        depth += 1
    if depth == max_unwrap:
        result.notes.append(f"redirect unwrapping stopped at limit of {max_unwrap}")

    result.redirect_chain = chain
    result.unwrap_depth = depth
    final = chain[-1]

    try:
        parts = urlsplit(final)
    except ValueError as exc:
        result.notes.append(f"unparseable URL: {exc}")
        return result

    result.scheme = (parts.scheme or "").lower()

    userinfo, host, port = _split_authority(parts.netloc)
    result.userinfo = userinfo
    result.host = host
    result.port = port
    result.path = parts.path

    if userinfo:
        result.notes.append(
            f"authority contains userinfo '{userinfo}' before the real host '{host}'"
        )

    numeric = _parse_numeric_host(host)
    if numeric is not None:
        dotted, form = numeric
        result.is_ip_literal = True
        result.ip_literal_form = form
        if form != "dotted" and form != "ipv6":
            result.notes.append(
                f"host is an IP address written in {form} form; resolves to {dotted}"
            )
        try:
            addr = ipaddress.ip_address(dotted)
            result.is_private_ip = addr.is_private or addr.is_loopback
        except ValueError:
            pass
        result.host = dotted
    else:
        result.is_shortener = host in SHORTENER_HOSTS

    rebuilt_authority = result.host
    if result.port is not None:
        rebuilt_authority = f"{rebuilt_authority}:{result.port}"
    result.normalised = f"{result.scheme}://{rebuilt_authority}{parts.path}"
    if parts.query:
        result.normalised += "?" + parts.query

    return result


def analyse_urls(raws: list[str]) -> list[AnalysedURL]:
    return [analyse_url(r) for r in raws]
