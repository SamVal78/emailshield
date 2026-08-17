"""
Email authentication analysis: SPF, DKIM, DMARC and alignment.

This is the module most worth understanding, because it is the one most commonly
got wrong.

An Authentication-Results header is just text. Anyone can put
`Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass` into a
message they send. It carries no cryptographic protection of its own. Its meaning
comes entirely from *who added it*: only the header stamped by a mail server you
trust says anything about the message.

Headers are prepended as a message travels, so the topmost Authentication-Results
header is the one added last, by the server closest to the recipient. That is the
one to trust. A detection that reads the first matching header in document order,
or that searches all of them for "pass", is bypassed by the sender simply
including their own.

This module therefore requires the caller to declare which authserv-id values are
trusted. There is no sensible default, because the answer depends on whose mail
infrastructure you are protecting.

Everything here parses headers only. No DNS lookups, no key verification. The
results are what the boundary server reported, and the code says so rather than
implying it verified anything itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .domains import registrable_domain


VALID_RESULTS = {
    "none", "pass", "fail", "softfail", "neutral", "temperror", "permerror",
    "policy", "bestguesspass",
}


@dataclass
class MethodResult:
    method: str                    # "spf", "dkim", "dmarc", "arc", ...
    result: str                    # "pass", "fail", ...
    properties: dict[str, str] = field(default_factory=dict)


@dataclass
class AuthResultsHeader:
    index: int                     # 0 is topmost in the file
    raw: str
    authserv_id: str
    methods: dict[str, MethodResult] = field(default_factory=dict)
    trusted: bool = False


@dataclass
class AuthAssessment:
    headers: list[AuthResultsHeader]
    trusted_header: AuthResultsHeader | None
    spf: str = "absent"
    dkim: str = "absent"
    dmarc: str = "absent"
    spf_domain: str = ""
    dkim_domain: str = ""
    from_domain: str = ""
    spf_aligned: bool | None = None
    dkim_aligned: bool | None = None
    dmarc_pass_computed: bool | None = None
    untrusted_claims: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


_AUTHSERV_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:;|$)")
_METHOD_RE = re.compile(
    r"(?ix)\b(spf|dkim|dmarc|arc|iprev|auth|dkim-adsp|sender-id)\s*=\s*"
    r"([A-Za-z]+)"
)
_PROPERTY_RE = re.compile(
    r"""(?ix)
    \b(header\.[a-z0-9_\-]+|smtp\.[a-z0-9_\-]+|policy\.[a-z0-9_\-]+|body\.[a-z0-9_\-]+)
    \s*=\s*
    ("[^"]*"|[^\s;()]+)
    """
)


def parse_auth_results_header(raw: str, index: int) -> AuthResultsHeader:
    """Parse one Authentication-Results header into methods and properties."""
    # Strip CFWS comments, which are legal and are sometimes used to smuggle
    # misleading text such as "(spf=pass)" past a naive substring check.
    without_comments = re.sub(r"\([^()]*\)", " ", raw)

    authserv_match = _AUTHSERV_RE.match(without_comments)
    authserv_id = authserv_match.group(1).lower() if authserv_match else ""

    header = AuthResultsHeader(index=index, raw=raw, authserv_id=authserv_id)

    # Split into clauses so that properties attach to the method they follow.
    body = without_comments
    if ";" in body:
        body = body.split(";", 1)[1]

    for clause in body.split(";"):
        method_match = _METHOD_RE.search(clause)
        if not method_match:
            continue
        method = method_match.group(1).lower()
        result = method_match.group(2).lower()
        if result not in VALID_RESULTS:
            result = "unknown"

        properties: dict[str, str] = {}
        for prop_match in _PROPERTY_RE.finditer(clause):
            key = prop_match.group(1).lower()
            value = prop_match.group(2).strip('"').lower()
            properties[key] = value

        # A repeated method in one header is ambiguous. Keep the first and note it.
        if method in header.methods:
            continue
        header.methods[method] = MethodResult(method, result, properties)

    return header


def _domain_of(value: str) -> str:
    """Pull a domain out of an address-or-domain property value."""
    v = value.strip().strip("<>")
    if "@" in v:
        v = v.rpartition("@")[2]
    return v.strip().lower()


def _aligned(a: str, b: str, strict: bool) -> bool | None:
    """
    DMARC alignment between two domains.

    Strict alignment requires the domains to be identical. Relaxed alignment,
    which is the DMARC default, requires only that they share a registrable
    domain, so mail.example.com is aligned with example.com. Getting this wrong
    in either direction produces a wrong DMARC verdict: too strict and normal
    subdomain sending looks like a failure, too loose and any subdomain of a
    shared hosting provider looks aligned.
    """
    if not a or not b:
        return None
    if strict:
        return a == b
    return registrable_domain(a).registrable == registrable_domain(b).registrable


def assess_authentication(
    auth_headers: list[str],
    from_address: str,
    trusted_authserv_ids: set[str],
    relaxed_alignment: bool = True,
) -> AuthAssessment:
    """
    Evaluate authentication for a message.

    auth_headers must be in file order, topmost first, exactly as
    ParsedEmail.authentication_results provides them.

    trusted_authserv_ids are the authserv-id values belonging to mail servers
    under your control. Anything else is treated as an unverifiable claim by the
    sender.
    """
    parsed = [parse_auth_results_header(raw, i) for i, raw in enumerate(auth_headers)]

    from_domain = _domain_of(from_address)

    assessment = AuthAssessment(
        headers=parsed,
        trusted_header=None,
        from_domain=from_domain,
    )

    if not parsed:
        assessment.notes.append(
            "no Authentication-Results header present; the receiving server either "
            "did not evaluate authentication or did not record it"
        )
        return assessment

    # Walk from the top down and take the first header whose authserv-id is
    # trusted. Top-down matters: headers are prepended in transit, so the topmost
    # is the most recent and the closest to the recipient.
    for header in parsed:
        if header.authserv_id in trusted_authserv_ids:
            header.trusted = True
            assessment.trusted_header = header
            break

    for header in parsed:
        if header.trusted:
            continue
        claims = ", ".join(
            f"{m.method}={m.result}" for m in header.methods.values()
        ) or "no parseable methods"
        assessment.untrusted_claims.append(
            f"header {header.index} from authserv-id "
            f"'{header.authserv_id or '(unparsed)'}' claims {claims}"
        )

    if assessment.trusted_header is None:
        assessment.notes.append(
            "no Authentication-Results header came from a trusted authserv-id. "
            "Every result present was supplied by an untrusted hop and must not be "
            "read as evidence that the message authenticated."
        )
        return assessment

    if len(parsed) > 1:
        assessment.notes.append(
            f"{len(parsed)} Authentication-Results headers present; used index "
            f"{assessment.trusted_header.index} "
            f"('{assessment.trusted_header.authserv_id}') and ignored the rest"
        )

    trusted = assessment.trusted_header

    spf = trusted.methods.get("spf")
    dkim = trusted.methods.get("dkim")
    dmarc = trusted.methods.get("dmarc")

    if spf:
        assessment.spf = spf.result
        assessment.spf_domain = _domain_of(
            spf.properties.get("smtp.mailfrom")
            or spf.properties.get("smtp.helo")
            or ""
        )
    if dkim:
        assessment.dkim = dkim.result
        assessment.dkim_domain = _domain_of(dkim.properties.get("header.d", ""))
    if dmarc:
        assessment.dmarc = dmarc.result

    # Alignment. SPF authenticates the envelope sender, DKIM authenticates the
    # signing domain. Neither is the From header the reader sees, so DMARC exists
    # to require that at least one of them aligns with it.
    assessment.spf_aligned = (
        _aligned(assessment.spf_domain, from_domain, not relaxed_alignment)
        if assessment.spf == "pass" else None
    )
    assessment.dkim_aligned = (
        _aligned(assessment.dkim_domain, from_domain, not relaxed_alignment)
        if assessment.dkim == "pass" else None
    )

    computed = bool(
        (assessment.spf == "pass" and assessment.spf_aligned)
        or (assessment.dkim == "pass" and assessment.dkim_aligned)
    )
    assessment.dmarc_pass_computed = computed

    if assessment.spf == "pass" and assessment.spf_aligned is False:
        assessment.notes.append(
            f"SPF passed for '{assessment.spf_domain}' but that does not align with "
            f"the From domain '{from_domain}'. A pass only proves the envelope "
            "sender was authorised, not that the visible sender is genuine."
        )
    if assessment.dkim == "pass" and assessment.dkim_aligned is False:
        assessment.notes.append(
            f"DKIM signature is valid for '{assessment.dkim_domain}', which does not "
            f"align with the From domain '{from_domain}'."
        )
    if assessment.dmarc != "absent" and assessment.dmarc_pass_computed is not None:
        reported_pass = assessment.dmarc == "pass"
        if reported_pass != computed:
            assessment.notes.append(
                f"the trusted server reported dmarc={assessment.dmarc} but alignment "
                f"computed from the SPF and DKIM results gives "
                f"{'pass' if computed else 'fail'}. Worth investigating the "
                "discrepancy rather than assuming either is right."
            )

    return assessment
