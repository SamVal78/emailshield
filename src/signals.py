"""
The six EmailShield signals.

Each signal is a pure function: it takes a ParsedEmail plus configuration and
returns a list of Findings. A Finding records what was observed and why it might
matter. It carries a weight, but no signal decides the outcome on its own and no
signal knows the threshold. Combining and thresholding happen in score.py, so
that the weights can be calibrated against the corpus rather than guessed.

Each Finding also carries a `benign_explanations` list. That is not decoration.
An analyst working a queue needs the innocent reading in front of them, and a rule
that cannot state one is usually a rule that will generate noise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .attachments import inspect_attachment
from .auth import assess_authentication
from .domains import assess_domain, registrable_domain, skeleton
from .parse import ParsedEmail
from .received import ChainAssessment, assess_chain
from .urls import analyse_url


@dataclass
class Finding:
    signal_id: str
    title: str
    weight: int
    evidence: list[str] = field(default_factory=list)
    benign_explanations: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    analyst_actions: list[str] = field(default_factory=list)
    confidence: str = "medium"        # low, medium, high: quality of the evidence
    suppresses_credit: bool = False
    """
    When True, negative-weight findings are ignored for this message.

    Set only on findings where a passing authentication result or a long sender
    history is actively misleading rather than reassuring. A request to change
    bank details is the case: if the sending account has been compromised, the
    message will authenticate perfectly and the sender will have years of
    history, and those two facts are exactly what makes the fraud work.
    """


@dataclass
class EmailContext:
    """
    Facts computed once and shared between signals.

    Cross-signal suppression lives here. Several observations are only meaningful
    in combination: an envelope sender that differs from the From domain is the
    normal state of affairs for bulk mail and matters only when DMARC alignment
    has also failed. Computing DMARC once and letting the header signal read it
    avoids two signals independently reporting halves of the same fact.
    """
    dmarc_pass: bool | None = None
    has_trusted_auth_header: bool = False
    chain: ChainAssessment | None = None
    dkim_carried_dmarc: bool = False
    """True when DKIM aligned but SPF did not: the signature of forwarded mail."""


@dataclass
class Config:
    """
    Deployment-specific configuration.

    None of these have sensible universal defaults, which is the point. A tool
    shipped with an empty protected_domains set silently detects nothing, and a
    tool shipped with an empty trusted_authserv_ids set trusts nothing. Both
    failure modes are made explicit at load time rather than discovered later.
    """
    protected_domains: set[str] = field(default_factory=set)
    trusted_authserv_ids: set[str] = field(default_factory=set)
    trusted_mail_hosts: set[str] = field(default_factory=set)
    known_senders: dict[str, int] = field(default_factory=dict)   # address -> prior count
    allowlisted_domains: set[str] = field(default_factory=set)
    high_value_actions: set[str] = field(default_factory=set)


# =========================================================================== #
# ES-HDR-001  Sender identity mismatch
# =========================================================================== #
#
# Threat hypothesis: an attacker who cannot send from a domain will instead make
# the message *look* like it came from it, by putting a trusted name or address in
# the display name while the real address, the reply destination, or the envelope
# sender points elsewhere.
#
# Required fields: From, Reply-To, Return-Path.
# MITRE: T1566.002 (spearphishing link), T1656 (impersonation).

_ADDRESS_IN_TEXT_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def signal_header_mismatch(email: ParsedEmail, config: Config, ctx: EmailContext) -> list[Finding]:
    findings: list[Finding] = []

    from_domain = registrable_domain(
        email.from_address.rpartition("@")[2]
    ).registrable if email.from_address else ""

    # 1. An email address inside the display name that differs from the real one.
    embedded = _ADDRESS_IN_TEXT_RE.findall(email.from_display_name or "")
    for candidate in embedded:
        if candidate.lower() != email.from_address.lower():
            findings.append(Finding(
                signal_id="ES-HDR-001",
                title="Display name contains a different email address",
                weight=35,
                confidence="high",
                evidence=[
                    f"display name shows '{candidate}'",
                    f"actual From address is '{email.from_address}'",
                    "many mail clients show only the display name, so the reader "
                    "sees the first and never the second",
                ],
                benign_explanations=[
                    "some ticketing and CRM systems put the original requester's "
                    "address in the display name when relaying a message",
                ],
                mitre=["T1566.002", "T1656"],
                analyst_actions=[
                    "check whether the embedded address belongs to a real internal user",
                    "confirm with the named sender out of band, not by replying",
                ],
            ))

    # 2. Display name claims a protected organisation, From domain is elsewhere.
    display_skeleton = skeleton(email.from_display_name or "")
    for protected in sorted(config.protected_domains):
        org_label = protected.split(".")[0]
        if not org_label or len(org_label) < 4:
            continue
        if skeleton(org_label) in display_skeleton and from_domain != protected:
            findings.append(Finding(
                signal_id="ES-HDR-001",
                title="Display name claims a protected organisation from an external domain",
                weight=30,
                confidence="medium",
                evidence=[
                    f"display name '{email.from_display_name}' references '{org_label}'",
                    f"From domain is '{from_domain}', not '{protected}'",
                ],
                benign_explanations=[
                    "suppliers, recruiters and partner organisations legitimately "
                    "reference a company name in their display name",
                    "an employee sending from a personal address about work",
                ],
                mitre=["T1656"],
                analyst_actions=[
                    "establish whether the sending domain has any relationship "
                    "with the organisation",
                ],
            ))
            break

    # 3. Reply-To on a different registrable domain from From.
    #
    # Suppressed when DMARC aligns. Marketing platforms, helpdesks and mailing
    # lists all set a Reply-To on another domain as a matter of routine, so on a
    # message that provably came from the domain it claims this observation has
    # essentially no diagnostic value and was the largest single source of false
    # positives in the corpus sweep.
    for reply in ([] if ctx.dmarc_pass else email.reply_to):
        reply_domain = registrable_domain(reply.rpartition("@")[2]).registrable
        if from_domain and reply_domain and reply_domain != from_domain:
            findings.append(Finding(
                signal_id="ES-HDR-001",
                title="Reply-To points to a different domain from From",
                weight=25,
                confidence="medium",
                evidence=[
                    f"From is '{email.from_address}' (domain '{from_domain}')",
                    f"Reply-To is '{reply}' (domain '{reply_domain}')",
                    "a reply goes to the Reply-To address, so the conversation "
                    "continues with whoever controls that domain",
                ],
                benign_explanations=[
                    "mailing lists, marketing platforms and helpdesk systems set "
                    "Reply-To to a different domain as a matter of routine",
                    "a person sending from one address but wanting replies at another",
                ],
                mitre=["T1566.002"],
                analyst_actions=[
                    "check whether the Reply-To domain was registered recently",
                    "look for other messages in the estate with the same Reply-To",
                ],
            ))
            break

    # 4. Return-Path on a different registrable domain from From.
    #
    # Same reasoning, and more strongly: a Return-Path that differs from From is
    # the *expected* state for any mail sent through a bulk platform or forwarded
    # by a list. It only becomes evidence when alignment has failed.
    if email.return_path and from_domain and not ctx.dmarc_pass:
        rp_domain = registrable_domain(email.return_path.rpartition("@")[2]).registrable
        if rp_domain and rp_domain != from_domain:
            findings.append(Finding(
                signal_id="ES-HDR-001",
                title="Envelope sender does not match the From domain",
                weight=15,
                confidence="low",
                evidence=[
                    f"Return-Path domain is '{rp_domain}'",
                    f"From domain is '{from_domain}'",
                ],
                benign_explanations=[
                    "this is the normal state of affairs for any mail sent through "
                    "a bulk sending platform, a mailing list, or a forwarder",
                    "it is only meaningful in combination with a DMARC alignment failure",
                ],
                mitre=["T1566"],
                analyst_actions=[
                    "read this alongside the SPF alignment result rather than alone",
                ],
            ))

    return findings


# =========================================================================== #
# ES-AUTH-002  Authentication and alignment
# =========================================================================== #
#
# Threat hypothesis: an attacker sending as a domain they do not control will fail
# DMARC alignment, because they can neither be listed in that domain's SPF record
# nor sign with its DKIM key.
#
# Required fields: Authentication-Results from a trusted hop, From.
# MITRE: T1585.002 (email accounts), T1566.
#
# The nuance that makes this signal worth building carefully: a *pass* is weak
# evidence of legitimacy, because an attacker's own domain passes its own SPF and
# DKIM happily. Only alignment with the visible From domain means anything.

def signal_authentication(email: ParsedEmail, config: Config, ctx: EmailContext) -> list[Finding]:
    findings: list[Finding] = []

    auth = assess_authentication(
        email.authentication_results,
        email.from_address,
        config.trusted_authserv_ids,
    )

    if auth.untrusted_claims:
        findings.append(Finding(
            signal_id="ES-AUTH-002",
            title="Message carries authentication results from untrusted hops",
            weight=20,
            confidence="high",
            evidence=[
                "an Authentication-Results header is plain text with no integrity "
                "protection, so a sender can add one claiming anything",
                *auth.untrusted_claims,
                "only a header stamped by a mail server under your control is evidence",
            ],
            benign_explanations=[
                "legitimate mail relayed through an intermediate provider often "
                "carries that provider's genuine results",
                "forwarding through a mailing list adds a hop with its own header",
            ],
            mitre=["T1585.002"],
            analyst_actions=[
                "confirm which authserv-id your own boundary uses, and whether the "
                "trusted list in this tool is correct",
            ],
        ))

    if auth.trusted_header is None:
        findings.append(Finding(
            signal_id="ES-AUTH-002",
            title="No authentication result from a trusted server",
            weight=15,
            confidence="low",
            evidence=auth.notes or ["no trusted Authentication-Results header found"],
            benign_explanations=[
                "the receiving server may not perform authentication checks",
                "the trusted authserv-id list may simply be incomplete, which is a "
                "configuration problem in this tool rather than a property of the email",
            ],
            mitre=[],
            analyst_actions=[
                "verify the boundary server's authserv-id before drawing any "
                "conclusion from this finding",
            ],
        ))
        return findings

    if auth.dmarc_pass_computed is False:
        detail = []
        if auth.spf == "pass" and auth.spf_aligned is False:
            detail.append(
                f"SPF passed for '{auth.spf_domain}' but does not align with the "
                f"From domain '{auth.from_domain}'"
            )
        elif auth.spf in {"fail", "softfail", "none", "absent"}:
            detail.append(f"SPF result was '{auth.spf}'")
        if auth.dkim == "pass" and auth.dkim_aligned is False:
            detail.append(
                f"DKIM is valid for '{auth.dkim_domain}' but does not align with "
                f"'{auth.from_domain}'"
            )
        elif auth.dkim in {"fail", "none", "absent"}:
            detail.append(f"DKIM result was '{auth.dkim}'")

        # Forwarding is the ordinary explanation for an alignment failure, and the
        # Received chain can show it directly rather than leaving it as a caveat in
        # the analyst's head. Where the chain corroborates forwarding, the weight
        # drops and the finding says why.
        forwarded = bool(ctx.chain and ctx.chain.forwarded)
        weight = 20 if forwarded else 40
        chain_evidence: list[str] = []
        if forwarded and ctx.chain:
            chain_evidence.append(
                f"the Received chain shows the message passed through "
                f"'{ctx.chain.forwarding_host}', so an SPF alignment failure is "
                "expected here and is weak evidence of spoofing"
            )
        elif ctx.chain and ctx.chain.hops and not ctx.chain.forwarded:
            chain_evidence.append(
                "the Received chain shows no intermediate forwarder, which removes "
                "the most common innocent explanation for this failure"
            )

        findings.append(Finding(
            signal_id="ES-AUTH-002",
            title="DMARC alignment fails for the visible sender domain",
            weight=weight,
            confidence="high",
            evidence=[
                *chain_evidence,
                f"trusted result from '{auth.trusted_header.authserv_id}'",
                *detail,
                "DMARC requires SPF or DKIM to pass *and* to align with the From "
                "domain. Neither did.",
                *auth.notes,
            ],
            benign_explanations=[
                "a mailing list or forwarder rewrites the envelope and breaks SPF "
                "alignment while the message itself is entirely genuine. This is the "
                "single most common false positive for this signal.",
                "a sender whose own DMARC and SPF records are misconfigured",
                "a legitimate third party sending on the domain's behalf without "
                "having been added to its SPF record",
            ],
            mitre=["T1585.002", "T1566"],
            analyst_actions=[
                "check the Received chain for evidence of forwarding before treating "
                "this as spoofing",
                "look up whether the From domain publishes a DMARC policy at all",
            ],
        ))

    if auth.dmarc_pass_computed is True:
        findings.append(Finding(
            signal_id="ES-AUTH-002",
            title="Authentication and alignment pass",
            weight=-20,
            confidence="medium",
            evidence=[
                f"trusted result from '{auth.trusted_header.authserv_id}'",
                f"spf={auth.spf} (domain '{auth.spf_domain}', aligned={auth.spf_aligned})",
                f"dkim={auth.dkim} (domain '{auth.dkim_domain}', aligned={auth.dkim_aligned})",
                "this proves the message came from the domain it claims. It does not "
                "prove the domain is trustworthy, or that the account was not compromised.",
            ],
            benign_explanations=[],
            mitre=[],
            analyst_actions=[
                "if the content is still suspicious, consider account compromise "
                "rather than spoofing",
            ],
        ))

    for note in auth.notes:
        if "discrepancy" in note:
            findings.append(Finding(
                signal_id="ES-AUTH-002",
                title="Reported DMARC result disagrees with computed alignment",
                weight=10,
                confidence="low",
                evidence=[note],
                benign_explanations=[
                    "the receiving server may apply local policy or ARC results this "
                    "tool does not evaluate",
                ],
                mitre=[],
                analyst_actions=["compare against the raw headers by hand"],
            ))

    return findings


# =========================================================================== #
# ES-URL-003  Suspicious links
# =========================================================================== #
#
# Threat hypothesis: the destination of a link in a phishing email is disguised,
# either structurally (userinfo, numeric host, nested redirect) or visually
# (lookalike domain, mismatched anchor text).
#
# Required fields: HTML and text bodies.
# MITRE: T1566.002.

def signal_urls(email: ParsedEmail, config: Config, ctx: EmailContext) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for link in email.links:
        analysed = analyse_url(link.href)
        if analysed.normalised in seen:
            continue
        seen.add(analysed.normalised)

        host = analysed.host
        if not host:
            continue

        domain_view = assess_domain(host, config.protected_domains)

        # Structural obfuscation.
        if analysed.userinfo:
            findings.append(Finding(
                signal_id="ES-URL-003",
                title="Link authority uses the userinfo trick",
                weight=45,
                confidence="high",
                evidence=[
                    f"link: {analysed.original}",
                    f"the text before the @ ('{analysed.userinfo}') is userinfo, not a host",
                    f"the browser will connect to '{host}'",
                ],
                benign_explanations=[
                    "a handful of internal tools still embed credentials in URLs, "
                    "though browsers have deprecated it",
                ],
                mitre=["T1566.002"],
                analyst_actions=["treat the real host as the destination and pivot on it"],
            ))

        if analysed.is_ip_literal:
            weight = 30 if analysed.ip_literal_form == "dotted" else 45
            findings.append(Finding(
                signal_id="ES-URL-003",
                title="Link points at a bare IP address",
                weight=weight,
                confidence="high",
                evidence=[
                    f"link: {analysed.original}",
                    f"host is the IP {host}, written in {analysed.ip_literal_form} form",
                    *analysed.notes,
                ],
                benign_explanations=[
                    "internal monitoring interfaces are often reached by IP, which is "
                    "why a private address is much less alarming than a public one",
                ],
                mitre=["T1566.002"],
                analyst_actions=[
                    "an IP URL cannot present a valid certificate for a brand name, "
                    "so a login page there is illegitimate by construction",
                ],
            ))

        if analysed.unwrap_depth > 0:
            findings.append(Finding(
                signal_id="ES-URL-003",
                title="Link wraps another destination in its query string",
                weight=10,
                confidence="low",
                evidence=[
                    "redirect chain: " + " -> ".join(analysed.redirect_chain),
                    f"final host: {host}",
                ],
                benign_explanations=[
                    "click tracking, SSO return URLs and safe-link rewriting all do "
                    "this on legitimate mail constantly. On its own this means nothing.",
                ],
                mitre=["T1566.002"],
                analyst_actions=["assess the innermost destination, not the wrapper"],
            ))

        if analysed.is_shortener:
            findings.append(Finding(
                signal_id="ES-URL-003",
                title="Link uses a URL shortener",
                weight=15,
                confidence="medium",
                evidence=[
                    f"link: {analysed.original}",
                    f"'{host}' is a known shortening service, so the destination "
                    "cannot be assessed from the message alone",
                ],
                benign_explanations=[
                    "shorteners are used heavily in legitimate marketing and on "
                    "social platforms",
                ],
                mitre=["T1566.002"],
                analyst_actions=[
                    "expand it in a sandboxed environment, never from a workstation, "
                    "and never by clicking from the message",
                ],
            ))

        # Visual deception.
        for match in domain_view.lookalikes:
            if match.kind == "exact_skeleton":
                weight, conf = 50, "high"
            elif match.kind == "subdomain_spoof":
                weight, conf = 40, "high"
            else:
                weight = 35 if match.distance == 1 else 25
                conf = "medium"
            findings.append(Finding(
                signal_id="ES-URL-003",
                title=f"Link domain resembles a protected domain ({match.kind})",
                weight=weight,
                confidence=conf,
                evidence=[
                    f"link: {analysed.original}",
                    match.detail,
                    *domain_view.notes,
                ],
                benign_explanations=[
                    "short domains collide by chance, so a distance of 2 on a brand "
                    "of six characters is much weaker evidence than on one of twelve",
                    "an organisation's own regional or marketing domains often look "
                    "like near misses and should be in the protected set instead",
                ],
                mitre=["T1566.002"],
                analyst_actions=[
                    "check the registration date of the domain",
                    "if it is a homoglyph match there is no innocent explanation; "
                    "block it",
                ],
            ))

        if domain_view.mixed_scripts and not domain_view.lookalikes:
            findings.append(Finding(
                signal_id="ES-URL-003",
                title="Link hostname mixes Unicode scripts",
                weight=30,
                confidence="medium",
                evidence=[
                    f"link: {analysed.original}",
                    f"decoded hostname: {domain_view.decoded_host}",
                    "a hostname that is mostly Latin with isolated Cyrillic or Greek "
                    "characters is characteristic of homoglyph abuse",
                ],
                benign_explanations=[
                    "genuinely non-Latin domains exist and are legitimate; the signal "
                    "here is the mixing, not the script",
                ],
                mitre=["T1566.002"],
                analyst_actions=["compare the decoded form against the brand it resembles"],
            ))

        # Anchor text that names a different host from the href.
        anchor = (link.anchor_text or "").strip()
        if anchor and re.search(r"(?i)\b[a-z0-9\-]+\.[a-z]{2,}\b", anchor):
            anchor_analysed = analyse_url(anchor)
            anchor_host = anchor_analysed.host
            if anchor_host and anchor_host != host:
                anchor_reg = registrable_domain(anchor_host).registrable
                real_reg = registrable_domain(host).registrable
                if anchor_reg != real_reg:
                    findings.append(Finding(
                        signal_id="ES-URL-003",
                        title="Visible link text names a different domain from the destination",
                        weight=40,
                        confidence="high",
                        evidence=[
                            f"the reader sees '{anchor}'",
                            f"the link actually goes to '{host}'",
                        ],
                        benign_explanations=[
                            "safe-link and click-tracking rewriting produces exactly "
                            "this pattern on legitimate mail, so check whether the "
                            "destination belongs to a known security or marketing vendor",
                        ],
                        mitre=["T1566.002"],
                        analyst_actions=[
                            "identify the owner of the destination domain before "
                            "deciding; this is high signal but also the most common "
                            "false positive in gateways that rewrite links",
                        ],
                    ))

    return findings


# =========================================================================== #
# ES-ATT-004  Attachment risk
# =========================================================================== #
#
# Threat hypothesis: the attachment is not what its filename claims, or is a type
# that executes on open.
#
# Required fields: attachment filenames, declared MIME types, payload bytes.
# MITRE: T1566.001, T1204.002.

def signal_attachments(email: ParsedEmail, config: Config, ctx: EmailContext) -> list[Finding]:
    findings: list[Finding] = []

    for attachment in email.attachments:
        result = inspect_attachment(
            attachment.filename,
            attachment.declared_content_type,
            attachment.payload,
            attachment.size_bytes,
        )

        if result.has_bidi_control:
            findings.append(Finding(
                signal_id="ES-ATT-004",
                title="Attachment filename contains a bidirectional override",
                weight=55,
                confidence="high",
                evidence=[f"raw filename: {result.filename!r}", *result.notes],
                benign_explanations=[
                    "none. There is no legitimate reason to place a direction "
                    "override control inside a filename.",
                ],
                mitre=["T1566.001", "T1036.002"],
                analyst_actions=["quarantine and search the estate for the same filename"],
            ))

        if result.double_extension:
            findings.append(Finding(
                signal_id="ES-ATT-004",
                title="Attachment uses a double extension",
                weight=45,
                confidence="high",
                evidence=[f"filename: {result.display_filename}", *result.notes],
                benign_explanations=[
                    "compound extensions such as .tar.gz are normal; this finding "
                    "only fires when the final extension is directly executable",
                ],
                mitre=["T1036.007"],
                analyst_actions=["quarantine"],
            ))

        if result.category == "executable":
            findings.append(Finding(
                signal_id="ES-ATT-004",
                title=f"Attachment is directly executable (.{result.effective_extension})",
                weight=45,
                confidence="high",
                evidence=[
                    f"filename: {result.display_filename}",
                    f"detected type from leading bytes: {result.detected_type}",
                ],
                benign_explanations=[
                    "developers and IT staff exchange scripts and installers "
                    "legitimately, which is why sender history matters here",
                ],
                mitre=["T1566.001", "T1204.002"],
                analyst_actions=[
                    "confirm with the sender out of band whether they attached it",
                ],
            ))

        if result.type_mismatch:
            findings.append(Finding(
                signal_id="ES-ATT-004",
                title="Attachment contents do not match its extension",
                weight=40,
                confidence="high",
                evidence=[f"filename: {result.display_filename}", *result.notes],
                benign_explanations=[
                    "some tools write files with a generic extension, and a few "
                    "formats share container signatures",
                ],
                mitre=["T1036"],
                analyst_actions=["treat the detected type as the real one"],
            ))

        if result.contains_macro_project:
            disguised = result.effective_extension in {"docx", "xlsx", "pptx"}
            findings.append(Finding(
                signal_id="ES-ATT-004",
                title="Attachment contains a VBA macro project",
                weight=50 if disguised else 30,
                confidence="high",
                evidence=[
                    f"filename: {result.display_filename}",
                    "container includes vbaProject.bin",
                    "a .docx cannot legitimately contain a macro project, so the "
                    "extension has been changed to look harmless"
                    if disguised else
                    "the extension correctly advertises macro capability",
                ],
                benign_explanations=[
                    "macro-enabled templates are still used in finance and "
                    "engineering teams, so a .xlsm from a known internal sender is "
                    "routine",
                ],
                mitre=["T1566.001", "T1204.002", "T1059.005"],
                analyst_actions=[
                    "do not open outside a sandbox",
                    "if it is disguised, quarantine without further analysis",
                ],
            ))

        if result.category == "macro" and not result.contains_macro_project:
            findings.append(Finding(
                signal_id="ES-ATT-004",
                title=f"Attachment is a macro-capable format (.{result.effective_extension})",
                weight=15,
                confidence="low",
                evidence=[
                    f"filename: {result.display_filename}",
                    "no macro project was found inside, so the capability is unused",
                ],
                benign_explanations=[
                    "extremely common in legitimate business mail",
                ],
                mitre=["T1566.001"],
                analyst_actions=["no action on this finding alone"],
            ))

        for note in result.notes:
            if "password protected" in note:
                findings.append(Finding(
                    signal_id="ES-ATT-004",
                    title="Attachment is an encrypted archive",
                    weight=35,
                    confidence="medium",
                    evidence=[f"filename: {result.display_filename}", note],
                    benign_explanations=[
                        "sending sensitive documents in an encrypted archive is a "
                        "legitimate and fairly common practice",
                    ],
                    mitre=["T1027.002"],
                    analyst_actions=[
                        "note that the password is usually in the message body, which "
                        "means the sender intended the recipient to bypass scanning",
                    ],
                ))
            elif "entries that can execute" in note:
                findings.append(Finding(
                    signal_id="ES-ATT-004",
                    title="Archive contains executable entries",
                    weight=45,
                    confidence="high",
                    evidence=[f"filename: {result.display_filename}", note],
                    benign_explanations=[
                        "software distribution archives legitimately contain binaries",
                    ],
                    mitre=["T1566.001"],
                    analyst_actions=["quarantine and inspect in a sandbox"],
                ))

    return findings


# =========================================================================== #
# ES-SOC-005  Social engineering pressure
# =========================================================================== #
#
# Threat hypothesis: the message manufactures urgency, authority or fear to push
# the recipient into acting before they verify.
#
# This is the weakest signal in the tool and is weighted accordingly. Keyword
# matching is trivially evaded by rephrasing and fires readily on legitimate mail:
# genuine password expiry notices, genuine invoices and genuine security alerts all
# use this language because they are genuinely urgent. It is included because
# combined with an authentication failure it is meaningful, and alone it is not.
#
# MITRE: T1534, T1566.

PRESSURE_PATTERNS: list[tuple[str, str, int]] = [
    (r"(?i)\b(within|in)\s+\d+\s+(hours?|minutes?|days?)\b", "deadline", 8),
    (r"(?i)\b(immediate(ly)?|urgent(ly)?|as soon as possible|right away)\b", "urgency", 6),
    (r"(?i)\b(will be (suspended|deactivated|deleted|closed|terminated))\b", "threat of loss", 10),
    (r"(?i)\b(fail(ure)? to (respond|act|comply))\b", "consequence framing", 8),
    (r"(?i)\b(final (notice|warning|reminder))\b", "escalation framing", 8),
    (r"(?i)\bdo not (share|forward|tell|discuss)\b", "secrecy request", 12),
    (r"(?i)\b(confidential|discreet(ly)?)\b.{0,40}\b(request|matter|transfer)\b", "secrecy framing", 10),
]

CREDENTIAL_PATTERNS: list[tuple[str, str, int]] = [
    (r"(?i)\b(verify|confirm|validate|update|re-?enter)\b.{0,30}\b(password|credentials?|account|identity)\b", "credential request", 20),
    (r"(?i)\b(sign|log)\s?in\b.{0,40}\b(to (avoid|prevent|restore|reactivate))\b", "login lure", 18),
    (r"(?i)\b(mfa|2fa|multi-?factor|authenticator)\b.{0,40}\b(reset|re-?enrol|re-?register|approve|code)\b", "MFA manipulation", 25),
    (r"(?i)\b(one-?time (code|password|passcode)|otp)\b", "OTP solicitation", 20),
    (r"(?i)\bpassword\s+(expir|reset)", "password lure", 15),
]

PAYMENT_PATTERNS: list[tuple[str, str, int]] = [
    (r"(?i)\b(change|update|amend|new)\b.{0,30}\b(bank|account|payment|remittance|iban|sort code|routing)\b", "payment redirection", 30),
    (r"(?i)\b(wire|transfer|remit)\b.{0,30}\b(urgent|today|immediately|asap)\b", "urgent transfer", 25),
    (r"(?i)\b(invoice|payment)\b.{0,30}\b(overdue|outstanding|unpaid)\b", "invoice pressure", 10),
    (r"(?i)\b(gift cards?|itunes cards?|crypto(currency)?|bitcoin)\b", "untraceable payment", 25),
]


def _scan(text: str, patterns: list[tuple[str, str, int]]) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    for pattern, label, weight in patterns:
        match = re.search(pattern, text)
        if match:
            hits.append((label, weight, match.group(0).strip()))
    return hits


def signal_social_engineering(email: ParsedEmail, config: Config, ctx: EmailContext) -> list[Finding]:
    findings: list[Finding] = []
    haystack = f"{email.subject}\n{email.body_text}\n{email.body_html}"

    groups = [
        ("Credential or MFA solicitation", CREDENTIAL_PATTERNS, ["T1566.002", "T1621"],
         ["genuine password expiry and MFA enrolment notices use identical language",
          "IT service desks send exactly these messages legitimately"],
         ["verify the message against the identity provider's own admin logs",
          "never assess an MFA prompt by the email alone"]),
        ("Payment or banking change request", PAYMENT_PATTERNS, ["T1566", "T1657"],
         ["real suppliers do change bank details, and real invoices do fall overdue",
          "finance teams send urgent payment requests constantly"],
         ["confirm any banking change by telephone using a number held on file, "
          "never a number from the email",
          "require dual authorisation for the change"]),
        ("Pressure and secrecy framing", PRESSURE_PATTERNS, ["T1534"],
         ["deadlines and urgency appear throughout normal business correspondence",
          "this is the single noisiest signal in the tool"],
         ["treat as supporting context only"]),
    ]

    for title, patterns, mitre, benign, actions in groups:
        hits = _scan(haystack, patterns)
        if not hits:
            continue
        total = min(sum(w for _, w, _ in hits), 40)
        findings.append(Finding(
            signal_id="ES-SOC-005",
            title=title,
            weight=total,
            confidence="low",
            # A banking-change request is the one social-engineering finding that
            # authentication cannot help with, because business email compromise
            # sends it from a real, fully authenticated, long-established account.
            suppresses_credit=(title == "Payment or banking change request"),
            evidence=[f"{label}: matched text '{snippet}'" for label, _, snippet in hits],
            benign_explanations=benign,
            mitre=mitre,
            analyst_actions=actions,
        ))

    return findings


# =========================================================================== #
# ES-CTX-006  Sender context
# =========================================================================== #
#
# Threat hypothesis: a first-time sender asking for something consequential is a
# different proposition from a long-standing correspondent doing the same.
#
# This signal is honest fiction. The sender history here is a synthetic dictionary.
# It demonstrates the code path and the reasoning, and proves nothing about
# real-world accuracy, because no real history exists to test against.
#
# MITRE: supporting context, no direct technique.

def signal_sender_context(email: ParsedEmail, config: Config, ctx: EmailContext) -> list[Finding]:
    findings: list[Finding] = []
    address = email.from_address.lower()
    if not address:
        return findings

    domain = registrable_domain(address.rpartition("@")[2]).registrable
    prior = config.known_senders.get(address, 0)

    if domain in config.allowlisted_domains:
        findings.append(Finding(
            signal_id="ES-CTX-006",
            title="Sender domain is allowlisted",
            weight=-25,
            confidence="low",
            evidence=[
                f"'{domain}' appears in the configured allowlist",
                "an allowlist reduces suspicion; it does not establish safety, and it "
                "is exactly what an attacker targets by compromising a trusted partner",
            ],
            benign_explanations=[],
            mitre=[],
            analyst_actions=[
                "if other signals are strong, suspect supplier compromise rather "
                "than treating the allowlist as conclusive",
            ],
        ))
        return findings

    if prior == 0:
        findings.append(Finding(
            signal_id="ES-CTX-006",
            title="First contact from this sender",
            weight=10,
            confidence="low",
            evidence=[
                f"no prior messages recorded from '{address}'",
                "first contact is normal; it matters only alongside a request for "
                "money, credentials or urgency",
            ],
            benign_explanations=[
                "every legitimate correspondent is a first-time sender once",
                "recruitment, sales and supplier onboarding are all first contact",
            ],
            mitre=[],
            analyst_actions=["weigh alongside what the message actually asks for"],
        ))
    elif prior >= 20:
        findings.append(Finding(
            signal_id="ES-CTX-006",
            title="Established correspondent",
            weight=-15,
            confidence="low",
            evidence=[
                f"{prior} prior messages recorded from '{address}'",
                "history reduces the likelihood of a cold spoof but says nothing "
                "about account compromise, where the history is genuine",
            ],
            benign_explanations=[],
            mitre=[],
            analyst_actions=[
                "if authentication also passes and the content is still wrong, "
                "compromise of a real account is the leading hypothesis",
            ],
        ))

    return findings


ALL_SIGNALS = (
    signal_header_mismatch,
    signal_authentication,
    signal_urls,
    signal_attachments,
    signal_social_engineering,
    signal_sender_context,
)


def build_context(email: ParsedEmail, config: Config) -> EmailContext:
    """Compute the facts that more than one signal needs."""
    auth = assess_authentication(
        email.authentication_results,
        email.from_address,
        config.trusted_authserv_ids,
    )
    chain = assess_chain(
        [hop.raw for hop in email.received_hops],
        email.from_address,
        config.trusted_mail_hosts,
        envelope_to=email.to[0] if email.to else "",
    )
    return EmailContext(
        dmarc_pass=auth.dmarc_pass_computed,
        has_trusted_auth_header=auth.trusted_header is not None,
        chain=chain,
        dkim_carried_dmarc=bool(
            auth.dkim == "pass" and auth.dkim_aligned
            and auth.spf != "pass"
        ),
    )


def run_all_signals(email: ParsedEmail, config: Config) -> list[Finding]:
    ctx = build_context(email, config)
    findings: list[Finding] = []
    for signal in ALL_SIGNALS:
        findings.extend(signal(email, config, ctx))
    return findings
