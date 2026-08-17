"""
Tests for EmailShield.

These are written to encode the specific ways each part could be silently wrong,
rather than to raise a coverage number. The negative tests matter more than the
positive ones: a rule that fires on a phish is easy, and a rule that stays quiet
on a mailing list is the whole job.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from src.attachments import inspect_attachment
from src.auth import assess_authentication, parse_auth_results_header
from src.domains import (
    assess_domain,
    damerau_levenshtein,
    decode_punycode_host,
    has_mixed_scripts,
    registrable_domain,
    skeleton,
)
from src.evaluate import score_corpus
from src.main import DEFAULT_CONFIG, DEFAULT_CORPUS, load_config
from src.parse import parse_email_bytes, parse_email_file
from src.score import THRESHOLDS, requires_human_approval, score_findings
from src.signals import Config, Finding, run_all_signals
from src.urls import analyse_url

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def config() -> Config:
    return load_config(DEFAULT_CONFIG)


def triage(name: str, config: Config):
    email = parse_email_file(DEFAULT_CORPUS / name)
    return score_findings(run_all_signals(email, config), config), email


# --------------------------------------------------------------------------- #
# Public suffix handling
# --------------------------------------------------------------------------- #

def test_multi_label_suffix_is_not_split_naively():
    """
    Guards against treating co.uk as the registrable domain.

    Without this, northgate.co.uk and anything-else.co.uk share a registrable
    domain, so every UK domain appears aligned with every other UK domain and
    DMARC alignment becomes meaningless.
    """
    assert registrable_domain("mail.northgate.co.uk").registrable == "northgate.co.uk"
    assert registrable_domain("northgate.co.uk").registrable == "northgate.co.uk"
    assert registrable_domain("a.b.c.northgate.co.uk").registrable == "northgate.co.uk"


def test_unknown_suffix_is_flagged_rather_than_guessed_silently():
    parts = registrable_domain("something.wibblewobble")
    assert parts.suffix_known is False


# --------------------------------------------------------------------------- #
# Edit distance
# --------------------------------------------------------------------------- #

def test_transposition_counts_as_one_edit():
    """
    Plain Levenshtein scores a swap as 2 and would let a convincing typosquat
    fall outside a distance-1 threshold.
    """
    assert damerau_levenshtein("exmaple", "example") == 1
    assert damerau_levenshtein("example", "example") == 0
    assert damerau_levenshtein("", "abc") == 3


# --------------------------------------------------------------------------- #
# Homoglyphs and punycode
# --------------------------------------------------------------------------- #

def test_cyrillic_homoglyph_folds_onto_ascii_skeleton():
    assert skeleton("n\u043erthgate") == skeleton("northgate")


def test_punycode_is_decoded_before_comparison():
    decoded, had = decode_punycode_host("xn--nrthgate-nbh.co.uk")
    assert had is True
    assert decoded != "xn--nrthgate-nbh.co.uk"


def test_homoglyph_domain_is_detected_as_exact_skeleton():
    result = assess_domain("xn--nrthgate-nbh.co.uk", {"northgate.co.uk"})
    kinds = {m.kind for m in result.lookalikes}
    assert "exact_skeleton" in kinds


def test_protected_domain_and_its_subdomains_are_not_lookalikes_of_themselves():
    """A subdomain of a protected domain must not be reported as impersonating it."""
    for host in ("northgate.co.uk", "mail.northgate.co.uk", "identity.northgate.co.uk"):
        result = assess_domain(host, {"northgate.co.uk"})
        assert result.is_protected is True
        assert result.lookalikes == []


def test_protected_domain_in_a_subdomain_of_another_domain_is_a_spoof():
    result = assess_domain("northgate.co.uk.secure-login.example", {"northgate.co.uk"})
    assert result.is_protected is False
    assert any(m.kind == "subdomain_spoof" for m in result.lookalikes)


def test_wholly_non_latin_domain_is_not_flagged_as_mixed_script():
    """
    Mixing scripts is the signal, not the presence of a non-Latin script. A domain
    that is entirely Cyrillic is a normal domain for a Russian-language site.
    """
    assert has_mixed_scripts("\u043f\u0440\u0438\u043c\u0435\u0440") is False
    assert has_mixed_scripts("n\u043erthgate") is True


# --------------------------------------------------------------------------- #
# URL deobfuscation
# --------------------------------------------------------------------------- #

def test_userinfo_does_not_become_the_host():
    result = analyse_url("https://www.northgate.co.uk@evil.example/login")
    assert result.host == "evil.example"
    assert result.userinfo == "www.northgate.co.uk"


@pytest.mark.parametrize("url,expected_form", [
    ("http://192.0.2.5/x", "dotted"),
    ("http://3232235777/x", "decimal"),
    ("http://0xC0A80101/x", "hex"),
])
def test_numeric_host_forms_are_recognised(url, expected_form):
    result = analyse_url(url)
    assert result.is_ip_literal is True
    assert result.ip_literal_form == expected_form


def test_nested_redirect_is_unwrapped_to_the_real_destination():
    result = analyse_url(
        "https://tracking.example/?url=https%3A%2F%2Fevil.example%2Fpay"
    )
    assert result.host == "evil.example"
    assert result.unwrap_depth == 1


def test_redirect_unwrapping_terminates_on_a_self_referential_chain():
    """A crafted loop must not hang the parser."""
    result = analyse_url("https://a.example/?url=https%3A%2F%2Fa.example%2F%3Furl%3D")
    assert result.unwrap_depth <= 5


def test_ordinary_url_is_left_alone():
    result = analyse_url("https://identity.northgate.co.uk/enrol")
    assert result.host == "identity.northgate.co.uk"
    assert result.is_shortener is False
    assert result.is_ip_literal is False
    assert result.userinfo == ""


# --------------------------------------------------------------------------- #
# Authentication: the trusted hop problem
# --------------------------------------------------------------------------- #

def test_forged_auth_header_from_an_untrusted_hop_is_not_believed():
    """
    The core evasion this module exists to stop. The sender supplies their own
    Authentication-Results header claiming everything passed. A tool that searches
    all headers for "pass", or reads them in the wrong order, is fooled.
    """
    result = assess_authentication(
        auth_headers=[
            "mx.attacker.example; spf=pass; dkim=pass; dmarc=pass",
        ],
        from_address="ceo@northgate.co.uk",
        trusted_authserv_ids={"mx1.northgate.co.uk"},
    )
    assert result.trusted_header is None
    assert result.dmarc_pass_computed is None
    assert result.untrusted_claims


def test_topmost_trusted_header_wins_over_a_lower_forged_one():
    result = assess_authentication(
        auth_headers=[
            "mx1.northgate.co.uk; spf=fail smtp.mailfrom=evil.example; "
            "dkim=none; dmarc=fail header.from=northgate.co.uk",
            "mx.attacker.example; spf=pass; dkim=pass; dmarc=pass",
        ],
        from_address="ceo@northgate.co.uk",
        trusted_authserv_ids={"mx1.northgate.co.uk"},
    )
    assert result.trusted_header is not None
    assert result.trusted_header.authserv_id == "mx1.northgate.co.uk"
    assert result.dmarc_pass_computed is False


def test_spf_pass_for_an_unaligned_domain_does_not_pass_dmarc():
    """
    An attacker's own domain passes its own SPF. Only alignment with the visible
    From domain means anything, and conflating the two is the most common way this
    check is got wrong.
    """
    result = assess_authentication(
        auth_headers=[
            "mx1.northgate.co.uk; spf=pass smtp.mailfrom=bulk.evil.example; "
            "dkim=none; dmarc=fail header.from=northgate.co.uk",
        ],
        from_address="ceo@northgate.co.uk",
        trusted_authserv_ids={"mx1.northgate.co.uk"},
    )
    assert result.spf == "pass"
    assert result.spf_aligned is False
    assert result.dmarc_pass_computed is False


def test_relaxed_alignment_accepts_a_subdomain():
    result = assess_authentication(
        auth_headers=[
            "mx1.northgate.co.uk; spf=pass smtp.mailfrom=bounce.northgate.co.uk; "
            "dkim=none",
        ],
        from_address="alerts@northgate.co.uk",
        trusted_authserv_ids={"mx1.northgate.co.uk"},
    )
    assert result.spf_aligned is True
    assert result.dmarc_pass_computed is True


def test_dkim_alone_can_carry_dmarc_when_spf_fails():
    """This is the forwarded-mail case and it must not be treated as spoofing."""
    result = assess_authentication(
        auth_headers=[
            "mx1.northgate.co.uk; spf=fail smtp.mailfrom=list.example; "
            "dkim=pass header.d=calderfreight.example; dmarc=pass "
            "header.from=calderfreight.example",
        ],
        from_address="elena@calderfreight.example",
        trusted_authserv_ids={"mx1.northgate.co.uk"},
    )
    assert result.dmarc_pass_computed is True


def test_comment_text_cannot_smuggle_a_result():
    """CFWS comments are legal; a result hidden inside one must not be parsed."""
    header = parse_auth_results_header(
        "mx1.northgate.co.uk; spf=fail (spf=pass) smtp.mailfrom=evil.example", 0
    )
    assert header.methods["spf"].result == "fail"


def test_empty_trusted_list_trusts_nothing():
    result = assess_authentication(
        auth_headers=["mx1.northgate.co.uk; spf=pass; dkim=pass; dmarc=pass"],
        from_address="a@northgate.co.uk",
        trusted_authserv_ids=set(),
    )
    assert result.trusted_header is None


# --------------------------------------------------------------------------- #
# Attachments
# --------------------------------------------------------------------------- #

def _ooxml(with_macro: bool) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document/>")
        if with_macro:
            archive.writestr("word/vbaProject.bin", b"placeholder")
    return buffer.getvalue()


def test_macro_project_inside_a_docx_is_found():
    result = inspect_attachment("report.docx", "application/octet-stream",
                               _ooxml(with_macro=True))
    assert result.contains_macro_project is True


def test_plain_docx_is_not_reported_as_containing_macros():
    result = inspect_attachment("report.docx", "application/octet-stream",
                               _ooxml(with_macro=False))
    assert result.contains_macro_project is False
    assert result.type_mismatch is False


def test_extension_that_contradicts_the_leading_bytes_is_caught():
    result = inspect_attachment("invoice.pdf", "application/pdf", b"MZ\x90\x00rest")
    assert result.type_mismatch is True
    assert result.detected_type == "windows-executable"


def test_bidi_override_in_filename_is_detected_and_the_real_name_recovered():
    result = inspect_attachment("statement\u202efdp.exe", "application/octet-stream",
                               b"MZ\x90")
    assert result.has_bidi_control is True
    assert result.display_filename.endswith(".exe")


def test_compound_extension_is_not_a_double_extension():
    """archive.tar.gz has two extensions and is entirely ordinary."""
    result = inspect_attachment("archive.tar.gz", "application/gzip", b"\x1f\x8b\x08")
    assert result.double_extension is False


def test_document_then_executable_is_a_double_extension():
    result = inspect_attachment("invoice.pdf.exe", "application/octet-stream", b"MZ\x90")
    assert result.double_extension is True


def test_encrypted_archive_is_noticed():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.txt", "x")
    raw = bytearray(buffer.getvalue())

    # Python's zipfile cannot write an encrypted archive, so the flag is set by
    # hand. It has to be set in two places: the local file header (PK\x03\x04,
    # flags at offset 6) and the central directory entry (PK\x01\x02, flags at
    # offset 8). zipfile.infolist() reads the central directory, so setting only
    # the local header leaves the archive looking unencrypted.
    raw[6] |= 0x01
    central = raw.find(b"PK\x01\x02")
    assert central != -1, "no central directory found in the test archive"
    raw[central + 8] |= 0x01

    result = inspect_attachment("docs.zip", "application/zip", bytes(raw))
    assert any("password protected" in n for n in result.notes)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def test_encoded_subject_is_decoded_before_signals_see_it():
    raw = (
        b"From: a@example\r\n"
        b"To: b@northgate.co.uk\r\n"
        b"Subject: =?utf-8?B?VXJnZW50OiB2ZXJpZnkgeW91ciBwYXNzd29yZA==?=\r\n"
        b"\r\n"
        b"body\r\n"
    )
    email = parse_email_bytes(raw)
    assert "Urgent" in email.subject


def test_anchor_text_and_href_are_kept_separate():
    raw = (
        b"From: a@example\r\nTo: b@northgate.co.uk\r\n"
        b"Subject: t\r\nContent-Type: text/html\r\n\r\n"
        b"<a href='https://evil.example/x'>northgate.co.uk</a>\r\n"
    )
    email = parse_email_bytes(raw)
    assert email.links[0].href == "https://evil.example/x"
    assert email.links[0].anchor_text == "northgate.co.uk"


def test_malformed_message_does_not_raise():
    """
    A parser that crashes is a bypass: the message goes unanalysed. Malformed
    input must degrade to a warning.
    """
    email = parse_email_bytes(b"\xff\xfe not really an email at all")
    assert isinstance(email.parse_warnings, list)


# --------------------------------------------------------------------------- #
# Scoring behaviour
# --------------------------------------------------------------------------- #

def test_a_single_weak_finding_does_not_reach_investigate():
    verdict = score_findings([
        Finding(signal_id="ES-CTX-006", title="First contact from this sender",
                weight=10, confidence="low"),
    ])
    assert verdict.action == "allow"


def test_decisive_finding_sets_a_floor_regardless_of_score():
    """
    Arithmetic must not be able to dilute a finding that has no innocent
    explanation. A bidi override in a filename is one such finding.
    """
    verdict = score_findings([
        Finding(
            signal_id="ES-ATT-004",
            title="Attachment filename contains a bidirectional override",
            weight=5, confidence="high",
        ),
    ])
    assert verdict.action in {"quarantine", "escalate"}


def test_credits_cannot_zero_out_a_payment_change_request():
    """The business email compromise case that scored 0 before this rule existed."""
    findings = [
        Finding(signal_id="ES-SOC-005", title="Payment or banking change request",
                weight=40, confidence="low", suppresses_credit=True),
        Finding(signal_id="ES-AUTH-002", title="Authentication and alignment pass",
                weight=-20, confidence="medium"),
        Finding(signal_id="ES-CTX-006", title="Established correspondent",
                weight=-15, confidence="low"),
    ]
    verdict = score_findings(findings)
    assert verdict.score == 40
    assert verdict.action != "allow"


def test_score_never_goes_negative():
    verdict = score_findings([
        Finding(signal_id="ES-AUTH-002", title="Authentication and alignment pass",
                weight=-20, confidence="medium"),
    ])
    assert verdict.score == 0


def test_confidence_stays_low_when_only_weak_findings_contribute():
    findings = [
        Finding(signal_id="ES-SOC-005", title="Pressure and secrecy framing",
                weight=40, confidence="low"),
        Finding(signal_id="ES-CTX-006", title="First contact from this sender",
                weight=25, confidence="low"),
    ]
    verdict = score_findings(findings)
    assert verdict.score >= THRESHOLDS["quarantine"]
    assert verdict.confidence == "low"
    assert requires_human_approval(verdict) is True


def test_high_confidence_blocking_verdict_does_not_demand_approval():
    findings = [
        Finding(signal_id="ES-AUTH-002",
                title="DMARC alignment fails for the visible sender domain",
                weight=40, confidence="high"),
        Finding(signal_id="ES-URL-003",
                title="Link domain resembles a protected domain (exact_skeleton)",
                weight=50, confidence="high"),
    ]
    verdict = score_findings(findings)
    assert verdict.action in {"quarantine", "escalate"}
    assert requires_human_approval(verdict) is False


def test_silent_signals_are_reported():
    """
    An analyst needs to know what was checked and found nothing, not only what
    fired. Absence of a finding is information.
    """
    verdict = score_findings([
        Finding(signal_id="ES-CTX-006", title="First contact from this sender",
                weight=10, confidence="low"),
    ])
    assert "ES-AUTH-002" in verdict.signals_silent
    assert "ES-CTX-006" not in verdict.signals_silent


# --------------------------------------------------------------------------- #
# End to end against the corpus
# --------------------------------------------------------------------------- #

def test_every_corpus_message_has_a_label():
    labels = json.loads((ROOT / "data" / "labels.json").read_text())
    on_disk = {p.name for p in DEFAULT_CORPUS.glob("*.eml")}
    assert on_disk == set(labels)


def test_whole_corpus_lands_inside_its_action_band(config):
    """
    The calibration check. If a threshold or a weight is changed and this fails,
    the sweep in docs/calibration.md needs redoing rather than the test relaxing.
    """
    wrong = [s for s in score_corpus(config) if not s.correct]
    assert wrong == [], "\n".join(
        f"{s.name}: got {s.action} (score {s.score}), "
        f"expected {s.action_min}..{s.action_max}"
        for s in wrong
    )


def test_forwarded_mail_is_not_treated_as_spoofing(config):
    """The most important false positive in the whole project."""
    verdict, _ = triage("hard-01-forwarded-spf-break.eml", config)
    assert verdict.action == "allow"


def test_genuine_mfa_notice_is_not_quarantined_on_language_alone(config):
    verdict, _ = triage("hard-02-genuine-mfa-reset.eml", config)
    assert verdict.action in {"allow", "investigate"}


def test_bulk_marketing_mail_is_not_quarantined(config):
    """
    Shortener, urgency, and anchor text that differs from the href, all from a
    legitimate sending platform. Before cross-signal suppression this scored 74
    and was quarantined.
    """
    verdict, _ = triage("hard-04-marketing-shortener.eml", config)
    assert verdict.action in {"allow", "investigate"}


def test_internal_script_attachment_is_not_quarantined(config):
    verdict, _ = triage("hard-06-internal-script-attachment.eml", config)
    assert verdict.action in {"allow", "investigate"}


def test_authenticated_homoglyph_phish_is_still_caught(config):
    """
    Proves a DMARC pass is not treated as evidence of legitimacy. This message
    passes SPF, DKIM and DMARC for the attacker's own homoglyph domain.
    """
    verdict, _ = triage("phish-02-homoglyph-domain.eml", config)
    assert verdict.action in {"quarantine", "escalate"}


def test_every_positive_finding_carries_evidence(config):
    """
    A finding with a weight but no evidence is an unexplainable alert, which the
    tool is specifically supposed not to produce.
    """
    for path in sorted(DEFAULT_CORPUS.glob("*.eml")):
        email = parse_email_file(path)
        for finding in run_all_signals(email, config):
            if finding.weight > 0:
                assert finding.evidence, f"{path.name}: {finding.title} has no evidence"


def test_positive_findings_offer_a_benign_explanation_or_state_there_is_none(config):
    """
    Only two findings in the tool are allowed to have no innocent explanation.
    Everything else must state one, because a rule whose author cannot think of a
    false positive has not finished thinking.
    """
    exempt = {
        "Attachment filename contains a bidirectional override",
    }
    for path in sorted(DEFAULT_CORPUS.glob("*.eml")):
        email = parse_email_file(path)
        for finding in run_all_signals(email, config):
            if finding.weight > 0 and finding.title not in exempt:
                assert finding.benign_explanations, (
                    f"{path.name}: {finding.title} lists no benign explanation"
                )


# --------------------------------------------------------------------------- #
# Enforced constraints
# --------------------------------------------------------------------------- #

def test_no_network_access_anywhere_in_the_pipeline(config):
    """
    Turns "this tool makes no network requests" from a claim in the README into
    something enforced.

    Every socket operation is replaced with one that raises, then the entire corpus
    is analysed. If any code path anywhere tries to resolve a name, open a
    connection or fetch a URL, this fails.

    It matters because fetching a URL from a suspicious email confirms to the
    sender that the message was opened and leaks the analyst's egress address.
    """
    import socket as socket_module

    class BlockedSocket(Exception):
        pass

    def refuse(*_args, **_kwargs):
        raise BlockedSocket("network access attempted during analysis")

    saved = {
        name: getattr(socket_module, name, None)
        for name in ("socket", "create_connection", "getaddrinfo",
                     "gethostbyname", "gethostbyname_ex", "gethostbyaddr")
    }
    try:
        for name in saved:
            if saved[name] is not None:
                setattr(socket_module, name, refuse)

        for path in sorted(DEFAULT_CORPUS.glob("*.eml")):
            email = parse_email_file(path)
            verdict = score_findings(run_all_signals(email, config), config)
            assert verdict.action in {"allow", "investigate", "quarantine", "escalate"}
    finally:
        for name, original in saved.items():
            if original is not None:
                setattr(socket_module, name, original)


def test_ingest_output_contains_no_personal_data():
    """
    The metadata dataset must carry no addresses, domains, IPs or URLs.

    The schema in extract_features is the real defence. This asserts the result,
    because a schema that drifts is a schema that leaks.
    """
    import re as re_module
    import sys

    sys.path.insert(0, str(ROOT))
    from tools.ingest_real import build_record

    config = load_config(DEFAULT_CONFIG)
    forbidden = [
        (re_module.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "email address"),
        (re_module.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "IPv4 address"),
        (re_module.compile(r"(?i)https?://"), "URL"),
        (re_module.compile(r"(?i)northgate"), "organisation name"),
        (re_module.compile(r"(?i)\.example\b"), "domain"),
    ]
    for path in sorted(DEFAULT_CORPUS.glob("*.eml")):
        record = build_record(path, path.read_bytes(), "benign", config)
        serialised = json.dumps(record)
        for pattern, description in forbidden:
            assert not pattern.search(serialised), (
                f"{path.name}: ingest record leaked a {description}"
            )


def test_ingest_refuses_to_write_inside_the_repository():
    import sys
    sys.path.insert(0, str(ROOT))
    from tools.ingest_real import in_repo, looks_icloud

    assert in_repo(ROOT / "data" / "real.jsonl") is True
    assert in_repo(Path("/tmp/real.jsonl")) is False
    assert looks_icloud(Path.home() / "Desktop" / "samples") is True
    assert looks_icloud(Path("/tmp/samples")) is False


# --------------------------------------------------------------------------- #
# Received chain
# --------------------------------------------------------------------------- #

def test_untrusted_hops_are_identified_by_our_own_by_clause():
    from src.received import assess_chain

    result = assess_chain(
        received_headers=[
            "from forum.example (203.0.113.44) by mx1.northgate.co.uk; "
            "Tue, 16 Jan 2024 09:12:00 +0000",
            "from mail.calderfreight.example (203.0.113.9) by forum.example; "
            "Tue, 16 Jan 2024 09:11:41 +0000",
        ],
        from_address="elena@calderfreight.example",
        trusted_hosts={"mx1.northgate.co.uk"},
    )
    assert result.boundary_index == 0
    assert len(result.untrusted_hops) == 1


def test_forwarding_is_detected_from_the_chain():
    from src.received import assess_chain

    result = assess_chain(
        received_headers=[
            "from forum.example (203.0.113.44) by mx1.northgate.co.uk; "
            "Tue, 16 Jan 2024 09:12:00 +0000",
            "from mail.calderfreight.example (203.0.113.9) by forum.example; "
            "Tue, 16 Jan 2024 09:11:41 +0000",
        ],
        from_address="elena@calderfreight.example",
        trusted_hosts={"mx1.northgate.co.uk"},
    )
    assert result.forwarded is True
    assert result.forwarding_host == "forum.example"


def test_chain_with_no_trusted_hop_is_reported_as_unusable():
    """
    If no hop names one of our servers, the whole chain is sender-supplied. Saying
    so is the correct behaviour; treating it as a path is not.
    """
    from src.received import assess_chain

    result = assess_chain(
        received_headers=["from a.example by b.example; Tue, 16 Jan 2024 09:00:00 +0000"],
        from_address="x@a.example",
        trusted_hosts={"mx1.northgate.co.uk"},
    )
    assert result.boundary_index is None
    assert any("supplied by the sender" in n for n in result.notes)


def test_forwarding_evidence_reduces_the_alignment_failure_weight(config):
    """
    A DMARC failure on forwarded mail is much weaker evidence than one on directly
    delivered mail, and the chain can show the difference.
    """
    from src.parse import parse_email_bytes
    from src.signals import run_all_signals

    base = (
        b"From: Elena <elena@calderfreight.example>\r\n"
        b"To: dana@northgate.co.uk\r\n"
        b"Subject: contract\r\n"
        b"Authentication-Results: mx1.northgate.co.uk; "
        b"spf=fail smtp.mailfrom=list.example; dkim=none; dmarc=fail\r\n"
    )
    forwarded = base + (
        b"Received: from forum.example (203.0.113.44) by mx1.northgate.co.uk; "
        b"Tue, 16 Jan 2024 09:12:00 +0000\r\n"
        b"Received: from mail.calderfreight.example by forum.example; "
        b"Tue, 16 Jan 2024 09:11:00 +0000\r\n\r\nbody\r\n"
    )
    direct = base + (
        b"Received: from evil.example (198.51.100.7) by mx1.northgate.co.uk; "
        b"Tue, 16 Jan 2024 09:12:00 +0000\r\n\r\nbody\r\n"
    )

    def alignment_weight(raw: bytes) -> int:
        email = parse_email_bytes(raw)
        for finding in run_all_signals(email, config):
            if finding.title == "DMARC alignment fails for the visible sender domain":
                return finding.weight
        return 0

    assert alignment_weight(forwarded) < alignment_weight(direct)


# --------------------------------------------------------------------------- #
# Ablation
# --------------------------------------------------------------------------- #

def test_ablation_reproduces_the_baseline_when_nothing_is_removed(config):
    from src.ablate import load_synthetic, measure

    cases = load_synthetic(config)
    baseline = measure(cases)
    assert baseline.fp == 0
    assert baseline.fn == 0


def test_removing_the_url_signal_costs_recall(config):
    """
    The homoglyph message is caught by ES-URL-003. If removing that signal stops
    costing anything, either the corpus or the signal has changed and the ablation
    write-up needs revisiting.
    """
    from src.ablate import load_synthetic, measure

    cases = load_synthetic(config)
    assert measure(cases, excluded="ES-URL-003").recall < measure(cases).recall
