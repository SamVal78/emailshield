#!/usr/bin/env python3
"""
Build the synthetic EmailShield corpus.

Every message here is fabricated. The fictional organisation is Northgate
Logistics (northgate.co.uk). All addresses are from RFC 5737 documentation ranges
and all external domains use the RFC 6761 reserved .example TLD, which gives each
fictional organisation its own registrable domain. No attachment contains executable code: the "executables" are a two-byte
MZ header followed by ASCII placeholder text, which is enough to exercise the
magic-byte check and nothing else.

The corpus is deliberately weighted towards hard cases. Four obvious phish and
four obvious benign messages prove very little. The six ambiguous ones are where
threshold choices actually get tested, and they are the reason the calibration
sweep in evaluate.py produces a defensible number rather than a flattering one.

Labels are the ground truth used by evaluate.py:
    "malicious" - should end up at quarantine or escalate
    "benign"    - should end up at allow or investigate
The label is the intent of the message, not the action. The mapping from label to
acceptable action lives in evaluate.py so it can be argued about separately.
"""

from __future__ import annotations

import io
import json
import zipfile
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "data" / "corpus"

ORG = "northgate.co.uk"
BOUNDARY = "mx1.northgate.co.uk"          # our trusted authserv-id


# --------------------------------------------------------------------------- #
# Attachment payload builders
# --------------------------------------------------------------------------- #

def fake_pdf(text: str = "placeholder") -> bytes:
    return b"%PDF-1.4\n% synthetic placeholder, not a real PDF\n" + text.encode()


def fake_exe() -> bytes:
    return b"MZ" + b"\x90" * 6 + b"SYNTHETIC-PLACEHOLDER-NOT-A-REAL-EXECUTABLE"


def ooxml(with_macro: bool) -> bytes:
    """A minimal OOXML container, optionally carrying a macro project."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("_rels/.rels", "<Relationships/>")
        archive.writestr("word/document.xml", "<document>synthetic</document>")
        if with_macro:
            archive.writestr(
                "word/vbaProject.bin",
                b"SYNTHETIC-PLACEHOLDER-NO-MACRO-CODE-PRESENT",
            )
    return buffer.getvalue()


def zip_with(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


# --------------------------------------------------------------------------- #
# Message builder
# --------------------------------------------------------------------------- #

def build(
    filename: str,
    subject: str,
    from_header: str,
    to: str,
    text: str,
    html: str | None = None,
    reply_to: str | None = None,
    return_path: str | None = None,
    auth_results: list[str] | None = None,
    received: list[str] | None = None,
    attachments: list[tuple[str, str, bytes]] | None = None,
    extra_headers: list[tuple[str, str]] | None = None,
) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_header
    msg["To"] = to
    msg["Date"] = "Tue, 16 Jan 2024 09:14:02 +0000"
    msg["Message-ID"] = f"<{filename.replace('.eml', '')}@synthetic.invalid>"

    if reply_to:
        msg["Reply-To"] = reply_to
    if return_path:
        msg["Return-Path"] = return_path

    # Headers are prepended in transit, so the topmost is the most recent. The
    # lists below are written topmost-first, which is the order they must appear
    # in the file for the trusted-hop logic to be exercised correctly.
    for value in (auth_results or []):
        msg["Authentication-Results"] = value
    for value in (received or []):
        msg["Received"] = value
    for key, value in (extra_headers or []):
        msg[key] = value

    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")

    for name, content_type, payload in (attachments or []):
        maintype, _, subtype = content_type.partition("/")
        msg.add_attachment(
            payload, maintype=maintype, subtype=subtype, filename=name
        )

        msg.set_boundary(f"===============emailshield-{filename.removesuffix('.eml')}==")
    (CORPUS / filename).write_bytes(msg.as_bytes())


LABELS: dict[str, dict[str, object]] = {}


def label(
    filename: str,
    verdict: str,
    note: str,
    action_min: str | None = None,
    action_max: str | None = None,
) -> None:
    """
    Record ground truth for one message.

    `verdict` is the intent of the message. `action_min` and `action_max` bound the
    range of recommended actions that count as correct, and they are a separate
    judgement from the label.

    The separation matters. A message can be unambiguously malicious and still not
    be something a tool should quarantine automatically: business email compromise
    arrives from a real, authenticated, long-established account, and the only
    honest machine response is to put it in front of a human. Collapsing "this is
    malicious" into "this should be blocked" is how tools end up quarantining
    legitimate invoice runs.
    """
    if action_min is None:
        action_min = "quarantine" if verdict == "malicious" else "allow"
    if action_max is None:
        action_max = "escalate" if verdict == "malicious" else "investigate"
    LABELS[filename] = {
        "label": verdict,
        "action_min": action_min,
        "action_max": action_max,
        "note": note,
    }


# =========================================================================== #
# Obvious phishing
# =========================================================================== #

def phish_credential_harvest() -> None:
    name = "phish-01-credential-harvest.eml"
    build(
        name,
        subject="Action required: your Northgate password expires in 4 hours",
        from_header='"Northgate IT Support" <it-support@northgate-secure.example>',
        to="dana.okafor@northgate.co.uk",
        reply_to="helpdesk@mail-relay.example",
        return_path="bounce@bulk.example",
        auth_results=[
            f"{BOUNDARY}; spf=fail (sender IP is 198.51.100.77) "
            "smtp.mailfrom=bulk.example; dkim=none; dmarc=fail "
            "header.from=northgate-secure.example",
        ],
        received=[
            f"from mail.example (198.51.100.77) by {BOUNDARY}; "
            "Tue, 16 Jan 2024 09:14:02 +0000",
        ],
        text=(
            "Your password will be deactivated within 4 hours.\n\n"
            "Verify your account credentials immediately to avoid suspension:\n"
            "https://northgate.co.uk.secure-login.example/verify\n\n"
            "Northgate IT Support"
        ),
        html=(
            "<html><body><p>Your password will be deactivated within 4 hours.</p>"
            "<p>Please <a href='https://northgate.co.uk.secure-login.example/verify'>"
            "verify your account credentials</a> immediately to avoid suspension.</p>"
            "</body></html>"
        ),
    )
    label(name, "malicious",
          "SPF fail, DMARC fail, subdomain spoof of the protected domain, "
          "credential request with a deadline")


def phish_homoglyph() -> None:
    name = "phish-02-homoglyph-domain.eml"
    build(
        name,
        subject="Invoice NG-4471 ready for approval",
        from_header='"Northgate Finance" <finance@xn--nrthgate-nbh.co.uk>',
        to="dana.okafor@northgate.co.uk",
        auth_results=[
            f"{BOUNDARY}; spf=pass smtp.mailfrom=xn--nrthgate-nbh.co.uk; "
            "dkim=pass header.d=xn--nrthgate-nbh.co.uk; dmarc=pass "
            "header.from=xn--nrthgate-nbh.co.uk",
        ],
        text=(
            "Invoice NG-4471 is ready for your approval.\n\n"
            "https://xn--nrthgate-nbh.co.uk/invoices/4471\n"
        ),
        html=(
            "<html><body><p>Invoice NG-4471 is ready.</p>"
            "<p><a href='https://xn--nrthgate-nbh.co.uk/invoices/4471'>"
            "northgate.co.uk/invoices</a></p></body></html>"
        ),
    )
    label(name, "malicious",
          "authentication passes for the attacker's own homoglyph domain: the "
          "case that proves a DMARC pass is not evidence of legitimacy")


def phish_bidi_attachment() -> None:
    name = "phish-03-bidi-attachment.eml"
    # U+202E reverses display of what follows: the real name ends .exe but the
    # reader sees something ending .pdf
    display_trick = "statement\u202efdp.exe"
    build(
        name,
        subject="Remittance statement attached",
        from_header='"Accounts" <accounts@invoices-portal.example>',
        to="finance@northgate.co.uk",
        auth_results=[
            f"{BOUNDARY}; spf=softfail smtp.mailfrom=invoices-portal.example; "
            "dkim=none; dmarc=fail header.from=invoices-portal.example",
        ],
        text="Please find the remittance statement attached.\n",
        attachments=[(display_trick, "application/octet-stream", fake_exe())],
    )
    label(name, "malicious",
          "bidirectional override in the filename, which has no innocent explanation")


def phish_macro_disguised() -> None:
    name = "phish-04-macro-disguised-docx.eml"
    build(
        name,
        subject="Updated supplier bank details - please action today",
        from_header='"Priya Nandra" <p.nandra@northgate-logistics.example>',
        to="finance@northgate.co.uk",
        reply_to="p.nandra@secure-mail.example",
        auth_results=[
            f"{BOUNDARY}; spf=fail smtp.mailfrom=northgate-logistics.example; "
            "dkim=none; dmarc=fail header.from=northgate-logistics.example",
            "mx.attacker.example; spf=pass; dkim=pass; dmarc=pass",
        ],
        text=(
            "Please find our new bank account details attached.\n"
            "Our previous account is closed, so kindly update the remittance "
            "details and process today. Do not share these details externally.\n"
        ),
        attachments=[(
            "new-bank-details.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ooxml(with_macro=True),
        )],
    )
    label(name, "malicious",
          "payment redirection, macro project inside a .docx, and a forged "
          "Authentication-Results header from an untrusted hop")


# =========================================================================== #
# Obvious benign
# =========================================================================== #

def benign_internal_notice() -> None:
    name = "benign-01-internal-notice.eml"
    build(
        name,
        subject="Office closure: Friday 26 January",
        from_header='"Facilities Team" <facilities@northgate.co.uk>',
        to="all-staff@northgate.co.uk",
        return_path="facilities@northgate.co.uk",
        auth_results=[
            f"{BOUNDARY}; spf=pass smtp.mailfrom=northgate.co.uk; "
            "dkim=pass header.d=northgate.co.uk; dmarc=pass "
            "header.from=northgate.co.uk",
        ],
        text=(
            "The Leeds office will be closed on Friday 26 January for planned "
            "electrical work. Please work from home that day.\n"
        ),
    )
    label(name, "benign", "internal, fully aligned authentication, no links")


def benign_supplier_invoice() -> None:
    name = "benign-02-known-supplier-invoice.eml"
    build(
        name,
        subject="Invoice 88214 from Calder Freight",
        from_header='"Calder Freight Accounts" <accounts@calderfreight.example>',
        to="finance@northgate.co.uk",
        return_path="accounts@calderfreight.example",
        auth_results=[
            f"{BOUNDARY}; spf=pass smtp.mailfrom=calderfreight.example; "
            "dkim=pass header.d=calderfreight.example; dmarc=pass "
            "header.from=calderfreight.example",
        ],
        text=(
            "Invoice 88214 is attached, payable on the usual 30 day terms.\n"
            "Bank details are unchanged.\n"
        ),
        attachments=[("invoice-88214.pdf", "application/pdf", fake_pdf("invoice"))],
    )
    label(name, "benign", "allowlisted supplier, aligned auth, PDF matches its bytes")


def benign_calendar() -> None:
    name = "benign-03-meeting-request.eml"
    build(
        name,
        subject="Depot review, Thursday 10:00",
        from_header='"Marcus Bell" <marcus.bell@northgate.co.uk>',
        to="dana.okafor@northgate.co.uk",
        auth_results=[
            f"{BOUNDARY}; spf=pass smtp.mailfrom=northgate.co.uk; "
            "dkim=pass header.d=northgate.co.uk; dmarc=pass "
            "header.from=northgate.co.uk",
        ],
        text="Can we move the depot review to Thursday at 10:00? Marcus\n",
    )
    label(name, "benign", "internal colleague, established sender")


def benign_newsletter() -> None:
    name = "benign-04-industry-newsletter.eml"
    build(
        name,
        subject="Freight Weekly: capacity outlook for Q1",
        from_header='"Freight Weekly" <news@freightweekly.example>',
        to="dana.okafor@northgate.co.uk",
        reply_to="no-reply@freightweekly.example",
        return_path="bounce-1182@mailer.example",
        auth_results=[
            f"{BOUNDARY}; spf=pass smtp.mailfrom=mailer.example; "
            "dkim=pass header.d=freightweekly.example; dmarc=pass "
            "header.from=freightweekly.example",
        ],
        text=(
            "This week: capacity outlook, fuel duty consultation, port delays.\n"
            "Read online: https://freightweekly.example/2024/03\n"
        ),
        html=(
            "<html><body><p>This week: capacity outlook.</p>"
            "<p><a href='https://freightweekly.example/2024/03'>Read online</a></p>"
            "</body></html>"
        ),
    )
    label(name, "benign",
          "bulk sender: Return-Path and Reply-To both differ from From, which is "
          "normal for mailing platforms and must not alone raise the action")


# =========================================================================== #
# Hard cases. These are the ones that decide whether the thresholds are any good.
# =========================================================================== #

def hard_forwarded_spf_break() -> None:
    name = "hard-01-forwarded-spf-break.eml"
    build(
        name,
        subject="FW: Contract amendment for signature",
        from_header='"Elena Marsh" <elena.marsh@calderfreight.example>',
        to="dana.okafor@northgate.co.uk",
        return_path="listserv@logistics-forum.example",
        auth_results=[
            f"{BOUNDARY}; spf=fail (envelope from logistics-forum.example) "
            "smtp.mailfrom=logistics-forum.example; "
            "dkim=pass header.d=calderfreight.example; dmarc=pass "
            "header.from=calderfreight.example",
        ],
        received=[
            f"from forum.example (203.0.113.44) by {BOUNDARY}; "
            "Tue, 16 Jan 2024 09:12:00 +0000",
            "from mail.calderfreight.example (203.0.113.9) by forum.example; "
            "Tue, 16 Jan 2024 09:11:41 +0000",
        ],
        text=(
            "Forwarding the contract amendment for your signature, as discussed.\n"
            "Please return it by Friday.\n"
        ),
        attachments=[("amendment-v3.pdf", "application/pdf", fake_pdf("amendment"))],
    )
    label(name, "benign",
          "SPF fails because a mailing list rewrote the envelope, but DKIM still "
          "aligns. The single most important false positive to get right.")


def hard_genuine_mfa_reset() -> None:
    name = "hard-02-genuine-mfa-reset.eml"
    build(
        name,
        subject="Your MFA device has been reset",
        from_header='"Northgate Identity" <no-reply@northgate.co.uk>',
        to="dana.okafor@northgate.co.uk",
        auth_results=[
            f"{BOUNDARY}; spf=pass smtp.mailfrom=northgate.co.uk; "
            "dkim=pass header.d=northgate.co.uk; dmarc=pass "
            "header.from=northgate.co.uk",
        ],
        text=(
            "Your multi-factor authenticator has been reset by the service desk.\n"
            "You must re-register a device within 24 hours or your account will be "
            "suspended.\n"
            "Re-enrol: https://identity.northgate.co.uk/enrol\n"
        ),
        html=(
            "<html><body><p>Your authenticator has been reset. You must re-register "
            "within 24 hours or your account will be suspended.</p>"
            "<p><a href='https://identity.northgate.co.uk/enrol'>Re-enrol your "
            "device</a></p></body></html>"
        ),
    )
    label(name, "benign",
          "textbook phishing language used entirely legitimately by the real IdP. "
          "Tests whether ES-SOC-005 alone can push a message to quarantine.")


def hard_new_supplier_invoice() -> None:
    name = "hard-03-first-contact-invoice.eml"
    build(
        name,
        subject="Invoice 0041 - Harrowgate Pallets (new supplier)",
        from_header='"Harrowgate Pallets" <accounts@harrowgatepallets.example>',
        to="finance@northgate.co.uk",
        return_path="accounts@harrowgatepallets.example",
        auth_results=[
            f"{BOUNDARY}; spf=pass smtp.mailfrom=harrowgatepallets.example; "
            "dkim=pass header.d=harrowgatepallets.example; dmarc=pass "
            "header.from=harrowgatepallets.example",
        ],
        text=(
            "Please find our first invoice attached, 0041, payment outstanding on "
            "receipt. Our bank details are on the invoice.\n"
        ),
        attachments=[("invoice-0041.pdf", "application/pdf", fake_pdf("0041"))],
    )
    label(name, "benign",
          "first contact plus payment language plus an attachment, all legitimate. "
          "Tests that context signals do not accumulate into a quarantine.")


def hard_marketing_shortener() -> None:
    name = "hard-04-marketing-shortener.eml"
    build(
        name,
        subject="Last chance: warehouse automation webinar tomorrow",
        from_header='"Meridian Events" <events@meridianevents.example>',
        to="dana.okafor@northgate.co.uk",
        reply_to="replies@meridian-mailer.example",
        return_path="bounce@meridian-mailer.example",
        auth_results=[
            f"{BOUNDARY}; spf=pass smtp.mailfrom=meridian-mailer.example; "
            "dkim=pass header.d=meridianevents.example; dmarc=pass "
            "header.from=meridianevents.example",
        ],
        text=(
            "Final reminder: our webinar starts tomorrow at 14:00. Register "
            "immediately to secure a place: https://bit.ly/mrdn-web\n"
        ),
        html=(
            "<html><body><p>Final reminder, register immediately.</p>"
            "<p><a href='https://bit.ly/mrdn-web'>meridianevents.example/register</a>"
            "</p></body></html>"
        ),
    )
    label(name, "benign",
          "shortener, urgency, and anchor text that does not match the href, all "
          "from a genuine marketing platform. The hardest benign case in the set.")


def hard_compromised_supplier() -> None:
    name = "hard-05-compromised-supplier.eml"
    build(
        name,
        subject="RE: Invoice 88214 - updated remittance account",
        from_header='"Calder Freight Accounts" <accounts@calderfreight.example>',
        to="finance@northgate.co.uk",
        return_path="accounts@calderfreight.example",
        auth_results=[
            f"{BOUNDARY}; spf=pass smtp.mailfrom=calderfreight.example; "
            "dkim=pass header.d=calderfreight.example; dmarc=pass "
            "header.from=calderfreight.example",
        ],
        text=(
            "Further to invoice 88214, our bank account has changed. Please update "
            "the remittance details to the new account below and process payment "
            "today. Kindly keep this confidential until our announcement.\n"
        ),
    )
    label(name, "malicious",
          "fully authenticated, allowlisted, established sender, and still "
          "malicious because the account is compromised. Authentication cannot "
          "detect this; only the payment-change request can. Correct outcome is "
          "investigate rather than quarantine: on the evidence available to the "
          "tool this is indistinguishable from a genuine bank-detail change, and "
          "the control that catches it is a human telephoning a number held on "
          "file, not an automated block.",
          action_min="investigate")


def hard_it_script_attachment() -> None:
    name = "hard-06-internal-script-attachment.eml"
    build(
        name,
        subject="Rollout script for the depot terminals",
        from_header='"Marcus Bell" <marcus.bell@northgate.co.uk>',
        to="it-team@northgate.co.uk",
        auth_results=[
            f"{BOUNDARY}; spf=pass smtp.mailfrom=northgate.co.uk; "
            "dkim=pass header.d=northgate.co.uk; dmarc=pass "
            "header.from=northgate.co.uk",
        ],
        text="Here's the rollout script we discussed. Run it on the test terminal first.\n",
        attachments=[(
            "deploy-terminals.ps1",
            "text/plain",
            b"# synthetic placeholder, no commands\nWrite-Output 'placeholder'\n",
        )],
    )
    label(name, "benign",
          "a directly executable attachment sent legitimately by a known internal "
          "colleague. Tests that extension category alone does not quarantine.")


def main() -> None:
    CORPUS.mkdir(parents=True, exist_ok=True)
    for existing in CORPUS.glob("*.eml"):
        existing.unlink()

    for builder in (
        phish_credential_harvest, phish_homoglyph, phish_bidi_attachment,
        phish_macro_disguised,
        benign_internal_notice, benign_supplier_invoice, benign_calendar,
        benign_newsletter,
        hard_forwarded_spf_break, hard_genuine_mfa_reset, hard_new_supplier_invoice,
        hard_marketing_shortener, hard_compromised_supplier,
        hard_it_script_attachment,
    ):
        builder()

    (CORPUS.parent / "labels.json").write_text(
        json.dumps(LABELS, indent=2, sort_keys=True) + "\n"
    )

    print(f"wrote {len(LABELS)} messages to {CORPUS}")
    for name, meta in sorted(LABELS.items()):
        print(f"  {meta['label']:10} {name}")


if __name__ == "__main__":
    main()
