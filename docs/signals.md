# EmailShield signals

Six signals. Each one is documented under the same eight headings, because a rule
without a stated hypothesis, a false-positive profile and a tuning story is not
finished.

Weights are integers. They are not probabilities and they are not calibrated
against real mail volume. The reasoning behind each number is in
[calibration.md](calibration.md).

---

## ES-HDR-001 Sender identity mismatch

**1. Threat hypothesis.** An attacker who cannot send from a domain will instead
make the message look as though it came from it. The display name is the easiest
place to do this, because most mail clients show it and hide the address behind
it. The reply destination and the envelope sender are the next easiest.

**2. Required fields.** `From`, `Reply-To`, `Return-Path`.

**3. Detection logic.** Four separate checks.

| Check | Weight | Notes |
|---|---|---|
| An email address inside the display name that differs from the real `From` address | 35 | High confidence. The reader sees one address, the mail goes to another |
| Display name references a protected organisation while `From` is an external domain | 30 | Compared on the confusable-folded skeleton, so `N0rthgate` matches |
| `Reply-To` registrable domain differs from `From` | 25 | Suppressed entirely when DMARC aligns |
| `Return-Path` registrable domain differs from `From` | 15 | Suppressed entirely when DMARC aligns |

**4. MITRE.** T1566.002, T1656.

**5. Expected false positives.**
- Ticketing and CRM systems put the original requester's address in the display
  name when relaying.
- Suppliers, recruiters and partners legitimately name a company in their display
  name.
- Every mailing list, marketing platform and helpdesk sets a `Reply-To` on another
  domain. This was the single largest false-positive source in the corpus sweep,
  which is why the last two checks are now gated on DMARC.

**6. Synthetic test data.** `phish-01-credential-harvest.eml` (display name claims
Northgate IT, external domain, `Reply-To` elsewhere) against
`benign-04-industry-newsletter.eml` and `hard-04-marketing-shortener.eml`, which
both have a mismatched `Reply-To` and `Return-Path` and are entirely legitimate.

**7. Analyst steps.** Establish whether the sending domain has any relationship
with the organisation. Check the registration date of the `Reply-To` domain. Never
confirm by replying to the message.

**8. Effect on the score.** Additive. The strongest single check reaches 35, which
alone lands at *investigate* and not at *quarantine*, deliberately.

---

## ES-AUTH-002 Authentication and alignment

**1. Threat hypothesis.** An attacker sending as a domain they do not control
cannot make DMARC align, because they can neither appear in that domain's SPF
record nor sign with its DKIM key.

**2. Required fields.** `Authentication-Results` from a trusted hop, and `From`.

**3. Detection logic.** This is the signal most often got wrong, in three ways.

*The trusted hop.* An `Authentication-Results` header is plain text with no
integrity protection. A sender can add their own claiming `spf=pass; dkim=pass;
dmarc=pass`. Headers are prepended in transit, so the topmost is the one added
last, by the server closest to the recipient. The module walks from the top and
takes the first header whose authserv-id is in the configured trusted set. Every
other header is reported as an unverifiable claim, weight 20. If no trusted header
exists, no authentication conclusion is drawn at all.

*Alignment, not result.* A `pass` proves the message came from wherever it says it
came from at the envelope or signature level. An attacker's own domain passes its
own SPF happily. What matters is whether the passing domain shares a registrable
domain with the visible `From`. Relaxed alignment (the DMARC default) is used, so
`bounce.northgate.co.uk` aligns with `northgate.co.uk`.

*The registrable domain.* Alignment needs public suffix handling. Without it,
`northgate.co.uk` and `attacker.co.uk` share the "domain" `co.uk` and everything
aligns with everything.

| Outcome | Weight |
|---|---|
| DMARC alignment fails | +40 |
| Untrusted hops supplied their own results | +20 |
| No trusted header at all | +15 |
| Reported DMARC disagrees with computed alignment | +10 |
| Alignment passes | −20 |

**4. MITRE.** T1585.002, T1566.

**5. Expected false positives.** Mailing lists and forwarders rewrite the envelope
and break SPF alignment on entirely genuine mail. This is the most important false
positive in the project and the reason `hard-01-forwarded-spf-break.eml` exists:
SPF fails, DKIM still aligns, DMARC therefore passes, and the message must be
allowed. Also senders with their own misconfigured SPF, and third parties sending
on a domain's behalf without being listed in its SPF record.

**6. Synthetic test data.** `hard-01-forwarded-spf-break.eml`,
`phish-04-macro-disguised-docx.eml` (carries a forged header from
`mx.attacker.example` below the genuine one), and
`phish-02-homoglyph-domain.eml`, which passes everything for the attacker's own
domain.

**7. Analyst steps.** Read the `Received` chain for evidence of forwarding before
treating an alignment failure as spoofing. Check whether the `From` domain
publishes a DMARC policy at all. Confirm your own boundary authserv-id before
trusting anything this signal says.

**8. Effect on the score.** The 40 for an alignment failure is the largest single
weight from a non-decisive finding, and it is still below the quarantine threshold
of 60 on its own. A DMARC failure by itself is not sufficient grounds to remove
mail from someone's inbox.

**The pass is weaker than it looks.** `phish-02` authenticates perfectly. So does
`hard-05-compromised-supplier`. Authentication answers "did this come from the
domain it claims", not "is this message safe".

---

## ES-URL-003 Suspicious links

**1. Threat hypothesis.** The destination is disguised, either structurally or
visually.

**2. Required fields.** HTML and plain-text bodies, with `href` and anchor text
kept separate.

**3. Detection logic.**

*Structural.*

| Finding | Weight |
|---|---|
| Userinfo trick, `https://bank.com@evil.example/` | 45 |
| IP literal in decimal, hex or octal form | 45 |
| IP literal in ordinary dotted form | 30 |
| Known URL shortener | 15 |
| A nested URL in the query string | 10 |

*Visual.*

| Finding | Weight |
|---|---|
| Registrable domain with an identical confusable skeleton to a protected domain | 50 |
| A protected domain appearing as a subdomain label of another registrable domain | 40 |
| Anchor text naming a different registrable domain from the `href` | 40 |
| Edit distance 1 from a protected domain | 35 |
| Hostname mixing Unicode scripts | 30 |
| Edit distance 2 from a protected domain | 25 |

Lookalike detection runs after punycode decoding and confusable folding, and
compares registrable domains against the configured `protected_domains`. With an
empty protected set this signal detects no impersonation at all, which the CLI
warns about at load.

**4. MITRE.** T1566.002.

**5. Expected false positives.**
- Safe-link rewriting and click tracking produce anchor-text mismatches and nested
  redirects on legitimate mail constantly.
- Shorteners are heavily used in genuine marketing.
- Short brand names collide by chance, so distance 2 on a six-character brand is
  much weaker evidence than on a twelve-character one.
- An organisation's own regional and campaign domains look like near misses and
  belong in `protected_domains` rather than being detected as attacks on it.

**6. Synthetic test data.** `hard-04-marketing-shortener.eml` has a shortener and
an anchor mismatch and is benign. `phish-02-homoglyph-domain.eml` uses
`xn--nrthgate-nbh.co.uk`, which decodes to a Cyrillic-o spelling of northgate and
folds onto the same skeleton.

**7. Analyst steps.** Expand shorteners in a sandbox, never from a workstation and
never by clicking in the message. Check domain registration dates. For an exact
skeleton match there is no innocent explanation, so block it.

**8. Effect on the score.** An exact skeleton match is in `DECISIVE` and raises the
action floor to quarantine regardless of arithmetic.

**Design constraint.** The tool never resolves a URL. Fetching one confirms to the
sender that the message was read and leaks the analyst's egress address.

---

## ES-ATT-004 Attachment risk

**1. Threat hypothesis.** The attachment is not what its filename claims, or is a
type that executes when opened.

**2. Required fields.** Filename, declared MIME type, and the payload bytes.

**3. Detection logic.**

| Finding | Weight |
|---|---|
| Bidirectional override character in the filename | 55 |
| Macro project inside a container claiming to be `.docx` / `.xlsx` / `.pptx` | 50 |
| Double extension where the last one is directly executable | 45 |
| Directly executable extension | 45 |
| Archive containing executable entries | 45 |
| Leading bytes contradict the extension | 40 |
| Password-protected archive | 35 |
| Macro project in a correctly named macro format | 30 |
| Macro-capable format with no macro present | 15 |

Three checks are worth spelling out. Magic-byte comparison catches an `invoice.pdf`
whose bytes begin `MZ`. Container inspection opens the OOXML ZIP with the standard
library and looks for `vbaProject.bin`, which is how a `.docm` renamed to `.docx`
is caught. And `U+202E` in a filename makes the displayed name differ from the real
one, which has no legitimate use.

**4. MITRE.** T1566.001, T1204.002, T1036.002, T1036.007, T1027.002, T1059.005.

**5. Expected false positives.** Developers and IT staff exchange scripts and
installers legitimately, which is why sender context matters here. Compound
extensions such as `.tar.gz` are normal and are explicitly not treated as double
extensions. Encrypted archives are a legitimate way to send sensitive documents.

**6. Synthetic test data.** `phish-03-bidi-attachment.eml`,
`phish-04-macro-disguised-docx.eml`, `hard-06-internal-script-attachment.eml` (a
`.ps1` sent legitimately by a known colleague, which must not be quarantined), and
`benign-02-known-supplier-invoice.eml`.

**7. Analyst steps.** Confirm out of band that the sender attached it. Do not open
macro-bearing files outside a sandbox. For a bidi override, quarantine without
further analysis and search the estate for the same filename.

**8. Effect on the score.** Bidi overrides and double extensions are in `DECISIVE`.
Everything else is additive, so a `.ps1` from an established internal colleague
reaches 45 and then receives credits, landing at *allow*.

**Limits.** This is structural checking, not malware analysis. It cannot tell a
benign macro from a malicious one, and it does not detect an exploit in a
well-formed PDF.

---

## ES-SOC-005 Social engineering pressure

**1. Threat hypothesis.** The message manufactures urgency, authority, fear or
secrecy to make the recipient act before verifying.

**2. Required fields.** Subject and body, decoded.

**3. Detection logic.** Three pattern groups, each capped at 40 so a message
cannot reach the quarantine threshold on language alone.

| Group | Strongest patterns |
|---|---|
| Credential and MFA solicitation | MFA reset or re-enrolment (25), OTP solicitation (20), credential verification (20) |
| Payment and banking change | Bank detail change (30), urgent transfer (25), gift cards or crypto (25) |
| Pressure and secrecy | Secrecy request (12), threat of account loss (10), deadline (8) |

Every finding in this signal is marked low confidence. The payment group
additionally sets `suppresses_credit`.

**4. MITRE.** T1534, T1566, T1621, T1657.

**5. Expected false positives.** This is the noisiest signal in the tool by a wide
margin. Genuine password expiry notices, genuine MFA resets, genuine overdue
invoices and genuine urgent payment requests all use identical language, because
they are genuinely urgent. It is also the easiest signal to evade: rephrasing
defeats it entirely.

**6. Synthetic test data.** `hard-02-genuine-mfa-reset.eml` is the control. It
contains "reset", "within 24 hours", "will be suspended" and "re-register", and it
is a real notice from the real identity provider. It scores 8 and lands at *allow*.

**7. Analyst steps.** Treat as supporting context only. For any banking change,
telephone a number held on file, never one from the email, and require dual
authorisation.

**8. Effect on the score.** Group caps prevent accumulation. Low confidence on
every finding means a verdict resting only on this signal reports low confidence,
which triggers the human-approval requirement in `score.py`.

**Why keep such a weak signal.** Because it is the only signal that can see the
compromised-supplier case at all. Authentication passes, the sender is allowlisted
and has 88 prior messages, and the only thing wrong with the message is what it
asks for.

---

## ES-CTX-006 Sender context

**1. Threat hypothesis.** A first-time sender asking for something consequential is
a different proposition from a long-standing correspondent doing the same.

**2. Required fields.** `From`, plus configured sender history and allowlist.

**3. Detection logic.**

| Finding | Weight |
|---|---|
| First contact from this sender | +10 |
| Established correspondent, 20 or more prior messages | −15 |
| Sender domain is allowlisted | −25 |

**4. MITRE.** Supporting context, no direct technique.

**5. Expected false positives.** Every legitimate correspondent is a first-time
sender once. Recruitment, sales and supplier onboarding are all first contact. In
the other direction, an allowlist is exactly what an attacker targets: compromise
a trusted supplier and the allowlist works for them.

**6. Synthetic test data.** `hard-03-first-contact-invoice.eml` combines first
contact, payment language and an attachment, all legitimate, and scores 20.

**7. Analyst steps.** Weigh alongside what the message actually asks for. If
authentication passes, history is long and the content is still wrong, account
compromise is the leading hypothesis rather than spoofing.

**8. Effect on the score.** Negative weights reduce the total but can never take it
below zero, and are withheld entirely when a payment-change finding is present.

**This signal is honest fiction.** The history is a synthetic dictionary in
`data/config.json`. It demonstrates the code path and the reasoning. It says
nothing about real-world accuracy, because there is no real history to test
against.
