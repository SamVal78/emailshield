# EmailShield

An explainable phishing triage prototype. It reads one saved `.eml` file, evaluates
six signals against it, and prints a risk score, the evidence behind that score, and
a recommended analyst action.

**This is a defensive portfolio prototype built entirely on synthetic data.** It is
not an email gateway, it never touches a real mailbox, and it makes no network
requests of any kind. What it is and is not appears in full in
[docs/threat_model.md](docs/threat_model.md).

---

## The point of it

Any tool can print "this is phishing". The useful part is the reasoning, because
somebody has to decide whether to act on it and then defend that decision.

So every finding carries the evidence behind it, the innocent explanations to rule
out first, and what to check next. The score is separated from the confidence, since
a total of 74 built from keyword matches is a different situation from the same 74
built from a DMARC failure plus a homoglyph domain. And the thresholds were
calibrated by sweeping them against a labelled corpus rather than picked by feel.

The calibration harness found two real bugs in the scoring model. Both are written
up in [docs/calibration.md](docs/calibration.md), along with what was wrong and why
the fix was made in the code rather than by adjusting a label.

---

## Quick start

```bash
git clone <your-repo-url>
cd emailshield
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m src.main --all --brief      # triage the whole corpus
python -m src.main data/corpus/phish-02-homoglyph-domain.eml
python -m src.evaluate                # threshold sweep
python -m src.ablate                  # which signals earn their place
pytest                                # 58 tests
```

The analysis code is **standard library only**. `requirements.txt` contains test
tooling and nothing else. If pytest is unavailable, `python3 tools/run_tests.py`
runs the same suite.

Exit status is `1` when the recommended action is quarantine or escalate, so the
tool can be used in a pipeline.

---

## The six signals

| ID | Detects | Heaviest finding | MITRE |
|---|---|---|---|
| **ES-HDR-001** | Sender identity mismatch across `From`, `Reply-To`, `Return-Path` and display name | 35 | T1566.002, T1656 |
| **ES-AUTH-002** | SPF, DKIM and DMARC alignment, read only from a trusted hop | 40 | T1585.002 |
| **ES-URL-003** | Userinfo tricks, numeric hosts, nested redirects, shorteners, homoglyphs, typosquats | 50 | T1566.002 |
| **ES-ATT-004** | Magic-byte mismatch, macro containers, double extensions, bidi overrides | 55 | T1566.001, T1204.002 |
| **ES-SOC-005** | Urgency, credential and MFA lures, payment redirection | 40 (capped) | T1534, T1657 |
| **ES-CTX-006** | Sender history and allowlist context | −25 to +10 | supporting |

`Received` chain analysis (`src/received.py`) sits underneath ES-AUTH-002 rather
than being a signal of its own. It finds where our own estate ends, treats
everything below that as sender-supplied, and detects forwarding directly. Where the
chain shows an intermediate forwarder, the weight for a DMARC alignment failure drops
from 40 to 20, because forwarding is the ordinary explanation for that failure.

Each is documented under eight headings in [docs/signals.md](docs/signals.md):
threat hypothesis, required fields, detection logic, MITRE mapping, expected false
positives, test data, analyst steps, and effect on the score.

---

## Sample output

```
==========================================================================
ESCALATE     score 110   confidence high
phish-02-homoglyph-domain.eml
==========================================================================
From    : 'Northgate Finance' <finance@xn--nrthgate-nbh.co.uk>
Subject : Invoice NG-4471 ready for approval

Why this score
--------------------------------------------------------------------------

  [ +50] ES-URL-003  Link domain resembles a protected domain (exact_skeleton)
         confidence: high   MITRE: T1566.002
         - link: https://xn--nrthgate-nbh.co.uk/invoices/4471
         - 'nоrthgate.co.uk' renders identically to 'northgate.co.uk' after
           confusable folding (both reduce to 'northgate.co.uk')
         - hostname used punycode; decodes to 'nоrthgate.co.uk'
         - hostname mixes Unicode scripts, which is characteristic of homoglyph abuse
         benign explanations to rule out first:
           . short domains collide by chance, so a distance of 2 on a brand of six
             characters is much weaker evidence than on one of twelve
         next steps:
           > check the registration date of the domain
           > if it is a homoglyph match there is no innocent explanation; block it

  [ -20] ES-AUTH-002  Authentication and alignment pass
         ...
```

That message passes SPF, DKIM and DMARC, and is still escalated. Authentication
answers "did this come from the domain it claims", not "is this message safe".

---

## Three things worth reading the code for

### The trusted hop problem

An `Authentication-Results` header is plain text with no integrity protection.
Anyone can add one to a message they send, claiming `spf=pass; dkim=pass;
dmarc=pass`. Its meaning comes entirely from *who wrote it*.

Headers are prepended in transit, so the topmost is the one added last, by the
server closest to the recipient. `src/auth.py` walks from the top and takes the
first header whose authserv-id is in the configured trusted set. Everything else is
reported as an unverifiable claim by the sender.

A tool that searches all headers for "pass", or reads them in the wrong order, is
bypassed with one extra header. `phish-04-macro-disguised-docx.eml` in the corpus
carries a forged one for exactly this reason.

A second trap sits behind the first. A `pass` is not evidence of legitimacy, because
an attacker's own domain passes its own SPF happily. What matters is **alignment**:
whether the passing domain shares a registrable domain with the visible `From`. And
alignment needs public suffix handling, because without it `northgate.co.uk` and
`attacker.co.uk` share the "domain" `co.uk` and everything aligns with everything.

### Lookalike domains

Three separate problems that are often conflated, all in `src/domains.py`:

- **Registrable domain extraction.** `mail.example.co.uk` cannot be compared to
  anything until you know `co.uk` is a public suffix.
- **Homoglyphs.** `xn--nrthgate-nbh.co.uk` decodes to a Cyrillic-o spelling of
  northgate. Punycode is decoded, then characters are folded onto an ASCII skeleton,
  and two strings with the same skeleton are indistinguishable to a reader.
- **Typosquats.** Damerau-Levenshtein rather than plain Levenshtein, because a
  transposition is one edit to a human and two to Levenshtein, and `exmaple.com` is
  a very convincing squat.

All three need a comparison set. Edit distance against nothing is meaningless, so
`protected_domains` is explicit configuration and the CLI warns when it is empty.

### URL deobfuscation

`src/urls.py` unwraps what an attacker does to hide a destination:

| Trick | Example | Resolves to |
|---|---|---|
| Userinfo | `https://www.bank.com@evil.example/` | `evil.example` |
| Decimal IP | `http://3232235777/` | `192.168.1.1` |
| Hex IP | `http://0xC0A80101/` | `192.168.1.1` |
| Nested redirect | `?url=https%3A%2F%2Fevil.example` | `evil.example` |

Unwrapping is depth-bounded so a crafted loop cannot hang the parser, and anchor
text is kept separate from the `href` throughout, because the gap between what the
reader sees and where the link goes is the whole point.

---

## Repository layout

```
emailshield/
├── src/
│   ├── parse.py          MIME walking, RFC 2047 decoding, link and attachment extraction
│   ├── urls.py           URL deobfuscation and normalisation
│   ├── domains.py        public suffix, punycode, confusables, edit distance
│   ├── auth.py           trusted-hop Authentication-Results parsing, DMARC alignment
│   ├── attachments.py    magic bytes, OOXML containers, filename tricks
│   ├── signals.py        the six signals
│   ├── score.py          scoring, thresholds, action mapping, approval requirement
│   ├── received.py       Received chain parsing, trust boundary, forwarding
│   ├── evaluate.py       threshold sweep and confusion reporting
│   ├── ablate.py         ablation study and real-corpus evaluation
│   └── main.py           CLI
├── data/
│   ├── corpus/           14 synthetic .eml files
│   ├── labels.json       ground truth plus acceptable action bands
│   └── config.json       protected domains, trusted authserv-ids, synthetic history
├── tests/                58 tests
├── tools/
│   ├── build_corpus.py   regenerates the corpus
│   ├── ingest_real.py    defanging airlock for real email corpora
│   ├── splunk_export.py  verdicts as Splunk-ready NDJSON
│   └── run_tests.py      pytest stand-in for environments without it
├── .github/workflows/    CI: tests, calibration, ablation, lint
└── docs/
    ├── signals.md        the eight-point write-up per signal
    ├── calibration.md    the sweep, the thresholds, the bugs it found
    ├── ablation.md       what each signal contributes, and what it does not
    ├── threat_model.md   scope, trust boundaries, evasion, privacy, limits
    ├── real_corpus.md    how to validate against real mail without harm
    ├── splunk.md         SPL searches, including cross-project correlation
    └── interview_prep.md questions to be able to answer about this code
```

---

## The corpus

Fourteen synthetic messages against a fictional organisation, Northgate Logistics.
All external domains use the RFC 6761 reserved `.example` TLD so each fictional
organisation has its own registrable domain. All IP addresses are from RFC 5737
documentation ranges. No attachment contains executable code: the "executables" are
a two-byte `MZ` header followed by ASCII placeholder text.

Four obvious phishing messages and four obvious benign ones prove very little. The
six hard cases are the ones that decide whether the thresholds are any good:

| Message | Why it is hard |
|---|---|
| `hard-01-forwarded-spf-break` | SPF fails because a mailing list rewrote the envelope. DKIM still aligns. Genuine. The most important false positive in the project |
| `hard-02-genuine-mfa-reset` | "Reset", "within 24 hours", "will be suspended", "re-register". Textbook phishing language, entirely legitimate, from the real identity provider |
| `hard-03-first-contact-invoice` | First contact, payment language, attachment. All legitimate |
| `hard-04-marketing-shortener` | Shortener, urgency, and anchor text that does not match the href, from a real marketing platform |
| `hard-05-compromised-supplier` | Authenticates, allowlisted, 88 prior messages, and malicious. Asks for a bank account change |
| `hard-06-internal-script-attachment` | A `.ps1` sent legitimately by a known colleague |

---

## Design decisions

**No network access, anywhere.** Resolving a URL from a suspicious email confirms to
the sender that it was opened and leaks the analyst's egress address. The tool
reports that it cannot expand a shortener rather than expanding one.

**No verification is claimed.** SPF and DKIM results are read from a header a
receiving server wrote. The output says "the trusted server reported dkim=pass",
never "DKIM passed".

**Weak signals stay weak.** The social engineering patterns are capped at 40 per
group and marked low confidence, because a message must not be able to reach the
quarantine threshold on language alone. `hard-02` is the control that proves it.

**Two findings can override arithmetic.** A bidirectional override in a filename and
a domain that folds onto a protected domain's skeleton both raise the action floor
regardless of score, because neither has an innocent explanation.

**Cross-signal suppression.** A `Reply-To` on another domain is normal for bulk mail
and only meaningful alongside an alignment failure, so DMARC is computed once and
those findings are suppressed when it passes. The same observation can be evidence
or noise depending on what else is true.

**Credits are withheld where they mislead.** Business email compromise arrives from
a genuine, authenticated, long-established account. Letting those credits offset a
banking-change request scored the most expensive category of fraud at zero, which is
what the code did before `suppresses_credit` existed.

**Two constraints are enforced rather than documented.** A test replaces every
socket operation with one that raises, then analyses the whole corpus, so "makes no
network requests" fails the build if it ever stops being true. And another asserts
that the metadata dataset produced from real mail contains no addresses, domains, IPs
or URLs.

**High-impact actions need approval, not just a score.** `requires_human_approval()`
returns true for any quarantine or escalate that rests on less than high-confidence
evidence. A false negative is one incident; a false positive on an invoice run is a
hundred complaints and a tool nobody trusts.

---

## Limitations

Stated plainly, because a detection project claiming completeness is not credible.

- **Fourteen messages is not a validation set.** Real mail is overwhelmingly benign,
  often by four orders of magnitude. Precision of 1.00 here means the four obvious
  phishing messages score higher than the ten legitimate ones, which is a much
  smaller claim than it appears.
- **The corpus author wrote the rules.** Genuine blind spots cannot show up in a
  corpus built this way, by definition.
- **Weights are ordinal, not measured.** The claim behind 40 and 15 is only that the
  first is stronger evidence.
- **Keyword patterns are English and trivially evaded** by rephrasing.
- **The public suffix list is a documented subset**, not the real one. The code
  reports when it has fallen back to a two-label guess.
- **Confusable mapping is a hand-built subset** of the Unicode data.
- **No ARC, no `Received` chain analysis, no OCR, no attachment content analysis, no
  cross-message correlation, no persistence.**
- **The scoring model is published**, so a message can be composed to score 59.

Fuller analysis, including where a competent attacker would go first, is in
[docs/threat_model.md](docs/threat_model.md).

**On the synthetic corpus, four of the six signals show no measurable effect on
precision or recall.** The ablation in [docs/ablation.md](docs/ablation.md) reports
that plainly, along with which are redundant and which are kept deliberately for
cases the corpus does not contain. [docs/real_corpus.md](docs/real_corpus.md) is the
procedure for getting figures that are not self-graded, and it is written to be
followed without putting live malware in an iCloud folder.

## Ethics

Defensive only. All data synthetic. No exploitation code, no credential-access
tooling, no automated enforcement: every path outputs an analyst recommendation.
`.gitignore` excludes `*.eml` outside `data/corpus/` so real mail cannot be
committed by accident.
