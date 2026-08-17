# Threshold calibration

This document exists so that no number in `score.py` has to be defended with
"it seemed about right".

Reproduce everything here with:

```bash
python -m src.evaluate
python -m src.evaluate --confusion
```

---

## What is being measured

Every message in `data/corpus/` has an entry in `data/labels.json` with three
fields that matter:

- `label` — the intent of the message, malicious or benign.
- `action_min` and `action_max` — the band of recommended actions that count as
  correct.

Separating the label from the expected action is the most important decision in
this harness. A message can be unambiguously malicious and still be something no
automated tool should quarantine. `hard-05-compromised-supplier.eml` is exactly
that: it authenticates, it aligns, the sender is allowlisted with 88 prior
messages, and the only thing wrong with it is that it asks for a bank account
change. On the evidence available to a machine it is indistinguishable from a
genuine bank-detail change. Its band is `investigate..escalate`, because the
control that catches it is a human telephoning a number held on file.

Collapsing "malicious" into "must be blocked" is how tools end up quarantining
legitimate invoice runs.

---

## Current results

All 14 messages produce an action inside their band.

| Message | Label | Score | Action | Confidence |
|---|---|---|---|---|
| phish-01-credential-harvest | malicious | 219 | escalate | high |
| phish-04-macro-disguised-docx | malicious | 187 | escalate | high |
| phish-03-bidi-attachment | malicious | 150 | escalate | high |
| phish-02-homoglyph-domain | malicious | 110 | escalate | high |
| hard-04-marketing-shortener | benign | 34 | investigate | medium-high |
| hard-05-compromised-supplier | malicious | 30 | investigate | low |
| hard-03-first-contact-invoice | benign | 20 | allow | low |
| hard-06-internal-script-attachment | benign | 10 | allow | medium-high |
| hard-02-genuine-mfa-reset | benign | 8 | allow | low |
| benign-01-internal-notice | benign | 0 | allow | low |
| benign-02-known-supplier-invoice | benign | 0 | allow | low |
| benign-03-meeting-request | benign | 0 | allow | low |
| benign-04-industry-newsletter | benign | 0 | allow | low |
| hard-01-forwarded-spf-break | benign | 0 | allow | low |

---

## The sweep

The quarantine threshold swept from 0 to 160 in steps of 5. Positive cases are the
four messages whose `action_min` is quarantine.

| Threshold | TP | FP | FN | TN | Precision | Recall | First mistake introduced |
|---|---|---|---|---|---|---|---|
| 0 | 4 | 10 | 0 | 0 | 0.29 | 1.00 | blocks every benign message |
| 15 | 4 | 3 | 0 | 7 | 0.57 | 1.00 | |
| 25 | 4 | 2 | 0 | 8 | 0.67 | 1.00 | |
| 30 | 4 | 2 | 0 | 8 | 0.67 | 1.00 | |
| **35 to 110** | **4** | **0** | **0** | **10** | **1.00** | **1.00** | clean band |
| 115 | 3 | 0 | 1 | 10 | 1.00 | 0.75 | misses phish-02-homoglyph-domain |
| 155 | 2 | 0 | 2 | 10 | 1.00 | 0.50 | misses phish-03-bidi-attachment |

**Chosen quarantine threshold: 60.**

Not because it maximises F1. F1 is flat across the whole 35 to 110 band, so
optimising it would pick 35 arbitrarily. 60 is roughly the midpoint of the widest
band with no errors, which is the choice that tolerates the most drift in either
direction before something breaks.

The margins at 60 are worth knowing:

- Nearest false positive below: `hard-04-marketing-shortener` at 34. A 26-point
  margin, or roughly one more finding.
- Nearest true positive above: `phish-02-homoglyph-domain` at 110. A 50-point
  margin.

The investigate threshold of 25 was chosen to catch `hard-04` at 34 and
`hard-05` at 30 while leaving `hard-03-first-contact-invoice` at 20 alone. That
boundary is tight and is the first thing to revisit against real volume.

Escalate at 100 separates the four clear phishing messages from everything else.

**Read the right-hand column, not the F1 column.** F1 computed on fourteen
hand-written messages is noise. Knowing which specific message breaks at each
threshold is the part that transfers.

---

## Two bugs the sweep found

Both were design faults in the scoring, not corpus mistakes, and both were fixed
in the code rather than by adjusting a label.

### 1. Envelope mismatches quarantined legitimate bulk mail

`hard-04-marketing-shortener.eml` scored 74 and was quarantined. The contributions:

```
+40  ES-URL-003  Visible link text names a different domain from the destination
+25  ES-HDR-001  Reply-To points to a different domain from From
-20  ES-AUTH-002  Authentication and alignment pass
+15  ES-HDR-001  Envelope sender does not match the From domain
+15  ES-URL-003  Link uses a URL shortener
-15  ES-CTX-006  Established correspondent
+14  ES-SOC-005  Pressure and secrecy framing
```

The `Reply-To` and `Return-Path` findings were contributing 40 points to a message
that had *provably* come from the domain it claimed. Both findings even listed
"this is normal for bulk senders" in their own benign explanations, and the code
did nothing with that.

**Fix.** Cross-signal suppression. An `EmailContext` computes DMARC once and both
findings are suppressed when alignment passes. An envelope mismatch is only
evidence alongside an alignment failure. Score dropped to 34.

This is the general lesson: the same observation can be evidence or noise depending
on what else is true, and a signal that cannot see the rest of the message will get
it wrong.

### 2. Credits zeroed out a business email compromise

`hard-05-compromised-supplier.eml` scored 0 and was allowed:

```
+30  ES-SOC-005   Payment or banking change request
-20  ES-AUTH-002  Authentication and alignment pass
-15  ES-CTX-006   Established correspondent
```

The credits for passing authentication and long sender history exactly cancelled
the payment-change request. Which is the whole problem with business email
compromise: it arrives from a genuine, authenticated, long-established account, so
those two credits are at their most misleading precisely when they are least
deserved.

**Fix.** A `suppresses_credit` flag on the payment-change finding. When it is
present, negative weights are not applied and the reasoning output says so. Score
became 30, landing at investigate.

Deliberately scoped to payment changes only. Blanket credit suppression on all
credential and MFA language was tried first and pushed
`hard-02-genuine-mfa-reset.eml` to quarantine, which is a real notice from the real
identity provider. Authentication is good evidence for an internal IdP notice and
poor evidence for an external banking change, and the distinction is worth encoding
rather than smoothing over.

### A third bug, in the corpus itself

The first sweep also revealed that every fictional external organisation was a
subdomain of `example.com`, so they all reduced to the same registrable domain.
`calderfreight.example.com` and `northgate-logistics.example.com` appeared aligned
with each other and the allowlist matched the wrong things. The corpus moved to the
RFC 6761 reserved `.example` TLD so each organisation has its own registrable
domain.

Worth recording because it was a bug in the *evaluation*, and a harness that can
produce confidently wrong numbers is worse than no harness.

---

## Honest limits

**Fourteen messages is not a validation set.** Real mail is overwhelmingly benign,
often by four orders of magnitude. The false-positive rate that matters is the one
measured against hundreds of thousands of legitimate messages, and a corpus with a
4:10 ratio cannot estimate it. Precision of 1.00 here means "the four obvious
phishing messages score higher than the ten legitimate ones", which is a much
smaller claim than it looks.

**The corpus was written by the same person who wrote the rules.** Every hard case
exists because a specific failure mode was already in mind. Genuine blind spots do
not appear in a corpus built this way, by definition.

**Weights are ordinal, not measured.** The claim behind "40 for a DMARC failure and
15 for a shortener" is only that the first is stronger evidence than the second.
The ratio is not meaningful.

**No adversarial testing.** Nobody has tried to construct a message that scores 59.

**What would fix this.** A public phishing corpus such as Nazario or the Enron ham
set for volume, and a real mail flow for the benign baseline. Then the sweep would
produce a false-positive rate per thousand messages, which is the number an
operations team actually needs.
