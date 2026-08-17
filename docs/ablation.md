# Ablation

Every signal costs something: code to maintain, false positives to triage, and one
more thing an analyst has to understand. This is the check on whether each one earns
that.

Reproduce with:

```bash
python -m src.ablate
python -m src.ablate --data ~/emailshield-data/real.jsonl   # against real mail
```

Method: remove one signal's findings, re-score every message, recompute precision and
recall. Ablation runs on stored findings rather than on messages, so it also works
against the metadata-only dataset produced by `tools/ingest_real.py`.

---

## Result on the synthetic corpus

```
Dataset: data/corpus (synthetic, 14 messages)
  messages        14  (5 malicious, 9 benign)
  thresholds      investigate>=25, quarantine>=60, escalate>=100

Baseline at current weights and thresholds
----------------------------------------------------------------------------
  true positives       4
  false positives      0
  false negatives      0
  true negatives      10
  precision        1.000
  recall           1.000
  F1               1.000
  FP per 1000 benign  0.00

Ablation: each signal removed in turn
============================================================================
removed          TP   FP   FN   prec  recall     F1     dF1  verdict
----------------------------------------------------------------------------
nothing           4    0    0  1.000   1.000  1.000          baseline
ES-HDR-001        4    0    0  1.000   1.000  1.000  +0.000  no measurable effect
ES-AUTH-002       4    0    0  1.000   1.000  1.000  +0.000  no measurable effect
ES-URL-003        3    0    1  1.000   0.750  0.857  -0.143  carries weight
ES-ATT-004        3    0    1  1.000   0.750  0.857  -0.143  carries weight
ES-SOC-005        4    0    0  1.000   1.000  1.000  +0.000  no measurable effect
ES-CTX-006        4    0    0  1.000   1.000  1.000  +0.000  no measurable effect

Signals with no measurable effect on this dataset:
  ES-HDR-001
  ES-AUTH-002
  ES-SOC-005
  ES-CTX-006

No measurable effect is not the same as no value. Two readings are
possible and they need different responses:
  1. The signal is redundant here because another signal fires on the
     same messages. On a larger corpus it may be the only one that does.
  2. The signal exists for a case this corpus does not contain.

ES-SOC-005 is case 2 and is kept deliberately. It contributes nothing
to precision or recall, and it is the only signal that sees the
compromised-supplier message at all, because that message passes
authentication, is allowlisted, and has a long sender history. A
metric computed over a corpus without enough of those cases cannot
show its value, which is a limitation of the corpus rather than an
argument for deleting the signal.

Threshold headroom
----------------------------------------------------------------------------
  highest-scoring message that must NOT be blocked: 34
  lowest-scoring message that MUST be blocked:      110
  clean separation: any threshold in 35..110 is error-free
  configured: 60

Reminder: this is the synthetic corpus. Every number above is bounded
by the fact that the same person wrote the messages and the rules.
Run tools/ingest_real.py against a public corpus for figures that
mean something, and read docs/real_corpus.md first.
```

---

## What this says

**Two signals carry the metric.** ES-URL-003 and ES-ATT-004. Removing either costs a
true positive, because between them they catch the homoglyph domain and the
bidirectional-override filename, and both of those findings are in `DECISIVE` and set
the action floor directly.

**Four signals show no measurable effect.** ES-HDR-001, ES-AUTH-002, ES-SOC-005 and
ES-CTX-006. That result deserves a straight answer rather than a defence, and the
answer differs by signal.

### ES-AUTH-002 is redundant *here*, and would not be in production

The four messages that must be blocked are all caught by a decisive finding from
another signal. Authentication contributes evidence and confidence to those verdicts
but does not change any action, so removing it costs nothing on this corpus.

That is an artefact of the corpus, not a property of the signal. Every one of the four
phishing messages happens to carry a structural tell as well as an authentication
failure. Real phishing frequently carries only the authentication failure: an
otherwise unremarkable message from a spoofed domain, no lookalike, no attachment, no
obfuscated link. This corpus contains no such message, which is a gap worth adding
rather than a reason to trust the ablation.

It is also the signal doing the most work in the other direction. Its −20 credit and
the forwarding logic underneath it are what keep `hard-01-forwarded-spf-break` and
`hard-04-marketing-shortener` out of the quarantine queue. Ablation measures
contribution to catching things, and a signal whose main job is preventing false
positives is undervalued by that measure. Removing it does not change the action on
those two messages *at the current thresholds*, but it removes the margin.

### ES-HDR-001 overlaps with ES-URL-003 by design

Display-name impersonation and lookalike link domains tend to appear together,
because an attacker doing one usually does the other. On this corpus the URL signal
always fires first and harder. Keeping the header signal is cheap and it covers the
case of an impersonating message with no links at all, which the corpus lacks.

### ES-SOC-005 contributes nothing and is kept deliberately

This is the interesting one.

It adds no precision and no recall. It is the noisiest signal in the tool, it is
trivially evaded by rephrasing, and it is the reason
`hard-04-marketing-shortener` carried 14 points it did not deserve.

It is also **the only signal that sees `hard-05-compromised-supplier` at all.** That
message passes SPF, DKIM and DMARC, comes from an allowlisted domain with 88 prior
messages, has no attachment and no suspicious link. Authentication says it is genuine,
because it is: the account was compromised. Every structural signal is silent. The
only thing wrong with the message is what it asks for, and asking is language.

Business email compromise is among the most expensive categories of email fraud and it
is invisible to every other signal here. A metric that scores this signal at zero is
telling you the corpus does not contain enough of that case, not that the signal is
worthless.

The honest framing: it is retained because the failure mode it covers has no other
coverage, its weight is capped at 40 per group so it cannot reach quarantine alone,
and every finding it produces is marked low confidence so any verdict resting on it
triggers the human-approval requirement. It is not carrying the metric. It is carrying
a risk the metric cannot see.

### ES-CTX-006 is honest fiction

The sender history is a synthetic dictionary. It cannot demonstrate real-world value
because there is no real history behind it. Its contribution is architectural: it
shows where history would attach, and its `-25` allowlist credit is the exact
mechanism that a supplier-compromise attack exploits, which is worth demonstrating
even on invented data.

---

## What to do about it

1. **Add corpus cases that isolate each signal.** A spoofed-domain message with no
   lookalike, no attachment and no obfuscated link would give ES-AUTH-002 something to
   catch on its own. Same for an impersonating message with no links. Both gaps are in
   the corpus, not the code.
2. **Run the ablation against real mail.** Four signals showing no effect on fourteen
   synthetic messages is close to meaningless. On several thousand real ones the
   picture will differ, and probably reverse: ES-AUTH-002 should dominate.
3. **Do not delete a signal on the strength of this table.** The table measures
   contribution to a metric computed over a corpus that was written to test the code.
   Two of the four zero-scoring signals cover failure modes nothing else covers.

---

## The general point

Ablation is the right tool for asking whether a detection earns its place, and it
answers a narrower question than it appears to. It measures marginal contribution to
one metric on one dataset. A signal that prevents false positives, or that covers a
rare and expensive case, scores zero on that measure and should still be kept.

The value is not the ranking. It is being made to state, per signal, exactly why it is
there.
