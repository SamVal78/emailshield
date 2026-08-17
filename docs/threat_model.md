# Threat model

## What this is

A command-line triage prototype. It reads one saved `.eml` file, evaluates six
signals against it, and prints a score, the evidence behind that score, and a
recommended action.

## What this is not

Not an email gateway. It does not sit in a mail path, does not receive or send
mail, does not connect to a mailbox, and does not take action on anything. It has
no service, no queue, no persistence and no API. Deploying it in front of real mail
would require every part of that missing infrastructure plus a great deal of
evidence it does not currently have.

## Deliberate design constraints

**No network access, anywhere.** Not for URL resolution, not for DNS, not for
reputation lookups, not for DKIM key retrieval.

Fetching a URL from a suspicious email is an active step with two costs. It
confirms to the sender that the message reached a live recipient and was opened,
which for a targeted campaign is useful intelligence. And it exposes the analyst's
egress address, which tells the sender something about the organisation and lets
them serve different content to that address next time. Neither is worth the
convenience.

The consequence is stated plainly: this tool cannot tell you where a shortener
leads or whether a domain resolves. It reports that it cannot.

**No DNS means no verification.** SPF, DKIM and DMARC results are read from headers
that a receiving server wrote. Nothing is verified here. The code says "the trusted
server reported dkim=pass", never "DKIM passed".

**No content execution or sandboxing.** Attachments are inspected structurally.
Nothing is opened, rendered or run.

## Trust boundaries

| Input | Trust | Why |
|---|---|---|
| Message body and subject | None | Entirely attacker-controlled |
| `From`, `Reply-To`, `Return-Path` | None | All attacker-settable |
| Attachment filenames and MIME types | None | Claims made by the sender |
| Attachment bytes | None as content, useful as structure | Magic bytes are harder to fake than a name, but not impossible |
| `Authentication-Results` from an untrusted authserv-id | None | Plain text, no integrity protection, sender can add any number |
| `Authentication-Results` from a trusted authserv-id | Yes, and this is the only trusted input | Written by a server under our control |
| `Received` headers | Lower hops untrusted | Prepended in transit; anything below our own boundary is sender-supplied |
| `data/config.json` | Trusted | Local configuration |

The single most important line in that table is the split between the two
`Authentication-Results` rows. Everything the tool can say with confidence rests on
correctly identifying which header its own infrastructure wrote.

## Evasion

Where a competent attacker would go, roughly in order of ease.

**Rephrase the social engineering.** ES-SOC-005 is regex over English. "Kindly
update the remittance particulars at your earliest convenience" defeats the payment
patterns. Non-English mail defeats all of them. This is the weakest part of the tool
and is weighted to reflect it.

**Use an unrelated domain that passes its own DMARC.** No lookalike, no
impersonation, no authentication failure. `notifications-portal.example` sending as
itself. ES-AUTH-002 gives it a −20 credit. Only the content signals see anything,
and they are the weak ones.

**Compromise a real account.** Defeats authentication, sender history and the
allowlist simultaneously. `hard-05` is this case and the tool can only reach
*investigate* on it.

**Host the payload on a legitimate service.** A link to a file on a mainstream cloud
storage or documentation platform has no structural or visual tell at all. Nothing
in ES-URL-003 fires.

**Put the lure in an image.** No text to match, no links to parse. There is no OCR
here.

**Use a lookalike domain that is not near any protected domain.**
`northgate-invoices-portal.example` is not an edit-distance match for
`northgate.co.uk` and would not be caught by the lookalike logic. It is a
combosquat, and catching those needs brand-token matching rather than edit
distance, which is not implemented.

**Sit just under the threshold.** With the weights visible in the repository, an
attacker can compose a message scoring 59. This is an inherent property of a
published static scoring model.

**Nest the payload beyond inspection.** An encrypted archive with the password in
the body. Detected as encrypted, weight 35, contents unknowable.

**Exploit the public suffix subset.** The bundled suffix list is a documented
subset. A domain under a suffix not in it gets a two-label fallback, which can put
the registrable-domain boundary in the wrong place and break both alignment and
lookalike comparison. The code flags when it has fallen back, but the flag does not
currently change the weighting.

## Privacy

Email is among the most sensitive data an organisation holds. Notes for anyone
tempted to point this at real mail:

- The corpus is synthetic and committed. Real `.eml` files must never be, and
  `.gitignore` excludes `*.eml` outside `data/corpus/` for that reason.
- Full message bodies appear in the output, including in `--json`. Anything that
  captures that output inherits the sensitivity of the mail.
- Sender history is personal data. The synthetic version in `config.json` is a
  dictionary of made-up addresses. A real equivalent would need a retention policy
  and a lawful basis.
- Analysing someone's mail without their knowledge has consent and employment-law
  implications that are outside the scope of the code.

## Operational trade-offs

**Quarantine is not free.** A false negative is one incident. A false positive on an
invoice run is a hundred complaints, a delayed payment, and staff who start asking
to have the tool turned off. The costs are asymmetric and not in the direction
people assume, which is why `requires_human_approval()` exists and why the action
band for a benign message includes *investigate*.

**Automation requires high confidence, not just a high score.** `score.py` returns
score and confidence separately. A verdict of quarantine built from three
low-confidence keyword findings is flagged for human approval; the same action built
from a DMARC failure plus a homoglyph domain is not. Score answers how much
evidence there is, confidence answers how good it is, and collapsing them hides the
distinction that matters.

**Explainability is a control, not a nicety.** An analyst who cannot see why a
message scored 74 cannot overrule it, cannot tune it, and will eventually stop
reading its output.

## Known limitations

- Six signals. Real gateways run hundreds, plus reputation feeds, plus clustering
  across messages.
- No cross-message correlation. A campaign sending the same lure to forty staff is
  forty independent verdicts.
- No state and no persistence between runs.
- Sender history is synthetic.
- The public suffix list is a subset, not the real list.
- Confusable mapping is a hand-built subset of the Unicode data.
- No ARC evaluation, so legitimately forwarded mail that relies on ARC is not
  handled.
- No `Received` chain analysis beyond capturing the headers.
- English-language patterns only.
- No image or OCR analysis.
- No attachment content analysis.
- Thresholds calibrated on fourteen synthetic messages. See
  [calibration.md](calibration.md) for why that number should not be trusted.
