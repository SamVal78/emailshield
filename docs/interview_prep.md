# Interview preparation

Questions to be able to answer about this repository without reading the code. If a
question here is uncomfortable, that is where to spend the time.

Answer in your own words. A rehearsed paragraph sounds rehearsed.

---

## On the authentication signal

**Why is an `Authentication-Results` header not evidence on its own?**

It is plain text with no integrity protection. Anyone can add one to a message they
send. Its meaning comes from who wrote it, so only a header stamped by a server
under your control counts.

**How do you know which one that is?**

Headers are prepended as a message travels, so the topmost is the most recent and
closest to the recipient. The code walks from the top and takes the first header
whose authserv-id is in the trusted set.

**A message arrives with `spf=pass; dkim=pass; dmarc=pass` from your own boundary
server. Is it safe?**

No. It came from the domain it claims. Two cases survive that: the domain itself
belongs to the attacker, and the account has been compromised. `phish-02` in the
corpus is the first and `hard-05` is the second, and both authenticate cleanly.

**What is alignment and why does it matter more than the result?**

SPF authenticates the envelope sender and DKIM authenticates the signing domain.
Neither is the `From` header a reader sees. DMARC requires one of them to pass *and*
to share a registrable domain with `From`. An attacker's own domain passes its own
SPF, so without the alignment check a pass means nothing.

**Why do you need a public suffix list for that?**

Alignment compares registrable domains. Without knowing `co.uk` is a public suffix,
`northgate.co.uk` and `attacker.co.uk` both reduce to `co.uk` and everything aligns
with everything.

**Your suffix list is a subset of the real one. What breaks?**

A domain under an unlisted suffix falls back to a two-label guess, which can put the
boundary in the wrong place and break both alignment and lookalike comparison. The
code flags when it has fallen back. It does not currently weight that uncertainty,
which it arguably should.

---

## On false positives

**Which false positive worries you most?**

Legitimately forwarded mail. A mailing list rewrites the envelope, SPF fails against
the list's domain, and the message is entirely genuine. `hard-01` is that case: SPF
fails, DKIM still aligns, DMARC passes, and it must be allowed. Treating every SPF
failure as spoofing would quarantine a large fraction of normal traffic.

**Why does a benign message get an acceptable band of allow *or* investigate?**

Because sending a borderline message to a human is not a failure. Quarantining it
is. The band encodes that difference.

**Your marketing email scored 74 and was quarantined. What did you do?**

The `Reply-To` and `Return-Path` findings were contributing 40 points to a message
that had provably come from the domain it claimed. Both findings already listed
"normal for bulk senders" in their own benign explanations, and the code ignored
that. I added cross-signal suppression: DMARC is computed once and both findings are
dropped when alignment passes. It fell to 34.

**How would you reduce false positives further without losing detection?**

Three things in order. Get a real benign baseline, because I cannot measure a false
positive rate against ten messages. Add the organisation's own regional and campaign
domains to the protected set so they stop looking like near misses. And make the
weak signals conditional rather than additive, so keyword matches only count when
something structural has already fired.

---

## On scoring

**Why is the quarantine threshold 60?**

The sweep shows perfect separation anywhere from 35 to 110. F1 is flat across that
whole band, so optimising it would pick 35 arbitrarily. 60 is near the midpoint,
which tolerates the most drift in either direction before something breaks. Nearest
false positive is 26 points below, nearest true positive 50 points above.

**Why not just pick the highest F1?**

F1 on fourteen hand-written messages is noise. The useful output of the sweep is
which specific message breaks at each threshold, not the metric.

**Why are score and confidence separate?**

Score is how much evidence there is. Confidence is how good it is. Three keyword
matches can accumulate the same total as a DMARC failure plus a homoglyph domain,
and those are different situations. Collapsing them hides the thing that decides
whether to act automatically.

**Something scores 30 and is malicious. Is that a failure?**

Not necessarily. `hard-05` is business email compromise: authenticated, allowlisted,
88 prior messages, asking for a bank detail change. On the evidence available to a
machine it is indistinguishable from a genuine change. Investigate is the correct
answer, and the control that catches it is a person telephoning a number held on
file.

**Why can two findings override the score entirely?**

A bidirectional override in a filename and a domain that folds onto a protected
domain's skeleton have no innocent explanation. Arithmetic should not be able to
dilute them, so they set a floor on the action.

**Explain `suppresses_credit`.**

Passing authentication and a long sender history normally reduce suspicion. For a
banking-change request they are actively misleading, because compromise produces
both. Before I added the flag, that message scored zero. Now credits are withheld
when a payment-change finding is present, and the reasoning output says so.

**Why only payment changes, not credential requests too?**

I tried the broader version first and it pushed `hard-02` to quarantine, which is a
genuine MFA notice from the real identity provider. Authentication is good evidence
for an internal notice and poor evidence for an external banking change.

---

## On evasion

**How would you get a message past this?**

Rephrase the social engineering, since the patterns are English regex. Or send from
an unrelated domain that passes its own DMARC, with the payload hosted on a
mainstream cloud service, and put the lure in an image. Nothing structural fires and
there is no OCR. Or compromise a real account, which defeats authentication, history
and the allowlist at once.

**The weights are in a public repository. Is that a problem?**

Yes, and it is inherent to a published static model. A message can be composed to
score 59. Mitigations are non-public weights, randomised thresholds, or moving to a
model where a single strong structural finding is sufficient rather than additive.

**What is a combosquat and why does edit distance miss it?**

`northgate-invoices-portal.example`. It is nowhere near `northgate.co.uk` by edit
distance but reads as related to a human. Catching it needs brand-token matching
rather than distance, which is not implemented.

---

## On the wider design

**Why does the tool never fetch a URL?**

Two reasons. It confirms to the sender that the message reached a live recipient and
was opened, which for a targeted campaign is useful to them. And it leaks the
analyst's egress address, so they can serve different content to it next time. The
cost is that the tool cannot say where a shortener leads, and it reports that
honestly.

**When should a high-impact action require human approval rather than being
automated?**

When the confidence does not match the impact. `requires_human_approval()` returns
true for any quarantine or escalate resting on less than high-confidence evidence.
The costs are asymmetric in the direction people do not expect: a missed phish is
one incident, a wrongly quarantined invoice run is a hundred complaints and a tool
the business stops trusting.

**Why is a benign email so easily mistaken for phishing?**

Because the features overlap almost completely. Real password resets are urgent.
Real invoices are overdue. Real suppliers do change bank details. Real marketing
uses shorteners and rewrites links. Legitimate bulk mail has a `Reply-To` on another
domain and fails SPF alignment through forwarders. Nearly every individual signal
appears in normal traffic, which is why weights are small, caps exist, and
combination matters more than any single observation.

**What would you build next?**

A real benign baseline, because every number in the calibration document is limited
by that. Then `Received` chain analysis to distinguish forwarding from spoofing
directly rather than inferring it from DKIM. Then cross-message correlation, since a
campaign hitting forty staff currently produces forty independent verdicts.

**Describe this project honestly in one sentence.**

A defensive triage prototype on synthetic data that produces explainable phishing
verdicts, with thresholds calibrated against a labelled corpus and its limitations
documented.

**What it is not:** a production email security platform. It has no service, no mail
path integration, no persistence, and a fourteen-message evaluation set.

---

## On the ablation

**Four of your six signals show no measurable effect. Why keep them?**

Because ablation measures marginal contribution to one metric on one dataset, and
that is a narrower question than "is this signal worth having". Two of the four cover
failure modes nothing else covers. ES-SOC-005 scores zero and is the only signal that
sees the compromised-supplier message, which passes authentication, is allowlisted and
has 88 prior messages. ES-AUTH-002 scores zero because every phishing message in my
corpus also carries a structural tell, which is a gap in the corpus rather than a
property of the signal.

**So your corpus is inadequate?**

Yes, and the ablation is how I found out. It has no spoofed-domain message that lacks
a lookalike, an attachment and an obfuscated link, which is a common real shape and
would be caught by authentication alone. That is written up as the first thing to fix.

**Which signal would dominate on real mail?**

ES-AUTH-002, almost certainly. Most phishing fails DMARC alignment and carries nothing
else structural. My corpus is unrepresentative in exactly the way that hides it.

**A signal that prevents false positives scores zero on ablation. Does that bother
you?**

It is the main weakness of the method. Removing ES-AUTH-002 does not change any action
at the current thresholds, but its credit and the forwarding logic are what keep the
forwarded contract and the marketing email out of the quarantine queue. It removes the
margin without moving the metric. A better measure would sweep thresholds with the
signal removed and report how much headroom is lost.

---

## On real-corpus validation

**Why is a false-positive rate per thousand more useful than precision?**

Precision depends on the ratio of malicious to benign mail in your sample. Real mail is
overwhelmingly benign, often by four orders of magnitude, so precision measured on a
half-and-half corpus is meaningless operationally. False positives per thousand benign
messages converts directly into helpdesk workload, which is the thing anyone deciding
whether to deploy it will ask about.

**You handled real phishing samples. How did you do that safely?**

A `.eml` on disk is inert, and the tool never renders, never fetches and never writes
an attachment to disk. The risk is in handling. So: Terminal only, never Finder,
because double-clicking hands it to Mail.app and Quick Look renders it. Nothing in
Desktop, Documents or iCloud Drive, because syncing malware to Apple is a problem.
Nothing inside the repository. Samples deleted after ingest.

**And the privacy side?**

The ingest step writes derived findings only: a truncated hash, the label, the score,
the finding titles and weights, and categorical features. No bodies, no addresses, no
domains, no filenames, no attachment bytes. The schema is the defence, and there is a
secondary scan that aborts the run if a serialised record matches anything resembling
an address, an IP or a URL. A test asserts the same thing in CI.

**Why abort rather than warn?**

A warning inside a batch of ten thousand messages is a warning nobody reads.

**What is the residual risk you did not eliminate?**

Antivirus can quarantine samples mid-run and silently reduce the count, so an ingest
can be incomplete without saying so. And if the benign baseline is personal mail, other
people's correspondence passes through the tool even though none of it persists. That
needs stating in any write-up, because it changes how the number should be read.

---

## On the Received chain

**What can you trust in a Received chain?**

Only the hops at or above your own boundary. Headers are prepended, so the topmost is
the most recent, and the boundary is the lowest hop whose `by` clause names one of your
servers. Everything below it was supplied by the sender and can be fabricated
wholesale, including a long plausible journey.

**How does that help with false positives?**

A DMARC alignment failure has one common innocent explanation, which is forwarding. The
chain shows it directly: a hop below the boundary whose host belongs to neither the
sender's domain nor ours. Where that is present the weight drops from 40 to 20 and the
finding explains why, instead of leaving the analyst to work it out.

**Why not just trust DKIM surviving as the forwarding signal?**

It usually works and it cannot name the forwarder. It also fails when the forwarder
breaks the signature, which some mailing lists do by modifying the body, and in that
case there is nothing left to infer from.

---

## On CI

**What does the pipeline check beyond the tests?**

Four things. The tests. That the committed corpus still matches what the generator
produces, so it cannot drift from its source. That the calibration still holds, so a
weight change that breaks a threshold fails the build rather than passing quietly. And
the ablation, so the write-up cannot become stale without anyone noticing.
