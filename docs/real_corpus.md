# Validating against real email, safely

The synthetic corpus cannot produce a false-positive rate that means anything,
because the same person wrote the messages and the rules. Real corpora can. They
also contain live malicious links, real attachments, and real people's
correspondence.

This document is the procedure. Read all of it before downloading anything.

---

## What is and is not dangerous

**A `.eml` file on disk is inert.** It is a text file. Reading it and parsing it
cannot trigger anything. EmailShield reads bytes, parses text, holds attachment
payloads in memory only, and makes no network request of any kind, which
`test_no_network_access_anywhere_in_the_pipeline` enforces by blocking sockets and
running the whole corpus through.

The danger is in three actions, none of which this tool performs:

1. **Opening the file in a mail client.** Mail.app renders HTML, loads remote images,
   which beacons the sender that the message was opened, and may auto-preview
   attachments. This is the significant one.
2. **Clicking or expanding a link.** Confirms a live recipient and can serve a
   payload.
3. **Extracting an attachment to disk and opening it.**

So the risk lives almost entirely in how the files are handled around the tool, not
in the analysis.

---

## The four rules

**1. Terminal only. Never open the folder in Finder.**

Double-clicking a `.eml` hands it to Mail.app. Selecting one and pressing space
triggers Quick Look, which renders content. Neither is recoverable once done.

**2. Nothing in a synced folder.**

Desktop, Documents and iCloud Drive synchronise by default on most Macs. Uploading
malware samples to Apple is a privacy problem and a good way to get an account
flagged. Use `~/mail-samples`, which is not synced.

`tools/ingest_real.py` refuses to read from or write to a synced path. That is a
backstop, not permission to be careless.

**3. Nothing real inside the repository, ever.**

Not gitignored, not in a subfolder. Outside it entirely.

Real messages contain real names, addresses and correspondence. Pushing them to a
public repository publishes personal data and redistributes live malware. `.gitignore`
excludes `*.eml` outside `data/corpus/`, and the ingest tool refuses to write its
output inside the repository without an explicit override, but the reliable control is
keeping the samples somewhere else.

**4. Delete the samples when the ingest is done.**

`--purge-source` does it. The dangerous artefacts should exist for minutes.

---

## Expect antivirus to react

macOS XProtect, or anything else installed, may quarantine sample files during the
download or mid-run. That is the tool on your machine working correctly. It is not a
compromise. It will silently remove files, so if the ingest count is lower than the
file count, this is usually why.

---

## What the ingest step actually does

`tools/ingest_real.py` is an airlock. It reads live messages, runs the full analysis
in memory, and writes out **derived findings only**.

Written:

- a truncated SHA-256 of the file, as an opaque identifier
- the label given on the command line
- score, action, confidence, and whether human approval is required
- each finding: signal id, title, weight, confidence
- categorical features: authentication results, hop counts, attachment categories and
  size buckets, URL structure flags

Never written:

- message bodies or subjects
- email addresses, display names, recipients
- domain names or IP addresses
- attachment filenames or any attachment bytes
- raw headers of any kind

Two defences. The primary one is the schema: `extract_features` builds records from a
fixed set of flags, counts and fixed-vocabulary terms, so free text has no route in.
The secondary one is `assert_no_pii`, which scans the serialised record for anything
resembling an address, an IP or a URL and aborts the whole run if it finds one. It
aborts rather than warning, because a warning inside a batch of ten thousand is a
warning nobody reads.

`test_ingest_output_contains_no_personal_data` asserts the same thing in CI against
the synthetic corpus, including that the fictional organisation name never appears.

---

## Choosing a corpus

You need two things, and the second is harder to find than the first.

**Malicious.** Public phishing collections exist. Prefer any distribution that has
attachments stripped or that is headers-only: you lose the ability to exercise
ES-ATT-004 on real data, and gain not having live payloads on your laptop. That is a
reasonable trade for a portfolio project.

**Benign.** This is the one that matters and the one people skip. Precision and
recall computed on a corpus that is half phishing tell you almost nothing, because
real mail is overwhelmingly benign, often by four orders of magnitude. Without a
large benign set you cannot produce a false-positive rate, which is the only figure
an operations team will ask about.

The SpamAssassin public corpus includes a ham set and is mostly plain text with few
attachments, which makes it a sensible starting point.

**Check the licence and terms of any corpus before using it, and do not
redistribute it.** Some require registration or agreement to conditions on
publication.

**A note on your own mailbox.** Exporting your own mail as a benign set is tempting
and gives a realistic baseline. It also means your correspondents' personal data
passes through the tool. The metadata output contains none of it, and if anyone else
is on those messages they have not agreed to it. If you do this, use the defanged
output only, delete the exports, and say in the write-up that the benign baseline was
personal mail rather than an organisational flow, because that affects how the number
should be read.

---

## The procedure

```bash
# 1. Somewhere outside iCloud, Desktop and Documents
mkdir -p ~/mail-samples/phish ~/mail-samples/ham

# 2. Put the corpus there. Terminal only. Do not open the folder in Finder.

# 3. Dry run first: analyse, report, write nothing, delete nothing
cd ~/Projects/emailshield
source .venv/bin/activate
python3 tools/ingest_real.py --source ~/mail-samples/phish \
    --label malicious --limit 50 --dry-run

# 4. Real ingest, output outside the repository
python3 tools/ingest_real.py --source ~/mail-samples/phish \
    --label malicious --out ~/emailshield-data/real.jsonl

python3 tools/ingest_real.py --source ~/mail-samples/ham \
    --label benign --out ~/emailshield-data/real.jsonl

# 5. Confirm the dataset carries nothing sensitive.
#    Every one of these should return nothing.
grep -cE "@" ~/emailshield-data/real.jsonl
grep -cE "https?://" ~/emailshield-data/real.jsonl
grep -cE "([0-9]{1,3}\.){3}[0-9]{1,3}" ~/emailshield-data/real.jsonl

# 6. Delete the live samples
python3 tools/ingest_real.py --source ~/mail-samples/phish \
    --label malicious --out /dev/null --dry-run   # confirm count first
rm -rf ~/mail-samples

# 7. Evaluate
python3 -m src.ablate --data ~/emailshield-data/real.jsonl
```

---

## Reading the result honestly

Expect the false-positive rate to be worse than the synthetic corpus suggests.
Fourteen hand-written messages with a 4:10 ratio flatter the tool considerably, and
real benign mail contains marketing, mailing lists, forwarders, transactional
notices and automated alerts, all of which trip individual signals.

That is the finding, not a failure. "The tool achieves recall of X on real phishing
at a cost of Y false positives per thousand legitimate messages, and here is which
signal is responsible for most of them" is a far stronger thing to be able to say
than perfect scores on a corpus you wrote yourself.

The specific numbers, once produced, belong in
[calibration.md](calibration.md) alongside the synthetic figures, with both clearly
labelled. Do not replace one with the other: the contrast between them is the
interesting part.
