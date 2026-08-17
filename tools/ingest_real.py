#!/usr/bin/env python3
"""
Defanging ingest for real email corpora.

Purpose
-------
Public phishing and ham corpora are the only way to measure a false-positive rate
that means anything. They also contain live malicious links, real attachments, and
real people's correspondence. This script is the airlock between the two facts.

It reads live `.eml` files, runs the full EmailShield analysis in memory, and
writes out **derived findings only**. What is written contains:

  - a truncated hash of the file, as an opaque identifier
  - the label supplied on the command line
  - the score, action and confidence
  - each finding: signal id, title, weight, confidence
  - categorical features: authentication results, attachment categories, URL
    structure flags, counts

What is never written:

  - message bodies or subjects
  - email addresses, display names, or recipient lists
  - domain names or IP addresses
  - attachment filenames or any attachment bytes
  - raw headers of any kind

The output therefore carries no personal data and nothing executable. It is safe
to keep, and safe to commit, though the default is still to keep it outside the
repository.

Safety behaviour
----------------
  - Refuses to write output inside the repository unless `--allow-in-repo`.
  - Refuses to read from or write to an iCloud-synced location.
  - Never writes attachment payloads to disk. Payloads exist only in memory,
    for the duration of one file's analysis.
  - Never opens a network connection. `tests` enforces this by blocking sockets.
  - `--purge-source` deletes the live samples after a successful ingest, so the
    dangerous artefacts are short-lived.

Usage
-----
    # dry run: report what would be written, write nothing
    python3 tools/ingest_real.py --source ~/mail-samples/phish --label malicious --dry-run

    # real ingest to a location outside the repo
    python3 tools/ingest_real.py --source ~/mail-samples/phish --label malicious \
        --out ~/emailshield-data/real.jsonl

    # then delete the live samples
    python3 tools/ingest_real.py --source ~/mail-samples/phish --label malicious \
        --out ~/emailshield-data/real.jsonl --purge-source
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.attachments import inspect_attachment                      # noqa: E402
from src.auth import assess_authentication                          # noqa: E402
from src.domains import assess_domain                               # noqa: E402
from src.main import DEFAULT_CONFIG, load_config                    # noqa: E402
from src.parse import parse_email_bytes                             # noqa: E402
from src.score import requires_human_approval, score_findings       # noqa: E402
from src.signals import Config, build_context, run_all_signals      # noqa: E402
from src.urls import analyse_url                                    # noqa: E402


# Locations macOS synchronises to iCloud by default. Malware samples in a synced
# folder get uploaded to Apple, which is both a privacy problem and a good way to
# have an account flagged.
ICLOUD_MARKERS = (
    "/Library/Mobile Documents",
    "/Mobile Documents/",
    "com~apple~CloudDocs",
)
LIKELY_SYNCED_DIRS = ("Desktop", "Documents")

# Anything that looks like it could identify a person. Used as a final assertion on
# the serialised record rather than as the primary defence, which is the schema.
_PII_PATTERNS = (
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),                 # email address
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),              # IPv4
    re.compile(r"(?i)\bhxxps?://"),                          # defanged URL
    re.compile(r"(?i)\bhttps?://"),                          # live URL
)


def looks_icloud(path: Path) -> bool:
    resolved = str(path.expanduser().resolve())
    if any(marker in resolved for marker in ICLOUD_MARKERS):
        return True
    home = str(Path.home())
    for name in LIKELY_SYNCED_DIRS:
        candidate = os.path.join(home, name)
        if resolved == candidate or resolved.startswith(candidate + os.sep):
            return True
    return False


def in_repo(path: Path) -> bool:
    try:
        path.expanduser().resolve().relative_to(ROOT)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Feature extraction: categorical only, nothing identifying
# --------------------------------------------------------------------------- #

def size_bucket(size: int) -> str:
    for limit, name in ((1024, "<1KB"), (100 * 1024, "1-100KB"),
                        (1024 * 1024, "100KB-1MB"), (10 * 1024 * 1024, "1-10MB")):
        if size < limit:
            return name
    return ">10MB"


def extract_features(email, config: Config) -> dict:
    """
    Reduce a message to categorical facts.

    Everything here is a flag, a count or a fixed vocabulary term. No free text,
    no identifiers, no domains. If a field could vary with who sent the message,
    it does not belong in this function.
    """
    auth = assess_authentication(
        email.authentication_results, email.from_address, config.trusted_authserv_ids
    )
    ctx = build_context(email, config)

    url_flags = {
        "count": 0, "userinfo": 0, "ip_literal": 0, "obfuscated_ip": 0,
        "shortener": 0, "nested_redirect": 0, "punycode": 0, "mixed_script": 0,
        "anchor_mismatch": 0,
    }
    seen: set[str] = set()
    for link in email.links:
        analysed = analyse_url(link.href)
        if not analysed.host or analysed.normalised in seen:
            continue
        seen.add(analysed.normalised)
        url_flags["count"] += 1
        url_flags["userinfo"] += bool(analysed.userinfo)
        url_flags["ip_literal"] += bool(analysed.is_ip_literal)
        url_flags["obfuscated_ip"] += bool(
            analysed.is_ip_literal
            and analysed.ip_literal_form not in {"dotted", "ipv6"}
        )
        url_flags["shortener"] += bool(analysed.is_shortener)
        url_flags["nested_redirect"] += bool(analysed.unwrap_depth)
        domain_view = assess_domain(analysed.host, config.protected_domains)
        url_flags["punycode"] += bool(domain_view.contained_punycode)
        url_flags["mixed_script"] += bool(domain_view.mixed_scripts)

    attachments = []
    for item in email.attachments:
        result = inspect_attachment(
            item.filename, item.declared_content_type, item.payload, item.size_bytes
        )
        attachments.append({
            # Deliberately no filename: filenames routinely contain personal names,
            # client names and reference numbers.
            "extension": result.effective_extension[:12],
            "category": result.category,
            "detected_type": result.detected_type,
            "size_bucket": size_bucket(result.size_bytes),
            "type_mismatch": result.type_mismatch,
            "macro_project": result.contains_macro_project,
            "double_extension": result.double_extension,
            "bidi_control": result.has_bidi_control,
        })

    return {
        "spf": auth.spf,
        "dkim": auth.dkim,
        "dmarc_reported": auth.dmarc,
        "dmarc_computed": auth.dmarc_pass_computed,
        "trusted_auth_header": auth.trusted_header is not None,
        "untrusted_auth_header_count": len(auth.untrusted_claims),
        "auth_header_count": len(email.authentication_results),
        "received_hop_count": len(email.received_hops),
        "chain_forwarded": bool(ctx.chain and ctx.chain.forwarded),
        "chain_time_anomalies": len(ctx.chain.time_anomalies) if ctx.chain else 0,
        "reply_to_present": bool(email.reply_to),
        "return_path_present": bool(email.return_path),
        "has_html_body": bool(email.body_html),
        "has_text_body": bool(email.body_text),
        "body_length_bucket": size_bucket(len(email.body_text) + len(email.body_html)),
        "attachment_count": len(email.attachments),
        "urls": url_flags,
        "attachments": attachments,
        "parse_warning_count": len(email.parse_warnings),
    }


def build_record(path: Path, data: bytes, label: str, config: Config) -> dict:
    email = parse_email_bytes(data, path="<redacted>")
    findings = run_all_signals(email, config)
    verdict = score_findings(findings, config)

    return {
        # An opaque, stable identifier. Truncated so it cannot be used to confirm
        # possession of a specific known file by brute force comparison.
        "id": hashlib.sha256(data).hexdigest()[:16],
        "label": label,
        "score": verdict.score,
        "action": verdict.action,
        "confidence": verdict.confidence,
        "requires_human_approval": requires_human_approval(verdict),
        "decisive": len(verdict.decisive_findings),
        # Findings without their evidence strings. The evidence is the useful part
        # for an analyst and the dangerous part for a dataset, because it quotes
        # the message.
        "findings": [
            {
                "signal_id": f.signal_id,
                "title": f.title,
                "weight": f.weight,
                "confidence": f.confidence,
                "suppresses_credit": f.suppresses_credit,
            }
            for f in findings
        ],
        "features": extract_features(email, config),
    }


def assert_no_pii(record: dict) -> None:
    """
    Final check on the serialised record.

    The schema is the real defence: the record is built from a fixed set of
    categorical fields, so personal data has no route in. This is the belt to that
    braces, and it fails loudly rather than warning, because a warning in a batch
    of ten thousand messages is a warning nobody reads.
    """
    serialised = json.dumps(record)
    for pattern in _PII_PATTERNS:
        match = pattern.search(serialised)
        if match:
            raise SystemExit(
                "ingest aborted: the output record matched a pattern that can carry "
                f"personal or dangerous data ({pattern.pattern!r}). This is a bug in "
                "extract_features and must be fixed rather than bypassed."
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ingest_real",
        description="Turn live email samples into a metadata-only dataset.",
    )
    parser.add_argument("--source", required=True,
                        help="directory of .eml files")
    parser.add_argument("--label", required=True, choices=["malicious", "benign"])
    parser.add_argument("--out", default=str(Path.home() / "emailshield-data" / "real.jsonl"))
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true",
                        help="analyse and report, write nothing")
    parser.add_argument("--purge-source", action="store_true",
                        help="delete the source .eml files after a successful ingest")
    parser.add_argument("--allow-in-repo", action="store_true",
                        help="permit writing output inside the repository")
    args = parser.parse_args(argv)

    source = Path(args.source).expanduser()
    out = Path(args.out).expanduser()

    if not source.is_dir():
        raise SystemExit(f"source is not a directory: {source}")

    if looks_icloud(source):
        raise SystemExit(
            f"refusing to read from {source}: that path is synchronised to iCloud. "
            "Move the samples somewhere outside Desktop, Documents and iCloud Drive, "
            "for example ~/mail-samples."
        )
    if looks_icloud(out):
        raise SystemExit(
            f"refusing to write to {out}: that path is synchronised to iCloud."
        )
    if in_repo(out) and not args.allow_in_repo:
        raise SystemExit(
            f"refusing to write inside the repository ({out}). The dataset should "
            "live outside it so it cannot be committed by accident. Pass "
            "--allow-in-repo only if you have read the file and are certain."
        )

    config = load_config(Path(args.config))

    files = sorted(p for p in source.glob("*.eml") if p.is_file())
    if not files:
        files = sorted(p for p in source.iterdir() if p.is_file())
    if args.limit:
        files = files[: args.limit]

    if not files:
        raise SystemExit(f"no files found in {source}")

    print(f"source        : {source}")
    print(f"files         : {len(files)}")
    print(f"label         : {args.label}")
    print(f"output        : {'(dry run, nothing written)' if args.dry_run else out}")
    print()

    records: list[dict] = []
    failures = 0
    for index, path in enumerate(files, start=1):
        try:
            data = path.read_bytes()
            record = build_record(path, data, args.label, config)
            assert_no_pii(record)
            records.append(record)
        except SystemExit:
            raise
        except Exception as exc:
            failures += 1
            # A crash on one message must not stop the batch, and must not be
            # silent either: an unparseable message that is skipped is a message
            # that was never evaluated.
            print(f"  [{index}] failed: {type(exc).__name__}", file=sys.stderr)
        if index % 250 == 0:
            print(f"  {index}/{len(files)}")

    if not records:
        raise SystemExit("no records produced; nothing written")

    actions: dict[str, int] = {}
    for record in records:
        actions[record["action"]] = actions.get(record["action"], 0) + 1

    print()
    print(f"analysed      : {len(records)}")
    print(f"failed        : {failures}")
    for action in ("allow", "investigate", "quarantine", "escalate"):
        count = actions.get(action, 0)
        share = 100 * count / len(records)
        print(f"  {action:12} {count:6}  {share:5.1f}%")

    if args.dry_run:
        print()
        print("dry run: no output written, no source files deleted")
        return 0

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    print()
    print(f"appended {len(records)} records to {out}")

    if args.purge_source:
        removed = 0
        for path in files:
            try:
                path.unlink()
                removed += 1
            except OSError as exc:
                print(f"  could not delete {path.name}: {exc}", file=sys.stderr)
        print(f"deleted {removed} source files")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
