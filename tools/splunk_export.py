#!/usr/bin/env python3
"""
Export EmailShield verdicts as Splunk-ready NDJSON.

Why this exists
---------------
A detection that lives only in a terminal is a script. A detection that lands in a
SIEM alongside other telemetry is a control, because that is where correlation
happens and where an analyst actually works. SentinelLab already ships events to a
local Splunk index, and this puts EmailShield verdicts next to them so the two
projects answer questions together rather than separately.

The interesting query is the cross-project one. SentinelLab's SL-IDP-003 fires on an
unusual login for a user. EmailShield fires on a credential-harvesting email sent to
that same user. Neither is conclusive; the pair, ordered correctly in time, is a
phishing-to-account-takeover chain. Neither tool can see it alone.

Output shape
------------
One JSON object per line, one line per verdict, timestamped so Splunk can index it.
Evidence strings are included, because this output stays local and is meant for an
analyst to read. That is the opposite decision from tools/ingest_real.py, which
strips evidence because its output is a dataset that persists.

    python3 tools/splunk_export.py --out out/emailshield_alerts.json
    python3 tools/splunk_export.py --source ~/mail-samples --out out/alerts.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.main import DEFAULT_CONFIG, DEFAULT_CORPUS, load_config     # noqa: E402
from src.parse import parse_email_file                               # noqa: E402
from src.score import requires_human_approval, score_findings        # noqa: E402
from src.signals import run_all_signals                              # noqa: E402


def to_event(path: Path, email, verdict) -> dict:
    return {
        # Splunk needs a timestamp it can recognise. The message Date header is
        # attacker-controlled, so analysis time is used for _time and the claimed
        # date is carried separately as a field.
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "claimed_date": email.date,
        "tool": "emailshield",
        "source_file": path.name,
        "action": verdict.action,
        "score": verdict.score,
        "confidence": verdict.confidence,
        "requires_human_approval": requires_human_approval(verdict),
        "decisive_finding_count": len(verdict.decisive_findings),
        "from_address": email.from_address,
        "from_display_name": email.from_display_name,
        "from_domain": email.from_address.rpartition("@")[2].lower(),
        "reply_to": email.reply_to,
        "recipients": email.to,
        "subject": email.subject,
        "signals_fired": sorted({f.signal_id for f in verdict.findings}),
        "signals_silent": verdict.signals_silent,
        "attachment_names": [a.filename for a in email.attachments],
        "url_hosts": sorted({
            link.href.split("/")[2].lower()
            for link in email.links
            if "//" in link.href and len(link.href.split("/")) > 2
        }),
        "findings": [
            {
                "signal_id": f.signal_id,
                "title": f.title,
                "weight": f.weight,
                "confidence": f.confidence,
                "mitre": f.mitre,
                "evidence": f.evidence,
            }
            for f in verdict.findings
        ],
        "reasoning": verdict.reasoning,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="splunk_export")
    parser.add_argument("--source", default=str(DEFAULT_CORPUS),
                        help="directory of .eml files")
    parser.add_argument("--out", default="out/emailshield_alerts.json")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--min-action", default="allow",
                        choices=["allow", "investigate", "quarantine", "escalate"],
                        help="only export verdicts at or above this action")
    args = parser.parse_args(argv)

    order = ("allow", "investigate", "quarantine", "escalate")
    floor = order.index(args.min_action)

    config = load_config(Path(args.config))
    source = Path(args.source).expanduser()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    with out.open("w", encoding="utf-8") as handle:
        for path in sorted(source.glob("*.eml")):
            email = parse_email_file(path)
            verdict = score_findings(run_all_signals(email, config), config)
            if order.index(verdict.action) < floor:
                continue
            handle.write(json.dumps(to_event(path, email, verdict), default=str) + "\n")
            written += 1

    print(f"wrote {written} events to {out}")
    print()
    print("Next: Splunk web UI, Settings > Add Data > Upload, choose this file.")
    print("Set sourcetype to  emailshield:alert  and index to  sentinellab")
    print("(or a new emailshield index). See docs/splunk.md for the searches.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
