"""
EmailShield command line interface.

    python -m src.main data/corpus/phish-01-credential-harvest.eml
    python -m src.main --all
    python -m src.main --all --brief
    python -m src.main <file> --json

Exit status is 0 when the recommended action is allow or investigate, and 1 when
it is quarantine or escalate, so the tool can be used in a pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .parse import parse_email_file
from .score import Verdict, requires_human_approval, score_findings
from .signals import Config, run_all_signals

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ROOT / "data" / "config.json"
DEFAULT_CORPUS = ROOT / "data" / "corpus"


def load_config(path: Path) -> Config:
    raw = json.loads(path.read_text())
    config = Config(
        protected_domains=set(raw.get("protected_domains", [])),
        trusted_authserv_ids={s.lower() for s in raw.get("trusted_authserv_ids", [])},
        trusted_mail_hosts={s.lower() for s in raw.get("trusted_mail_hosts", [])},
        known_senders={k.lower(): v for k, v in raw.get("known_senders", {}).items()},
        allowlisted_domains=set(raw.get("allowlisted_domains", [])),
    )
    if not config.protected_domains:
        print(
            "warning: protected_domains is empty, so lookalike detection cannot "
            "compare against anything and ES-URL-003 will miss every impersonation",
            file=sys.stderr,
        )
    if not config.trusted_authserv_ids:
        print(
            "warning: trusted_authserv_ids is empty, so no Authentication-Results "
            "header can be trusted and ES-AUTH-002 will report nothing usable",
            file=sys.stderr,
        )
    return config


def analyse(path: Path, config: Config) -> tuple[Verdict, object]:
    email = parse_email_file(path)
    findings = run_all_signals(email, config)
    return score_findings(findings, config), email


def print_report(path: Path, verdict: Verdict, email, brief: bool = False) -> None:
    bar = "=" * 74
    print(bar)
    print(f"{verdict.action.upper():<12} score {verdict.score:<5} "
          f"confidence {verdict.confidence}")
    print(f"{path.name}")
    print(bar)
    print(f"From    : {email.from_display_name!r} <{email.from_address}>")
    print(f"Subject : {email.subject}")
    if email.reply_to:
        print(f"Reply-To: {', '.join(email.reply_to)}")
    print()

    if requires_human_approval(verdict):
        print("** This action removes mail from a user's reach and the supporting")
        print("** evidence is not high confidence. An analyst should approve it")
        print("** rather than letting it apply automatically.")
        print()

    if brief:
        for signal_id, title, weight in verdict.contributions:
            print(f"  {weight:+4}  {signal_id}  {title}")
        print()
        return

    print("Why this score")
    print("-" * 74)
    for finding in sorted(verdict.findings, key=lambda f: -abs(f.weight)):
        print(f"\n  [{finding.weight:+4}] {finding.signal_id}  {finding.title}")
        print(f"         confidence: {finding.confidence}"
              + (f"   MITRE: {', '.join(finding.mitre)}" if finding.mitre else ""))
        for item in finding.evidence:
            print(f"         - {item}")
        if finding.benign_explanations:
            print("         benign explanations to rule out first:")
            for item in finding.benign_explanations:
                print(f"           . {item}")
        if finding.analyst_actions:
            print("         next steps:")
            for item in finding.analyst_actions:
                print(f"           > {item}")

    print()
    print("How the action was reached")
    print("-" * 74)
    for line in verdict.reasoning:
        print(f"  {line}")

    if email.parse_warnings:
        print()
        print("Parser warnings")
        print("-" * 74)
        for warning in email.parse_warnings:
            print(f"  {warning}")
    print()


def verdict_to_dict(path: Path, verdict: Verdict) -> dict:
    return {
        "file": path.name,
        "action": verdict.action,
        "score": verdict.score,
        "confidence": verdict.confidence,
        "requires_human_approval": requires_human_approval(verdict),
        "decisive_findings": verdict.decisive_findings,
        "signals_silent": verdict.signals_silent,
        "findings": [asdict(f) for f in verdict.findings],
        "reasoning": verdict.reasoning,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="emailshield",
        description="Explainable triage for a single synthetic email.",
    )
    parser.add_argument("path", nargs="?", help="path to a .eml file")
    parser.add_argument("--all", action="store_true",
                        help="analyse every .eml in the bundled corpus")
    parser.add_argument("--brief", action="store_true",
                        help="one line per finding")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    args = parser.parse_args(argv)

    config = load_config(Path(args.config))

    if args.all:
        paths = sorted(DEFAULT_CORPUS.glob("*.eml"))
    elif args.path:
        paths = [Path(args.path)]
    else:
        parser.error("give a path or use --all")
        return 2

    results = []
    worst = 0
    for path in paths:
        verdict, email = analyse(path, config)
        results.append(verdict_to_dict(path, verdict))
        if verdict.action in {"quarantine", "escalate"}:
            worst = 1
        if not args.json:
            print_report(path, verdict, email, brief=args.brief)

    if args.json:
        print(json.dumps(results, indent=2, default=str))

    return worst


if __name__ == "__main__":
    raise SystemExit(main())
