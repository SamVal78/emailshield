"""
Ablation and real-corpus evaluation.

Two questions this answers that the basic sweep cannot.

**Does each signal earn its place?** Turn one off, re-score, and see what changes.
A signal that costs nothing when removed is either redundant with another signal or
not doing anything, and either way that is worth knowing rather than assuming. A
signal that is kept despite contributing no accuracy needs a stated reason.

**What is the false-positive rate on mail nobody wrote for this tool?** The
synthetic corpus cannot answer that, because it was written by the same person who
wrote the rules. `tools/ingest_real.py` produces a metadata-only dataset from a real
corpus, and this module reports against it.

    python -m src.ablate                       # ablation on the synthetic corpus
    python -m src.ablate --data ~/emailshield-data/real.jsonl
    python -m src.ablate --data ~/emailshield-data/real.jsonl --ablate

Ablation works on stored findings, so the real dataset supports it without needing
the original messages. Changing a *weight* would need a re-ingest; removing a signal
does not.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from .evaluate import ACTION_ORDER, score_corpus
from .main import DEFAULT_CONFIG, load_config
from .score import ALL_SIGNAL_IDS, THRESHOLDS, Verdict, score_findings
from .signals import Config, Finding

BLOCKING = {"quarantine", "escalate"}


@dataclass
class Case:
    """One evaluated message, from either the synthetic corpus or a real dataset."""
    name: str
    label: str
    findings: list[Finding]
    action_min: str = "allow"
    action_max: str = "escalate"

    def rescore(self, excluded: str | None = None) -> Verdict:
        kept = [f for f in self.findings if f.signal_id != excluded]
        return score_findings(kept)

    @property
    def must_block(self) -> bool:
        return ACTION_ORDER.index(self.action_min) >= ACTION_ORDER.index("quarantine")


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def load_synthetic(config: Config) -> list[Case]:
    from .main import DEFAULT_CORPUS
    from .parse import parse_email_file
    from .signals import run_all_signals

    labels = json.loads((Path(__file__).resolve().parent.parent
                         / "data" / "labels.json").read_text())
    cases: list[Case] = []
    for path in sorted(DEFAULT_CORPUS.glob("*.eml")):
        meta = labels[path.name]
        email = parse_email_file(path)
        cases.append(Case(
            name=path.name,
            label=meta["label"],
            findings=run_all_signals(email, config),
            action_min=meta.get("action_min", "allow"),
            action_max=meta.get("action_max", "escalate"),
        ))
    return cases


def load_dataset(path: Path) -> list[Case]:
    """
    Load a metadata-only dataset written by tools/ingest_real.py.

    Findings are reconstructed without their evidence strings, which is exactly
    what the ingest step withheld. Scoring does not read evidence, so the
    arithmetic here is identical to the arithmetic on live messages.
    """
    cases: list[Case] = []
    with path.expanduser().open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            findings = [
                Finding(
                    signal_id=item["signal_id"],
                    title=item["title"],
                    weight=item["weight"],
                    confidence=item["confidence"],
                    suppresses_credit=item.get("suppresses_credit", False),
                )
                for item in record["findings"]
            ]
            label = record["label"]
            cases.append(Case(
                name=record["id"],
                label=label,
                findings=findings,
                action_min="quarantine" if label == "malicious" else "allow",
                action_max="escalate" if label == "malicious" else "investigate",
            ))
    return cases


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #

@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fp_per_thousand(self) -> float:
        """
        False positives per thousand benign messages.

        This is the number an operations team asks for, because it converts
        directly into a helpdesk workload. Precision does not, since it depends on
        the ratio of malicious to benign mail in the sample rather than in reality.
        """
        benign = self.fp + self.tn
        return 1000 * self.fp / benign if benign else 0.0


def measure(cases: list[Case], excluded: str | None = None) -> Metrics:
    metrics = Metrics()
    for case in cases:
        blocked = case.rescore(excluded).action in BLOCKING
        if case.must_block:
            if blocked:
                metrics.tp += 1
            else:
                metrics.fn += 1
        else:
            if blocked:
                metrics.fp += 1
            else:
                metrics.tn += 1
    return metrics


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #

def report_baseline(cases: list[Case], source: str) -> Metrics:
    baseline = measure(cases)
    malicious = sum(1 for c in cases if c.label == "malicious")
    benign = len(cases) - malicious

    print(f"Dataset: {source}")
    print(f"  messages        {len(cases)}  ({malicious} malicious, {benign} benign)")
    print(f"  thresholds      investigate>={THRESHOLDS['investigate']}, "
          f"quarantine>={THRESHOLDS['quarantine']}, "
          f"escalate>={THRESHOLDS['escalate']}")
    print()
    print("Baseline at current weights and thresholds")
    print("-" * 76)
    print(f"  true positives  {baseline.tp:6}")
    print(f"  false positives {baseline.fp:6}")
    print(f"  false negatives {baseline.fn:6}")
    print(f"  true negatives  {baseline.tn:6}")
    print(f"  precision       {baseline.precision:6.3f}")
    print(f"  recall          {baseline.recall:6.3f}")
    print(f"  F1              {baseline.f1:6.3f}")
    print(f"  FP per 1000 benign  {baseline.fp_per_thousand:.2f}")
    print()
    return baseline


def report_ablation(cases: list[Case], baseline: Metrics) -> None:
    print("Ablation: each signal removed in turn")
    print("=" * 76)
    print(f"{'removed':14} {'TP':>4} {'FP':>4} {'FN':>4} "
          f"{'prec':>6} {'recall':>7} {'F1':>6} {'dF1':>7}  verdict")
    print("-" * 76)
    print(f"{'nothing':14} {baseline.tp:>4} {baseline.fp:>4} {baseline.fn:>4} "
          f"{baseline.precision:>6.3f} {baseline.recall:>7.3f} "
          f"{baseline.f1:>6.3f} {'':>7}  baseline")

    rows: list[tuple[str, Metrics, float]] = []
    for signal_id in ALL_SIGNAL_IDS:
        metrics = measure(cases, excluded=signal_id)
        delta = metrics.f1 - baseline.f1
        rows.append((signal_id, metrics, delta))

    for signal_id, metrics, delta in rows:
        if delta < -0.001:
            verdict = "carries weight"
        elif delta > 0.001:
            verdict = "removing it HELPS"
        else:
            verdict = "no measurable effect"
        print(f"{signal_id:14} {metrics.tp:>4} {metrics.fp:>4} {metrics.fn:>4} "
              f"{metrics.precision:>6.3f} {metrics.recall:>7.3f} "
              f"{metrics.f1:>6.3f} {delta:>+7.3f}  {verdict}")

    print()
    neutral = [s for s, _, d in rows if abs(d) <= 0.001]
    helps = [s for s, _, d in rows if d > 0.001]

    if helps:
        print("Signals whose removal improves the metric:")
        for signal_id in helps:
            print(f"  {signal_id} — costing accuracy on this dataset. Either retune "
                  "it or state explicitly why it stays.")
        print()
    if neutral:
        print("Signals with no measurable effect on this dataset:")
        for signal_id in neutral:
            print(f"  {signal_id}")
        print()
        print("No measurable effect is not the same as no value. Two readings are")
        print("possible and they need different responses:")
        print("  1. The signal is redundant here because another signal fires on the")
        print("     same messages. On a larger corpus it may be the only one that does.")
        print("  2. The signal exists for a case this corpus does not contain.")
        print()
        print("ES-SOC-005 is case 2 and is kept deliberately. It contributes nothing")
        print("to precision or recall, and it is the only signal that sees the")
        print("compromised-supplier message at all, because that message passes")
        print("authentication, is allowlisted, and has a long sender history. A")
        print("metric computed over a corpus without enough of those cases cannot")
        print("show its value, which is a limitation of the corpus rather than an")
        print("argument for deleting the signal.")


def report_threshold_interaction(cases: list[Case]) -> None:
    """Where the quarantine line could move without breaking anything."""
    scores = sorted(
        (case.rescore().score, case.must_block, case.name) for case in cases
    )
    highest_benign = max(
        (s for s, must, _ in scores if not must), default=0
    )
    lowest_malicious = min(
        (s for s, must, _ in scores if must), default=0
    )
    print()
    print("Threshold headroom")
    print("-" * 76)
    print(f"  highest-scoring message that must NOT be blocked: {highest_benign}")
    print(f"  lowest-scoring message that MUST be blocked:      {lowest_malicious}")
    if lowest_malicious > highest_benign:
        print(f"  clean separation: any threshold in "
              f"{highest_benign + 1}..{lowest_malicious} is error-free")
        print(f"  configured: {THRESHOLDS['quarantine']}")
    else:
        print("  the classes overlap on score, so no threshold separates them. "
              "Weights need work rather than the threshold.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="emailshield-ablate")
    parser.add_argument("--data", help="metadata dataset from tools/ingest_real.py")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--ablate", action="store_true",
                        help="run the ablation (default on when no --data given)")
    args = parser.parse_args(argv)

    if args.data:
        cases = load_dataset(Path(args.data))
        source = f"{args.data} (metadata only, no message content)"
    else:
        config = load_config(Path(args.config))
        cases = load_synthetic(config)
        source = "data/corpus (synthetic, 14 messages)"

    baseline = report_baseline(cases, source)
    report_ablation(cases, baseline)
    report_threshold_interaction(cases)

    if not args.data:
        print()
        print("Reminder: this is the synthetic corpus. Every number above is bounded")
        print("by the fact that the same person wrote the messages and the rules.")
        print("Run tools/ingest_real.py against a public corpus for figures that")
        print("mean something, and read docs/real_corpus.md first.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
