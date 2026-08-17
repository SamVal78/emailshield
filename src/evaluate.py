"""
Threshold calibration for EmailShield.

This is the module that turns "the threshold is 60 because it felt right" into
"the threshold is 60 because at 55 the forwarded-mail case is quarantined and at
70 the compromised-supplier case is released".

    python -m src.evaluate                # sweep and report
    python -m src.evaluate --confusion    # per-message table at current thresholds

What is being measured
----------------------
Each message has a ground-truth label of malicious or benign. The tool produces
one of four actions. The mapping used here:

    malicious message -> quarantine or escalate is correct
    benign message    -> allow or investigate is correct

That mapping is a policy decision, not a fact. Treating "investigate" as an
acceptable outcome for a benign message is what makes the tool usable: sending a
borderline message to a human is not a failure, whereas quarantining it is.

Then, at each candidate quarantine threshold:

    true positive   malicious, quarantined or escalated
    false negative  malicious, allowed or only flagged for investigation
    false positive  benign, quarantined or escalated
    true negative   benign, allowed or flagged for investigation

    precision = TP / (TP + FP)   of the mail we quarantined, how much deserved it
    recall    = TP / (TP + FN)   of the malicious mail, how much did we catch

Honest limits of this exercise
------------------------------
Fourteen hand-written messages is not a validation set. Real mail is overwhelmingly
benign, so the false-positive rate that matters is the one measured against
hundreds of thousands of legitimate messages, and a corpus with a 5:9 ratio cannot
estimate it. What this harness does give is a defensible reason for each threshold
and a record of which specific message breaks when it moves. That is worth more
than a number with no method behind it, and much less than a real evaluation.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from .main import DEFAULT_CONFIG, DEFAULT_CORPUS, load_config
from .parse import parse_email_file
from .score import THRESHOLDS, score_findings
from .signals import Config, run_all_signals

ROOT = Path(__file__).resolve().parent.parent
LABELS_PATH = ROOT / "data" / "labels.json"

BLOCKING_ACTIONS = {"quarantine", "escalate"}


ACTION_ORDER = ("allow", "investigate", "quarantine", "escalate")


@dataclass
class Scored:
    name: str
    label: str
    score: int
    action: str
    confidence: str
    note: str
    action_min: str = "allow"
    action_max: str = "escalate"

    @property
    def correct(self) -> bool:
        """True when the recommended action falls inside the acceptable band."""
        i = ACTION_ORDER.index(self.action)
        return (
            ACTION_ORDER.index(self.action_min) <= i <= ACTION_ORDER.index(self.action_max)
        )

    @property
    def must_block(self) -> bool:
        """Whether this message is one the quarantine line is supposed to catch."""
        return ACTION_ORDER.index(self.action_min) >= ACTION_ORDER.index("quarantine")


def score_corpus(config: Config) -> list[Scored]:
    labels = json.loads(LABELS_PATH.read_text())
    out: list[Scored] = []
    for path in sorted(DEFAULT_CORPUS.glob("*.eml")):
        meta = labels.get(path.name)
        if meta is None:
            raise SystemExit(f"{path.name} has no entry in labels.json")
        email = parse_email_file(path)
        verdict = score_findings(run_all_signals(email, config), config)
        out.append(Scored(
            name=path.name,
            label=meta["label"],
            score=verdict.score,
            action=verdict.action,
            confidence=verdict.confidence,
            note=meta["note"],
            action_min=meta.get("action_min", "allow"),
            action_max=meta.get("action_max", "escalate"),
        ))
    return out


@dataclass
class SweepRow:
    threshold: int
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        denominator = self.tp + self.fp
        return self.tp / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.tp + self.fn
        return self.tp / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def sweep(scored: list[Scored], lo: int = 0, hi: int = 160, step: int = 5) -> list[SweepRow]:
    """
    Sweep the quarantine threshold.

    Note the deliberate simplification: this sweeps the score against the label
    and ignores the decisive-finding floor in score.py, because that floor exists
    precisely so that certain messages are quarantined regardless of score. Rows
    here therefore describe what the arithmetic alone achieves, which is the thing
    a threshold choice can actually influence.
    """
    rows: list[SweepRow] = []
    for threshold in range(lo, hi + 1, step):
        tp = fp = fn = tn = 0
        for item in scored:
            blocked = item.score >= threshold
            if item.must_block:
                if blocked:
                    tp += 1
                else:
                    fn += 1
            else:
                # Includes the compromised-supplier case, which is malicious but
                # is not expected to be blocked automatically. Counting it as a
                # miss would push the threshold down and quarantine legitimate
                # invoice mail to catch something a human is better placed to catch.
                if blocked:
                    fp += 1
                else:
                    tn += 1
        rows.append(SweepRow(threshold, tp, fp, fn, tn))
    return rows


def report(config: Config) -> None:
    scored = score_corpus(config)

    print("Corpus scores at current thresholds")
    print("=" * 88)
    print(f"{'message':46} {'label':10} {'score':>5}  {'action':12} confidence")
    print("-" * 88)
    for item in sorted(scored, key=lambda s: -s.score):
        mark = "" if item.correct else (
            f"  <-- WRONG, expected {item.action_min}"
            + (f"..{item.action_max}" if item.action_max != item.action_min else "")
        )
        print(f"{item.name:46} {item.label:10} {item.score:>5}  "
              f"{item.action:12} {item.confidence}{mark}")

    print()
    print("Quarantine threshold sweep")
    print("=" * 88)
    print(f"{'thr':>4} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}  "
          f"{'precision':>9} {'recall':>7} {'f1':>6}   first mistake introduced")
    print("-" * 88)

    rows = sweep(scored)
    previous_mistakes: set[str] = set()
    for row in rows:
        mistakes = set()
        for item in scored:
            blocked = item.score >= row.threshold
            if item.label == "malicious" and not blocked:
                mistakes.add(f"missed {item.name}")
            if item.label == "benign" and blocked:
                mistakes.add(f"blocked {item.name}")
        new = sorted(mistakes - previous_mistakes)
        previous_mistakes = mistakes
        marker = "*" if row.threshold == THRESHOLDS["quarantine"] else " "
        print(f"{row.threshold:>4}{marker}{row.tp:>3} {row.fp:>3} {row.fn:>3} "
              f"{row.tn:>3}  {row.precision:>9.2f} {row.recall:>7.2f} {row.f1:>6.2f}   "
              f"{new[0] if new else ''}")

    best = max(rows, key=lambda r: (r.f1, -r.threshold))
    print()
    print(f"Highest F1 on this corpus: threshold {best.threshold} "
          f"(precision {best.precision:.2f}, recall {best.recall:.2f})")
    print(f"Configured quarantine threshold: {THRESHOLDS['quarantine']}")
    print()
    print("Read the sweep column on the right rather than the F1 column. F1 on "
          "fourteen messages is noise;")
    print("knowing exactly which message breaks at each threshold is the useful part.")


def confusion(config: Config) -> None:
    scored = score_corpus(config)
    wrong = [s for s in scored if not s.correct]
    print(f"{len(scored) - len(wrong)}/{len(scored)} messages produce an action "
          "inside their acceptable band")
    if not wrong:
        print("no misclassifications at the current thresholds")
        return
    print()
    for item in wrong:
        print(f"  {item.name}")
        print(f"    label {item.label}, action {item.action}, score {item.score}, "
              f"expected {item.action_min}..{item.action_max}")
        print(f"    corpus note: {item.note}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="emailshield-evaluate")
    parser.add_argument("--confusion", action="store_true")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    args = parser.parse_args(argv)

    config = load_config(Path(args.config))
    if args.confusion:
        confusion(config)
    else:
        report(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
