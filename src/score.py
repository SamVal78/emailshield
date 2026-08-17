"""
Scoring and action recommendation.

Two rules govern this module.

First, no finding is allowed to become a verdict on its own unless it has no
innocent explanation. Only two do: a bidirectional override in a filename, and a
domain that renders identically to a protected one after confusable folding.
Everything else contributes to a total.

Second, the score is not the whole output. Score answers "how much evidence is
there". Confidence answers "how good is that evidence". They are reported
separately, because a high score built entirely from keyword matches is a
different situation from the same score built from a DMARC failure plus a
homoglyph domain, and collapsing the two hides exactly the thing an analyst needs.

Thresholds are set in THRESHOLDS below and are calibrated against the labelled
corpus by evaluate.py. They are not intuitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .signals import Config, Finding


# Actions in increasing order of impact on the recipient.
ACTIONS = ("allow", "investigate", "quarantine", "escalate")

# Score at which each action begins to apply. Calibrated by evaluate.py against
# data/corpus/labels.json; see docs/calibration.md for the sweep that produced
# these numbers and the precision and recall they give on the corpus.
THRESHOLDS = {
    "investigate": 25,
    "quarantine": 60,
    "escalate": 100,
}

# Findings with no plausible innocent explanation. These set a floor on the action
# regardless of total score, because arithmetic should not be able to dilute them.
DECISIVE = {
    ("ES-ATT-004", "Attachment filename contains a bidirectional override"): "quarantine",
    ("ES-URL-003", "Link domain resembles a protected domain (exact_skeleton)"): "quarantine",
    ("ES-ATT-004", "Attachment uses a double extension"): "quarantine",
}

CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Verdict:
    score: int
    action: str
    confidence: str
    findings: list[Finding]
    contributions: list[tuple[str, str, int]] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)
    signals_evaluated: list[str] = field(default_factory=list)
    signals_silent: list[str] = field(default_factory=list)
    decisive_findings: list[str] = field(default_factory=list)


ALL_SIGNAL_IDS = (
    "ES-HDR-001", "ES-AUTH-002", "ES-URL-003",
    "ES-ATT-004", "ES-SOC-005", "ES-CTX-006",
)


def _overall_confidence(findings: list[Finding]) -> str:
    """
    Confidence in the verdict, driven by the best evidence that carries weight.

    A verdict resting only on low-confidence findings is reported as low even when
    the score is high, which is the case that matters: several keyword hits can
    accumulate a substantial score while proving very little.
    """
    positive = [f for f in findings if f.weight > 0]
    if not positive:
        return "low"
    best = max(CONFIDENCE_RANK[f.confidence] for f in positive)
    high_count = sum(1 for f in positive if f.confidence == "high")
    if best == 2 and high_count >= 2:
        return "high"
    if best == 2:
        return "medium-high"
    if best == 1:
        return "medium"
    return "low"


def score_findings(findings: list[Finding], config: Config | None = None) -> Verdict:
    credit_suppressed = any(f.suppresses_credit for f in findings)

    if credit_suppressed:
        # Business email compromise arrives from a genuine account: it
        # authenticates, it aligns, and the sender has years of history. Allowing
        # those credits to offset a banking-change request would let the tool score
        # the most expensive category of fraud at zero, which is precisely what it
        # did before this rule existed.
        total = sum(f.weight for f in findings if f.weight > 0)
    else:
        total = sum(f.weight for f in findings)

    # Credit should reduce suspicion but must never drive the total below zero and
    # produce a misleading "certainly safe" reading.
    total = max(total, 0)

    contributions = sorted(
        ((f.signal_id, f.title, f.weight) for f in findings),
        key=lambda row: -abs(row[2]),
    )

    action = "allow"
    for name in ("investigate", "quarantine", "escalate"):
        if total >= THRESHOLDS[name]:
            action = name

    decisive_hits: list[str] = []
    for finding in findings:
        floor = DECISIVE.get((finding.signal_id, finding.title))
        if floor and ACTIONS.index(floor) > ACTIONS.index(action):
            action = floor
            decisive_hits.append(f"{finding.signal_id}: {finding.title}")
        elif floor:
            decisive_hits.append(f"{finding.signal_id}: {finding.title}")

    confidence = _overall_confidence(findings)

    fired = {f.signal_id for f in findings}
    silent = [s for s in ALL_SIGNAL_IDS if s not in fired]

    reasoning: list[str] = []
    reasoning.append(
        f"total score {total} against thresholds "
        f"investigate>={THRESHOLDS['investigate']}, "
        f"quarantine>={THRESHOLDS['quarantine']}, "
        f"escalate>={THRESHOLDS['escalate']}"
    )
    if decisive_hits:
        reasoning.append(
            "action floor raised by a finding with no innocent explanation: "
            + "; ".join(decisive_hits)
        )
    if confidence in {"low", "medium"} and action in {"quarantine", "escalate"}:
        reasoning.append(
            "the score justifies this action but the supporting evidence is "
            f"{confidence} confidence, so a human should confirm before it is applied"
        )
    negatives = [f for f in findings if f.weight < 0]
    if negatives and credit_suppressed:
        reasoning.append(
            "credits were withheld because a finding is present that authentication "
            "and sender history cannot speak to: "
            + "; ".join(f"{f.title} ({f.weight}, not applied)" for f in negatives)
        )
    elif negatives:
        reasoning.append(
            "score reduced by: "
            + "; ".join(f"{f.title} ({f.weight})" for f in negatives)
        )
    if silent:
        reasoning.append(
            "signals evaluated and silent: " + ", ".join(silent)
        )

    return Verdict(
        score=total,
        action=action,
        confidence=confidence,
        findings=findings,
        contributions=contributions,
        reasoning=reasoning,
        signals_evaluated=list(ALL_SIGNAL_IDS),
        signals_silent=silent,
        decisive_findings=decisive_hits,
    )


def requires_human_approval(verdict: Verdict) -> bool:
    """
    Whether this verdict should be actioned automatically.

    Quarantine and escalate both remove mail from a person's reach or start an
    incident. Doing that automatically on medium or low confidence evidence turns
    a false positive into a business disruption, and the cost is asymmetric: a
    missed phish is one incident, a wrongly quarantined invoice run is a hundred
    complaints and a loss of trust in the tool.
    """
    if verdict.action in {"quarantine", "escalate"}:
        return CONFIDENCE_RANK.get(verdict.confidence.split("-")[0], 0) < 2
    return False
