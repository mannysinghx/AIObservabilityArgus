"""Severity & outcome scoring for span-level (L1/L2) findings.

Trace-level (L4) findings set their own severity from behavioral signals; this
module maps content-layer scores to a severity, respecting the taint class
(attempted-in-a-document is not the same as executed).
"""
from __future__ import annotations

from .models import (
    Category,
    Finding,
    LayerResult,
    Observation,
    Outcome,
    Severity,
    TaintClass,
)


def _severity_from_score(score01: float) -> Severity:
    # A single clear-injection rule (weight ~0.4-0.55) should register as at
    # least `low` so it appears in the feed and escalates; strong/stacked
    # signals climb to medium/high. L2/L3 refine these further.
    if score01 >= 0.85:
        return Severity.high
    if score01 >= 0.65:
        return Severity.medium
    if score01 >= 0.40:
        return Severity.low
    return Severity.info


def combine(
    obs: Observation,
    taint: TaintClass,
    l1: LayerResult,
    l2: LayerResult | None,
) -> Finding | None:
    """Fuse L1 + L2 into at most one span-level finding. Returns None if nothing
    crosses the reporting floor."""
    l2_score = l2.score if l2 else 0.0
    # Weighted fusion: classifiers, when present, dominate; heuristics provide a
    # floor and explainability. Ensemble disagreement (spread in l2.detail) nudges
    # the score up because a split vote is itself suspicious.
    if l2 and l2.detail:
        spread = max(l2.detail.values()) - min(l2.detail.values())
    else:
        spread = 0.0
    fused = max(l1.score * 0.6 + l2_score * 0.7, l1.score, l2_score)
    fused = min(1.0, fused + 0.1 * spread)

    # Reporting floor. Below this we record nothing (keeps the feed clean).
    if fused < 0.45 and not l1.matches:
        return None
    if fused < 0.35:
        return None

    # Category: prefer the highest-weight L1 match's category, else infer.
    if l1.matches:
        top = max(l1.matches, key=lambda m: m.weight)
        category = top.category
        excerpt = top.excerpt
        rule_ids = [m.rule_id for m in l1.matches]
        # An injection/jailbreak found *in ingested content* is indirect by
        # definition — relabel so the feed reflects the real attack class.
        if taint == TaintClass.untrusted_external and category in (
            Category.direct_injection,
            Category.jailbreak,
        ):
            category = Category.indirect_injection
    else:
        category = (
            Category.indirect_injection
            if taint == TaintClass.untrusted_external
            else Category.direct_injection
        )
        excerpt = (obs.content or "")[:160]
        rule_ids = []

    severity = _severity_from_score(fused)

    # Taint shapes outcome: an injection *in ingested content* is at least an
    # attempt; whether it succeeded is L4's call. Direct user injections are
    # attempts too (the model may or may not have complied).
    if taint == TaintClass.untrusted_external:
        outcome = Outcome.attempted
        # Indirect attempts on their own cap at 'high' — 'critical' requires L4
        # confirmation of downstream impact.
        if severity == Severity.critical:
            severity = Severity.high
    elif taint == TaintClass.user:
        outcome = Outcome.attempted
    else:
        outcome = Outcome.unknown

    return Finding(
        observation_id=obs.observation_id,
        trace_id=obs.trace_id,
        category=category,
        severity=severity,
        outcome=outcome,
        score=round(fused * 100, 1),
        l1_rules=rule_ids,
        l2_scores=(l2.detail if l2 else {}),
        evidence_excerpt=excerpt,
    )
