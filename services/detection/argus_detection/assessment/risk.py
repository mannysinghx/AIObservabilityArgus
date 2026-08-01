"""Transparent, deterministic, versioned risk-scoring engine (from InjectGuard).

Every score stores its raw factors, weights, base, confidence adjustment, final,
severity, and rationale so it is fully reproducible and recomputable after a
scoring-model change. `factors_from_signal` is the deterministic bridge from a
detection/assessment signal to factors: same signal + application context always
yields the same factors, so a rescore is a pure function of stored inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SCORING_VERSION = "1.0.0"

WEIGHTS = {
    "likelihood": 0.25,
    "impact": 0.30,
    "exposure": 0.20,
    "control_weakness": 0.20,
}
CONFIDENCE_MAX_ADJUST = 5  # ± points


@dataclass(frozen=True)
class RiskFactors:
    likelihood: int
    impact: int
    exposure: int
    control_weakness: int
    confidence: int

    def validate(self) -> None:
        for name in ("likelihood", "impact", "exposure", "control_weakness", "confidence"):
            v = getattr(self, name)
            if not (1 <= v <= 5):
                raise ValueError(f"{name} must be in 1..5, got {v}")


@dataclass(frozen=True)
class RiskResult:
    factors: RiskFactors
    weights: dict[str, float]
    base_score: int
    confidence_adjustment: int
    final_score: int
    severity: str
    rationale: str
    scoring_version: str = SCORING_VERSION
    contributions: dict[str, float] = field(default_factory=dict)


def _norm(v: int) -> float:
    return (v - 1) / 4  # map 1..5 → 0..1


def severity_for(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "informational"


def compute_risk(factors: RiskFactors, note: str = "") -> RiskResult:
    """Score the factors. `note` is appended to the rationale — used to record
    *why* a factor was set where it was when the reason is evidence rather than
    the default derivation (e.g. runtime telemetry raising likelihood). The
    score stays a pure function of the factors; the note only explains them."""
    factors.validate()
    contributions = {
        name: WEIGHTS[name] * _norm(getattr(factors, name))
        for name in WEIGHTS
    }
    base01 = sum(contributions.values())
    base_score = round(base01 * 100)

    conf_factor = (_norm(factors.confidence) - 0.5) * 2  # -1..+1
    conf_adj = round(conf_factor * CONFIDENCE_MAX_ADJUST)  # -5..+5
    final_score = max(0, min(100, base_score + conf_adj))
    severity = severity_for(final_score)

    rationale = (
        f"Base {base_score} from likelihood={factors.likelihood}, impact={factors.impact}, "
        f"exposure={factors.exposure}, control_weakness={factors.control_weakness} "
        f"(weighted). Confidence={factors.confidence} adjusts {conf_adj:+d} → {final_score} "
        f"({severity})."
    )
    if note:
        rationale = f"{rationale} {note}"
    return RiskResult(
        factors=factors,
        weights=dict(WEIGHTS),
        base_score=base_score,
        confidence_adjustment=conf_adj,
        final_score=final_score,
        severity=severity,
        rationale=rationale,
        contributions={k: round(v * 100, 2) for k, v in contributions.items()},
    )


# ── Signal → factors mapping ─────────────────────────────────────────────────

_IMPACT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
_CONFIDENCE = {"high": 5, "medium": 3, "low": 2}


def factors_from_signal(
    *,
    severity: str,
    confidence: str = "medium",
    is_public: bool = False,
    has_compensating_controls: bool = False,
    observed_exploitation: bool = False,
) -> RiskFactors:
    """Map a signal to factors.

    `observed_exploitation` is the Phase-4 synthesis input: the runtime side has
    actually recorded attempts of this weakness's attack class against THIS
    application. Without it, likelihood is only a proxy derived from impact —
    an informed guess about whether anyone would try. With it, guessing is over,
    so likelihood goes to its maximum. This is the one factor backed by evidence
    rather than inference, and it is deliberately the strongest.
    """
    impact = _IMPACT.get(severity, 3)
    likelihood = 5 if observed_exploitation else max(1, min(5, impact))
    exposure = 5 if is_public else 3
    control_weakness = 2 if has_compensating_controls else 4
    conf = _CONFIDENCE.get(confidence, 3)
    return RiskFactors(
        likelihood=likelihood,
        impact=impact,
        exposure=exposure,
        control_weakness=control_weakness,
        confidence=conf,
    )
