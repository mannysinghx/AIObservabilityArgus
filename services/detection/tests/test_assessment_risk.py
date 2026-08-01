"""Deterministic risk-engine tests (ported from InjectGuard's test_risk_engine.py)."""

from __future__ import annotations

import pytest

from argus_detection.assessment.risk import (
    RiskFactors,
    compute_risk,
    factors_from_signal,
    severity_for,
)


def test_max_factors_is_critical_100():
    r = compute_risk(RiskFactors(5, 5, 5, 5, 5))
    assert r.base_score == 95
    assert r.confidence_adjustment == 5
    assert r.final_score == 100
    assert r.severity == "critical"


def test_min_factors_clamps_to_zero():
    r = compute_risk(RiskFactors(1, 1, 1, 1, 1))
    assert r.base_score == 0
    assert r.confidence_adjustment == -5
    assert r.final_score == 0
    assert r.severity == "informational"


def test_mid_factors_are_medium():
    r = compute_risk(RiskFactors(3, 3, 3, 3, 3))
    assert r.confidence_adjustment == 0
    assert r.severity == "medium"
    assert 40 <= r.final_score <= 69


def test_base_weights_sum_to_095_confidence_is_separate_adjustment():
    # Likelihood 25 + impact 30 + exposure 20 + control 20 = 95%; confidence is the
    # remaining ±5% applied as an adjustment, not a base weight.
    r = compute_risk(RiskFactors(4, 4, 2, 2, 4))
    assert abs(sum(r.weights.values()) - 0.95) < 1e-9
    assert r.rationale
    assert r.scoring_version == "1.0.0"


def test_deterministic_recompute_is_stable():
    f = RiskFactors(4, 5, 3, 2, 3)
    assert compute_risk(f).final_score == compute_risk(f).final_score


def test_severity_bands():
    assert severity_for(95) == "critical"
    assert severity_for(75) == "high"
    assert severity_for(50) == "medium"
    assert severity_for(20) == "low"
    assert severity_for(5) == "informational"


def test_invalid_factor_raises():
    with pytest.raises(ValueError):
        compute_risk(RiskFactors(6, 1, 1, 1, 1))


def test_signal_mapping_is_deterministic():
    a = factors_from_signal(severity="high", confidence="medium", is_public=True)
    b = factors_from_signal(severity="high", confidence="medium", is_public=True)
    assert a == b
    assert a.exposure == 5  # public
    assert a.control_weakness == 4  # no compensating controls


def test_compensating_controls_lower_control_weakness():
    f = factors_from_signal(severity="high", has_compensating_controls=True)
    assert f.control_weakness == 2


# ── Phase-4 synthesis: runtime evidence raising likelihood ────────────────────

def test_observed_exploitation_maxes_likelihood():
    # Without evidence, likelihood is only a proxy derived from impact.
    theoretical = factors_from_signal(severity="medium")
    demonstrated = factors_from_signal(severity="medium", observed_exploitation=True)
    assert theoretical.likelihood == 3
    assert demonstrated.likelihood == 5
    # Only likelihood moves — evidence that an attack class is being attempted
    # says nothing about how bad it would be, or how exposed the app is.
    assert demonstrated.impact == theoretical.impact
    assert demonstrated.exposure == theoretical.exposure
    assert demonstrated.control_weakness == theoretical.control_weakness


def test_observed_exploitation_raises_the_score():
    lo = compute_risk(factors_from_signal(severity="medium"))
    hi = compute_risk(factors_from_signal(severity="medium", observed_exploitation=True))
    assert hi.final_score > lo.final_score


def test_observed_flag_is_not_free_severity():
    # A hygiene-grade finding that happens to share an attack class must not be
    # promoted to critical by evidence alone — impact still bounds the outcome.
    r = compute_risk(factors_from_signal(severity="low", observed_exploitation=True))
    assert r.severity in {"low", "medium"}


def test_note_is_appended_to_rationale_and_score_unchanged():
    f = factors_from_signal(severity="high", observed_exploitation=True)
    plain = compute_risk(f)
    noted = compute_risk(f, note="Likelihood is maximal because X was observed.")
    # The note explains the factors; it must never change the arithmetic.
    assert noted.final_score == plain.final_score
    assert noted.rationale.endswith("Likelihood is maximal because X was observed.")
    assert plain.rationale in noted.rationale
