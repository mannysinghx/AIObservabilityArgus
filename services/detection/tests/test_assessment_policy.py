"""Deterministic policy evaluator tests (ported from InjectGuard's test_policy_engine.py)."""

from __future__ import annotations

from argus_detection.assessment.policy import evaluate_conditions, evaluate_policy


def _ctx(**app):
    return {"application": app}


def test_boolean_and_scalar_conditions():
    conds = {
        "application.has_write_capable_tools": True,
        "application.human_approval_enabled": False,
    }
    assert evaluate_conditions(conds, _ctx(has_write_capable_tools=True, human_approval_enabled=False))
    assert not evaluate_conditions(conds, _ctx(has_write_capable_tools=True, human_approval_enabled=True))


def test_in_and_numeric_matchers():
    conds = {
        "application.environment": {"in": ["production"]},
        "application.open_critical_findings": {"gte": 1},
    }
    assert evaluate_conditions(conds, _ctx(environment="production", open_critical_findings=2))
    assert not evaluate_conditions(conds, _ctx(environment="staging", open_critical_findings=2))


def test_unknown_field_fails_closed():
    assert not evaluate_conditions({"application.missing": True}, _ctx())


def test_unknown_operator_fails_closed():
    assert not evaluate_conditions({"application.exposure": {"nope": 1}}, _ctx(exposure="public"))


def test_exists_matcher():
    assert evaluate_conditions({"application.exposure": {"exists": True}}, _ctx(exposure="public"))
    assert evaluate_conditions({"application.missing": {"exists": False}}, _ctx())


def test_empty_conditions_never_match():
    assert not evaluate_conditions({}, _ctx(exposure="public"))


def test_evaluate_policy_returns_action_on_match():
    policy = {
        "conditions": {
            "application.has_write_capable_tools": True,
            "application.human_approval_enabled": False,
        },
        "result_severity": "critical",
        "action": "block_deployment",
        "message": "Enable approval",
    }
    d = evaluate_policy(policy, _ctx(has_write_capable_tools=True, human_approval_enabled=False))
    assert d.matched and d.action == "block_deployment" and d.severity == "critical"

    d2 = evaluate_policy(policy, _ctx(has_write_capable_tools=False, human_approval_enabled=True))
    assert not d2.matched and d2.action == "inform"


def test_matches_regex():
    assert evaluate_conditions({"application.name": {"matches": "^prod-"}}, _ctx(name="prod-agent"))
    assert not evaluate_conditions({"application.name": {"matches": "^prod-"}}, _ctx(name="dev-agent"))
