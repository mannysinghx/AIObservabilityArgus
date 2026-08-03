"""Attack-template generator tests (docs/15 §1, phase 1).

Style matches test_assessment_graph.py / test_assessment_blastradius.py:
plain dataclass fixtures, one behavior per test, no mocking — the module
under test has no I/O to mock (see generator.py's docstring: it never sends
anything anywhere).
"""

from __future__ import annotations

from argus_detection.assessment.graph import GraphInsight
from argus_detection.redteam.generator import (
    GRAPH_ATTACK_TEMPLATES,
    RULE_ATTACK_TEMPLATES,
    FindingRef,
    build_attack_plan,
)


def test_every_current_scanner_rule_has_a_template():
    expected = {f"IG-PROMPT-{i:03d}" for i in range(1, 21)}
    assert set(RULE_ATTACK_TEMPLATES.keys()) == expected


def test_every_current_graph_insight_rule_has_a_template():
    expected = {
        "untrusted_to_trusted_instruction",
        "untrusted_into_memory",
        "model_output_to_interpreter",
        "cross_tenant_path",
        "model_controlled_authorization",
        "write_tool_without_approval",
        "retrieval_without_provenance",
    }
    assert set(GRAPH_ATTACK_TEMPLATES.keys()) == expected


def test_every_template_key_is_globally_unique():
    all_keys = [t.key for templates in RULE_ATTACK_TEMPLATES.values() for t in templates]
    all_keys += [t.key for templates in GRAPH_ATTACK_TEMPLATES.values() for t in templates]
    assert len(all_keys) == len(set(all_keys))


def test_every_template_has_a_non_empty_payload_and_rationale():
    for templates in list(RULE_ATTACK_TEMPLATES.values()) + list(GRAPH_ATTACK_TEMPLATES.values()):
        for t in templates:
            assert t.payload.strip()
            assert t.rationale.strip()


def test_a_mapped_finding_produces_one_attack_carrying_its_context():
    finding = FindingRef(rule_id="IG-PROMPT-014", category="rag-security", severity="high", document_name="support_agent_system_prompt")
    plan = build_attack_plan(findings=[finding])
    assert len(plan.attacks) == 1
    a = plan.attacks[0]
    assert a.source == "finding"
    assert a.source_id == "IG-PROMPT-014"
    assert a.category == "rag-security"
    assert a.document_name == "support_agent_system_prompt"
    assert a.payload  # a real payload string, not empty
    assert plan.unmapped_sources == ()


def test_an_unmapped_rule_id_is_reported_not_silently_dropped():
    finding = FindingRef(rule_id="IG-PROMPT-999-does-not-exist", category="made-up")
    plan = build_attack_plan(findings=[finding])
    assert plan.attacks == ()
    assert plan.unmapped_sources == ("IG-PROMPT-999-does-not-exist",)


def test_a_mapped_graph_insight_produces_an_attack_naming_its_components():
    insight = GraphInsight(
        rule="write_tool_without_approval", severity="high",
        message="irrelevant for this test", component_ids=("delete_account_tool",),
    )
    plan = build_attack_plan(insights=[insight])
    assert len(plan.attacks) == 1
    a = plan.attacks[0]
    assert a.source == "graph_insight"
    assert a.source_id == "write_tool_without_approval"
    assert a.target_component_ids == ("delete_account_tool",)
    assert a.severity_hint == "high"


def test_an_unmapped_graph_insight_rule_is_reported():
    insight = GraphInsight(rule="some_future_rule", severity="low", message="x", component_ids=())
    plan = build_attack_plan(insights=[insight])
    assert plan.attacks == ()
    assert plan.unmapped_sources == ("some_future_rule",)


def test_findings_and_insights_combine_in_one_plan():
    finding = FindingRef(rule_id="IG-PROMPT-001", category="prompt-separation")
    insight = GraphInsight(rule="cross_tenant_path", severity="high", message="x", component_ids=("a", "b"))
    plan = build_attack_plan(findings=[finding], insights=[insight])
    sources = {a.source for a in plan.attacks}
    assert sources == {"finding", "graph_insight"}
    assert len(plan.attacks) == 2


def test_duplicate_findings_deduplicate_to_one_attack():
    finding = FindingRef(rule_id="IG-PROMPT-001", category="prompt-separation")
    plan = build_attack_plan(findings=[finding, finding, finding])
    assert len(plan.attacks) == 1


def test_max_total_truncates_and_sets_the_flag():
    findings = [FindingRef(rule_id=f"IG-PROMPT-{i:03d}", category="x") for i in range(1, 11)]
    plan = build_attack_plan(findings=findings, max_total=3)
    assert len(plan.attacks) == 3
    assert plan.truncated is True


def test_no_truncation_flag_when_everything_fits():
    findings = [FindingRef(rule_id="IG-PROMPT-001", category="x")]
    plan = build_attack_plan(findings=findings, max_total=50)
    assert plan.truncated is False


def test_empty_input_yields_an_empty_untruncated_plan():
    plan = build_attack_plan()
    assert plan.attacks == ()
    assert plan.unmapped_sources == ()
    assert plan.truncated is False


def test_generator_never_imports_anything_network_capable():
    # A cheap but real tripwire: if a future edit adds an HTTP client import
    # to this module, that's the one change this proposal's own design doc
    # says needs its own review before it happens — this test makes that
    # change visible immediately rather than relying on someone noticing in
    # review.
    import argus_detection.redteam.generator as gen
    with open(gen.__file__, encoding="utf-8") as f:
        source = f.read()
    for forbidden in ("import requests", "import httpx", "import urllib", "import socket", "aiohttp"):
        assert forbidden not in source, f"unexpected network-capable import: {forbidden}"
