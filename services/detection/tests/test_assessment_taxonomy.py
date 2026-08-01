"""Taxonomy completeness: every category the assessment engines can emit must have
an explicit entry in the Argus-category mapping (a mapped Category or a deliberate
None), every graph rule must map, and every mapped value must be a real member of
the runtime Category enum. This is the contract that lets assessment findings be
stored/routed alongside runtime findings without inventing categories ad hoc.

Also the mitigation-coverage invariant ported from InjectGuard: every category a
scanner rule can emit must have at least one applicable mitigation in the catalog,
or a finding would ship with no "do this next".
"""

from __future__ import annotations

from argus_detection.assessment import taxonomy
from argus_detection.assessment.graph import GraphEdge, GraphNode, analyze_graph
from argus_detection.assessment.mitigations import CATALOG
from argus_detection.assessment.scanner.rules import ALL_RULES
from argus_detection.models import Category

_SCANNER_CATEGORIES = {r.category for r in ALL_RULES}

# All graph rules, exercised by constructing a graph that trips every one.
_GRAPH_RULES = {
    "untrusted_to_trusted_instruction",
    "untrusted_into_memory",
    "model_output_to_interpreter",
    "cross_tenant_path",
    "model_controlled_authorization",
    "write_tool_without_approval",
    "retrieval_without_provenance",
}


def test_every_scanner_category_has_explicit_mapping():
    unmapped = _SCANNER_CATEGORIES - set(taxonomy.ASSESSMENT_TO_ARGUS_CATEGORY)
    assert not unmapped, f"scanner categories missing from taxonomy: {sorted(unmapped)}"


def test_every_graph_rule_has_mapping():
    unmapped = _GRAPH_RULES - set(taxonomy.GRAPH_RULE_TO_ARGUS_CATEGORY)
    assert not unmapped, f"graph rules missing from taxonomy: {sorted(unmapped)}"


def test_graph_rule_set_matches_analyzer():
    """If a new insight rule is added to the analyzer, this test forces the author
    to extend the taxonomy too (the _GRAPH_RULES constant above is the tripwire)."""
    nodes = [
        GraphNode(id="u", label="User", node_type="user", trust_level="untrusted"),
        GraphNode(id="m", label="LLM", node_type="model",
                  attributes={"makes_authorization_decisions": True}),
        GraphNode(id="i", label="Sandbox", node_type="code_interpreter"),
        GraphNode(id="mem", label="Memory", node_type="memory_store"),
        GraphNode(id="t", label="writer", node_type="tool", can_write=True),
        GraphNode(id="d", label="Docs", node_type="document_source"),
    ]
    edges = [
        GraphEdge(source_id="u", target_id="m", edge_type="sends_prompt"),
        GraphEdge(source_id="u", target_id="mem", edge_type="writes_data"),
        GraphEdge(source_id="m", target_id="i", edge_type="invokes"),
        GraphEdge(source_id="d", target_id="m", edge_type="reads_data", tenant_boundary=True),
    ]
    emitted = {i.rule for i in analyze_graph(nodes, edges)}
    assert emitted == _GRAPH_RULES


def test_mapped_values_are_real_argus_categories():
    valid = {c.value for c in Category}
    for cat in _SCANNER_CATEGORIES:
        mapped = taxonomy.argus_category(cat)
        assert mapped is None or mapped in valid
    for rule in _GRAPH_RULES:
        mapped = taxonomy.argus_graph_category(rule)
        assert mapped in valid


def test_severity_mapping_covers_all_assessment_labels():
    for label in ("critical", "high", "medium", "low", "informational"):
        assert taxonomy.argus_severity(label) in {"critical", "high", "medium", "low", "info"}
    assert taxonomy.argus_severity("informational") == "info"


def test_all_finding_categories_have_a_mitigation():
    # Ported from InjectGuard's test_mitigation_coverage.py. "architecture" is
    # the category graph-derived findings carry.
    covered = {c for m in CATALOG for c in m.applicable_categories}
    needed = _SCANNER_CATEGORIES | {"architecture"}
    missing = needed - covered
    assert not missing, f"finding categories with no mitigation: {sorted(missing)}"
