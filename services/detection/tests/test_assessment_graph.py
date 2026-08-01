"""Architecture-graph analyzer tests (ported from InjectGuard's test_graph_analyzer.py,
adapted from ORM rows to the pure GraphNode/GraphEdge dataclasses)."""

from __future__ import annotations

from argus_detection.assessment.graph import GraphEdge, GraphNode, analyze_graph


def _rules(insights) -> set[str]:
    return {i.rule for i in insights}


def test_flags_untrusted_to_trusted_instruction_flow():
    src = GraphNode(id="u", label="User", node_type="user", trust_level="untrusted")
    dst = GraphNode(id="m", label="LLM", node_type="model", trust_level="trusted")
    edge = GraphEdge(source_id="u", target_id="m", edge_type="sends_prompt")
    assert "untrusted_to_trusted_instruction" in _rules(analyze_graph([src, dst], [edge]))


def test_flags_write_tool_without_approval():
    tool = GraphNode(
        id="t", label="delete_file", node_type="tool",
        can_write=True, requires_approval=False,
    )
    assert "write_tool_without_approval" in _rules(analyze_graph([tool], []))


def test_flags_model_controlled_authorization():
    model = GraphNode(
        id="m", label="LLM", node_type="model",
        attributes={"makes_authorization_decisions": True},
    )
    assert "model_controlled_authorization" in _rules(analyze_graph([model], []))


def test_flags_model_output_into_interpreter():
    model = GraphNode(id="m", label="LLM", node_type="model")
    interp = GraphNode(id="i", label="Sandbox", node_type="code_interpreter")
    edge = GraphEdge(source_id="m", target_id="i", edge_type="invokes")
    assert "model_output_to_interpreter" in _rules(analyze_graph([model, interp], [edge]))


def test_flags_cross_tenant_path():
    edge = GraphEdge(source_id="a", target_id="b", edge_type="reads_data", tenant_boundary=True)
    assert "cross_tenant_path" in _rules(analyze_graph([], [edge]))


def test_flags_retrieval_without_provenance():
    src = GraphNode(id="d", label="Docs", node_type="document_source")
    assert "retrieval_without_provenance" in _rules(analyze_graph([src], []))


def test_clean_graph_has_no_insights():
    user = GraphNode(id="u", label="User", node_type="user", trust_level="untrusted")
    tool = GraphNode(id="t", label="read_only", node_type="tool", can_write=False)
    assert analyze_graph([user, tool], []) == []
