"""Blast-radius reachability tests (docs/15 §5).

Style matches test_assessment_graph.py: plain GraphNode/GraphEdge fixtures,
one behavior per test, no mocking — the module under test has no I/O to mock.
"""

from __future__ import annotations

from argus_detection.assessment.blastradius import (
    blast_radius_for_insight,
    compute_blast_radius,
)
from argus_detection.assessment.graph import GraphEdge, GraphInsight, GraphNode


def _kinds(hop) -> set[str]:
    return set(hop.sink_kinds)


def test_direct_neighbor_with_sensitive_data_is_a_sink():
    src = GraphNode(id="a", label="Agent", node_type="tool")
    sink = GraphNode(id="b", label="Customer DB", node_type="other", attributes={"has_sensitive_data": True})
    edge = GraphEdge(source_id="a", target_id="b", edge_type="reads_data")
    result = compute_blast_radius([src, sink], [edge], "a")
    assert len(result.reachable_sinks) == 1
    assert result.reachable_sinks[0].node_id == "b"
    assert "sensitive_data" in _kinds(result.reachable_sinks[0])
    assert result.reachable_sinks[0].hops == 1


def test_memory_store_node_type_counts_as_sensitive_without_the_attribute():
    src = GraphNode(id="a", label="Agent", node_type="tool")
    mem = GraphNode(id="m", label="Session memory", node_type="memory_store")
    edge = GraphEdge(source_id="a", target_id="m", edge_type="writes_data")
    result = compute_blast_radius([src, mem], [edge], "a")
    assert "sensitive_data" in _kinds(result.reachable_sinks[0])


def test_write_capable_tool_is_flagged_as_write_action_sink():
    src = GraphNode(id="a", label="Agent", node_type="model")
    tool = GraphNode(id="t", label="delete_account", node_type="tool", can_write=True)
    edge = GraphEdge(source_id="a", target_id="t", edge_type="invokes")
    result = compute_blast_radius([src, tool], [edge], "a")
    assert "write_action" in _kinds(result.reachable_sinks[0])


def test_read_only_tool_is_not_a_sink():
    src = GraphNode(id="a", label="Agent", node_type="model")
    tool = GraphNode(id="t", label="search", node_type="tool", can_write=False)
    edge = GraphEdge(source_id="a", target_id="t", edge_type="invokes")
    result = compute_blast_radius([src, tool], [edge], "a")
    assert result.reachable_sinks == ()


def test_external_website_is_flagged_as_egress():
    src = GraphNode(id="a", label="Agent", node_type="tool")
    ext = GraphNode(id="e", label="attacker.example", node_type="external_website")
    edge = GraphEdge(source_id="a", target_id="e", edge_type="writes_data")
    result = compute_blast_radius([src, ext], [edge], "a")
    assert "external_egress" in _kinds(result.reachable_sinks[0])


def test_cross_tenant_edge_is_flagged():
    src = GraphNode(id="a", label="Agent", node_type="tool")
    other = GraphNode(id="b", label="Other tenant's data", node_type="other", attributes={"has_sensitive_data": True})
    edge = GraphEdge(source_id="a", target_id="b", edge_type="reads_data", tenant_boundary=True)
    result = compute_blast_radius([src, other], [edge], "a")
    assert "cross_tenant" in _kinds(result.reachable_sinks[0])


def test_hop_count_increases_along_a_chain():
    nodes = [
        GraphNode(id="a", node_type="user"),
        GraphNode(id="b", node_type="model"),
        GraphNode(id="c", node_type="tool", can_write=True),
    ]
    edges = [
        GraphEdge(source_id="a", target_id="b", edge_type="sends_prompt"),
        GraphEdge(source_id="b", target_id="c", edge_type="invokes"),
    ]
    result = compute_blast_radius(nodes, edges, "a")
    assert result.reachable_sinks[0].node_id == "c"
    assert result.reachable_sinks[0].hops == 2
    assert result.reachable_sinks[0].path == ("a", "b", "c")


def test_node_requiring_approval_gates_everything_downstream():
    nodes = [
        GraphNode(id="a", node_type="user"),
        GraphNode(id="gate", node_type="tool", requires_approval=True),
        GraphNode(id="sink", node_type="other", attributes={"has_sensitive_data": True}),
    ]
    edges = [
        GraphEdge(source_id="a", target_id="gate", edge_type="invokes"),
        GraphEdge(source_id="gate", target_id="sink", edge_type="writes_data"),
    ]
    result = compute_blast_radius(nodes, edges, "a")
    sink_hop = next(h for h in result.reachable_sinks if h.node_id == "sink")
    assert sink_hop.gated is True


def test_no_approval_gate_on_path_means_not_gated():
    nodes = [
        GraphNode(id="a", node_type="user"),
        GraphNode(id="sink", node_type="other", attributes={"has_sensitive_data": True}),
    ]
    edges = [GraphEdge(source_id="a", target_id="sink", edge_type="reads_data")]
    result = compute_blast_radius(nodes, edges, "a")
    assert result.reachable_sinks[0].gated is False


def test_shortest_path_wins_when_multiple_routes_exist():
    # a -> sink directly (1 hop), and a -> b -> sink (2 hops). BFS must report 1.
    nodes = [
        GraphNode(id="a", node_type="user"),
        GraphNode(id="b", node_type="tool"),
        GraphNode(id="sink", node_type="other", attributes={"has_sensitive_data": True}),
    ]
    edges = [
        GraphEdge(source_id="a", target_id="sink", edge_type="reads_data"),
        GraphEdge(source_id="a", target_id="b", edge_type="invokes"),
        GraphEdge(source_id="b", target_id="sink", edge_type="reads_data"),
    ]
    result = compute_blast_radius(nodes, edges, "a")
    assert len(result.reachable_sinks) == 1
    assert result.reachable_sinks[0].hops == 1


def test_cycle_terminates_and_does_not_duplicate_sinks():
    nodes = [
        GraphNode(id="a", node_type="user"),
        GraphNode(id="b", node_type="tool"),
        GraphNode(id="sink", node_type="other", attributes={"has_sensitive_data": True}),
    ]
    edges = [
        GraphEdge(source_id="a", target_id="b", edge_type="invokes"),
        GraphEdge(source_id="b", target_id="a", edge_type="invokes"),  # cycle back
        GraphEdge(source_id="b", target_id="sink", edge_type="reads_data"),
    ]
    result = compute_blast_radius(nodes, edges, "a")
    assert len(result.reachable_sinks) == 1
    assert result.truncated is False


def test_unreachable_node_is_excluded():
    nodes = [
        GraphNode(id="a", node_type="user"),
        GraphNode(id="isolated", node_type="other", attributes={"has_sensitive_data": True}),
    ]
    result = compute_blast_radius(nodes, [], "a")
    assert result.reachable_sinks == ()
    assert result.nodes_visited == 1


def test_no_sinks_reachable_returns_empty_but_still_reports_nodes_visited():
    nodes = [
        GraphNode(id="a", node_type="user"),
        GraphNode(id="b", node_type="model"),
    ]
    edges = [GraphEdge(source_id="a", target_id="b", edge_type="sends_prompt")]
    result = compute_blast_radius(nodes, edges, "a")
    assert result.reachable_sinks == ()
    assert result.nodes_visited == 2


def test_missing_start_node_returns_empty_result_not_an_error():
    result = compute_blast_radius([GraphNode(id="a")], [], "does-not-exist")
    assert result.reachable_sinks == ()
    assert result.nodes_visited == 0
    assert result.from_label == ""


def test_truncates_a_pathologically_long_chain():
    depth = 20
    nodes = [GraphNode(id=str(i), node_type="tool") for i in range(depth + 1)]
    nodes.append(GraphNode(id="sink", node_type="other", attributes={"has_sensitive_data": True}))
    edges = [GraphEdge(source_id=str(i), target_id=str(i + 1), edge_type="invokes") for i in range(depth)]
    edges.append(GraphEdge(source_id=str(depth), target_id="sink", edge_type="reads_data"))
    result = compute_blast_radius(nodes, edges, "0")
    assert result.truncated is True
    # The sink sits past _MAX_DEPTH, so it must not appear as reachable.
    assert all(h.node_id != "sink" for h in result.reachable_sinks)


def test_blast_radius_for_insight_walks_from_the_untrusted_component():
    user = GraphNode(id="u", label="User", node_type="user", trust_level="untrusted")
    model = GraphNode(id="m", label="LLM", node_type="model", trust_level="trusted")
    tool = GraphNode(id="t", label="delete_account", node_type="tool", can_write=True)
    edges = [
        GraphEdge(source_id="u", target_id="m", edge_type="sends_prompt"),
        GraphEdge(source_id="m", target_id="t", edge_type="invokes"),
    ]
    insight = GraphInsight(
        rule="untrusted_to_trusted_instruction",
        severity="high",
        message="irrelevant for this test",
        component_ids=("u", "m"),
    )
    results = blast_radius_for_insight([user, model, tool], edges, insight)
    assert len(results) == 1  # only "u" is untrusted among the named components
    assert results[0].from_node_id == "u"
    assert any(h.node_id == "t" for h in results[0].reachable_sinks)


def test_blast_radius_for_insight_falls_back_when_nothing_named_is_untrusted():
    tool = GraphNode(id="t", label="delete_account", node_type="tool", can_write=True, trust_level="trusted")
    insight = GraphInsight(
        rule="write_tool_without_approval",
        severity="high",
        message="irrelevant for this test",
        component_ids=("t",),
    )
    results = blast_radius_for_insight([tool], [], insight)
    assert len(results) == 1
    assert results[0].from_node_id == "t"
