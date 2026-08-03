"""Blast-radius reachability analysis over an architecture graph.

Design: docs/15 §5 ("Blast-radius / business-risk simulator"). A pure function
over the same GraphNode/GraphEdge shapes analyze_graph() already consumes — no
model calls, no storage, no dependency on the rest of the assessment engine
beyond those two dataclasses. This module is purely additive: nothing in
graph.py, risk.py, or any caller of them is imported by, or needs to import,
this file. Nothing existing changes shape or behavior as a result of it
existing.

Given a starting component (usually the untrusted-side node named by an
existing GraphInsight), it walks the graph forward and reports which
sensitive components ("sinks") are reachable, how many hops away, and
whether anything already gates the path (a component requiring human
approval).

Deliberately does NOT attempt to put a dollar figure on exposure — inventing
a valuation the engine has no basis for would be exactly the kind of
manufactured precision the rest of this codebase's risk-scoring avoids
(risk.py's rationale strings are all reproducible from stored factors, never
guessed). The output here is qualitative and hop-counted; a caller with its
own business-impact data can layer a valuation on top, but this module never
invents one.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .graph import GraphEdge, GraphInsight, GraphNode

# Node types treated as holding sensitive data outright, regardless of the
# `has_sensitive_data` attribute — the same memory/document vocabulary
# analyze_graph() already treats specially.
_SENSITIVE_NODE_TYPES = {"memory_store", "vector_database", "document_source"}

# Node types treated as an external egress point — reaching one of these means
# something can leave the application's own boundary.
_EGRESS_NODE_TYPES = {"external_website", "email_system", "file_upload"}

# A backstop, not the primary cycle guard (the `visited` set below already
# makes cycles safe — BFS never revisits a node). This exists so a
# pathologically large or malformed graph still terminates in bounded work
# rather than walking every node reachable through a thousand-node fan-out.
_MAX_DEPTH = 12


@dataclass(frozen=True)
class BlastRadiusHop:
    """One reachable sink, and how the walk got there."""

    node_id: str
    label: str
    # Why this node counts as a sink: sensitive_data | write_action |
    # external_egress | cross_tenant. A node can carry more than one.
    sink_kinds: tuple[str, ...]
    hops: int
    path: tuple[str, ...]  # node ids, source-first, including both ends
    gated: bool  # True if some component on the path already requires approval


@dataclass(frozen=True)
class BlastRadiusResult:
    from_node_id: str
    from_label: str
    reachable_sinks: tuple[BlastRadiusHop, ...]  # nearest first
    nodes_visited: int
    truncated: bool  # True if _MAX_DEPTH cut the walk short


def _sink_kinds(node: GraphNode) -> tuple[str, ...]:
    kinds: list[str] = []
    if node.attributes.get("has_sensitive_data") or node.node_type in _SENSITIVE_NODE_TYPES:
        kinds.append("sensitive_data")
    if node.node_type == "tool" and node.can_write:
        kinds.append("write_action")
    if node.node_type in _EGRESS_NODE_TYPES:
        kinds.append("external_egress")
    return tuple(kinds)


def compute_blast_radius(
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    from_node_id: str,
) -> BlastRadiusResult:
    """BFS forward from `from_node_id` along every edge in the graph.

    The graph doesn't model "read-only" vs "read-write" at the edge level
    beyond `edge_type`, and a walk narrowed to a specific subset of edge
    types would risk under-reporting what's actually reachable — this
    codebase's detection layers consistently choose the conservative
    (over-report, never silently miss) side of that trade-off elsewhere
    (see taint.py's "unknown → treat as user input"), so this does too.

    Returns each distinct sink node reached, nearest hop first. A node
    reachable by more than one path keeps its shortest one, since BFS visits
    nodes in non-decreasing depth order.
    """
    by_id = {n.id: n for n in nodes}
    start = by_id.get(from_node_id)
    if start is None:
        return BlastRadiusResult(
            from_node_id=from_node_id,
            from_label="",
            reachable_sinks=(),
            nodes_visited=0,
            truncated=False,
        )

    adjacency: dict[str, list[GraphEdge]] = {}
    for e in edges:
        if e.source_id:
            adjacency.setdefault(e.source_id, []).append(e)

    # node_id -> (depth, path-so-far, gated-so-far)
    visited: dict[str, tuple[int, tuple[str, ...], bool]] = {start.id: (0, (start.id,), False)}
    queue: deque[str] = deque([start.id])
    truncated = False

    while queue:
        current_id = queue.popleft()
        depth, path, gated_so_far = visited[current_id]
        if depth >= _MAX_DEPTH:
            truncated = True
            continue
        for edge in adjacency.get(current_id, []):
            target_id = edge.target_id
            if not target_id or target_id not in by_id or target_id in visited:
                continue
            target = by_id[target_id]
            visited[target_id] = (
                depth + 1,
                path + (target_id,),
                gated_so_far or target.requires_approval,
            )
            queue.append(target_id)

    sinks: list[BlastRadiusHop] = []
    for node_id, (depth, path, gated) in visited.items():
        if node_id == start.id:
            continue
        node = by_id[node_id]
        kinds = list(_sink_kinds(node))
        parent_id = path[-2]
        landing_edges = [e for e in adjacency.get(parent_id, []) if e.target_id == node_id]
        if any(e.tenant_boundary for e in landing_edges):
            kinds.append("cross_tenant")
        if kinds:
            sinks.append(
                BlastRadiusHop(
                    node_id=node.id,
                    label=node.label or node.id,
                    sink_kinds=tuple(kinds),
                    hops=depth,
                    path=path,
                    gated=gated,
                )
            )

    sinks.sort(key=lambda h: h.hops)
    return BlastRadiusResult(
        from_node_id=start.id,
        from_label=start.label or start.id,
        reachable_sinks=tuple(sinks),
        nodes_visited=len(visited),
        truncated=truncated,
    )


def blast_radius_for_insight(
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    insight: GraphInsight,
) -> list[BlastRadiusResult]:
    """Convenience wrapper: a GraphInsight from analyze_graph() already names
    the component(s) an untrusted flow touches (`component_ids`). Runs the
    walk from each *untrusted* component the insight names, so a caller can
    go straight from "here is a finding" to "here is what it can reach"
    without re-deriving the starting point.

    Falls back to every named component if none are marked untrusted, so a
    caller still gets an answer for insight types that don't turn on
    trust_level (e.g. `write_tool_without_approval`, which names a tool, not
    an untrusted source).
    """
    by_id = {n.id: n for n in nodes}
    untrusted_starts = [
        cid for cid in insight.component_ids if by_id.get(cid) and by_id[cid].trust_level == "untrusted"
    ]
    starts = untrusted_starts or list(insight.component_ids)
    return [compute_blast_radius(nodes, edges, cid) for cid in starts]
