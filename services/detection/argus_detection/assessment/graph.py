"""Deterministic trust-boundary analysis over an architecture graph (from InjectGuard).

A pure function over nodes + edges — no model calls, no storage. Flags the risky
flows: untrusted→trusted instructions, model-controlled authorization, cross-tenant
paths, write-capable tools without approval, untrusted content into memory, model
output into interpreters, retrieval sources without provenance.

InjectGuard ran this over ORM rows; here the graph is plain dataclasses so any
caller (API, worker, a future trace-derived topology builder) can construct one.
The rule ids and messages are unchanged — they are stable identifiers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_UNTRUSTED_SOURCES = {"user", "external_website", "email_system", "file_upload", "document_source"}
_INTERPRETERS = {"code_interpreter", "tool"}
_MEMORY = {"memory_store"}


@dataclass
class GraphNode:
    """One component. `node_type` is e.g. user|model|tool|code_interpreter|memory_store|
    document_source|vector_database|external_website; `trust_level` trusted|untrusted."""

    id: str
    label: str = ""
    node_type: str = "other"
    trust_level: str = "trusted"
    can_write: bool = False
    requires_approval: bool = False
    attributes: dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    source_id: str | None = None
    target_id: str | None = None
    edge_type: str = ""  # sends_prompt|invokes|retrieves_data|reads_data|writes_data|...
    tenant_boundary: bool = False
    name: str = ""


@dataclass(frozen=True)
class GraphInsight:
    rule: str
    severity: str
    message: str
    component_ids: tuple[str, ...] = ()


def analyze_graph(nodes: list[GraphNode], edges: list[GraphEdge]) -> list[GraphInsight]:
    by_id = {n.id: n for n in nodes}
    insights: list[GraphInsight] = []

    for edge in edges:
        src = by_id.get(edge.source_id) if edge.source_id else None
        dst = by_id.get(edge.target_id) if edge.target_id else None

        # Untrusted-to-trusted instruction flow.
        if (
            src
            and dst
            and edge.edge_type == "sends_prompt"
            and src.trust_level == "untrusted"
            and dst.trust_level == "trusted"
        ):
            insights.append(
                GraphInsight(
                    rule="untrusted_to_trusted_instruction",
                    severity="high",
                    message=f"Untrusted '{src.label}' sends instructions to trusted '{dst.label}'.",
                    component_ids=(src.id, dst.id),
                )
            )

        # Untrusted content entering memory.
        if src and dst and src.trust_level == "untrusted" and dst.node_type in _MEMORY:
            insights.append(
                GraphInsight(
                    rule="untrusted_into_memory",
                    severity="high",
                    message=f"Untrusted '{src.label}' writes into memory store '{dst.label}'.",
                    component_ids=(src.id, dst.id),
                )
            )

        # Model output entering an interpreter.
        if (
            src and dst and src.node_type == "model"
            and dst.node_type in _INTERPRETERS and edge.edge_type == "invokes"
        ):
            insights.append(
                GraphInsight(
                    rule="model_output_to_interpreter",
                    severity="critical",
                    message=f"Model '{src.label}' output flows into interpreter/tool '{dst.label}'.",
                    component_ids=(src.id, dst.id),
                )
            )

        # Cross-tenant data path.
        if edge.tenant_boundary and edge.edge_type in {"retrieves_data", "reads_data", "writes_data"}:
            insights.append(
                GraphInsight(
                    rule="cross_tenant_path",
                    severity="high",
                    message=f"Data crosses a tenant boundary via edge '{edge.name or edge.edge_type}'.",
                    component_ids=tuple(c for c in (edge.source_id, edge.target_id) if c),
                )
            )

    for node in nodes:
        # Model-controlled authorization.
        if node.node_type == "model" and node.attributes.get("makes_authorization_decisions"):
            insights.append(
                GraphInsight(
                    rule="model_controlled_authorization",
                    severity="critical",
                    message=f"Model '{node.label}' is marked as making authorization decisions.",
                    component_ids=(node.id,),
                )
            )
        # Write-capable tool without approval.
        if node.node_type == "tool" and node.can_write and not node.requires_approval:
            insights.append(
                GraphInsight(
                    rule="write_tool_without_approval",
                    severity="high",
                    message=f"Write-capable tool '{node.label}' does not require human approval.",
                    component_ids=(node.id,),
                )
            )
        # Retrieval source without provenance.
        _retrieval = node.node_type in {"document_source", "vector_database"}
        if _retrieval and not node.attributes.get("has_provenance"):
            insights.append(
                GraphInsight(
                    rule="retrieval_without_provenance",
                    severity="medium",
                    message=f"Retrieval source '{node.label}' has no provenance tracking.",
                    component_ids=(node.id,),
                )
            )

    return insights
