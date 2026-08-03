"""Pydantic request/response shapes for the /v1/assess endpoints.

Kept separate from argus_detection.models (the runtime scan shapes) because the
two surfaces version independently: a runtime scan is called per-span by the
worker; an assessment is called per-application by the web tier.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class PromptDoc(BaseModel):
    """One prompt under assessment. `name` is echoed back for correlation."""

    kind: str = "system"  # system|developer|tool_description|memory_instruction|...
    content: str
    name: str = ""


class AssessContext(BaseModel):
    """Deterministic application facts. Everything defaults to the safe-side
    assumption InjectGuard used: unknown facts neither suppress rules nor
    grant compensating-control credit."""

    has_write_capable_tools: bool = False
    human_approval_enabled: bool = False
    has_retrieval: bool = False
    is_public: bool = False
    tool_names_user_controlled: bool = False
    has_compensating_controls: bool = False
    has_sensitive_data: bool = False
    business_criticality: str = "medium"  # critical|high|medium|low
    # Phase-4 synthesis. Argus security-event categories this application has
    # actually seen in production (runtime taxonomy spelling, e.g.
    # "indirect_injection"). A finding whose argus_category appears here is a
    # demonstrated exposure rather than a theoretical one, and its likelihood
    # is scored accordingly. Supplied by the caller, which owns the telemetry —
    # this service stays pure and never queries anything.
    observed_categories: list[str] = Field(default_factory=list)


class RiskBreakdown(BaseModel):
    """The full transparent risk computation — reproducible from `factors` alone."""

    factors: dict[str, int]
    weights: dict[str, float]
    contributions: dict[str, float]
    base_score: int
    confidence_adjustment: int
    final_score: int
    severity: str
    rationale: str
    scoring_version: str


class MitigationRec(BaseModel):
    key: str
    title: str
    category: str
    priority: str
    difficulty: str
    expected_risk_reduction: int
    score: float
    rationale: str
    implementation_guidance: str
    validation_procedure: str


class AssessFinding(BaseModel):
    document_index: int
    document_name: str = ""
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    explanation: str
    affected_lines: list[int]
    evidence: str
    recommendation: str
    frameworks: list[dict[str, str]] = Field(default_factory=list)
    # Bridge into the runtime taxonomy (None = hygiene finding, no attack class).
    argus_category: str | None = None
    argus_severity: str
    # True when this weakness's attack class has been observed against this
    # application in production — the finding is demonstrated, not theoretical.
    observed_in_production: bool = False
    risk: RiskBreakdown
    mitigations: list[MitigationRec] = Field(default_factory=list)


class AssessPromptRequest(BaseModel):
    project_id: str = "default"
    documents: list[PromptDoc]
    context: AssessContext = Field(default_factory=AssessContext)
    # How many ranked mitigations to attach per finding (0 disables).
    top_mitigations: int = Field(default=3, ge=0, le=10)


class AssessPromptResponse(BaseModel):
    project_id: str
    finding_count: int
    max_severity: str | None = None      # native assessment label
    overall_risk: int = 0                # max finding final_score, 0 when clean
    scoring_version: str
    findings: list[AssessFinding] = Field(default_factory=list)


class GraphNodeIn(BaseModel):
    id: str
    label: str = ""
    node_type: str = "other"
    trust_level: str = "trusted"
    can_write: bool = False
    requires_approval: bool = False
    attributes: dict = Field(default_factory=dict)


class GraphEdgeIn(BaseModel):
    source: str | None = None
    target: str | None = None
    edge_type: str = ""
    tenant_boundary: bool = False
    name: str = ""


class AssessGraphRequest(BaseModel):
    project_id: str = "default"
    nodes: list[GraphNodeIn]
    edges: list[GraphEdgeIn] = Field(default_factory=list)


class GraphInsightOut(BaseModel):
    rule: str
    severity: str
    message: str
    component_ids: list[str] = Field(default_factory=list)
    argus_category: str | None = None
    argus_severity: str


class AssessGraphResponse(BaseModel):
    project_id: str
    insight_count: int
    max_severity: str | None = None
    insights: list[GraphInsightOut] = Field(default_factory=list)


class AssessBlastRadiusRequest(BaseModel):
    """docs/15 §5. Same graph shape as AssessGraphRequest, plus the component
    to walk forward from — typically the untrusted component named by a
    GraphInsight the caller already has from /v1/assess/graph."""

    project_id: str = "default"
    nodes: list[GraphNodeIn]
    edges: list[GraphEdgeIn] = Field(default_factory=list)
    from_node_id: str


class BlastRadiusHopOut(BaseModel):
    node_id: str
    label: str
    sink_kinds: list[str] = Field(default_factory=list)
    hops: int
    path: list[str] = Field(default_factory=list)
    gated: bool


class AssessBlastRadiusResponse(BaseModel):
    project_id: str
    from_node_id: str
    from_label: str
    sink_count: int
    reachable_sinks: list[BlastRadiusHopOut] = Field(default_factory=list)
    truncated: bool


class AssessPolicyRequest(BaseModel):
    project_id: str = "default"
    policy: dict
    context: dict


class AssessPolicyResponse(BaseModel):
    project_id: str
    matched: bool
    action: str
    severity: str
    message: str | None = None


class ReportRequest(BaseModel):
    """Render a report from data the caller has already gathered. This service
    owns no database, so the findings/controls arrive in the request; it owns
    the wording, the ordering, and the redaction backstop."""

    kind: str = "executive"        # executive | technical | governance
    format: str = "md"            # md | json | csv | pdf
    data: dict = Field(default_factory=dict)
