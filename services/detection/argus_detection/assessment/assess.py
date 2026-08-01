"""Assessment orchestration — glue between the API shapes and the pure engines.

scan → risk-score → rank mitigations → map into the runtime taxonomy. Pure and
synchronous: the heaviest input is a page of prompt text through 20 regex-class
rules, so there is nothing to queue.
"""

from __future__ import annotations

from dataclasses import asdict

from . import graph as graphmod
from . import taxonomy
from .mitigations import AppFacts, rank_mitigations
from .models import (
    AssessContext,
    AssessFinding,
    AssessGraphRequest,
    AssessGraphResponse,
    AssessPolicyRequest,
    AssessPolicyResponse,
    AssessPromptRequest,
    AssessPromptResponse,
    GraphInsightOut,
    MitigationRec,
    RiskBreakdown,
)
from .policy import evaluate_policy
from .risk import SCORING_VERSION, compute_risk, factors_from_signal
from .scanner import PromptDocument, RuleContext, scan_document

# Native assessment severity ordering (worst first) for max_severity rollups.
_SEV_ORDER = ["critical", "high", "medium", "low", "informational"]


def _worst(severities: list[str]) -> str | None:
    for s in _SEV_ORDER:
        if s in severities:
            return s
    return severities[0] if severities else None


def _rule_context(ctx: AssessContext) -> RuleContext:
    return RuleContext(
        has_write_capable_tools=ctx.has_write_capable_tools,
        human_approval_enabled=ctx.human_approval_enabled,
        has_retrieval=ctx.has_retrieval,
        is_public=ctx.is_public,
        tool_names_user_controlled=ctx.tool_names_user_controlled,
    )


def _app_facts(ctx: AssessContext) -> AppFacts:
    return AppFacts(
        exposure="public" if ctx.is_public else "internal",
        business_criticality=ctx.business_criticality,
        has_write_tools=ctx.has_write_capable_tools,
        has_sensitive_data=ctx.has_sensitive_data,
    )


def assess_prompts(req: AssessPromptRequest) -> AssessPromptResponse:
    rule_ctx = _rule_context(req.context)
    facts = _app_facts(req.context)

    findings: list[AssessFinding] = []
    for idx, doc in enumerate(req.documents):
        matches = scan_document(PromptDocument(kind=doc.kind, content=doc.content), rule_ctx)
        for m in matches:
            risk = compute_risk(
                factors_from_signal(
                    severity=m.severity,
                    confidence=m.confidence,
                    is_public=req.context.is_public,
                    has_compensating_controls=req.context.has_compensating_controls,
                )
            )
            recs = (
                rank_mitigations(m.category, facts)[: req.top_mitigations]
                if req.top_mitigations
                else []
            )
            findings.append(
                AssessFinding(
                    document_index=idx,
                    document_name=doc.name,
                    rule_id=m.rule_id,
                    title=m.title,
                    category=m.category,
                    severity=m.severity,
                    confidence=m.confidence,
                    explanation=m.explanation,
                    affected_lines=m.affected_lines,
                    evidence=m.evidence,
                    recommendation=m.recommendation,
                    frameworks=[asdict(f) for f in m.frameworks],
                    argus_category=taxonomy.argus_category(m.category),
                    argus_severity=taxonomy.argus_severity(m.severity),
                    risk=RiskBreakdown(
                        factors=asdict(risk.factors),
                        weights=risk.weights,
                        contributions=risk.contributions,
                        base_score=risk.base_score,
                        confidence_adjustment=risk.confidence_adjustment,
                        final_score=risk.final_score,
                        severity=risk.severity,
                        rationale=risk.rationale,
                        scoring_version=risk.scoring_version,
                    ),
                    mitigations=[
                        MitigationRec(
                            key=r.mitigation.key,
                            title=r.mitigation.title,
                            category=r.mitigation.category,
                            priority=r.mitigation.priority,
                            difficulty=r.mitigation.difficulty,
                            expected_risk_reduction=r.mitigation.expected_risk_reduction,
                            score=r.score,
                            rationale=r.rationale,
                            implementation_guidance=r.mitigation.implementation_guidance,
                            validation_procedure=r.mitigation.validation_procedure,
                        )
                        for r in recs
                    ],
                )
            )

    return AssessPromptResponse(
        project_id=req.project_id,
        finding_count=len(findings),
        max_severity=_worst([f.severity for f in findings]),
        overall_risk=max((f.risk.final_score for f in findings), default=0),
        scoring_version=SCORING_VERSION,
        findings=findings,
    )


def assess_graph(req: AssessGraphRequest) -> AssessGraphResponse:
    nodes = [
        graphmod.GraphNode(
            id=n.id,
            label=n.label,
            node_type=n.node_type,
            trust_level=n.trust_level,
            can_write=n.can_write,
            requires_approval=n.requires_approval,
            attributes=n.attributes,
        )
        for n in req.nodes
    ]
    edges = [
        graphmod.GraphEdge(
            source_id=e.source,
            target_id=e.target,
            edge_type=e.edge_type,
            tenant_boundary=e.tenant_boundary,
            name=e.name,
        )
        for e in req.edges
    ]
    insights = [
        GraphInsightOut(
            rule=i.rule,
            severity=i.severity,
            message=i.message,
            component_ids=list(i.component_ids),
            argus_category=taxonomy.argus_graph_category(i.rule),
            argus_severity=taxonomy.argus_severity(i.severity),
        )
        for i in graphmod.analyze_graph(nodes, edges)
    ]
    return AssessGraphResponse(
        project_id=req.project_id,
        insight_count=len(insights),
        max_severity=_worst([i.severity for i in insights]),
        insights=insights,
    )


def assess_policy(req: AssessPolicyRequest) -> AssessPolicyResponse:
    d = evaluate_policy(req.policy, req.context)
    return AssessPolicyResponse(
        project_id=req.project_id,
        matched=d.matched,
        action=d.action,
        severity=d.severity,
        message=d.message,
    )
