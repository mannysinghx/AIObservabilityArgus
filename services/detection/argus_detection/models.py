"""Shared domain types for the detection pipeline.

These mirror the ingestion-side observation model (docs/05) but carry only what
detection needs. Keeping them here (not importing from the TS side) keeps the
Python service independently testable.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class TaintClass(str, Enum):
    """Trust classification of a span's content (docs/04 §Trust model)."""

    system = "system"
    user = "user"
    untrusted_external = "untrusted_external"
    model = "model"


class ObservationType(str, Enum):
    span = "span"
    generation = "generation"
    retrieval = "retrieval"
    tool = "tool"
    event = "event"


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Category(str, Enum):
    direct_injection = "direct_injection"
    jailbreak = "jailbreak"
    indirect_injection = "indirect_injection"
    exfiltration = "exfiltration"
    excessive_agency = "excessive_agency"
    rag_poisoning = "rag_poisoning"
    prompt_leak = "prompt_leak"
    pii_egress = "pii_egress"
    canary_triggered = "canary_triggered"
    obfuscation = "obfuscation"


class Outcome(str, Enum):
    unknown = "unknown"
    attempted = "attempted"
    succeeded = "succeeded"
    blocked = "blocked"


# Severity ordering helper (higher = worse).
SEVERITY_ORDER = {
    Severity.info: 1,
    Severity.low: 2,
    Severity.medium: 3,
    Severity.high: 4,
    Severity.critical: 5,
}


class Observation(BaseModel):
    """One span/observation submitted for scanning."""

    observation_id: str
    trace_id: str = ""
    parent_id: str = ""
    type: ObservationType = ObservationType.span
    name: str = ""
    # The text to analyze. For a retrieval span this is the retrieved chunk;
    # for a tool span the tool output; for a generation the completion; etc.
    content: str = ""
    role: str = ""  # user | assistant | system | tool (when known)
    taint: Optional[TaintClass] = None  # None => infer from type + overrides
    taint_source: str = ""
    model: str = ""
    # Free-form attributes carried from the trace (gen_ai.*, argus.*).
    attributes: dict[str, str] = Field(default_factory=dict)


class RuleMatch(BaseModel):
    rule_id: str
    description: str
    weight: float
    category: Category
    excerpt: str = ""


class LayerResult(BaseModel):
    """Result of a single detection layer for one observation."""

    layer: str  # 'L1' | 'L2' | 'L3'
    score: float = 0.0  # 0..1 normalized
    matches: list[RuleMatch] = Field(default_factory=list)
    detail: dict[str, float] = Field(default_factory=dict)  # e.g. per-model L2 scores


class Finding(BaseModel):
    """A raised security event (pre-persistence shape)."""

    observation_id: str
    trace_id: str = ""
    category: Category
    severity: Severity
    outcome: Outcome = Outcome.unknown
    score: float  # 0..100
    l1_rules: list[str] = Field(default_factory=list)
    l2_scores: dict[str, float] = Field(default_factory=dict)
    l3_verdict: str = ""
    l4_signals: list[str] = Field(default_factory=list)
    evidence_excerpt: str = ""


class ScanRequest(BaseModel):
    """Scan a single observation (span-level: L1 + L2)."""

    project_id: str = "default"
    observation: Observation
    # Which tools the operator marked trusted/untrusted, from detection_config.
    tool_overrides: dict[str, str] = Field(default_factory=dict)
    enable_l2: bool = False


class ScanResponse(BaseModel):
    project_id: str
    observation_id: str
    taint: TaintClass
    findings: list[Finding] = Field(default_factory=list)
    layers: list[LayerResult] = Field(default_factory=list)


class TraceScanRequest(BaseModel):
    """Scan a completed trace (L4: taint propagation + behavioral analysis)."""

    project_id: str = "default"
    trace_id: str
    observations: list[Observation]
    tool_overrides: dict[str, str] = Field(default_factory=dict)
    # Canary tokens registered for this project (raw values, matched in egress).
    canaries: list[str] = Field(default_factory=list)


class TraceScanResponse(BaseModel):
    project_id: str
    trace_id: str
    findings: list[Finding] = Field(default_factory=list)
    taint_frontier_index: int = -1  # first taint-influenced observation, -1 if none
