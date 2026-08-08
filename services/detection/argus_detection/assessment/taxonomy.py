"""Assessment taxonomy → Argus security-event taxonomy.

InjectGuard's scanner categorizes *weaknesses* (how a prompt/architecture is
built unsafely); Argus's `Category` enum categorizes *attack events* (what a
hostile input did at runtime). They are different axes, so this mapping is
"closest attack class this weakness enables", used when an assessment finding
needs to live alongside runtime findings (dashboards, ClickHouse storage,
alert routing). It is advisory metadata on assessment responses — the native
assessment category is always preserved verbatim.

`None` means the weakness has no meaningful attack-class equivalent (pure
hygiene findings); callers must skip those when storing into security_events
rather than inventing a category.
"""

from __future__ import annotations

from ..models import Category, Severity

# Prompt-scanner categories (scanner/rules.py) → closest Argus attack category.
ASSESSMENT_TO_ARGUS_CATEGORY: dict[str, Category | None] = {
    "injection":         Category.direct_injection,
    "prompt-separation": Category.direct_injection,   # weak separation enables direct injection
    "context-isolation": Category.indirect_injection,
    "rag-security":      Category.rag_poisoning,
    "memory-protection": Category.rag_poisoning,      # memory poisoning is the same attack shape
    "prompt-leakage":    Category.prompt_leak,
    "sensitive-data":    Category.pii_egress,
    "cross-context":     Category.pii_egress,         # data crossing tenant/user boundaries
    "obfuscation":       Category.obfuscation,
    "tool-security":     Category.excessive_agency,
    "excessive-agency":  Category.excessive_agency,
    "authorization":     Category.excessive_agency,
    "human-approval":    Category.excessive_agency,
    "unsafe-output":     Category.excessive_agency,   # model output driving unchecked actions
    "prompt-quality":    None,                        # hygiene only — no attack class
    # L0 artifact findings (ARG-ART-*, docs/18). Unlike every other row here,
    # this is not "closest attack class" — supply_chain is its own runtime
    # category, because a malicious model file is not a variant of prompt
    # injection and filing it under one would make both harder to reason about.
    "supply-chain":      Category.supply_chain,
}

# Architecture-graph insight rules (graph.py) → closest Argus attack category.
GRAPH_RULE_TO_ARGUS_CATEGORY: dict[str, Category] = {
    "untrusted_to_trusted_instruction": Category.indirect_injection,
    "untrusted_into_memory":            Category.rag_poisoning,
    "model_output_to_interpreter":      Category.excessive_agency,
    "cross_tenant_path":                Category.pii_egress,
    "model_controlled_authorization":   Category.excessive_agency,
    "write_tool_without_approval":      Category.excessive_agency,
    "retrieval_without_provenance":     Category.rag_poisoning,
}

# Assessment severity labels → Argus Severity enum values. Identical except
# the lowest band ("informational" vs "info").
_SEVERITY: dict[str, Severity] = {
    "critical":      Severity.critical,
    "high":          Severity.high,
    "medium":        Severity.medium,
    "low":           Severity.low,
    "informational": Severity.info,
}


def argus_category(assessment_category: str) -> str | None:
    """Argus Category value for an assessment category, or None when unmapped."""
    cat = ASSESSMENT_TO_ARGUS_CATEGORY.get(assessment_category)
    return cat.value if cat else None


def argus_graph_category(graph_rule: str) -> str | None:
    cat = GRAPH_RULE_TO_ARGUS_CATEGORY.get(graph_rule)
    return cat.value if cat else None


def argus_severity(assessment_severity: str) -> str:
    return _SEVERITY.get(assessment_severity, Severity.medium).value
