"""Deterministic scanner engine. Runs the rule set over a prompt document.

The engine is a pure function: same input → same findings. A semantic classifier can be
layered on later behind the same Rule interface without changing callers.
"""

from __future__ import annotations

from .rules import ALL_RULES
from .types import PromptDocument, RuleContext, RuleMatch


def scan_document(doc: PromptDocument, ctx: RuleContext | None = None) -> list[RuleMatch]:
    context = ctx or RuleContext()
    matches: list[RuleMatch] = []
    for rule in ALL_RULES:
        matches.extend(rule.check(doc, context))
    # Stable order: severity then rule id.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    matches.sort(key=lambda m: (order.get(m.severity, 9), m.rule_id))
    return matches


def scan_prompt(kind: str, content: str, ctx: RuleContext | None = None) -> list[RuleMatch]:
    return scan_document(PromptDocument(kind=kind, content=content), ctx)
