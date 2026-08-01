"""Deterministic prompt scanner — rule interface, engine, and the built-in rules."""

from .engine import scan_document, scan_prompt
from .rules import ALL_RULES
from .types import FrameworkRef, PromptDocument, Rule, RuleContext, RuleMatch

__all__ = [
    "ALL_RULES",
    "FrameworkRef",
    "PromptDocument",
    "Rule",
    "RuleContext",
    "RuleMatch",
    "scan_document",
    "scan_prompt",
]
