"""Deterministic policy-as-code evaluator (from InjectGuard).

No LLM is ever consulted. Conditions are a flat map of dotted-path → matcher; ALL must be
true (implicit AND). Unknown fields evaluate to absent → false (fail closed), except the
explicit `{exists: false}` matcher. Unknown operators also fail closed — a typo in a
policy must never silently widen it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_ABSENT = object()


@dataclass(frozen=True)
class PolicyDecision:
    matched: bool
    action: str
    severity: str
    message: str | None


def _get(context: dict[str, Any], path: str) -> Any:
    node: Any = context
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return _ABSENT
    return node


def _match(value: Any, matcher: Any) -> bool:
    # Scalar equality.
    if not isinstance(matcher, dict):
        if value is _ABSENT:
            return False
        return value == matcher

    for op, operand in matcher.items():
        if op == "exists":
            present = value is not _ABSENT
            if present != bool(operand):
                return False
            continue
        if value is _ABSENT:
            return False
        if op == "in":
            if value not in operand:
                return False
        elif op == "gte":
            if not (isinstance(value, (int, float)) and value >= operand):
                return False
        elif op == "lte":
            if not (isinstance(value, (int, float)) and value <= operand):
                return False
        elif op == "gt":
            if not (isinstance(value, (int, float)) and value > operand):
                return False
        elif op == "lt":
            if not (isinstance(value, (int, float)) and value < operand):
                return False
        elif op == "matches":
            try:
                pat = re.compile(str(operand))
            except re.error:
                return False
            if not (isinstance(value, str) and pat.search(value)):
                return False
        else:
            # Unknown operator → fail closed.
            return False
    return True


def evaluate_conditions(conditions: dict[str, Any], context: dict[str, Any]) -> bool:
    """True only if every condition matches (implicit AND). Empty conditions never match."""
    if not conditions:
        return False
    return all(_match(_get(context, path), matcher) for path, matcher in conditions.items())


def evaluate_policy(policy: dict[str, Any], context: dict[str, Any]) -> PolicyDecision:
    """Evaluate a single policy dict {conditions, result_severity, action, message}."""
    matched = evaluate_conditions(policy.get("conditions", {}), context)
    return PolicyDecision(
        matched=matched,
        action=policy.get("action", "warn") if matched else "inform",
        severity=policy.get("result_severity", "medium") if matched else "informational",
        message=policy.get("message") if matched else None,
    )
