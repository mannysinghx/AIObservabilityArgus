"""Deterministic L0 engine. Runs the rule set over one artifact manifest.

Same contract as the prompt scanner (assessment/scanner/engine.py): a pure
function, same input → same findings, stable ordering. No I/O, no model calls,
no clock. That is what makes a verdict reproducible months later from the
stored manifest alone.
"""

from __future__ import annotations

from .rules import ALL_RULES
from .types import ArtifactContext, ArtifactManifest, ArtifactMatch

_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def scan_artifact(
    man: ArtifactManifest, ctx: ArtifactContext | None = None
) -> list[ArtifactMatch]:
    context = ctx or ArtifactContext()
    matches: list[ArtifactMatch] = []
    for rule in ALL_RULES:
        matches.extend(rule.check(man, context))
    # Stable order: severity, then rule id, then first offset — so a diff
    # between two scans of the same artifact is empty rather than reordered.
    matches.sort(key=lambda m: (
        _ORDER.get(m.severity, 9),
        m.rule_id,
        m.affected_lines[0] if m.affected_lines else -1,
    ))
    return matches


def max_severity(matches: list[ArtifactMatch]) -> str | None:
    if not matches:
        return None
    return min((m.severity for m in matches), key=lambda s: _ORDER.get(s, 9))
