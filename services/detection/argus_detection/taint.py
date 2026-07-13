"""Taint classification (docs/04 §Trust model).

Assigns a trust class to each observation when the SDK didn't label it, applying
operator tool-overrides. Retrieval outputs and tool results default to
`untrusted_external`; everything else falls back to its role/type.
"""
from __future__ import annotations

from .models import Observation, ObservationType, TaintClass


def classify(obs: Observation, tool_overrides: dict[str, str] | None = None) -> TaintClass:
    # Explicit SDK label always wins.
    if obs.taint is not None:
        return obs.taint

    overrides = tool_overrides or {}

    # Tool/retrieval spans: untrusted by default, unless operator overrode this
    # specific tool/source to 'trusted'.
    if obs.type in (ObservationType.retrieval, ObservationType.tool):
        key = obs.taint_source or obs.name
        override = overrides.get(key) or overrides.get(obs.name)
        if override == "trusted":
            return TaintClass.system  # treated as trusted content
        return TaintClass.untrusted_external

    # Role-based for chat spans.
    role = (obs.role or "").lower()
    if role == "system":
        return TaintClass.system
    if role == "user":
        return TaintClass.user
    if role in ("assistant", "model"):
        return TaintClass.model

    if obs.type == ObservationType.generation:
        return TaintClass.model

    # Unknown → treat as user input (the conservative default for scanning).
    return TaintClass.user
