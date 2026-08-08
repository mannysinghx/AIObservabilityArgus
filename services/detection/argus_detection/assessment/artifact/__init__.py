"""L0 — artifact integrity (docs/18).

Where the prompt scanner judges what an application *says* and L1–L4 judge what
its traffic *does*, this package judges the model file itself: what a pickle
stream would call the moment it is deserialized, before any inference exists to
observe.

Deterministic and pure, like every other engine under `assessment/`. The one
rule specific to this layer: opcodes are walked, never executed. Nothing here
may ever call `pickle.load`, `torch.load`, or `joblib.load`.

    build_manifest(bytes)  →  ArtifactManifest    (extract.py, pure)
    scan_artifact(manifest) →  [ArtifactMatch]    (engine.py, pure)
"""

from .allowlist import ALLOWLIST_VERSION, classify
from .engine import max_severity, scan_artifact
from .extract import build_manifest
from .rules import ALL_RULES
from .types import (
    ArtifactContext,
    ArtifactManifest,
    ArtifactMatch,
    GlobalRef,
    MemberRef,
)

__all__ = [
    "ALLOWLIST_VERSION",
    "ALL_RULES",
    "ArtifactContext",
    "ArtifactManifest",
    "ArtifactMatch",
    "GlobalRef",
    "MemberRef",
    "build_manifest",
    "classify",
    "max_severity",
    "scan_artifact",
]
