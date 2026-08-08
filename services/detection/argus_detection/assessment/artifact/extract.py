"""Bytes → ArtifactManifest.

Pure: takes bytes and a display name, returns a manifest. No path is opened
here. The CLI reads the file and calls this; the detection service never does,
which is what keeps `assessment` free of I/O (see assessment/__init__.py).

Splitting it this way also means the same extraction runs in CI, in the worker,
and in tests, so a manifest produced anywhere is judged identically everywhere.
"""

from __future__ import annotations

import hashlib
import json

from .opcodes import sniff_format, walk_pickle, walk_zip_archive
from .types import ArtifactManifest


def _safetensors_keys(data: bytes) -> tuple[list[str], list[str]]:
    """Tensor names from a safetensors header. Header-only — the tensor bytes
    are never touched, and the `safetensors` package is not required."""
    errors: list[str] = []
    try:
        n = int.from_bytes(data[:8], "little")
        header = json.loads(data[8:8 + n].decode("utf-8"))
        keys = sorted(k for k in header if k != "__metadata__")
        return keys, errors
    except Exception as e:  # noqa: BLE001
        return [], [f"safetensors header unreadable: {type(e).__name__}: {e}"]


def build_manifest(
    data: bytes,
    *,
    path: str = "",
    source_uri: str = "",
    revision: str = "",
) -> ArtifactManifest:
    """Extract everything the rules are allowed to know about one artifact."""
    fmt = sniff_format(data, path)
    man = ArtifactManifest(
        path=path,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        format=fmt,
        source_uri=source_uri,
        revision=revision,
    )

    if fmt == "torch_zip":
        globals_, counts, members, errors = walk_zip_archive(data)
        man.globals = globals_
        man.opcode_summary = counts
        man.archive_members = members
        man.parse_errors = errors
        # A zip with no pickle member is not a torch checkpoint. Say so rather
        # than silently reporting a clean pickle scan of nothing.
        if not any(m.is_pickle for m in members):
            man.format = "zip"
    elif fmt in ("pickle", "joblib", "numpy_pickle"):
        globals_, counts, errors = walk_pickle(data)
        man.globals = globals_
        man.opcode_summary = counts
        man.parse_errors = errors
    elif fmt == "safetensors":
        man.tensor_keys, man.parse_errors = _safetensors_keys(data)

    return man
