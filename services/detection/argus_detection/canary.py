"""Canary matching.

Split out of trace_analysis so it can be tested on its own and reused by the
span-level path. Two matching strategies, one per canary kind:

  generated — the value has a known prefix (``argus-cnry-``), so candidates are
              extracted from the text with one regex and compared by digest.
              The raw value never reaches this service.

  custom    — an arbitrary string the customer planted; substring match, which
              requires holding the value.

The generated path is preferred precisely because this service is the one that
handles hostile text all day. Anything it doesn't hold, it can't leak.
"""
from __future__ import annotations

import hashlib
import re

from .models import CanaryKind, CanaryRef

CANARY_PREFIX = "argus-cnry-"
# Mirrors CANARY_PATTERN in packages/shared/src/canaries.ts. Loose on length so a
# token that was truncated or re-encoded downstream still yields a candidate —
# the digest comparison is what actually decides, and a spurious candidate costs
# one sha256.
_CANARY_RE = re.compile(rf"{CANARY_PREFIX}[A-Za-z0-9_-]{{8,64}}")

# A canary must be long enough that it cannot occur by chance. Refusing to match
# on a short "custom" value is a guard against a customer registering something
# like "admin" and then being paged by every ordinary trace that mentions it.
_MIN_CUSTOM_LENGTH = 8


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def find_canaries(text: str, refs: list[CanaryRef]) -> list[CanaryRef]:
    """Every registered canary present in `text`, de-duplicated by canary id."""
    if not text or not refs:
        return []

    hits: dict[str, CanaryRef] = {}

    generated = {r.token_hash: r for r in refs if r.kind == CanaryKind.generated and r.token_hash}
    if generated:
        # One pass over the text regardless of how many canaries are registered:
        # extract candidates, then look each up by digest. A project with 500
        # canaries costs the same as a project with one.
        for candidate in set(_CANARY_RE.findall(text)):
            ref = generated.get(_sha256(candidate))
            if ref is not None:
                hits[ref.id] = ref

    for ref in refs:
        if ref.kind != CanaryKind.custom or ref.id in hits:
            continue
        if len(ref.value) < _MIN_CUSTOM_LENGTH:
            continue
        if ref.value in text:
            hits[ref.id] = ref

    return list(hits.values())


def legacy_refs(raw_values: list[str]) -> list[CanaryRef]:
    """Adapt the old `canaries: list[str]` request field to CanaryRef."""
    return [
        CanaryRef(id="", label="", kind=CanaryKind.custom, value=v)
        for v in raw_values
        if v
    ]
