"""L2 — ML classifier ensemble (pluggable, optional).

Phase 1 ships heuristics-only by default. This module defines the interface and
a lazy transformers-backed implementation so operators can enable open models
(Meta Prompt Guard 2, ProtectAI DeBERTa injection v2) without touching callers.

If `transformers`/`torch` aren't installed, `available()` returns False and the
pipeline simply skips L2 — the service still runs.
"""
from __future__ import annotations

import logging

from ..models import LayerResult, Observation, TaintClass

log = logging.getLogger("argus.detection.l2")

# Default ensemble (HF ids). Both are wrapped behind the same interface; scores
# are max-pooled across chunks and averaged across models (see scan()).
DEFAULT_MODELS = [
    "meta-llama/Llama-Prompt-Guard-2-86M",
    "protectai/deberta-v3-base-prompt-injection-v2",
]

_CHUNK = 512
_OVERLAP = 128


def available() -> bool:
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except ImportError:
        return False
    return True


def _chunks(text: str, size: int = _CHUNK, overlap: int = _OVERLAP):
    if len(text) <= size:
        yield text
        return
    step = size - overlap
    for i in range(0, len(text), step):
        yield text[i : i + size]
        if i + size >= len(text):
            break


class _ModelRegistry:
    """Lazily loads and caches HF text-classification pipelines."""

    def __init__(self) -> None:
        self._pipes: dict[str, object] = {}

    def get(self, model_id: str):
        if model_id in self._pipes:
            return self._pipes[model_id]
        from transformers import pipeline  # local import; optional dep

        pipe = pipeline("text-classification", model=model_id, truncation=True, max_length=_CHUNK)
        self._pipes[model_id] = pipe
        return pipe


_registry = _ModelRegistry()


def _injection_prob(result: list | dict) -> float:
    """Normalize a HF classifier output to P(injection). Label conventions
    differ per model (INJECTION / LABEL_1 / jailbreak); treat the 'unsafe' class
    as positive and fall back to 1 - P(benign)."""
    rows = result if isinstance(result, list) else [result]
    positive_labels = {"injection", "jailbreak", "label_1", "unsafe", "malicious"}
    benign_labels = {"benign", "safe", "label_0", "clean"}
    for row in rows:
        label = str(row.get("label", "")).lower()
        score = float(row.get("score", 0.0))
        if label in positive_labels:
            return score
        if label in benign_labels:
            return 1.0 - score
    return 0.0


def scan(
    obs: Observation,
    taint: TaintClass,
    models: list[str] | None = None,
) -> LayerResult:
    """Ensemble classify. Returns L2 LayerResult with per-model scores in detail.

    Only run this on content worth the cost — callers gate on taint/L1 (see
    pipeline.py). Documents are chunked; per-model score = max over chunks."""
    models = models or DEFAULT_MODELS
    text = obs.content or ""
    if not text.strip() or not available():
        return LayerResult(layer="L2", score=0.0, detail={})

    per_model: dict[str, float] = {}
    for model_id in models:
        try:
            pipe = _registry.get(model_id)
        except Exception:
            # A single bad model must not take out the layer, but it must not be
            # silent either: "L2 enabled" plus a model that never loads looks
            # exactly like "L2 enabled and nothing is malicious".
            log.warning("L2 model %s unavailable; skipping it for this scan", model_id, exc_info=True)
            continue
        best = 0.0
        for chunk in _chunks(text):
            try:
                out = pipe(chunk)
            except Exception:
                log.warning("L2 model %s failed on a chunk; scoring the rest", model_id, exc_info=True)
                continue
            best = max(best, _injection_prob(out if isinstance(out, list) else [out]))
        per_model[model_id.split("/")[-1]] = round(best, 4)

    if not per_model:
        return LayerResult(layer="L2", score=0.0, detail={})

    # Ensemble = mean of model scores; disagreement is surfaced via detail so
    # scoring can treat a split vote as its own escalation signal.
    score = sum(per_model.values()) / len(per_model)
    return LayerResult(layer="L2", score=score, detail=per_model)
