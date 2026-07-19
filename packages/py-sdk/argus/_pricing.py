"""Approximate per-token pricing (USD per 1M tokens) for auto cost estimation.

Deliberately approximate — cost analytics is for spotting the expensive model,
not billing. Unknown models resolve to 0 rather than a wrong guess. Matched by
longest known substring so dated model ids (e.g. gpt-4o-2024-xx) still resolve.
"""
from __future__ import annotations

# model-key -> (input_per_million, output_per_million)
_TABLE: dict[str, tuple[float, float]] = {
    # OpenAI
    "gpt-4.1-mini": (0.4, 1.6), "gpt-4.1-nano": (0.1, 0.4), "gpt-4.1": (2.0, 8.0),
    "gpt-4o-mini": (0.15, 0.6), "gpt-4o": (2.5, 10.0),
    "o4-mini": (1.1, 4.4), "o3-mini": (1.1, 4.4), "o3": (2.0, 8.0),
    "gpt-4-turbo": (10.0, 30.0), "gpt-4": (30.0, 60.0), "gpt-3.5-turbo": (0.5, 1.5),
    # Anthropic
    "claude-3-5-haiku": (0.8, 4.0), "claude-3-haiku": (0.25, 1.25),
    "claude-3-5-sonnet": (3.0, 15.0), "claude-3-7-sonnet": (3.0, 15.0),
    "claude-sonnet-4": (3.0, 15.0), "claude-opus-4": (15.0, 75.0), "claude-3-opus": (15.0, 75.0),
    # DeepSeek / Kimi (Moonshot) / Qwen — OpenAI-compatible
    "deepseek-reasoner": (0.55, 2.19), "deepseek-chat": (0.27, 1.1),
    "deepseek": (0.27, 1.1),   # family fallback (e.g. deepseek-v4-flash)
    "moonshot-v1-128k": (2.0, 2.0), "moonshot-v1": (1.0, 1.0),
    "moonshot": (1.0, 1.0), "kimi": (2.0, 2.0),
    "qwen": (0.4, 1.2),
    # Google Gemini
    "gemini-2.5-pro": (1.25, 10.0), "gemini-2.5-flash": (0.3, 2.5),
    "gemini-2.0-flash": (0.1, 0.4), "gemini-1.5-pro": (1.25, 5.0), "gemini-1.5-flash": (0.075, 0.3),
    # GLM / Zhipu
    "glm-4.6": (0.6, 2.2), "glm-4.5": (0.6, 2.2), "glm-4": (0.5, 1.5),
}

_KEYS = sorted(_TABLE, key=len, reverse=True)


def estimate_cost(model: str, input_tokens: int = 0, output_tokens: int = 0) -> float:
    if not model:
        return 0.0
    m = model.lower()
    for k in _KEYS:
        if k in m:
            in_p, out_p = _TABLE[k]
            return (input_tokens / 1e6) * in_p + (output_tokens / 1e6) * out_p
    return 0.0
