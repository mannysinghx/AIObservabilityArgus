"""Secret redaction for evidence excerpts and structured payloads.

Deterministic scrubbing applied before any assessment evidence leaves this
service. Never the *only* control — secrets should not reach these paths in
the first place — but a mandatory backstop. This intentionally targets
credential *shapes* (keys, tokens, password assignments), not PII: the
ingest-side redactor (packages/shared/src/redact.ts) owns PII masking, and
an assessment evidence line must keep enough of the prompt to stay useful.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "«redacted»"

# Ordered patterns; each maps a recognizable secret shape to a redaction.
_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-[A-Za-z0-9]{16,}"),                      # OpenAI-style keys
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),             # Slack tokens
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),                     # GitHub PAT
    re.compile(r"AKIA[0-9A-Z]{16}"),                         # AWS access key id
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    # The value is "not whitespace and not a structural character a serialized
    # form would put right after it" rather than a bare \S+. A bare \S+ against
    # a JSON-serialized string (e.g. `"evidence": "api_key=sk-XXXX"`) consumes
    # the closing quote along with the secret, corrupting the JSON — found via
    # a report rendered in json format, not by inspection.
    re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*[^\s\"',}\]]+"),
]

# Structured-payload field names whose values are always redacted.
SENSITIVE_FIELDS = {
    "password",
    "secret",
    "secret_key",
    "api_key",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "model_api_key",
}


def redact_text(text: str) -> str:
    """Redact known secret patterns from a string."""
    if not text:
        return text
    out = text
    for pat in _PATTERNS:
        out = pat.sub(REDACTED, out)
    return out


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact sensitive fields and secret-shaped values in a dict."""
    result: dict[str, Any] = {}
    for key, value in data.items():
        if key.lower() in SENSITIVE_FIELDS:
            result[key] = REDACTED
        elif isinstance(value, dict):
            result[key] = redact_mapping(value)
        elif isinstance(value, list):
            result[key] = [redact_value(v) for v in value]
        else:
            result[key] = redact_value(value)
    return result


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return redact_mapping(value)
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    return value
