"""Shared-secret authentication for the detection service.

The detection API takes arbitrary text and runs regex and (optionally) model
inference over it. Unauthenticated, that is a free CPU oracle for anyone who can
reach the port, and a way to probe exactly which payloads Argus does and does
not catch. Until now the only thing protecting it was network placement — one
misconfigured port away from public.

Configured with ``DETECTION_API_KEY``:

  * set   — every endpoint except ``/health`` requires
            ``Authorization: Bearer <key>``.
  * unset — requests are allowed and the service logs a warning at startup, and
            reports ``auth: false`` on ``/health``.

Unset is permissive on purpose. The worker and the detection service deploy as
separate units, so a hard requirement would break every existing deployment
during the window where one has rolled and the other has not. The warning and
the health flag are what make "unset" a visible state rather than a silent one.
"""
from __future__ import annotations

import hmac
import logging
import os

from fastapi import Header, HTTPException

log = logging.getLogger("argus.detection.auth")

_ENV = "DETECTION_API_KEY"


def configured_key() -> str:
    return os.environ.get(_ENV, "").strip()


def enabled() -> bool:
    return bool(configured_key())


def warn_if_unprotected() -> None:
    """Called once at startup so an unauthenticated deploy is loud, not silent."""
    if not enabled():
        log.warning(
            "%s is not set — the detection API is UNAUTHENTICATED. Anyone who can "
            "reach this port can submit scans. Set %s here and on the worker.",
            _ENV,
            _ENV,
        )


async def require_api_key(authorization: str | None = Header(default=None)) -> None:
    """FastAPI dependency. No-op when no key is configured."""
    expected = configured_key()
    if not expected:
        return
    prefix = "Bearer "
    presented = authorization[len(prefix):].strip() if (authorization or "").startswith(prefix) else ""
    # compare_digest so a wrong key can't be recovered a byte at a time from
    # response timing. It rejects non-ASCII outright, hence the encode.
    if not presented or not hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
        raise HTTPException(status_code=401, detail="invalid or missing detection API key")
