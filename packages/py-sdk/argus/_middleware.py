"""Pure-ASGI middleware for FastAPI/Starlette.

Implemented as raw ASGI (not BaseHTTPMiddleware) so the trace contextvar is set
in the *same* task as the endpoint — BaseHTTPMiddleware runs the endpoint in a
separate task, which breaks contextvar propagation from middleware to handler.
"""
from __future__ import annotations

import hashlib

from ._config import is_enabled
from ._tracing import Trace, set_current, reset_current


def _default_name(scope) -> str:
    return f"{scope.get('method', 'REQ')} {scope.get('path', '/')}"


def _header(scope, key: bytes) -> bytes | None:
    for k, v in scope.get("headers", []):
        if k == key:
            return v
    return None


def _default_session(scope) -> str:
    # Group by a hash of the auth token (never the raw token) — no DB hit.
    auth = _header(scope, b"authorization")
    if auth:
        return "s_" + hashlib.sha256(auth).hexdigest()[:24]
    sid = _header(scope, b"x-session-id")
    return sid.decode() if sid else ""


class Middleware:
    """Add with ``app.add_middleware(argus.Middleware)``.

    Options (all optional): ``name(scope)``, ``get_session_id(scope)``,
    ``get_user_id(scope)`` callables.
    """

    def __init__(self, app, *, name=None, get_session_id=None, get_user_id=None):
        self.app = app
        self._name = name
        self._get_session = get_session_id or _default_session
        self._get_user = get_user_id

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not is_enabled():
            return await self.app(scope, receive, send)
        try:
            meta = {"session_id": self._get_session(scope) or ""}
            if self._get_user:
                meta["user_id"] = self._get_user(scope) or ""
            name = (self._name(scope) if callable(self._name) else self._name) or _default_name(scope)
            trace = Trace(name, **meta)
        except Exception:
            return await self.app(scope, receive, send)

        token = set_current(trace)
        try:
            await self.app(scope, receive, send)
        finally:
            try:
                trace.finish()
            except Exception:
                pass
            reset_current(token)
