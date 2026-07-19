"""Trace context, the Trace buffer, and the background transport.

The transport is a daemon thread draining a queue and POSTing batches with the
stdlib only (urllib) — no dependency on the host app's http stack, and it never
runs on, or blocks, the request's event loop. Nothing here raises into the app.
"""
from __future__ import annotations

import atexit
import contextvars
import json
import secrets
import threading
import urllib.request
from base64 import b64encode
from datetime import datetime, timezone
from queue import Queue, Empty

from . import _config as cfg
from ._pricing import estimate_cost

# The trace bound to the current async/sync context. Set by the ASGI middleware
# or the trace() context manager; read by auto-instrumentation to attach spans.
_current: "contextvars.ContextVar[Trace | None]" = contextvars.ContextVar("argus_trace", default=None)


def _iso(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def _text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, default=str)
    except Exception:
        return str(v)


def _str_map(d) -> dict:
    if not isinstance(d, dict):
        return {}
    return {str(k): (v if isinstance(v, str) else _text(v)) for k, v in d.items() if v is not None}


class Trace:
    """Buffers observations for one logical run (usually one request)."""

    def __init__(self, name: str, **meta):
        c = cfg.get_config()
        self.trace_id = meta.get("trace_id") or _new_id("tr")
        self.name = name or "request"
        self.meta = meta
        self.started_at = datetime.now(timezone.utc)
        self.environment = meta.get("environment") or (c.environment if c else "production")
        self._obs_count = 0
        self._finished = False

    # ---- span recorders (all match the Argus IngestBatch shape) ----
    def generation(self, name, *, model="", provider="", input=None, output=None,
                   input_tokens=0, output_tokens=0, cost_usd=None, finish_reason="",
                   start_time=None, attributes=None):
        cost = estimate_cost(model, input_tokens, output_tokens) if cost_usd is None else cost_usd
        end = datetime.now(timezone.utc)
        self._emit({
            "observationId": _new_id("obs"), "traceId": self.trace_id, "parentId": "",
            "type": "generation", "name": name or model or "generation",
            "startTime": _iso(start_time or end), "endTime": _iso(end),
            "model": model, "provider": provider, "role": "assistant",
            "input": _text(input), "output": _text(output),
            "inputTokens": int(input_tokens or 0), "outputTokens": int(output_tokens or 0),
            "costUsd": float(cost or 0.0), "finishReason": finish_reason,
            "attributes": _str_map(attributes),
        })

    def retrieval(self, name, text, *, source="", attributes=None):
        t = _iso()
        self._emit({
            "observationId": _new_id("obs"), "traceId": self.trace_id, "parentId": "",
            "type": "retrieval", "name": name or "retrieval", "startTime": t, "endTime": t,
            "output": _text(text), "taintSource": source or name or "retrieval",
            "attributes": _str_map(attributes),
        })

    def tool(self, name, *, input=None, output=None, source="", attributes=None):
        t = _iso()
        self._emit({
            "observationId": _new_id("obs"), "traceId": self.trace_id, "parentId": "",
            "type": "tool", "name": name or "tool", "startTime": t, "endTime": t,
            "input": _text(input), "output": _text(output),
            "taintSource": source or name or "tool", "attributes": _str_map(attributes),
        })

    def _emit(self, obs: dict):
        self._obs_count += 1
        _enqueue_obs(obs)

    def finish(self):
        if self._finished:
            return
        self._finished = True
        # A run that recorded nothing worth observing is not a trace — skip it so
        # per-request middleware stays free for non-LLM traffic.
        if self._obs_count == 0:
            return
        m = self.meta
        _enqueue_trace({
            "traceId": self.trace_id, "name": self.name,
            "sessionId": m.get("session_id", ""), "userId": m.get("user_id", ""),
            "timestamp": _iso(self.started_at), "environment": self.environment,
            "release": m.get("release", ""), "metadata": _str_map(m.get("metadata")),
            "tags": list(m.get("tags") or []),
        })


def current_trace() -> "Trace | None":
    return _current.get()


def set_current(trace: "Trace | None"):
    return _current.set(trace)


def reset_current(token):
    _current.reset(token)


# --------------------------- transport ---------------------------

_q: "Queue" = Queue()
_worker: "threading.Thread | None" = None
_worker_lock = threading.Lock()


def _ensure_worker():
    global _worker
    if _worker and _worker.is_alive():
        return
    with _worker_lock:
        if _worker and _worker.is_alive():
            return
        _worker = threading.Thread(target=_run, name="argus-flush", daemon=True)
        _worker.start()
        atexit.register(flush)


def _enqueue_obs(obs: dict):
    if not cfg.is_enabled():
        return
    _q.put(("obs", obs))
    _ensure_worker()


def _enqueue_trace(tr: dict):
    if not cfg.is_enabled():
        return
    _q.put(("trace", tr))
    _ensure_worker()


def _drain_once(block: bool):
    c = cfg.get_config()
    traces, obs = [], []
    try:
        item = _q.get(timeout=c.flush_interval if (block and c) else 0)
    except Empty:
        return traces, obs
    items = [item]
    while len(items) < (c.max_batch if c else 100):
        try:
            items.append(_q.get_nowait())
        except Empty:
            break
    for kind, payload in items:
        (traces if kind == "trace" else obs).append(payload)
    return traces, obs


def _run():
    while True:
        traces, obs = _drain_once(block=True)
        if obs:
            _post({"traces": [], "observations": obs})
        if traces:
            _post({"traces": traces, "observations": []})


def _post(body: dict):
    c = cfg.get_config()
    if not c or not c.enabled:
        return
    try:
        auth = b64encode(f"{c.public_key}:{c.secret_key}".encode()).decode()
        req = urllib.request.Request(
            c.ingest_url, data=json.dumps(body).encode(),
            headers={"content-type": "application/json", "authorization": "Basic " + auth},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 (trusted URL)
            resp.read()
    except Exception as e:  # never raise into the app; degrade quietly
        cfg.warn_once("post-failed", f"ingestion request failed (non-fatal): {e}")
        cfg.log("post error", e)


def flush():
    """Drain everything currently queued, synchronously. Best-effort."""
    while True:
        traces, obs = _drain_once(block=False)
        if not traces and not obs:
            return
        if obs:
            _post({"traces": [], "observations": obs})
        if traces:
            _post({"traces": traces, "observations": []})
