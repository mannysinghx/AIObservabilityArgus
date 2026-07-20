"""argus — drop-in auto-instrumenting tracer for Argus (security-first AI observability).

    import argus
    argus.init()                          # reads ARGUS_* from the environment
    app.add_middleware(argus.Middleware)  # FastAPI: one trace per request

After init(), every OpenAI / Anthropic (and OpenAI-compatible: DeepSeek, Kimi,
Qwen) call is captured automatically — prompt, completion, tokens, cost, latency —
and scanned by Argus's detection pipeline. Optional one-liners for retrieval and
tool spans. Inert until ARGUS_PUBLIC_KEY / ARGUS_SECRET_KEY are set.
"""
from __future__ import annotations

from . import _config, _instrument
from ._config import is_enabled
from ._middleware import Middleware
from ._tracing import Trace, current_trace, set_current, reset_current, flush as _flush

__version__ = "0.1.0"
_initialized = False


def init(key: str | None = None, **opts):
    """Initialize the tracer. Idempotent.

        argus.init("ak_live_…")      # zero config: just the ingest key
        argus.init(key="ak_live_…")  # same
        argus.init()                 # reads ARGUS_KEY (or the legacy
                                     # ARGUS_PUBLIC_KEY/ARGUS_SECRET_KEY pair)

    The hosted ingest endpoint is built in, so no URL is needed.
    """
    global _initialized
    if key:
        opts["key"] = key
    cfg = _config.resolve(**opts)
    _config.set_config(cfg)
    if not cfg.enabled:
        _config.warn_once(
            "no-keys",
            'no ingest key — tracing is disabled, no data will be sent. '
            'Pass one: argus.init("ak_live_…") or set ARGUS_KEY.',
        )
    if not _initialized:
        _instrument.install(cfg)
        _initialized = True
        _config.log("initialized", cfg.ingest_url, "enabled=", cfg.enabled)


# ---- optional manual spans (attach to the active trace, else standalone) ----

def _on_trace(fn, name):
    if not is_enabled():
        return
    active = current_trace()
    if active is not None:
        fn(active)
        return
    t = Trace(name)
    fn(t)
    t.finish()


def retrieval(name, text, *, source="", attributes=None):
    _on_trace(lambda t: t.retrieval(name, text, source=source, attributes=attributes), name or "retrieval")


def tool(name, *, input=None, output=None, source="", attributes=None):
    _on_trace(lambda t: t.tool(name, input=input, output=output, source=source, attributes=attributes),
              name or "tool")


def generation(name, **kw):
    _on_trace(lambda t: t.generation(name, **kw), name or "generation")


def annotate(**meta):
    """Merge metadata (session_id, user_id, tags, ...) onto the active trace."""
    t = current_trace()
    if t is not None:
        t.meta.update(meta)


def flush():
    _flush()


class trace:
    """Group calls into one trace outside a request — worker/Temporal activities,
    scripts. Works as a sync or async context manager:

        async with argus.trace("my-activity"):
            ...  # LLM calls here are grouped
    """

    def __init__(self, name, **meta):
        self._t = Trace(name, **meta)
        self._token = None

    def __enter__(self):
        self._token = set_current(self._t)
        return self._t

    def __exit__(self, *exc):
        try:
            self._t.finish()
        finally:
            if self._token is not None:
                reset_current(self._token)
        return False

    async def __aenter__(self):
        return self.__enter__()

    async def __aexit__(self, *exc):
        return self.__exit__(*exc)


__all__ = [
    "init", "Middleware", "trace", "retrieval", "tool", "generation",
    "annotate", "flush", "current_trace", "__version__",
]
