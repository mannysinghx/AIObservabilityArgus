"""Central config + singleton state for the Argus Python tracer."""
from __future__ import annotations

import os
import sys
import threading
from dataclasses import dataclass, field

# Hosted Argus ingest endpoint. Baked in so a customer never configures a URL —
# self-hosters override with ingest_url / ARGUS_INGEST_URL.
_DEFAULT_INGEST = "https://argusingest-production.up.railway.app/api/public/ingestion"


@dataclass
class Config:
    key: str = ""          # single write-only ingest key ("ak_live_…")
    public_key: str = ""   # legacy pair
    secret_key: str = ""
    ingest_url: str = _DEFAULT_INGEST
    environment: str = "production"
    flush_interval: float = 2.0          # seconds
    max_batch: int = 100
    instrument_openai: bool = True
    instrument_anthropic: bool = True
    debug: bool = False

    @property
    def enabled(self) -> bool:
        return bool(self.key or (self.public_key and self.secret_key))


_state: Config | None = None
_lock = threading.Lock()
_warned: set[str] = set()


def resolve(**opts) -> Config:
    env = os.environ
    return Config(
        key=opts.get("key") or env.get("ARGUS_KEY", ""),
        public_key=opts.get("public_key") or env.get("ARGUS_PUBLIC_KEY", ""),
        secret_key=opts.get("secret_key") or env.get("ARGUS_SECRET_KEY", ""),
        ingest_url=opts.get("ingest_url") or env.get("ARGUS_INGEST_URL", _DEFAULT_INGEST),
        # Auto-detect the environment tag so it isn't one more thing to configure.
        environment=opts.get("environment") or env.get("ARGUS_ENV") or env.get("APP_ENV") or "production",
        flush_interval=float(opts.get("flush_interval", 2.0)),
        max_batch=int(opts.get("max_batch", 100)),
        instrument_openai=opts.get("instrument_openai", True),
        instrument_anthropic=opts.get("instrument_anthropic", True),
        debug=bool(opts.get("debug", env.get("ARGUS_DEBUG") == "1")),
    )


def set_config(cfg: Config) -> None:
    global _state
    _state = cfg


def get_config() -> Config | None:
    return _state


def is_enabled() -> bool:
    return bool(_state and _state.enabled)


def log(*args) -> None:
    if _state and _state.debug:
        print("[argus]", *args, file=sys.stderr)


def warn_once(key: str, msg: str) -> None:
    with _lock:
        if key in _warned:
            return
        _warned.add(key)
    print("[argus] " + msg, file=sys.stderr)
