"""The detection API must not be an open oracle.

The scan endpoints run regex and (optionally) model inference on caller-supplied
text. Unauthenticated, that is free CPU for anyone who can reach the port and a
way to probe exactly which payloads Argus does and does not catch. These tests
pin both halves of the contract: protected when a key is set, and *deliberately*
open when one isn't (so a rolling deploy doesn't break, and so anyone who
changes that default has to change a test that says why).
"""
from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

SCAN_BODY = {
    "project_id": "p1",
    "observation": {"observation_id": "o1", "trace_id": "t1", "content": "hello"},
}


def _client(monkeypatch, key: str | None):
    """Build an app with DETECTION_API_KEY set (or not). The dependency reads
    the environment per-request, but the startup warning is module-level, so
    reimport to get a clean app each time."""
    if key is None:
        monkeypatch.delenv("DETECTION_API_KEY", raising=False)
    else:
        monkeypatch.setenv("DETECTION_API_KEY", key)
    import argus_detection.app as app_mod

    importlib.reload(app_mod)
    return TestClient(app_mod.app)


def test_scan_requires_key_when_configured(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    assert c.post("/v1/scan", json=SCAN_BODY).status_code == 401


def test_scan_rejects_wrong_key(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    r = c.post("/v1/scan", json=SCAN_BODY, headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_scan_accepts_correct_key(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    r = c.post("/v1/scan", json=SCAN_BODY, headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200


def test_trace_scan_is_protected_too(monkeypatch):
    """The trace endpoint is the expensive one (O(n^2) over spans) — it must not
    be left open just because the span endpoint was remembered."""
    c = _client(monkeypatch, "s3cret")
    body = {"project_id": "p1", "trace_id": "t1", "observations": []}
    assert c.post("/v1/scan/trace", json=body).status_code == 401
    r = c.post("/v1/scan/trace", json=body, headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200


def test_open_when_unconfigured_but_health_says_so(monkeypatch):
    """Unset is permissive on purpose (see auth.py) — but /health must report it,
    so an unauthenticated deployment is discoverable rather than assumed."""
    c = _client(monkeypatch, None)
    assert c.post("/v1/scan", json=SCAN_BODY).status_code == 200
    assert c.get("/health").json()["auth"] is False


def test_health_is_public_even_when_protected(monkeypatch):
    """Health checks come from the platform's prober, which has no credentials."""
    c = _client(monkeypatch, "s3cret")
    r = c.get("/health")
    assert r.status_code == 200
    assert r.json()["auth"] is True


@pytest.mark.parametrize("header", ["", "Basic s3cret", "bearer s3cret", "Bearer ", "s3cret"])
def test_malformed_authorization_headers_are_rejected(monkeypatch, header):
    c = _client(monkeypatch, "s3cret")
    headers = {"Authorization": header} if header else {}
    assert c.post("/v1/scan", json=SCAN_BODY, headers=headers).status_code == 401


def test_surrounding_whitespace_in_the_token_is_tolerated(monkeypatch):
    """Deliberate leniency, pinned so it isn't "fixed" by accident. Config
    plumbing (compose files, Railway variables, shell exports) picks up stray
    whitespace constantly, and a credential that fails only on an invisible
    character produces an outage nobody can diagnose. It costs nothing: the
    trimmed value still has to match exactly."""
    c = _client(monkeypatch, "s3cret")
    r = c.post("/v1/scan", json=SCAN_BODY, headers={"Authorization": "Bearer  s3cret "})
    assert r.status_code == 200
