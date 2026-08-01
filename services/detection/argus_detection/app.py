"""Argus detection service — FastAPI surface.

Endpoints:
  GET  /health              liveness + which layers are active (public)
  POST /v1/scan             scan one observation (L1 + optional L2)
  POST /v1/scan/trace       scan a completed trace (L4 behavioral analysis)
  POST /v1/assess/prompt    static prompt assessment (rules + risk + mitigations)
  POST /v1/assess/graph     architecture-graph trust-boundary analysis
  POST /v1/assess/policy    deterministic policy evaluation

The security worker (apps/worker) calls the scan endpoints per-event; the web
tier calls the assess endpoints per-application. Keeping both behind HTTP lets
the TS side stay model-free and lets this service scale separately.

All non-health endpoints require `Authorization: Bearer $DETECTION_API_KEY`
when that variable is set; see auth.py for why unset is permissive.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from . import __version__
from .assessment import SCORING_VERSION
from .assessment.assess import assess_graph, assess_policy, assess_prompts
from .assessment.models import (
    AssessGraphRequest,
    AssessGraphResponse,
    AssessPolicyRequest,
    AssessPolicyResponse,
    AssessPromptRequest,
    AssessPromptResponse,
)
from .assessment.scanner import ALL_RULES
from .auth import enabled as auth_enabled
from .auth import require_api_key, warn_if_unprotected
from .layers import classifiers
from .models import ScanRequest, ScanResponse, TraceScanRequest, TraceScanResponse
from .pipeline import scan_observation, scan_trace


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    warn_if_unprotected()
    yield


app = FastAPI(title="Argus Detection", version=__version__, lifespan=lifespan)


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        # Surfaced so an operator can tell an unauthenticated deployment from a
        # protected one without reading the environment of a running container.
        "auth": auth_enabled(),
        "layers": {
            "L1_heuristics": True,
            "L2_classifiers": classifiers.available(),
            "L4_trace_analysis": True,
        },
        # Static assessment engine (ported from InjectGuard) — surfaced so a
        # deploy can be verified from /health alone.
        "assessment": {
            "prompt_rules": len(ALL_RULES),
            "scoring_version": SCORING_VERSION,
        },
    }


@app.post("/v1/scan", response_model=ScanResponse, dependencies=[Depends(require_api_key)])
def scan(req: ScanRequest) -> ScanResponse:
    return scan_observation(req)


@app.post("/v1/scan/trace", response_model=TraceScanResponse, dependencies=[Depends(require_api_key)])
def scan_trace_endpoint(req: TraceScanRequest) -> TraceScanResponse:
    return scan_trace(req)


@app.post(
    "/v1/assess/prompt",
    response_model=AssessPromptResponse,
    dependencies=[Depends(require_api_key)],
)
def assess_prompt_endpoint(req: AssessPromptRequest) -> AssessPromptResponse:
    return assess_prompts(req)


@app.post(
    "/v1/assess/graph",
    response_model=AssessGraphResponse,
    dependencies=[Depends(require_api_key)],
)
def assess_graph_endpoint(req: AssessGraphRequest) -> AssessGraphResponse:
    return assess_graph(req)


@app.post(
    "/v1/assess/policy",
    response_model=AssessPolicyResponse,
    dependencies=[Depends(require_api_key)],
)
def assess_policy_endpoint(req: AssessPolicyRequest) -> AssessPolicyResponse:
    return assess_policy(req)
