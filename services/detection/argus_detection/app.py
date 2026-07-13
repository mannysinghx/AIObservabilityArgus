"""Argus detection service — FastAPI surface.

Endpoints:
  GET  /health           liveness + which layers are active
  POST /v1/scan          scan one observation (L1 + optional L2)
  POST /v1/scan/trace    scan a completed trace (L4 behavioral analysis)

The security worker (apps/worker) calls these. Keeping detection behind HTTP
lets the TS ingestion side stay model-free and lets detection scale separately.
"""
from __future__ import annotations

from fastapi import FastAPI

from . import __version__
from .layers import classifiers
from .models import ScanRequest, ScanResponse, TraceScanRequest, TraceScanResponse
from .pipeline import scan_observation, scan_trace

app = FastAPI(title="Argus Detection", version=__version__)


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "layers": {
            "L1_heuristics": True,
            "L2_classifiers": classifiers.available(),
            "L4_trace_analysis": True,
        },
    }


@app.post("/v1/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> ScanResponse:
    return scan_observation(req)


@app.post("/v1/scan/trace", response_model=TraceScanResponse)
def scan_trace_endpoint(req: TraceScanRequest) -> TraceScanResponse:
    return scan_trace(req)
