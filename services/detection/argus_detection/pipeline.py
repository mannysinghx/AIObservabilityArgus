"""Detection pipeline orchestration.

Ties the layers together with cheap-first escalation (docs/04):
  span scan:  L1 always → L2 only when taint is untrusted OR L1 flagged
  trace scan: L4 over the whole trace

Kept free of I/O so it's unit-testable; the FastAPI app (app.py) is the only
network surface.
"""
from __future__ import annotations

from .layers import classifiers, heuristics, trace_analysis
from .models import (
    Finding,
    ScanRequest,
    ScanResponse,
    TraceScanRequest,
    TraceScanResponse,
)
from . import taint as taint_mod
from .scoring import combine

# L2 runs when L1 score clears this even for trusted content (an escalation).
_L1_ESCALATE = 0.4


def scan_observation(req: ScanRequest, ruleset: str = "default-v1") -> ScanResponse:
    obs = req.observation
    taint = taint_mod.classify(obs, req.tool_overrides)

    l1 = heuristics.scan(obs, taint, ruleset=ruleset)
    layers = [l1]

    l2 = None
    should_l2 = req.enable_l2 and (
        taint == taint_mod.TaintClass.untrusted_external or l1.score >= _L1_ESCALATE
    )
    if should_l2 and classifiers.available():
        l2 = classifiers.scan(obs, taint)
        layers.append(l2)

    findings: list[Finding] = []
    finding = combine(obs, taint, l1, l2)
    if finding is not None:
        findings.append(finding)

    return ScanResponse(
        project_id=req.project_id,
        observation_id=obs.observation_id,
        taint=taint,
        findings=findings,
        layers=layers,
    )


def scan_trace(req: TraceScanRequest) -> TraceScanResponse:
    findings, frontier = trace_analysis.analyze(
        req.trace_id,
        req.observations,
        tool_overrides=req.tool_overrides,
        canaries=req.canaries,
    )
    return TraceScanResponse(
        project_id=req.project_id,
        trace_id=req.trace_id,
        findings=findings,
        taint_frontier_index=frontier,
    )
