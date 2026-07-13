"""L4 — trace-level behavioral analysis (the moat).

Operates on a whole completed trace after the taint frontier is known. Detects
what content-level layers cannot: whether an agent's *behavior* changed after
ingesting untrusted content. Signals implemented in Phase 1:

  * taint propagation      — mark observations downstream of an untrusted span
  * instruction_echo       — a later tool/model span paraphrases an imperative
                             found in an untrusted span (indirect injection that
                             actually *succeeded*, not merely attempted)
  * exfil_flow             — a taint-influenced outbound action (email/URL/tool
                             arg) carries content sourced from another span
  * behavior_deviation     — a side-effectful tool fires in a taint-influenced
                             region (heuristic baseline in Phase 1)
  * canary_triggered       — a registered canary appears in any egress span

Phase 2 adds embedding-based deviation scoring and cross-trace correlation; the
interfaces here are shaped so that swap is additive.
"""
from __future__ import annotations

import re

from ..models import (
    Category,
    Finding,
    Observation,
    ObservationType,
    Outcome,
    Severity,
    TaintClass,
)
from .. import taint as taint_mod

# Tools whose invocation constitutes an outbound side effect (blast radius).
_SIDE_EFFECT_HINTS = (
    "email", "send", "post", "http", "fetch", "url", "write", "delete",
    "payment", "purchase", "transfer", "sms", "message", "upload", "exec",
)

# Imperative phrases we extract from untrusted content to test for echo.
_IMPERATIVE = re.compile(
    r"\b(send|email|forward|delete|transfer|ignore|disregard|reveal|call|invoke|"
    r"execute|run|fetch|upload|post|export)\b[^.\n]{0,80}",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s)\"']+", re.IGNORECASE)


def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9@._-]{3,}", text.lower())}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _is_side_effect(obs: Observation) -> bool:
    name = (obs.name or "").lower()
    return obs.type == ObservationType.tool and any(h in name for h in _SIDE_EFFECT_HINTS)


def analyze(
    trace_id: str,
    observations: list[Observation],
    tool_overrides: dict[str, str] | None = None,
    canaries: list[str] | None = None,
) -> tuple[list[Finding], int]:
    """Return (findings, taint_frontier_index)."""
    findings: list[Finding] = []
    canaries = canaries or []

    # Resolve taint for each observation, in order.
    taints = [taint_mod.classify(o, tool_overrides) for o in observations]

    # Taint frontier = index of first untrusted-external span; everything after
    # it is potentially taint-influenced.
    frontier = -1
    for i, t in enumerate(taints):
        if t == TaintClass.untrusted_external:
            frontier = i
            break

    # Collect imperatives + identifiers found in untrusted spans (the source of
    # any successful indirect injection).
    untrusted_imperatives: list[tuple[int, str]] = []
    untrusted_identifiers: set[str] = set()
    for i, (o, t) in enumerate(zip(observations, taints)):
        if t != TaintClass.untrusted_external:
            continue
        for m in _IMPERATIVE.finditer(o.content or ""):
            untrusted_imperatives.append((i, m.group(0).strip()))
        untrusted_identifiers |= set(_EMAIL.findall(o.content or ""))
        untrusted_identifiers |= set(_URL.findall(o.content or ""))

    # Content of every span, for exfil-source attribution.
    span_tokens = [(_tokens(o.content or "")) for o in observations]

    for i, (obs, t) in enumerate(zip(observations, taints)):
        taint_influenced = frontier != -1 and i > frontier and t != TaintClass.untrusted_external
        signals: list[str] = []
        category = Category.indirect_injection
        outcome = Outcome.unknown
        severity = Severity.medium
        evidence = ""

        text = obs.content or ""

        # ---- canary egress (behavior-based, near-zero FP) ----
        for canary in canaries:
            if canary and canary in text and t in (TaintClass.model, TaintClass.untrusted_external):
                findings.append(
                    Finding(
                        observation_id=obs.observation_id,
                        trace_id=trace_id,
                        category=Category.canary_triggered,
                        severity=Severity.critical,
                        outcome=Outcome.succeeded,
                        score=98.0,
                        l4_signals=["canary_triggered"],
                        evidence_excerpt=f"canary token present in {obs.type.value} span",
                    )
                )

        if not taint_influenced and not (_is_side_effect(obs) and frontier != -1 and i > frontier):
            continue

        # ---- instruction echo: does this span paraphrase an untrusted imperative? ----
        best_echo = 0.0
        echo_src = ""
        this_tokens = span_tokens[i]
        for src_idx, imp in untrusted_imperatives:
            if src_idx >= i:
                continue
            sim = _jaccard(_tokens(imp), this_tokens)
            if sim > best_echo:
                best_echo = sim
                echo_src = imp
        if best_echo >= 0.35:
            signals.append("instruction_echo")
            outcome = Outcome.succeeded
            evidence = f"echoes untrusted imperative: “{echo_src[:80]}”"

        # ---- exfil flow: outbound action carrying other spans' content ----
        if _is_side_effect(obs):
            # recipients/URLs in this span that came from untrusted content
            targets = set(_EMAIL.findall(text)) | set(_URL.findall(text))
            to_untrusted = targets & untrusted_identifiers
            # content from *other* (non-adjacent) spans present in this outbound payload
            carried = set()
            for j, jt in enumerate(span_tokens):
                if j == i or not jt:
                    continue
                if taints[j] in (TaintClass.user, TaintClass.system, TaintClass.model, TaintClass.untrusted_external):
                    if _jaccard(jt, this_tokens) >= 0.25 and taints[j] != TaintClass.untrusted_external:
                        carried.add(j)
            if to_untrusted or (carried and best_echo >= 0.35):
                signals.append("exfil_flow")
                category = Category.exfiltration
                outcome = Outcome.succeeded
                severity = Severity.critical
                if to_untrusted:
                    evidence = f"outbound to attacker-controlled target: {', '.join(list(to_untrusted)[:2])}"

        # ---- behavior deviation: side-effect tool in taint-influenced region ----
        if _is_side_effect(obs) and frontier != -1 and i > frontier:
            signals.append("behavior_deviation")
            if severity == Severity.medium:
                severity = Severity.high

        if not signals:
            continue

        # Severity bump for blast radius (side-effectful downstream).
        if "exfil_flow" in signals or "instruction_echo" in signals and _is_side_effect(obs):
            severity = Severity.critical

        score = {
            Severity.medium: 55.0,
            Severity.high: 75.0,
            Severity.critical: 92.0,
        }.get(severity, 55.0)

        findings.append(
            Finding(
                observation_id=obs.observation_id,
                trace_id=trace_id,
                category=category,
                severity=severity,
                outcome=outcome,
                score=score,
                l4_signals=signals,
                evidence_excerpt=evidence or f"taint-influenced {obs.type.value} span",
            )
        )

    return findings, frontier
