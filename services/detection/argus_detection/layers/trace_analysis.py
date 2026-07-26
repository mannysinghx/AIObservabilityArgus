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

from .. import canary as canary_mod
from .. import taint as taint_mod
from ..models import (
    CanaryRef,
    Category,
    Finding,
    Observation,
    ObservationType,
    Outcome,
    Severity,
    TaintClass,
)

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


def _is_egress(obs: Observation, taint: TaintClass) -> bool:
    """Could content in this span have left the system?

    Model output and tool spans, both of which are places a planted marker has
    no legitimate reason to appear. Retrieval spans are deliberately excluded:
    a canary *arriving* from the corpus it was planted in is the system working
    as designed, and alerting on it would make the feature unusable for the main
    case — planting a canary in a document you also index.
    """
    if obs.type in (ObservationType.tool, ObservationType.generation):
        return True
    return taint == TaintClass.model


def analyze(
    trace_id: str,
    observations: list[Observation],
    tool_overrides: dict[str, str] | None = None,
    canaries: list[str] | None = None,
    canary_refs: list[CanaryRef] | None = None,
) -> tuple[list[Finding], int]:
    """Return (findings, taint_frontier_index)."""
    findings: list[Finding] = []
    # `canaries` (raw strings) is the pre-CanaryRef interface; adapt rather than
    # branch, so there is one matching path below.
    refs = list(canary_refs or []) + canary_mod.legacy_refs(canaries or [])

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
    # any successful indirect injection). Side-effect tool spans (send_email,
    # send_notification, ...) are excluded as *sources*: they're untrusted by
    # default so their own output gets scanned, but a tool's destination
    # address is an action the model took, not content it read — counting it
    # here would make every outbound call match itself and manufacture a
    # guaranteed "exfiltration" finding regardless of whether the target was
    # ever actually seen in attacker-influenced content.
    untrusted_imperatives: list[tuple[int, str]] = []
    untrusted_identifiers: set[str] = set()
    for i, (o, t) in enumerate(zip(observations, taints)):
        if t != TaintClass.untrusted_external or _is_side_effect(o):
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

        # ---- canary egress (behaviour-based, near-zero FP) ----
        #
        # Checked on every span before the taint-influence filter below, and
        # independently of it. A canary hit needs no corroboration and no taint
        # frontier: the marker was somewhere it could only have come from, and
        # it is now here. Gating it on the rest of L4's reasoning would mean the
        # product's most reliable signal could be suppressed by its least.
        if _is_egress(obs, t):
            for hit in canary_mod.find_canaries(text, refs):
                findings.append(
                    Finding(
                        observation_id=obs.observation_id,
                        trace_id=trace_id,
                        category=Category.canary_triggered,
                        severity=Severity.critical,
                        outcome=Outcome.succeeded,
                        score=98.0,
                        l4_signals=["canary_triggered"],
                        evidence_excerpt=(
                            f"canary {hit.label or hit.id or 'token'} appeared in a "
                            f"{obs.type.value} span"
                        ),
                        canary_id=hit.id,
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
                # The outer guard here used to list all four TaintClass members,
                # which is every possible value — so it tested nothing, and the
                # only real condition was the untrusted_external exclusion in
                # the inner branch. Stated directly: we're looking for content
                # that came from a *trusted* span and ended up in this outbound
                # payload. Untrusted spans are excluded because content flowing
                # from the attacker's own document back out again is the
                # attacker quoting themselves, not data being exfiltrated.
                if taints[j] == TaintClass.untrusted_external:
                    continue
                if _jaccard(jt, this_tokens) >= 0.25:
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
