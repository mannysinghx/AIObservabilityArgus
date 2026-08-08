"""L0 artifact-scanner quality gate (docs/18 Phase 0).

This is the gate the whole feature is built behind. The naive version of this
detector — "a pickle containing REDUCE is malicious" — fires on every model
ever saved, and a supply-chain alert that cries wolf gets muted on day two,
after which the real one is invisible. So Phase 0 ships nothing user-facing
until these numbers hold.

The bar, and why it differs from the L1 gate:

  * **Zero false positives at DECISION_SEVERITY.** Not "high precision" —
    zero. An artifact alert says "do not load this model", which stops a
    deploy. It has to be right.
  * **100% recall on the malicious corpus.** Every fixture is a technique we
    have decided to detect; missing one means the technique works.

DECISION_SEVERITY is `high` because that is the band that alerts and blocks.
Below it live two deliberate non-alerts: ARG-ART-001 (unrecognized global,
medium — a project's own classes land here constantly) and ARG-ART-005
(code-capable format, low — true of every pickle in the fleet). Both are
inventory signals. Counting them as false positives would push the design
toward suppressing them, and they are worth having.

Do not lower these floors to make a red build green.
"""

from __future__ import annotations

import pytest

from argus_detection.assessment.artifact import (
    ALLOWLIST_VERSION,
    ArtifactContext,
    build_manifest,
    scan_artifact,
)

from .artifact_corpus import Fixture, load_corpus

# The severity at which a finding alerts a human or blocks a pipeline.
DECISION_SEVERITY = "high"

_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

# Regression floors. Raise as the detector improves; never lower without a
# reviewed reason written into the commit.
MIN_RECALL = 1.0
MAX_FALSE_POSITIVES = 0

# Pinned so a change to the allowlist is a deliberate, visible act rather than
# a silent shift in what the product considers safe.
EXPECTED_ALLOWLIST_VERSION = "1.1.0"


def _alerting(fx: Fixture):
    """Findings from one fixture at or above the decision severity."""
    man = build_manifest(fx.data, path=fx.filename)
    ctx = ArtifactContext(first_party_prefixes=fx.first_party_prefixes)
    floor = _ORDER[DECISION_SEVERITY]
    matches = scan_artifact(man, ctx)
    return [m for m in matches if _ORDER.get(m.severity, 9) <= floor], matches


def _metrics():
    tp = fp = tn = fn = 0
    misses, false_alarms = [], []
    for fx in load_corpus():
        alerting, _ = _alerting(fx)
        hostile = fx.label == "malicious"
        if hostile and alerting:
            tp += 1
        elif hostile:
            fn += 1
            misses.append(fx.id)
        elif alerting:
            fp += 1
            false_alarms.append((fx.id, [m.rule_id for m in alerting]))
        else:
            tn += 1
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": tp / (tp + fn) if (tp + fn) else 1.0,
        "misses": misses, "false_alarms": false_alarms,
    }


# ---------------------------------------------------------------- corpus


def test_corpus_is_substantial():
    corpus = load_corpus()
    benign = [f for f in corpus if f.label == "benign"]
    malicious = [f for f in corpus if f.label == "malicious"]
    assert len(benign) >= 15, "benign corpus too small to trust a zero-FP claim"
    assert len(malicious) >= 20, "malicious corpus too small to claim coverage"
    assert len({f.id for f in corpus}) == len(corpus), "duplicate fixture ids"


def test_corpus_has_authentic_benign_fixtures():
    """At least some of the benign corpus must be real pickle output.

    Hand-assembled fixtures prove what the allowlist does with a name we chose.
    Only `pickle.dumps` proves what pickle actually emits, and that is the half
    that can surprise us.
    """
    authentic = [f for f in load_corpus() if f.label == "benign" and f.kind == "authentic"]
    assert len(authentic) >= 10


# ---------------------------------------------------------------- the gate


def test_zero_false_positives_on_benign_corpus():
    m = _metrics()
    assert m["fp"] <= MAX_FALSE_POSITIVES, (
        f"{m['fp']} benign artifact(s) would alert at severity>={DECISION_SEVERITY}: "
        f"{m['false_alarms']}\n"
        f"This is the number that decides whether anyone leaves L0 switched on."
    )


def test_full_recall_on_malicious_corpus():
    m = _metrics()
    assert m["recall"] >= MIN_RECALL, (
        f"recall {m['recall']:.3f} < {MIN_RECALL}; missed {m['misses']}\n"
        f"Every fixture is a technique we decided to detect."
    )


@pytest.mark.parametrize("fx", [f for f in load_corpus() if f.label == "malicious"],
                         ids=lambda f: f.id)
def test_each_malicious_fixture_raises_its_expected_rules(fx):
    """Recall alone is not enough — the right rule has to fire.

    A fixture caught by the wrong rule is caught by accident, and the accident
    disappears the next time the rules change.
    """
    _, matches = _alerting(fx)
    fired = {m.rule_id for m in matches}
    missing = set(fx.expect_rules) - fired
    assert not missing, (
        f"{fx.id}: expected {sorted(fx.expect_rules)}, fired {sorted(fired)} "
        f"(missing {sorted(missing)}) — {fx.note}"
    )


@pytest.mark.parametrize("fx", [f for f in load_corpus() if f.label == "benign"],
                         ids=lambda f: f.id)
def test_each_benign_fixture_is_quiet(fx):
    alerting, _ = _alerting(fx)
    assert not alerting, (
        f"{fx.id} would alert with {[m.rule_id for m in alerting]} — {fx.note}\n"
        f"evidence: {[m.evidence for m in alerting]}"
    )


def test_safetensors_produces_nothing_at_all():
    """The inert format is the recommendation the whole layer points at.

    If converting to safetensors still produced findings, the advice would be
    worthless.
    """
    fx = next(f for f in load_corpus() if f.id == "benign-safetensors")
    man = build_manifest(fx.data, path=fx.filename)
    assert man.format == "safetensors"
    assert man.tensor_keys == ["weight"]
    assert scan_artifact(man) == []


# ---------------------------------------------------------------- pins


def test_allowlist_version_is_pinned():
    assert ALLOWLIST_VERSION == EXPECTED_ALLOWLIST_VERSION, (
        "the allowlist changed; bump EXPECTED_ALLOWLIST_VERSION in the same "
        "commit so the change is visible in review"
    )


def test_print_report(capsys):
    m = _metrics()
    corpus = load_corpus()
    with capsys.disabled():
        print(f"\n=== Argus L0 artifact quality gate (allowlist {ALLOWLIST_VERSION}) ===")
        print(f"  corpus: {len(corpus)} fixtures "
              f"({sum(f.label == 'benign' for f in corpus)} benign / "
              f"{sum(f.label == 'malicious' for f in corpus)} malicious)")
        print(f"  decision severity: >={DECISION_SEVERITY}")
        print(f"  TP={m['tp']}  FP={m['fp']}  TN={m['tn']}  FN={m['fn']}")
        print(f"  recall={m['recall']:.3f}  false positives={m['fp']}")
        if m["misses"]:
            print(f"  MISSES:       {m['misses']}")
        if m["false_alarms"]:
            print(f"  FALSE ALARMS: {m['false_alarms']}")
