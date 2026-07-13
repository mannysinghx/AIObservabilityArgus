"""Detection quality gate (docs/04 §False-positive management).

Runs the L1 span pipeline over the labeled corpus and asserts precision/recall
stay above a floor. This is a REGRESSION GUARD: a PR that touches rules or
scoring and drops these numbers fails CI. Raise the floors as the ruleset (and
later L2/L3) improve — never lower them to make a red build green without a
deliberate, reviewed reason.

Positive prediction = the span pipeline raises at least one finding at or above
`DECISION_SEVERITY`. Heuristics-only is expected to be recall-strong and
precision-decent; L2/L3 (Phase 1.5+) push precision up.
"""
from __future__ import annotations

import json
from pathlib import Path


from argus_detection.models import Observation, ObservationType, ScanRequest, Severity
from argus_detection.models import SEVERITY_ORDER
from argus_detection.pipeline import scan_observation

_CORPUS = Path(__file__).resolve().parent.parent / "argus_detection" / "corpus" / "span_corpus.jsonl"

# A span counts as "flagged" if it produces a finding at this severity or higher.
DECISION_SEVERITY = Severity.low

# Regression floors — current heuristic-only baseline sits comfortably above.
MIN_RECALL = 0.90       # catch attacks
MIN_PRECISION = 0.80    # don't cry wolf
MIN_BENIGN_SPECIFICITY = 0.80  # of benign spans, fraction correctly left alone


def _load():
    rows = []
    for line in _CORPUS.read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _flagged(row) -> bool:
    obs = Observation(
        observation_id=row["id"],
        content=row["content"],
        type=ObservationType(row.get("type", "span")),
        taint=row.get("taint"),
    )
    resp = scan_observation(ScanRequest(observation=obs, tool_overrides={}))
    floor = SEVERITY_ORDER[DECISION_SEVERITY]
    return any(SEVERITY_ORDER[f.severity] >= floor for f in resp.findings)


def _metrics():
    rows = _load()
    tp = fp = tn = fn = 0
    misses, false_alarms = [], []
    for row in rows:
        is_attack = row["label"] == "attack"
        flagged = _flagged(row)
        if is_attack and flagged:
            tp += 1
        elif is_attack and not flagged:
            fn += 1
            misses.append(row["id"])
        elif not is_attack and flagged:
            fp += 1
            false_alarms.append(row["id"])
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    specificity = tn / (tn + fp) if (tn + fp) else 1.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "specificity": specificity,
        "misses": misses, "false_alarms": false_alarms,
    }


def test_corpus_not_empty():
    rows = _load()
    assert len(rows) >= 20
    assert any(r["label"] == "attack" for r in rows)
    assert any(r["label"] == "benign" for r in rows)


def test_recall_floor():
    m = _metrics()
    print(f"\nrecall={m['recall']:.3f} misses={m['misses']}")
    assert m["recall"] >= MIN_RECALL, f"recall {m['recall']:.3f} < {MIN_RECALL}; missed {m['misses']}"


def test_precision_floor():
    m = _metrics()
    print(f"\nprecision={m['precision']:.3f} false_alarms={m['false_alarms']}")
    assert m["precision"] >= MIN_PRECISION, (
        f"precision {m['precision']:.3f} < {MIN_PRECISION}; false alarms {m['false_alarms']}"
    )


def test_benign_specificity_floor():
    m = _metrics()
    assert m["specificity"] >= MIN_BENIGN_SPECIFICITY, (
        f"specificity {m['specificity']:.3f} < {MIN_BENIGN_SPECIFICITY}; "
        f"false alarms {m['false_alarms']}"
    )


def test_print_report(capsys):
    m = _metrics()
    with capsys.disabled():
        print("\n=== Argus detection quality gate (L1 heuristics) ===")
        print(f"  TP={m['tp']}  FP={m['fp']}  TN={m['tn']}  FN={m['fn']}")
        print(f"  precision={m['precision']:.3f}  recall={m['recall']:.3f}  "
              f"specificity={m['specificity']:.3f}")
        if m["misses"]:
            print(f"  misses:       {m['misses']}")
        if m["false_alarms"]:
            print(f"  false alarms: {m['false_alarms']}")
