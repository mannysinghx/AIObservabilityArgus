"""Route-level tests for /v1/assess/artifact (docs/18 Phase 1).

The rules have their own corpus and gate (test_artifact_quality_gate.py); these
pin the HTTP contract the web tier and the CLI depend on — manifest in, enriched
findings out, with the taxonomy bridge, risk breakdown and mitigations present.

The one property worth naming: this endpoint must stay reachable without the
artifact. The caller holds a file that may be tens of gigabytes and sends a few
kilobytes of manifest, and every test here is written that way on purpose.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from argus_detection.app import app
from argus_detection.assessment.artifact import ALLOWLIST_VERSION

client = TestClient(app)

# A manifest as the CLI would produce it for a checkpoint carrying os.system
# buried in data.pkl — the model-smuggling shape.
SMUGGLED = {
    "project_id": "p1",
    "artifacts": [{
        "path": "pytorch_model.bin",
        "sha256": "e" * 64,
        "size_bytes": 2048,
        "format": "torch_zip",
        "source_uri": "hf://acme/encoder",
        "revision": "abc123",
        "globals": [
            {"module": "collections", "name": "OrderedDict", "opcode": "GLOBAL",
             "offset": 2, "member": "archive/data.pkl"},
            {"module": "torch._utils", "name": "_rebuild_tensor_v2", "opcode": "GLOBAL",
             "offset": 30, "member": "archive/data.pkl"},
            {"module": "os", "name": "system", "opcode": "GLOBAL",
             "offset": 64, "member": "archive/data.pkl"},
        ],
        "archive_members": [
            {"name": "archive/data.pkl", "raw_name": "archive/data.pkl", "is_pickle": True},
            {"name": "archive/data/0", "raw_name": "archive/data/0"},
        ],
    }],
}

CLEAN = {
    "project_id": "p1",
    "artifacts": [{
        "path": "model.safetensors",
        "sha256": "a" * 64,
        "size_bytes": 1024,
        "format": "safetensors",
        "tensor_keys": ["encoder.weight"],
    }],
}


def test_smuggled_checkpoint_is_critical():
    res = client.post("/v1/assess/artifact", json=SMUGGLED)
    assert res.status_code == 200
    body = res.json()
    assert body["project_id"] == "p1"
    assert body["max_severity"] == "critical"
    assert body["finding_count"] == len(body["findings"]) > 0
    assert body["allowlist_version"] == ALLOWLIST_VERSION
    assert body["scoring_version"] == "1.0.0"

    exec_finding = next(f for f in body["findings"] if f["rule_id"] == "ARG-ART-002")
    assert exec_finding["severity"] == "critical"
    assert "os.system" in exec_finding["evidence"]
    # The member is part of the evidence: "somewhere in this 40 GB archive" is
    # not an actionable statement.
    assert "archive/data.pkl" in exec_finding["evidence"]


def test_findings_carry_the_llm05_framework_reference():
    """The reason this feature exists. LLM05 was in the framework registry with
    zero rules citing it, so governance reports promised a row nothing could
    populate."""
    body = client.post("/v1/assess/artifact", json=SMUGGLED).json()
    refs = {
        (fr["framework"], fr["requirement"])
        for f in body["findings"] for fr in f["frameworks"]
    }
    assert ("OWASP-LLM", "LLM05") in refs


def test_findings_bridge_into_the_runtime_taxonomy():
    """What lets an artifact finding sit next to security_events in the UI."""
    body = client.post("/v1/assess/artifact", json=SMUGGLED).json()
    for f in body["findings"]:
        assert f["category"] == "supply-chain"
        assert f["argus_category"] == "supply_chain"
        assert f["argus_severity"] in {"info", "low", "medium", "high", "critical"}


def test_findings_carry_risk_and_mitigations():
    body = client.post("/v1/assess/artifact", json=SMUGGLED).json()
    f = next(f for f in body["findings"] if f["rule_id"] == "ARG-ART-002")
    assert f["risk"]["final_score"] > 0
    assert f["risk"]["scoring_version"] == "1.0.0"
    assert set(f["risk"]["factors"]) == {
        "likelihood", "impact", "exposure", "control_weakness", "confidence",
    }
    keys = {m["key"] for m in f["mitigations"]}
    assert keys, "supply-chain findings must rank mitigations, not just a recommendation string"
    assert "MIT-SAFETENSORS" in keys or "MIT-ARTIFACT-PINNING" in keys


def test_clean_safetensors_produces_nothing():
    body = client.post("/v1/assess/artifact", json=CLEAN).json()
    assert body["finding_count"] == 0
    assert body["findings"] == []
    assert body["max_severity"] is None
    assert body["overall_risk"] == 0


def test_first_party_prefixes_silence_the_projects_own_classes():
    """Without this every custom nn.Module reports as an unrecognized reference
    — true, useless, and the fastest way to get the signal ignored."""
    payload = {
        "project_id": "p1",
        "artifacts": [{
            "path": "encoder.pt", "sha256": "b" * 64, "format": "pickle",
            "globals": [
                {"module": "acme_ml.models", "name": "TextEncoder", "offset": 4},
            ],
        }],
    }
    noisy = client.post("/v1/assess/artifact", json=payload).json()
    assert any(f["rule_id"] == "ARG-ART-001" for f in noisy["findings"])

    quiet = client.post(
        "/v1/assess/artifact", json={**payload, "first_party_prefixes": ["acme_ml."]},
    ).json()
    assert not any(f["rule_id"] == "ARG-ART-001" for f in quiet["findings"])


def test_document_index_and_name_identify_the_artifact():
    """Findings share storage with prompt assessments, so the artifact has to
    arrive in the columns that schema already has."""
    body = client.post("/v1/assess/artifact", json={
        "project_id": "p1",
        "artifacts": [CLEAN["artifacts"][0], SMUGGLED["artifacts"][0]],
    }).json()
    for f in body["findings"]:
        assert f["document_index"] == 1          # all findings are on the second artifact
        assert f["document_name"] == "pytorch_model.bin"


def test_empty_artifact_list_is_valid_and_clean():
    body = client.post("/v1/assess/artifact", json={"project_id": "p1", "artifacts": []}).json()
    assert body["finding_count"] == 0
    assert body["max_severity"] is None


def test_malformed_manifest_is_rejected_not_guessed():
    res = client.post("/v1/assess/artifact", json={"project_id": "p1"})
    assert res.status_code == 422


def test_health_reports_the_live_allowlist():
    """Which allowlist is deployed decides every verdict this endpoint returns,
    so it has to be answerable without reading a container's environment."""
    body = client.get("/health").json()
    assert body["artifact"]["allowlist_version"] == ALLOWLIST_VERSION
    assert body["artifact"]["rules"] >= 10
