"""`argus-modelscan` CLI tests (docs/18 Phase 1).

The CLI's contract with CI is its exit code, so that is what most of these pin.
A gate that prints alarming text and exits 0 is not a gate.
"""

from __future__ import annotations

import json

import pytest

from argus_detection.cli.modelscan import main, manifest_for_path

from .artifact_corpus import load_corpus


@pytest.fixture
def models(tmp_path):
    """A directory of real artifact bytes, mixed clean and hostile."""
    keep = {
        "mal-os-system": "evil.pkl",
        "mal-torch-zip-payload": "pytorch_model.bin",
        "mal-zip-native-lib": "suspicious.pt",
        "benign-torch-zip": "checkpoint.pt",
        "benign-safetensors": "model.safetensors",
        "benign-sklearn-joblib": "classifier.joblib",
        "benign-main-module-class": "run1.pt",
    }
    for fx in load_corpus():
        if fx.id in keep:
            (tmp_path / keep[fx.id]).write_bytes(fx.data)
    return tmp_path


# ---------------------------------------------------------------- exit codes


def test_hostile_artifact_exits_1(models, capsys):
    assert main([str(models / "evil.pkl"), "--no-color"]) == 1
    assert "ARG-ART-002" in capsys.readouterr().out


def test_clean_artifact_exits_0(models, capsys):
    assert main([str(models / "model.safetensors"), "--no-color"]) == 0


def test_directory_scan_exits_1_when_any_artifact_is_hostile(models):
    assert main([str(models), "--no-color"]) == 1


def test_missing_path_exits_2(tmp_path):
    assert main([str(tmp_path / "nope.pt")]) == 2


def test_unreachable_server_exits_2_not_0(models, capsys):
    """Fail closed. A gate that passes because it could not reach its server
    reports 'clean' for every build after the URL rots, which is worse than
    having no gate at all — nobody investigates a green build."""
    code = main([str(models / "evil.pkl"), "--server", "http://127.0.0.1:1", "--no-color"])
    assert code == 2
    assert "unreachable" in capsys.readouterr().err


# ---------------------------------------------------------------- thresholds


def test_fail_on_critical_ignores_a_high_finding(models):
    """suspicious.pt raises ARG-ART-007 (high) and nothing critical."""
    assert main([str(models / "suspicious.pt"), "--no-color"]) == 1
    assert main([str(models / "suspicious.pt"), "--fail-on", "critical", "--no-color"]) == 0


def test_fail_on_none_never_fails(models):
    assert main([str(models / "evil.pkl"), "--fail-on", "none", "--no-color"]) == 0


def test_medium_findings_do_not_fail_the_default_gate(models):
    """run1.pt is a training-script class (__main__.MyTransformer) — an
    inventory signal, not a reason to stop a deploy."""
    assert main([str(models / "run1.pt"), "--no-color"]) == 0


def test_first_party_prefix_silences_unrecognized(models, capsys):
    main([str(models / "run1.pt"), "--no-color"])
    assert "ARG-ART-001" in capsys.readouterr().out
    main([str(models / "run1.pt"), "--first-party", "__main__", "--no-color"])
    assert "ARG-ART-001" not in capsys.readouterr().out


# ---------------------------------------------------------------- output


def test_json_output_is_machine_readable(models, capsys):
    main([str(models / "pytorch_model.bin"), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["mode"] == "local"
    assert payload["finding_count"] > 0
    assert payload["artifacts"][0]["format"] == "torch_zip"
    assert len(payload["artifacts"][0]["sha256"]) == 64
    assert any(f["rule_id"] == "ARG-ART-002" for f in payload["findings"])


def test_report_names_the_archive_member(models, capsys):
    """'os.system somewhere in this 40 GB archive' is not actionable."""
    main([str(models / "pytorch_model.bin"), "--no-color"])
    assert "archive/data.pkl" in capsys.readouterr().out


# ---------------------------------------------------------------- extraction


def test_manifest_hashes_and_sniffs_from_disk(models):
    man = manifest_for_path(models / "pytorch_model.bin")
    assert man.format == "torch_zip"
    assert len(man.sha256) == 64
    assert man.size_bytes > 0
    assert any(g.qualname == "os.system" for g in man.globals)
    assert any(m.is_pickle for m in man.archive_members)


def test_oversized_pickle_is_reported_not_silently_skipped(models):
    """Above the inline cap the walk cannot run. That must surface as a parse
    error — a size limit that renders as 'no findings' is a silent false
    negative on exactly the largest artifacts."""
    man = manifest_for_path(models / "evil.pkl", max_inline=4)
    assert man.globals == []
    assert man.parse_errors and "cap" in man.parse_errors[0]


def test_directory_walk_skips_non_model_files(models):
    (models / "README.md").write_text("not a model")
    (models / "train.py").write_text("import torch")
    man_paths = {p.name for p in __import__(
        "argus_detection.cli.modelscan", fromlist=["collect"],
    ).collect([str(models)])}
    assert "README.md" not in man_paths
    assert "train.py" not in man_paths
    assert "evil.pkl" in man_paths


def test_explicitly_named_file_is_scanned_whatever_its_extension(models):
    """A directory walk filters by extension; naming a file is an instruction,
    and a payload renamed to .txt is precisely the case worth catching."""
    odd = models / "weights.dat"
    odd.write_bytes((models / "evil.pkl").read_bytes())
    assert main([str(odd), "--no-color"]) == 1
