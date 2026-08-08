"""`argus-modelscan` — scan model artifacts for code-execution payloads.

    argus-modelscan ./models/                     # scan a tree, fail on high+
    argus-modelscan model.pt --fail-on critical   # looser CI gate
    argus-modelscan model.pt --format json        # machine-readable
    argus-modelscan model.pt --server http://localhost:8000

Two judgement modes, and the difference matters:

  **local** (default) — rules run in-process. No service, no network, no
  credentials, which is what makes this usable as a CI gate in a container
  that has nothing else. The engine is the same code the service runs.

  **--server** — the manifest is POSTed to /v1/assess/artifact and the
  service's verdict wins. Use this when the deployment's allowlist may be newer
  than the installed CLI, or when the run should be recorded centrally.

Either way the weights never move: the manifest is kilobytes, and a
multi-gigabyte checkpoint has no business crossing a network when the module
names inside it are the entire question.

Exit codes:  0 clean · 1 findings at or above the threshold · 2 usage/IO error
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import asdict
from pathlib import Path

from ..assessment.artifact import (
    ALLOWLIST_VERSION,
    ArtifactContext,
    ArtifactManifest,
    scan_artifact,
)
from ..assessment.artifact.extract import safetensors_keys
from ..assessment.artifact.opcodes import sniff_format, walk_pickle, walk_zip_archive

SEVERITIES = ["critical", "high", "medium", "low", "informational"]
_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# Extensions worth opening when walking a directory. Anything else is skipped
# silently — a repo full of .py and .md should not produce a wall of "unknown
# format" lines that train people to ignore the output.
MODEL_GLOBS = (
    "*.pt", "*.pth", "*.ckpt", "*.bin", "*.pkl", "*.pickle", "*.joblib",
    "*.npy", "*.h5", "*.hdf5", "*.safetensors", "*.gguf", "*.onnx", "*.model",
)

# Read the whole file only below this. Above it, zips are walked lazily from
# disk and other formats are hashed but not opcode-walked (reported honestly as
# a parse error rather than silently as clean).
DEFAULT_MAX_INLINE = 2 * 1024**3  # 2 GiB

_ANSI = {
    "critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m",
    "low": "\033[36m", "informational": "\033[2m", "reset": "\033[0m",
}


def _color(s: str, sev: str, on: bool) -> str:
    return f"{_ANSI.get(sev, '')}{s}{_ANSI['reset']}" if on else s


def _sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def manifest_for_path(path: Path, max_inline: int = DEFAULT_MAX_INLINE) -> ArtifactManifest:
    """Read one artifact and extract its manifest.

    This is the I/O half that `assessment/artifact/extract.py` deliberately does
    not do. The walkers it calls are the same pure functions the corpus tests,
    so the only thing that differs between here and the service is who opened
    the file.
    """
    sha256, size = _sha256_file(path)
    with path.open("rb") as f:
        head = f.read(8192)
    fmt = sniff_format(head, path.name)

    man = ArtifactManifest(
        path=str(path), sha256=sha256, size_bytes=size, format=fmt,
        source_uri=path.resolve().as_uri(),
    )

    if fmt == "torch_zip":
        # Lazy: only pickle members are decompressed, so a 40 GB checkpoint
        # costs whatever its data.pkl costs.
        globals_, counts, members, errors = walk_zip_archive(str(path))
        man.globals, man.opcode_summary = globals_, counts
        man.archive_members, man.parse_errors = members, errors
        if not any(m.is_pickle for m in members):
            man.format = "zip"
    elif fmt in ("pickle", "joblib", "numpy_pickle"):
        if size > max_inline:
            man.parse_errors = [
                f"{size} bytes exceeds the {max_inline}-byte inline cap; not opcode-walked"
            ]
        else:
            man.globals, man.opcode_summary, man.parse_errors = walk_pickle(path.read_bytes())
    elif fmt == "safetensors":
        with path.open("rb") as f:
            header = f.read(8)
            n = int.from_bytes(header, "little") if len(header) == 8 else 0
            blob = header + f.read(min(n, 16 * 1024 * 1024))
        man.tensor_keys, man.parse_errors = safetensors_keys(blob)

    return man


def collect(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and any(fnmatch.fnmatch(f.name, g) for g in MODEL_GLOBS):
                    out.append(f)
        elif p.is_file():
            out.append(p)  # an explicitly named file is scanned whatever it is
        else:
            print(f"argus-modelscan: no such file or directory: {raw}", file=sys.stderr)
    return out


def _manifest_wire(man: ArtifactManifest) -> dict:
    d = asdict(man)
    # `is_code_capable` is a property, not a field, so asdict misses it — and
    # the server recomputes it from `format` anyway.
    return d


def judge_remote(manifests: list[ArtifactManifest], server: str, api_key: str,
                 first_party: list[str], project: str) -> list[dict]:
    body = json.dumps({
        "project_id": project,
        "artifacts": [_manifest_wire(m) for m in manifests],
        "first_party_prefixes": first_party,
    }).encode()
    headers = {"content-type": "application/json"}
    if api_key:
        headers["authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(
        server.rstrip("/") + "/v1/assess/artifact", data=body, headers=headers, method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read())
    return payload.get("findings", [])


def judge_local(manifests: list[ArtifactManifest], first_party: list[str]) -> list[dict]:
    ctx = ArtifactContext(first_party_prefixes=tuple(first_party))
    out: list[dict] = []
    for man in manifests:
        for m in scan_artifact(man, ctx):
            out.append({
                "document_name": man.path,
                "rule_id": m.rule_id, "title": m.title, "severity": m.severity,
                "confidence": m.confidence, "explanation": m.explanation,
                "evidence": m.evidence, "recommendation": m.recommendation,
                "affected_lines": m.affected_lines,
                "frameworks": [asdict(f) for f in m.frameworks],
                "sha256": man.sha256, "format": man.format,
            })
    return out


def render_text(findings: list[dict], manifests: list[ArtifactManifest],
                threshold: str, color: bool) -> None:
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        by_file.setdefault(f.get("document_name", ""), []).append(f)

    for man in manifests:
        hits = by_file.get(man.path, [])
        worst = min((f["severity"] for f in hits), key=lambda s: _ORDER.get(s, 9)) if hits else None
        head = f"{man.path}  [{man.format}]  {man.sha256[:16]}"
        print(_color(head, worst or "informational", color and bool(worst)))
        if not hits:
            print("    no findings")
        for f in sorted(hits, key=lambda x: _ORDER.get(x["severity"], 9)):
            sev = f["severity"]
            gate = "!" if _ORDER.get(sev, 9) <= _ORDER[threshold] else " "
            print(f"  {gate} {_color(sev.upper().ljust(8), sev, color)} "
                  f"{f['rule_id']}  {f['title']}")
            if f.get("evidence"):
                print(f"      evidence: {f['evidence']}")
            if _ORDER.get(sev, 9) <= _ORDER[threshold] and f.get("recommendation"):
                print(f"      → {f['recommendation']}")
        print()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="argus-modelscan",
        description="Scan model artifacts for code-execution payloads (Argus L0, docs/18).",
    )
    ap.add_argument("paths", nargs="+", help="files or directories to scan")
    ap.add_argument("--fail-on", default="high", choices=[*SEVERITIES, "none"],
                    help="exit 1 when a finding at this severity or worse is present "
                         "(default: high; 'none' never fails)")
    ap.add_argument("--format", default="text", choices=["text", "json"])
    ap.add_argument("--first-party", action="append", default=[], metavar="PREFIX",
                    help="import prefix belonging to your own code, e.g. 'acme_ml.' "
                         "(repeatable). Without it your own model classes report as "
                         "unrecognized references.")
    ap.add_argument("--server", default=os.environ.get("ARGUS_DETECTION_URL", ""),
                    help="detection service base URL; judge remotely instead of in-process")
    ap.add_argument("--api-key", default=os.environ.get("DETECTION_API_KEY", ""))
    ap.add_argument("--project", default=os.environ.get("ARGUS_PROJECT", "default"))
    ap.add_argument("--max-inline", type=int, default=DEFAULT_MAX_INLINE,
                    help=argparse.SUPPRESS)
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)

    files = collect(args.paths)
    if not files:
        print("argus-modelscan: nothing to scan", file=sys.stderr)
        return 2

    manifests = []
    for f in files:
        try:
            manifests.append(manifest_for_path(f, args.max_inline))
        except OSError as e:
            print(f"argus-modelscan: cannot read {f}: {e}", file=sys.stderr)
            return 2

    try:
        findings = (
            judge_remote(manifests, args.server, args.api_key, args.first_party, args.project)
            if args.server
            else judge_local(manifests, args.first_party)
        )
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        # Fail closed and loudly. A CI gate that silently passes because the
        # scanner could not reach its server is worse than no gate: it reports
        # "clean" for every build after the URL rots.
        print(f"argus-modelscan: detection service unreachable at {args.server}: {e}",
              file=sys.stderr)
        return 2

    color = not args.no_color and sys.stdout.isatty()
    if args.format == "json":
        json.dump({
            "allowlist_version": ALLOWLIST_VERSION,
            "mode": "server" if args.server else "local",
            "artifacts": [
                {"path": m.path, "sha256": m.sha256, "format": m.format,
                 "size_bytes": m.size_bytes}
                for m in manifests
            ],
            "finding_count": len(findings),
            "findings": findings,
        }, sys.stdout, indent=2)
        print()
    else:
        render_text(findings, manifests, args.fail_on if args.fail_on != "none" else "critical",
                    color)

    if args.fail_on == "none":
        return 0
    floor = _ORDER[args.fail_on]
    blocking = [f for f in findings if _ORDER.get(f["severity"], 9) <= floor]
    if blocking:
        if args.format == "text":
            # Flush first. stdout is block-buffered when piped (CI logs always
            # are) while stderr is not, so without this the verdict overtakes
            # the report it is summarizing and the log reads back-to-front.
            sys.stdout.flush()
            print(f"FAILED: {len(blocking)} finding(s) at or above '{args.fail_on}' "
                  f"across {len({f.get('document_name') for f in blocking})} artifact(s).",
                  file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
