"""Assessment reports — executive, technical, governance (InjectGuard port).

All four output formats are rendered here rather than split between services, so
there is exactly one definition of what a report says. The caller supplies the
data (it owns the database); this module owns the wording, the ordering, and the
redaction backstop.

Every format — including the JSON one — passes its text through redact_text
before it leaves. A report is the artifact most likely to be emailed, dropped in
a ticket, or attached to an audit response, which makes it the worst possible
place for a credential to survive. The engine already redacts evidence at
extraction; this is the second pass that catches anything a caller added.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from .redaction import redact_text

REPORT_KINDS = ("executive", "technical", "governance")
REPORT_FORMATS = ("md", "json", "csv", "pdf")

REDACTION_NOTE = (
    "Secrets are redacted from this report automatically. Evidence excerpts are "
    "truncated and may omit context; consult the source prompt for the full text."
)

# ── PDF writer (ported verbatim from InjectGuard; dependency-free) ────────────

PAGE_W, PAGE_H = 612, 792  # US Letter, points
MARGIN = 54
FONT_SIZE = 10
LEADING = 14
MAX_CHARS = 92
LINES_PER_PAGE = (PAGE_H - 2 * MARGIN) // LEADING


def _escape(text: str) -> str:
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _wrap(lines: list[str]) -> list[str]:
    out: list[str] = []
    for raw in lines:
        s = raw.rstrip("\n")
        if not s:
            out.append("")
            continue
        while len(s) > MAX_CHARS:
            cut = s.rfind(" ", 0, MAX_CHARS)
            cut = cut if cut > 0 else MAX_CHARS
            out.append(s[:cut])
            s = s[cut:].lstrip()
        out.append(s)
    return out


def _paginate(lines: list[str]) -> list[list[str]]:
    wrapped = _wrap(lines)
    pages = [wrapped[i : i + LINES_PER_PAGE] for i in range(0, len(wrapped), LINES_PER_PAGE)]
    return pages or [[""]]


def text_to_pdf(lines: list[str]) -> bytes:
    """A valid multi-page Helvetica PDF from plain text lines."""
    pages = _paginate(lines)
    objects: list[bytes] = []

    n_pages = len(pages)
    font_obj_num = 3 + 2 * n_pages
    kids_nums = [3 + 2 * i + 1 for i in range(n_pages)]

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{k} 0 R" for k in kids_nums)
    objects.append(f"<< /Type /Pages /Count {n_pages} /Kids [{kids}] >>".encode())

    for i, page_lines in enumerate(pages):
        content_num = 3 + 2 * i
        y = PAGE_H - MARGIN
        stream_parts = ["BT", f"/F1 {FONT_SIZE} Tf", f"{LEADING} TL", f"{MARGIN} {y} Td"]
        for j, line in enumerate(page_lines):
            if j > 0:
                stream_parts.append("T*")
            stream_parts.append(f"({_escape(line)}) Tj")
        stream_parts.append("ET")
        stream = "\n".join(stream_parts).encode()
        while len(objects) < content_num - 1:
            objects.append(b"<< >>")
        objects.append(b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream))
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
                f"/Resources << /Font << /F1 {font_obj_num} 0 R >> >> "
                f"/Contents {content_num} 0 R >>"
            ).encode()
        )

    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for idx, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{idx} 0 obj\n".encode() + body + b"\nendobj\n"

    xref_pos = len(out)
    count = len(objects) + 1
    out += f"xref\n0 {count}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode()
    return bytes(out)


# ── content ──────────────────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}


def _sorted_findings(findings: list[dict]) -> list[dict]:
    """Worst first, and within a severity the demonstrated ones first — a reader
    who stops after the first page should have seen the things that matter."""
    return sorted(
        findings,
        key=lambda f: (
            _SEV_ORDER.get(str(f.get("severity", "")), 9),
            0 if f.get("observed_in_production") else 1,
            -int(f.get("risk_score") or 0),
        ),
    )


def _counts(findings: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "unknown"))
        out[sev] = out.get(sev, 0) + 1
    return out


def _header(data: dict[str, Any], title: str) -> list[str]:
    return [
        f"{title} — {data.get('project_name') or 'Application'}",
        f"Generated {data.get('generated_at', '')}",
        "",
    ]


def _executive_lines(data: dict[str, Any]) -> list[str]:
    findings = _sorted_findings(data.get("findings") or [])
    counts = _counts(findings)
    observed = [f for f in findings if f.get("observed_in_production")]
    lines = _header(data, "Executive summary")
    lines += [
        "OVERVIEW",
        f"  Open findings: {len(findings)}",
        (
            f"  Critical: {counts.get('critical', 0)}   High: {counts.get('high', 0)}   "
            f"Medium: {counts.get('medium', 0)}   Low: {counts.get('low', 0)}"
        ),
        f"  Highest risk score: {data.get('overall_risk', 0)}",
        f"  Weaknesses observed being attempted in production: {len(observed)}",
        "",
    ]
    if observed:
        lines += [
            "SEEN IN PRODUCTION",
            "  These are not theoretical. Argus has recorded this class of attack",
            "  against this application, so they are scored at maximum likelihood.",
        ]
        lines += [f"    - {f.get('title', '')} ({f.get('rule_id', '')})" for f in observed[:10]]
        lines += [""]
    lines += ["TOP RISKS"]
    if findings:
        for f in findings[:5]:
            lines.append(f"  [{str(f.get('severity', '')).upper()}] {f.get('title', '')}")
            if f.get("recommendation"):
                lines.append(f"      Next step: {f['recommendation']}")
    else:
        lines.append("  No open findings.")
    cov = data.get("coverage") or {}
    if cov:
        total = sum(int(v) for v in cov.values())
        lines += [
            "",
            "CONTROL COVERAGE",
            f"  Implemented: {cov.get('implemented', 0)} of {total}",
            (
                f"  In progress: {cov.get('in_progress', 0)}   "
                f"Not implemented: {cov.get('not_implemented', 0)}"
            ),
        ]
    lines += ["", REDACTION_NOTE]
    return lines


def _technical_lines(data: dict[str, Any]) -> list[str]:
    findings = _sorted_findings(data.get("findings") or [])
    lines = _header(data, "Technical findings")
    if not findings:
        return lines + ["No open findings.", "", REDACTION_NOTE]
    for i, f in enumerate(findings, start=1):
        lines += [
            f"{i}. [{str(f.get('severity', '')).upper()}] {f.get('rule_id', '')} — {f.get('title', '')}",
            (
                f"   Category: {f.get('category', '')}   Confidence: {f.get('confidence', '')}"
                f"   Risk: {f.get('risk_score', '')}"
            ),
        ]
        if f.get("observed_in_production"):
            lines.append("   OBSERVED IN PRODUCTION — this attack class has been attempted here.")
        if f.get("document_name"):
            lines.append(f"   Prompt: {f['document_name']}")
        if f.get("explanation"):
            lines.append(f"   {f['explanation']}")
        if f.get("evidence"):
            lines.append(f"   Evidence: {f['evidence']}")
        if f.get("recommendation"):
            lines.append(f"   Fix: {f['recommendation']}")
        for m in (f.get("mitigations") or [])[:3]:
            lines.append(
                f"     - {m.get('title', '')} ({m.get('priority', '')} priority, "
                f"{m.get('difficulty', '')} effort)"
            )
        fws = f.get("frameworks") or []
        if fws:
            refs = ", ".join(f"{x.get('framework', '')} {x.get('requirement', '')}" for x in fws)
            lines.append(f"   Standards: {refs}")
        lines.append("")
    lines += [REDACTION_NOTE]
    return lines


def _governance_lines(data: dict[str, Any]) -> list[str]:
    controls = data.get("controls") or []
    lines = _header(data, "Governance report")
    cov = data.get("coverage") or {}
    total = sum(int(v) for v in cov.values()) or len(controls)
    lines += [
        "CONTROL STATUS",
        f"  Implemented: {cov.get('implemented', 0)} of {total}",
        f"  In progress: {cov.get('in_progress', 0)}",
        f"  Not implemented: {cov.get('not_implemented', 0)}",
        f"  Not applicable: {cov.get('not_applicable', 0)}",
        "",
        "CONTROLS",
    ]
    if not controls:
        lines.append("  No controls adopted for this application.")
    for c in controls:
        lines.append(f"  [{str(c.get('status', '')).replace('_', ' ')}] {c.get('control_key', '')} "
                     f"— {c.get('objective', '')}")
        if c.get("owner"):
            lines.append(f"      Owner: {c['owner']}")
        if c.get("evidence"):
            lines.append(f"      Evidence: {c['evidence']}")
        fws = c.get("frameworks") or []
        if fws:
            refs = ", ".join(f"{x.get('framework', '')} {x.get('requirement', '')}" for x in fws)
            lines.append(f"      Standards: {refs}")
    findings = _sorted_findings(data.get("findings") or [])
    counts = _counts(findings)
    lines += [
        "",
        "OUTSTANDING RISK",
        (
            f"  Open findings: {len(findings)} "
            f"(critical {counts.get('critical', 0)}, high {counts.get('high', 0)})"
        ),
        "",
        REDACTION_NOTE,
    ]
    return lines


_RENDERERS = {
    "executive": _executive_lines,
    "technical": _technical_lines,
    "governance": _governance_lines,
}


def _csv_bytes(data: dict[str, Any], kind: str) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    if kind == "governance":
        w.writerow(["control_key", "domain", "objective", "status", "owner", "evidence"])
        for c in data.get("controls") or []:
            w.writerow([
                c.get("control_key", ""), c.get("domain", ""), c.get("objective", ""),
                c.get("status", ""), c.get("owner", ""), redact_text(str(c.get("evidence", ""))),
            ])
    else:
        w.writerow([
            "rule_id", "title", "category", "severity", "risk_score",
            "observed_in_production", "document", "evidence", "recommendation",
        ])
        for f in _sorted_findings(data.get("findings") or []):
            w.writerow([
                f.get("rule_id", ""), f.get("title", ""), f.get("category", ""),
                f.get("severity", ""), f.get("risk_score", ""),
                "yes" if f.get("observed_in_production") else "no",
                f.get("document_name", ""), redact_text(str(f.get("evidence", ""))),
                f.get("recommendation", ""),
            ])
    return buf.getvalue().encode("utf-8")


def render(kind: str, fmt: str, data: dict[str, Any]) -> tuple[bytes, str]:
    """Render a report. Returns (body, media_type). Unknown kind/format raise."""
    if kind not in REPORT_KINDS:
        raise ValueError(f"kind must be one of {REPORT_KINDS}")
    if fmt not in REPORT_FORMATS:
        raise ValueError(f"format must be one of {REPORT_FORMATS}")

    lines = [redact_text(x) for x in _RENDERERS[kind](data)]

    if fmt == "pdf":
        return text_to_pdf(lines), "application/pdf"
    if fmt == "md":
        # The line renderers already produce a readable plain-text layout; the
        # markdown flavour just promotes the title and fences the body so it
        # survives being pasted into a ticket without reflowing.
        body = f"# {lines[0]}\n\n{lines[1]}\n\n```\n" + "\n".join(lines[2:]) + "\n```\n"
        return body.encode("utf-8"), "text/markdown; charset=utf-8"
    if fmt == "csv":
        return _csv_bytes(data, kind), "text/csv; charset=utf-8"

    payload = {
        "kind": kind,
        "project": data.get("project_name", ""),
        "generated_at": data.get("generated_at", ""),
        "summary": {
            "findings": len(data.get("findings") or []),
            "by_severity": _counts(data.get("findings") or []),
            "overall_risk": data.get("overall_risk", 0),
            "coverage": data.get("coverage") or {},
        },
        "findings": _sorted_findings(data.get("findings") or []),
        "controls": data.get("controls") or [],
        "redaction_note": REDACTION_NOTE,
    }
    # Redact the serialized form, not just the fields we thought to cover.
    return redact_text(json.dumps(payload, indent=2, default=str)).encode("utf-8"), "application/json"
