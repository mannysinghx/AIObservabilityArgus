"""Deterministic L0 artifact rules (docs/18 §4.2).

Phase 0 implements the pickle and archive rules — everything judgeable from a
manifest alone. ARG-ART-008..014 (Keras, ONNX, ledger, signing, CVE) arrive
with the phases that give them something to check against.

Rule ids are stable identifiers that storage and the taxonomy key on. Never
renumber them; append instead. Same contract as IG-PROMPT-001..020.

Band → rule mapping, so adding a callable to the allowlist never means editing
rule logic:

    EXEC      → ARG-ART-002  critical
    GADGET    → ARG-ART-002  high      (indirect call primitive)
    NET       → ARG-ART-003  critical
    FS        → ARG-ART-004  high
    OBFUSCATE → ARG-ART-015  medium
"""

from __future__ import annotations

from typing import ClassVar

from ..redaction import redact_text
from ..scanner.types import FrameworkRef
from .allowlist import ALLOWLIST_VERSION, classify
from .types import ArtifactContext, ArtifactManifest, ArtifactMatch

LLM05 = FrameworkRef(framework="OWASP-LLM", requirement="LLM05")
LLM03 = FrameworkRef(framework="OWASP-LLM", requirement="LLM03")

CATEGORY = "supply-chain"

# How many offending references to name in one finding before summarizing. A
# payload can repeat a call thousands of times; the evidence field is for a
# human, not a log.
_MAX_EVIDENCE = 5


def _evidence(refs) -> str:
    shown = ", ".join(f"{r.qualname} @{r.offset}" + (f" in {r.member}" if r.member else "")
                      for r in refs[:_MAX_EVIDENCE])
    extra = len(refs) - _MAX_EVIDENCE
    if extra > 0:
        shown += f", +{extra} more"
    return redact_text(shown)[:400]


def _offsets(refs) -> list[int]:
    return sorted({r.offset for r in refs})


class _BandRule:
    """Fires on every global whose DENY band matches.

    One class, five instances — the bands differ in severity and wording, not
    in logic, and duplicating the loop five times is how the five copies drift.
    """

    category = CATEGORY
    frameworks: ClassVar[list[FrameworkRef]] = [LLM05]

    def __init__(self, *, id: str, band: str, title: str, severity: str,
                 explanation: str, recommendation: str) -> None:
        self.id = id
        self.band = band
        self.title = title
        self.default_severity = severity
        self.explanation = explanation
        self.recommendation = recommendation

    def check(self, man: ArtifactManifest, ctx: ArtifactContext) -> list[ArtifactMatch]:
        hits = [
            ref for ref in man.globals
            if classify(ref.module, ref.name, ctx.first_party_prefixes) == ("denied", self.band)
        ]
        if not hits:
            return []
        return [ArtifactMatch(
            rule_id=self.id,
            title=self.title,
            category=self.category,
            severity=self.default_severity,
            confidence="high",
            explanation=self.explanation,
            affected_lines=_offsets(hits),
            evidence=_evidence(hits),
            recommendation=self.recommendation,
            frameworks=list(self.frameworks),
        )]


EXEC_RULE = _BandRule(
    id="ARG-ART-002", band="exec", severity="critical",
    title="Code-execution primitive in a model artifact",
    explanation=(
        "The pickle stream resolves a callable that executes code or spawns a "
        "process. Deserializing this artifact runs that callable — before any "
        "inference happens and before any other Argus detector has anything to "
        "read. There is no legitimate reason for a saved model to reference it."
    ),
    recommendation=(
        "Do not load this artifact. Quarantine it, and re-derive the model from "
        "a trusted source. If the source is trusted, re-serialize to safetensors, "
        "which cannot carry executable content."
    ),
)

GADGET_RULE = _BandRule(
    id="ARG-ART-002", band="gadget", severity="high",
    title="Indirect-call primitive in a model artifact",
    explanation=(
        "The pickle stream resolves a callable that invokes arbitrary methods or "
        "attributes by name (methodcaller, attrgetter, getattr). Harmless alone, "
        "these are the standard way a payload reaches a dangerous method without "
        "naming it directly, which is what defeats a scanner that only checks for "
        "os.system."
    ),
    recommendation=(
        "Inspect the surrounding opcodes to see what is being called. Treat as "
        "hostile unless the reference is explained by a known serializer."
    ),
)

NET_RULE = _BandRule(
    id="ARG-ART-003", band="net", severity="critical",
    title="Network primitive in a model artifact",
    explanation=(
        "The pickle stream resolves a callable that opens a network connection. "
        "A model file has no reason to contact anything on load; this is the "
        "shape of beaconing or second-stage download."
    ),
    recommendation=(
        "Do not load this artifact. Quarantine it and preserve it for analysis — "
        "the destination is evidence."
    ),
)

FS_RULE = _BandRule(
    id="ARG-ART-004", band="fs", severity="high",
    title="Filesystem-mutation primitive in a model artifact",
    explanation=(
        "The pickle stream resolves a callable that writes, deletes, or changes "
        "permissions on files. Loading a model should not modify the filesystem; "
        "this is the shape of persistence or of tampering with the host."
    ),
    recommendation="Do not load this artifact. Quarantine and re-derive from a trusted source.",
)

OBFUSCATION_RULE = _BandRule(
    id="ARG-ART-015", band="obf", severity="medium",
    title="Decode/decompress helper in a model artifact",
    explanation=(
        "The pickle stream resolves a base64/zlib-class helper. These appear in "
        "legitimate artifacts, so this is not on its own an alert — but they are "
        "also how a payload smuggles a second stage past a scanner that only "
        "reads literal module names. Read it together with any other finding on "
        "this artifact."
    ),
    recommendation=(
        "Corroborate. Alone this is informational; alongside an ARG-ART-002/003 "
        "hit it indicates a staged payload."
    ),
)


class UnrecognizedGlobalRule:
    """Every global that is neither known-dangerous nor known-ordinary.

    Deliberately medium and deliberately not an alert. Custom `nn.Module`
    subclasses are pickled by name constantly, so a project's own classes land
    here as a matter of course — treating that as critical would bury the
    feature in false alarms on day one, which is the failure mode this whole
    layer is designed around. It is an inventory signal: "these are the
    third-party callables your artifacts reach for."
    """

    id = "ARG-ART-001"
    title = "Unrecognized global reference in a model artifact"
    category = CATEGORY
    default_severity = "medium"
    frameworks: ClassVar[list[FrameworkRef]] = [LLM05]

    def check(self, man: ArtifactManifest, ctx: ArtifactContext) -> list[ArtifactMatch]:
        hits = [
            ref for ref in man.globals
            if classify(ref.module, ref.name, ctx.first_party_prefixes)[0] == "unrecognized"
        ]
        if not hits:
            return []
        modules = sorted({r.module for r in hits})
        return [ArtifactMatch(
            rule_id=self.id,
            title=self.title,
            category=self.category,
            severity=self.default_severity,
            confidence="medium",
            explanation=(
                f"{len(hits)} reference(s) across {len(modules)} module(s) are not on "
                f"the known-good list (allowlist {ALLOWLIST_VERSION}) and are not "
                f"recognized as first-party code. This is an inventory signal, not an "
                f"alert: unknown does not mean hostile. Review the modules and, if they "
                f"are yours, register their prefix so future scans stay quiet."
            ),
            affected_lines=_offsets(hits),
            evidence=_evidence(hits),
            recommendation=(
                "Confirm each module belongs to a dependency you intend to ship, then "
                "add its prefix to the project's first-party list or the allowlist."
            ),
            frameworks=list(self.frameworks),
        )]


class CodeCapableFormatRule:
    """The format itself is the weakness.

    Low, not medium: this fires on every pickle-backed model in the fleet, and
    a medium on everything is a filter people turn off. It earns its place as
    the inventory that answers "how much of our estate could execute on load",
    which is the question SUP-2 is written against.
    """

    id = "ARG-ART-005"
    title = "Code-capable serialization format"
    category = CATEGORY
    default_severity = "low"
    frameworks: ClassVar[list[FrameworkRef]] = [LLM05]

    def check(self, man: ArtifactManifest, ctx: ArtifactContext) -> list[ArtifactMatch]:
        if not man.is_code_capable:
            return []
        return [ArtifactMatch(
            rule_id=self.id,
            title=self.title,
            category=self.category,
            severity=self.default_severity,
            confidence="high",
            explanation=(
                f"This artifact is stored as {man.format}, a format that executes "
                f"arbitrary code on load by design. Nothing here says this file is "
                f"malicious — it says that trusting it is a decision about its source, "
                f"because the format offers no protection of its own."
            ),
            affected_lines=[],
            evidence=f"format={man.format}",
            recommendation=(
                "Convert to safetensors for weights-only artifacts. Where the format "
                "cannot change, pin the artifact by digest and require a signature."
            ),
            frameworks=list(self.frameworks),
        )]


class ArchiveTraversalRule:
    """Member names that escape the extraction directory."""

    id = "ARG-ART-006"
    title = "Path traversal in a weights archive"
    category = CATEGORY
    default_severity = "critical"
    frameworks: ClassVar[list[FrameworkRef]] = [LLM05]

    def check(self, man: ArtifactManifest, ctx: ArtifactContext) -> list[ArtifactMatch]:
        bad = [
            m for m in man.archive_members
            if m.raw_name.startswith("/")
            or m.raw_name.startswith("\\")
            or ".." in m.raw_name.replace("\\", "/").split("/")
            or (len(m.raw_name) > 1 and m.raw_name[1] == ":")  # C:\ style
        ]
        if not bad:
            return []
        names = ", ".join(m.raw_name for m in bad[:_MAX_EVIDENCE])
        return [ArtifactMatch(
            rule_id=self.id,
            title=self.title,
            category=self.category,
            severity=self.default_severity,
            confidence="high",
            explanation=(
                "An archive member names an absolute path or escapes its directory "
                "with '..'. Extracting this archive writes outside the intended "
                "location — the classic zip-slip, applied to a model file."
            ),
            affected_lines=[],
            evidence=redact_text(names)[:400],
            recommendation="Do not extract or load. Quarantine the artifact.",
            frameworks=list(self.frameworks),
        )]


class NonTensorMemberRule:
    """Executable or source members riding along inside a weights archive."""

    id = "ARG-ART-007"
    title = "Non-tensor member in a weights archive"
    category = CATEGORY
    default_severity = "high"
    frameworks: ClassVar[list[FrameworkRef]] = [LLM05, LLM03]

    SUSPICIOUS_EXT: ClassVar[tuple[str, ...]] = (
        ".py", ".pyc", ".pyo", ".pyd", ".so", ".dylib", ".dll", ".sh", ".bash",
        ".zsh", ".bat", ".cmd", ".ps1", ".exe", ".elf", ".jar", ".php",
    )

    def check(self, man: ArtifactManifest, ctx: ArtifactContext) -> list[ArtifactMatch]:
        bad = [m for m in man.archive_members
               if m.raw_name.lower().endswith(self.SUSPICIOUS_EXT)]
        if not bad:
            return []
        names = ", ".join(m.raw_name for m in bad[:_MAX_EVIDENCE])
        return [ArtifactMatch(
            rule_id=self.id,
            title=self.title,
            category=self.category,
            severity=self.default_severity,
            confidence="high",
            explanation=(
                "A weights archive contains source, script, or native-library "
                "members. Weights archives hold tensors and metadata; executable "
                "content inside one is either a packaging mistake or a payload, and "
                "both are worth stopping on."
            ),
            affected_lines=[],
            evidence=redact_text(names)[:400],
            recommendation=(
                "Inspect the members before loading. Rebuild the artifact from "
                "weights alone if they are not explained."
            ),
            frameworks=list(self.frameworks),
        )]


class MalformedStreamRule:
    """A stream the walker could not fully decode.

    Worth its own finding rather than a log line: a pickle crafted to break
    naive parsers is a known evasion, and 'the scanner gave up' must never be
    presented to a human as 'the scanner found nothing'.
    """

    id = "ARG-ART-016"
    title = "Malformed or undecodable serialized stream"
    category = CATEGORY
    default_severity = "high"
    frameworks: ClassVar[list[FrameworkRef]] = [LLM05]

    def check(self, man: ArtifactManifest, ctx: ArtifactContext) -> list[ArtifactMatch]:
        if not man.parse_errors:
            return []
        return [ArtifactMatch(
            rule_id=self.id,
            title=self.title,
            category=self.category,
            severity=self.default_severity,
            confidence="medium",
            explanation=(
                "The opcode walk did not complete. The artifact may be truncated or "
                "corrupt, or it may be shaped to defeat static inspection. Either "
                "way the scan is incomplete, so a clean result on the rest of this "
                "artifact does not mean it is clean."
            ),
            affected_lines=[],
            evidence=redact_text("; ".join(man.parse_errors[:_MAX_EVIDENCE]))[:400],
            recommendation=(
                "Re-fetch the artifact from its source and rescan. If it still fails "
                "to decode, treat it as untrusted and do not load it."
            ),
            frameworks=list(self.frameworks),
        )]


ALL_RULES: list = [
    EXEC_RULE,
    GADGET_RULE,
    NET_RULE,
    FS_RULE,
    OBFUSCATION_RULE,
    UnrecognizedGlobalRule(),
    CodeCapableFormatRule(),
    ArchiveTraversalRule(),
    NonTensorMemberRule(),
    MalformedStreamRule(),
]
