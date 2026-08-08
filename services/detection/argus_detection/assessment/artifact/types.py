"""Artifact-scanner data types (docs/18 §4.1).

The manifest is the extraction/judgement seam. Extraction reads bytes and is
inherently I/O, so it happens at the edge — a CLI on the machine that already
holds the file. Judgement is a pure function of the manifest, so it runs here,
in a service that has committed to touching no disk and no network.

That split is also why a multi-gigabyte checkpoint never crosses a network:
the manifest is kilobytes.

Mirrors assessment/scanner/types.py deliberately — same Rule protocol shape,
same match record, so findings from both engines land in the same storage and
the same UI without a translation layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..scanner.types import FrameworkRef

Severity = str  # critical|high|medium|low|informational

# Formats that can execute code on load, and formats that cannot. Membership
# here is the whole basis of ARG-ART-005, so it is data rather than a condition
# buried in a rule.
CODE_CAPABLE_FORMATS = frozenset({"pickle", "torch_zip", "joblib", "keras_h5", "numpy_pickle"})
INERT_FORMATS = frozenset({"safetensors", "gguf"})


@dataclass(frozen=True)
class GlobalRef:
    """One `module.name` a pickle stream resolves.

    Every pickle payload must ultimately name a callable through GLOBAL,
    STACK_GLOBAL, or INST. This record is what the rules judge, and `offset`
    is what points a human at the byte that produced it.
    """

    module: str
    name: str
    opcode: str          # GLOBAL | STACK_GLOBAL | INST | OBJ | EXT
    offset: int          # byte offset in the pickle stream
    member: str = ""     # archive member the stream came from ('' = the file itself)

    @property
    def qualname(self) -> str:
        return f"{self.module}.{self.name}"


@dataclass(frozen=True)
class MemberRef:
    """One entry in a weights archive (`.pt` is a zip)."""

    name: str
    size: int = 0
    compress_type: int = 0
    is_pickle: bool = False
    # Preserved verbatim from the zip header: path traversal is judged on what
    # the archive actually claims, not on a normalized version of it.
    raw_name: str = ""

    def __post_init__(self) -> None:
        if not self.raw_name:
            object.__setattr__(self, "raw_name", self.name)


@dataclass
class ArtifactManifest:
    """Everything the rules are allowed to know about an artifact.

    Deliberately flat and JSON-serializable: the CLI produces it, HTTP carries
    it, the engine consumes it. Nothing here is a handle to a file.
    """

    path: str = ""
    sha256: str = ""
    size_bytes: int = 0
    format: str = "unknown"
    source_uri: str = ""
    revision: str = ""

    globals: list[GlobalRef] = field(default_factory=list)
    opcode_summary: dict[str, int] = field(default_factory=dict)
    archive_members: list[MemberRef] = field(default_factory=list)
    tensor_keys: list[str] = field(default_factory=list)
    declared_arch: str = ""
    onnx_custom_ops: list[str] = field(default_factory=list)
    onnx_external_data: list[str] = field(default_factory=list)
    keras_layer_types: list[str] = field(default_factory=list)

    # Set when extraction hit a malformed stream. A truncated or deliberately
    # corrupt pickle is itself worth reporting: it is what a payload built to
    # break naive parsers looks like, and silently returning "no globals found"
    # would read as "clean".
    parse_errors: list[str] = field(default_factory=list)

    @property
    def is_code_capable(self) -> bool:
        return self.format in CODE_CAPABLE_FORMATS


@dataclass
class ArtifactContext:
    """Project facts a rule may consider. All optional, all deterministic.

    Mirrors scanner.types.RuleContext: unknown facts never suppress a rule and
    never grant credit.
    """

    # Import prefixes belonging to the customer's own code. A checkpoint that
    # references `mycompany.models.Encoder` is ordinary; without this the only
    # honest verdict is "unrecognized", which is why ARG-ART-001 is an
    # inventory signal rather than an alert.
    first_party_prefixes: tuple[str, ...] = ()
    require_signature: bool = False
    extras: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ArtifactMatch:
    """One finding. Field-for-field compatible with scanner.types.RuleMatch so
    both engines share storage, reports and the Findings view."""

    rule_id: str
    title: str
    category: str
    severity: Severity
    confidence: str             # high|medium|low
    explanation: str
    affected_lines: list[int]   # pickle opcode byte offsets
    evidence: str
    recommendation: str
    frameworks: list[FrameworkRef] = field(default_factory=list)


@runtime_checkable
class ArtifactRule(Protocol):
    id: str
    title: str
    category: str
    default_severity: Severity
    frameworks: list[FrameworkRef]

    def check(self, man: ArtifactManifest, ctx: ArtifactContext) -> list[ArtifactMatch]: ...
