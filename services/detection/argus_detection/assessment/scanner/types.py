"""Scanner rule interface + data types. Deterministic-first; a rule MAY request a
semantic classifier but every built-in rule is fully deterministic."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

Severity = str  # critical|high|medium|low|informational


@dataclass(frozen=True)
class FrameworkRef:
    framework: str
    requirement: str


@dataclass
class PromptDocument:
    """A prompt under analysis. `kind` is e.g. system|developer|tool_description|
    memory_instruction|output_instruction — rules may scope themselves to kinds."""

    kind: str
    content: str

    @property
    def lines(self) -> list[str]:
        return self.content.splitlines()


@dataclass
class RuleContext:
    """Application/architecture facts available to rules (all optional, deterministic)."""

    has_write_capable_tools: bool = False
    human_approval_enabled: bool = False
    has_retrieval: bool = False
    is_public: bool = False
    tool_names_user_controlled: bool = False
    extras: dict = field(default_factory=dict)


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    title: str
    category: str
    severity: Severity
    confidence: str  # high|medium|low
    explanation: str
    affected_lines: list[int]
    evidence: str
    recommendation: str
    frameworks: list[FrameworkRef] = field(default_factory=list)


@runtime_checkable
class Rule(Protocol):
    id: str
    title: str
    category: str
    default_severity: Severity
    frameworks: list[FrameworkRef]

    def check(self, doc: PromptDocument, ctx: RuleContext) -> list[RuleMatch]: ...
