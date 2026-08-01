"""The 20 built-in deterministic prompt rules (IG-PROMPT-001..020, from InjectGuard).

Not regex-only: rules combine regex, structural, and context heuristics behind the Rule
interface. Golden tests pin each rule's output; the rule ids are stable identifiers that
downstream storage and the taxonomy mapping key on — never renumber them.
"""

from __future__ import annotations

import re
from typing import ClassVar

from ..redaction import redact_text
from .types import FrameworkRef, PromptDocument, Rule, RuleContext, RuleMatch

# --- shared patterns ---
PLACEHOLDER = re.compile(r"(\{\{?\s*\w+\s*\}?\}|\$\{?\w+\}?|<[a-zA-Z_]\w*>|%\(?\w*\)?[sd])")
INSTRUCTION_VERB = re.compile(
    r"\b(you must|you should|always|never|follow|obey|execute|do not|ignore|comply)\b", re.IGNORECASE
)
DELIMITER = re.compile(r"(```|\"\"\"|<data>|</data>|<untrusted>|-----|====|###\s)")
SECRET_HINT = re.compile(
    r"(sk-[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    r"|-----BEGIN|\b(password|api[_-]?key|secret|token)\b\s*[:=]\s*\S+)",
    re.IGNORECASE,
)


def _lines_matching(doc: PromptDocument, pattern: re.Pattern[str]) -> list[int]:
    return [i + 1 for i, line in enumerate(doc.lines) if pattern.search(line)]


def _evidence(doc: PromptDocument, line_nos: list[int]) -> str:
    if not line_nos:
        return ""
    idx = line_nos[0] - 1
    text = doc.lines[idx] if 0 <= idx < len(doc.lines) else ""
    return redact_text(text.strip())[:200]


def _fr(framework: str, requirement: str) -> FrameworkRef:
    return FrameworkRef(framework=framework, requirement=requirement)


class PatternRule:
    """Fires when any `triggers` pattern matches and no `mitigators` pattern matches."""

    def __init__(
        self,
        *,
        id: str,
        title: str,
        category: str,
        severity: str,
        confidence: str,
        explanation: str,
        recommendation: str,
        triggers: list[str],
        mitigators: list[str] | None = None,
        kinds: set[str] | None = None,
        frameworks: list[FrameworkRef] | None = None,
    ) -> None:
        self.id = id
        self.title = title
        self.category = category
        self.default_severity = severity
        self.confidence = confidence
        self.explanation = explanation
        self.recommendation = recommendation
        self.triggers = [re.compile(t, re.IGNORECASE) for t in triggers]
        self.mitigators = [re.compile(m, re.IGNORECASE) for m in (mitigators or [])]
        self.kinds = kinds
        self.frameworks = frameworks or []

    def check(self, doc: PromptDocument, ctx: RuleContext) -> list[RuleMatch]:
        if self.kinds and doc.kind not in self.kinds:
            return []
        content = doc.content
        if any(m.search(content) for m in self.mitigators):
            return []
        line_nos: list[int] = []
        for pat in self.triggers:
            line_nos.extend(_lines_matching(doc, pat))
        line_nos = sorted(set(line_nos))
        if not line_nos:
            return []
        return [
            RuleMatch(
                rule_id=self.id,
                title=self.title,
                category=self.category,
                severity=self.default_severity,
                confidence=self.confidence,
                explanation=self.explanation,
                affected_lines=line_nos,
                evidence=_evidence(doc, line_nos),
                recommendation=self.recommendation,
                frameworks=self.frameworks,
            )
        ]


# --- custom rules that need structural / context logic ---
class UntrustedMixedRule:
    id = "IG-PROMPT-001"
    title = "Untrusted data mixed with instructions"
    category = "prompt-separation"
    default_severity = "high"
    frameworks: ClassVar[list[FrameworkRef]] = [_fr("OWASP-LLM", "LLM01")]

    def check(self, doc: PromptDocument, ctx: RuleContext) -> list[RuleMatch]:
        lines = [
            i + 1
            for i, line in enumerate(doc.lines)
            if PLACEHOLDER.search(line) and INSTRUCTION_VERB.search(line)
        ]
        if not lines:
            return []
        return [
            RuleMatch(
                rule_id=self.id, title=self.title, category=self.category,
                severity=self.default_severity, confidence="medium",
                explanation="A user/retrieved variable is interpolated on the same line as "
                            "instruction text, with no role/delimiter separation.",
                affected_lines=lines, evidence=_evidence(doc, lines),
                recommendation="Separate untrusted variables from instructions using explicit "
                               "delimiters or a distinct message role.",
                frameworks=self.frameworks,
            )
        ]


class MissingDelimiterRule:
    id = "IG-PROMPT-002"
    title = "Missing delimiters around external content"
    category = "context-isolation"
    default_severity = "medium"
    frameworks: ClassVar[list[FrameworkRef]] = [_fr("OWASP-LLM", "LLM01")]

    def check(self, doc: PromptDocument, ctx: RuleContext) -> list[RuleMatch]:
        ph = _lines_matching(doc, PLACEHOLDER)
        if not ph or DELIMITER.search(doc.content):
            return []
        return [
            RuleMatch(
                rule_id=self.id, title=self.title, category=self.category,
                severity=self.default_severity, confidence="medium",
                explanation="Injected variables are not wrapped in delimiters (e.g. "
                            "<data>…</data> or fenced blocks).",
                affected_lines=ph, evidence=_evidence(doc, ph),
                recommendation="Wrap interpolated content in clear delimiters and instruct the "
                               "model to treat delimited content as data.",
                frameworks=self.frameworks,
            )
        ]


class SecretInPromptRule:
    id = "IG-PROMPT-003"
    title = "Secret or sensitive value in prompt"
    category = "sensitive-data"
    default_severity = "high"
    frameworks: ClassVar[list[FrameworkRef]] = [_fr("OWASP-LLM", "LLM06")]

    def check(self, doc: PromptDocument, ctx: RuleContext) -> list[RuleMatch]:
        lines = _lines_matching(doc, SECRET_HINT)
        if not lines:
            return []
        return [
            RuleMatch(
                rule_id=self.id, title=self.title, category=self.category,
                severity=self.default_severity, confidence="high",
                explanation="The prompt appears to contain a credential or secret value.",
                affected_lines=lines, evidence=_evidence(doc, lines),
                recommendation="Remove secrets from prompts; inject them server-side at call time "
                               "and never expose them to the model.",
                frameworks=self.frameworks,
            )
        ]


class VariableUnescapedRule:
    id = "IG-PROMPT-013"
    title = "Prompt variable inserted without escaping"
    category = "injection"
    default_severity = "medium"
    frameworks: ClassVar[list[FrameworkRef]] = [_fr("OWASP-LLM", "LLM01")]
    _adjacent = re.compile(r"[`\"'<>{](\{\{?\s*\w+\s*\}?\}|\$\{?\w+\}?)|(\{\{?\s*\w+\s*\}?\}|\$\{?\w+\}?)[`\"'<>}]")

    def check(self, doc: PromptDocument, ctx: RuleContext) -> list[RuleMatch]:
        lines = [i + 1 for i, line in enumerate(doc.lines) if self._adjacent.search(line)]
        if not lines:
            return []
        return [
            RuleMatch(
                rule_id=self.id, title=self.title, category=self.category,
                severity=self.default_severity, confidence="low",
                explanation="A variable is placed directly adjacent to a structural/delimiter "
                            "token without escaping, enabling delimiter breakout.",
                affected_lines=lines, evidence=_evidence(doc, lines),
                recommendation="Escape or encode interpolated values and keep them clear of "
                               "structural tokens.",
                frameworks=self.frameworks,
            )
        ]


class WriteWithoutApprovalRule:
    id = "IG-PROMPT-012"
    title = "Missing human confirmation for high-impact action"
    category = "human-approval"
    default_severity = "high"
    frameworks: ClassVar[list[FrameworkRef]] = [_fr("OWASP-LLM", "LLM08")]
    _write = re.compile(r"\b(delete|remove|send|transfer|purchase|pay|modify|update|drop|wire)\b", re.IGNORECASE)
    _approval = re.compile(r"\b(confirm|approval|human review|authorize|verify with)\b", re.IGNORECASE)

    def check(self, doc: PromptDocument, ctx: RuleContext) -> list[RuleMatch]:
        content = doc.content
        content_write = self._write.search(content) and not self._approval.search(content)
        ctx_write = ctx.has_write_capable_tools and not ctx.human_approval_enabled
        if not (content_write or ctx_write):
            return []
        lines = _lines_matching(doc, self._write) or [1]
        return [
            RuleMatch(
                rule_id=self.id, title=self.title, category=self.category,
                severity=self.default_severity, confidence="medium",
                explanation="A high-impact/irreversible action is described without a human "
                            "confirmation step.",
                affected_lines=lines, evidence=_evidence(doc, lines),
                recommendation="Require explicit human approval before any write or irreversible "
                               "action; enforce it server-side, not via the prompt alone.",
                frameworks=self.frameworks,
            )
        ]


class UserControlledToolRule:
    id = "IG-PROMPT-015"
    title = "User-controlled tool name or description"
    category = "tool-security"
    default_severity = "high"
    frameworks: ClassVar[list[FrameworkRef]] = [_fr("OWASP-LLM", "LLM08")]

    def check(self, doc: PromptDocument, ctx: RuleContext) -> list[RuleMatch]:
        placeholder_in_tool = doc.kind == "tool_description" and bool(PLACEHOLDER.search(doc.content))
        if not (placeholder_in_tool or ctx.tool_names_user_controlled):
            return []
        lines = _lines_matching(doc, PLACEHOLDER) or [1]
        return [
            RuleMatch(
                rule_id=self.id, title=self.title, category=self.category,
                severity=self.default_severity, confidence="medium",
                explanation="A tool name or description is sourced from user/template input, "
                            "allowing tool-definition injection.",
                affected_lines=lines, evidence=_evidence(doc, lines),
                recommendation="Define tool names and descriptions statically server-side; never "
                               "from user-controlled data.",
                frameworks=self.frameworks,
            )
        ]


# --- declarative pattern rules ---
_PATTERN_RULES = [
    PatternRule(
        id="IG-PROMPT-004", title="Contradictory instructions", category="prompt-quality",
        severity="low", confidence="low",
        explanation="The prompt both forbids and requires disclosing information.",
        recommendation="Resolve conflicting directives; keep a single, unambiguous disclosure policy.",
        triggers=[r"(never|do not|don't)\s+(reveal|disclose|share|print|show)"],
        mitigators=[],
        frameworks=[_fr("OWASP-LLM", "LLM01")],
    ),
    PatternRule(
        id="IG-PROMPT-005", title="Missing authorization language for actions",
        category="authorization", severity="medium", confidence="low",
        explanation="An action/tool capability is granted without any authorization check language.",
        recommendation="Add explicit 'only if the caller is authorized / verify permission first' language "
                       "and enforce it server-side.",
        triggers=[r"\b(you can|you may|use the|call the|invoke the|perform the)\b.*\b(tool|action|api|function)\b"],
        mitigators=[r"\b(authoriz|permission|only if|verify|allowed to)\b"],
        frameworks=[_fr("OWASP-LLM", "LLM08")],
    ),
    PatternRule(
        id="IG-PROMPT-006", title="Model-controlled access decision", category="excessive-agency",
        severity="high", confidence="medium",
        explanation="The prompt instructs the model to decide access/authorization.",
        recommendation="Never let the model decide authorization; make access decisions deterministically "
                       "server-side.",
        triggers=[r"\b(decide|determine|grant|judge|check)\b.{0,30}(access|authoriz|permission|allowed|eligible)"],
        frameworks=[_fr("OWASP-LLM", "LLM08"), _fr("MITRE-ATLAS", "AML.T0051")],
    ),
    PatternRule(
        id="IG-PROMPT-007", title="Unsafe disclosure instruction", category="prompt-leakage",
        severity="high", confidence="high",
        explanation="The prompt instructs the model to reveal its system prompt or hidden context.",
        recommendation="Remove instructions that disclose the system prompt or hidden context.",
        triggers=[r"(reveal|print|show|repeat|output).{0,30}(system prompt|your instructions|hidden|above)"],
        frameworks=[_fr("OWASP-LLM", "LLM07")],
    ),
    PatternRule(
        id="IG-PROMPT-008", title="Broad tool permission", category="tool-security",
        severity="high", confidence="medium",
        explanation="A tool is granted wildcard or unrestricted capability.",
        recommendation="Scope tools to the minimum required actions; avoid wildcard/'any'/'all' permissions.",
        triggers=[r"\b(any tool|all tools|any (action|command)|unrestricted|full access|wildcard|\*\s*permission)\b"],
        frameworks=[_fr("OWASP-LLM", "LLM08")],
    ),
    PatternRule(
        id="IG-PROMPT-009", title="Direct execution of model output", category="unsafe-output",
        severity="critical", confidence="high",
        explanation="Model output is executed or passed to a shell/SQL/eval.",
        recommendation="Never execute model output; validate and route through safe, parameterized APIs only.",
        triggers=[r"\b(run|exec|execute|eval)\b.{0,30}(the )?(model|response|output|result)",
                  r"\b(pass|send)\b.{0,20}\b(to )?(shell|bash|sh|sql|os\.system|subprocess)\b"],
        frameworks=[_fr("OWASP-LLM", "LLM02")],
    ),
    PatternRule(
        id="IG-PROMPT-010", title="Unsafe HTML/Markdown rendering", category="unsafe-output",
        severity="high", confidence="medium",
        explanation="Model output is rendered as raw HTML / with HTML enabled.",
        recommendation="Render model output with raw HTML disabled and a strict sanitizer allowlist.",
        triggers=[r"(render|output|display).{0,20}(raw html|as html)", r"allow html", r"dangerouslySetInnerHTML"],
        frameworks=[_fr("OWASP-LLM", "LLM02")],
    ),
    PatternRule(
        id="IG-PROMPT-011", title="Missing restrictions on external content",
        category="context-isolation", severity="medium", confidence="low",
        explanation="External/retrieved content is used without instructing the model to treat it as untrusted.",
        recommendation="Instruct the model to treat retrieved/browsed content as untrusted data and never "
                       "follow instructions within it.",
        triggers=[r"\b(browse|fetch|retriev|search results|web page|the document|the url)\b"],
        mitigators=[r"\b(untrusted|do not follow|treat as (data|reference)|ignore instructions)\b"],
        frameworks=[_fr("OWASP-LLM", "LLM01")],
    ),
    PatternRule(
        id="IG-PROMPT-014", title="Retrieved text treated as trusted instructions",
        category="rag-security", severity="high", confidence="medium",
        explanation="The prompt tells the model to follow/obey retrieved or document content.",
        recommendation="Treat retrieved content strictly as data; never follow instructions contained in it.",
        triggers=[
            (
                r"\b(follow|obey|execute|comply with|do what)\b.{0,30}"
                r"\b(retrieved|document|context|search results|the file)\b"
            )
        ],
        frameworks=[_fr("OWASP-LLM", "LLM01")],
    ),
    PatternRule(
        id="IG-PROMPT-016", title="Persistent memory without validation",
        category="memory-protection", severity="medium", confidence="low",
        explanation="Content is written to persistent memory without validation/sanitization.",
        recommendation="Validate and sanitize any content before storing it in agent memory.",
        triggers=[r"\b(remember|store|save|persist|write to memory)\b"],
        mitigators=[r"\b(validate|sanitize|verify|check)\b"],
        kinds={"memory_instruction", "system", "developer"},
        frameworks=[_fr("OWASP-LLM", "LLM01")],
    ),
    PatternRule(
        id="IG-PROMPT-017", title="Encoding/obfuscation passthrough", category="obfuscation",
        severity="medium", confidence="medium",
        explanation="The prompt instructs the model to decode/interpret encoded input.",
        recommendation="Do not decode and act on encoded input; treat decoded content as untrusted data.",
        triggers=[r"\b(base64|rot13|hex(adecimal)?|decode|interpret encoded|unescape)\b"],
        frameworks=[_fr("OWASP-LLM", "LLM01")],
    ),
    PatternRule(
        id="IG-PROMPT-018", title="Overly broad system authority granted to user input",
        category="prompt-separation", severity="high", confidence="medium",
        explanation="User input can reassign the model's role or override prior instructions.",
        recommendation="Prevent user input from setting system-level directives or reassigning roles.",
        triggers=[
            (
                r"\b(you are now|act as|ignore (all )?previous|new instructions|"
                r"forget (the|your) instructions|system:)\b"
            )
        ],
        frameworks=[_fr("OWASP-LLM", "LLM01")],
    ),
    PatternRule(
        id="IG-PROMPT-019", title="Missing output guard for sensitive data",
        category="sensitive-data", severity="low", confidence="low",
        explanation="Sensitive context is present without an instruction to keep it out of output.",
        recommendation="Add explicit 'never include secrets/PII in output' guards.",
        triggers=[r"\b(secret|password|ssn|social security|pii|confidential|private key)\b"],
        mitigators=[r"\b(do not (include|output|reveal)|never (include|output)|redact)\b"],
        frameworks=[_fr("OWASP-LLM", "LLM06")],
    ),
    PatternRule(
        id="IG-PROMPT-020", title="Cross-context data exposure risk", category="cross-context",
        severity="high", confidence="low",
        explanation="The prompt combines multiple users'/tenants' data without separation.",
        recommendation="Never concatenate multiple users'/tenants' data in one context; enforce per-tenant "
                       "isolation.",
        triggers=[r"\b(other users|all customers|every (user|customer)|across tenants|all tenants|combine .* users)\b"],
        frameworks=[_fr("OWASP-LLM", "LLM06")],
    ),
]

ALL_RULES: list[Rule] = [
    UntrustedMixedRule(),
    MissingDelimiterRule(),
    SecretInPromptRule(),
    VariableUnescapedRule(),
    WriteWithoutApprovalRule(),
    UserControlledToolRule(),
    *_PATTERN_RULES,
]
