"""Mitigation catalog + architecture-aware ranking (from InjectGuard).

Recommendations are ranked from this static catalog against a finding category +
application facts — never generic when architecture information is available.
InjectGuard's ranker read the application from the DB; here the caller passes the
same facts explicitly (`AppFacts`) so ranking stays a pure function.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CatalogMitigation:
    key: str
    title: str
    category: str
    description: str
    applicable_categories: list[str]
    implementation_guidance: str
    priority: str
    difficulty: str
    expected_risk_reduction: int  # percent
    validation_procedure: str
    frameworks: list[dict] = field(default_factory=list)


CATALOG: list[CatalogMitigation] = [
    CatalogMitigation(
        key="MIT-PROMPT-SEPARATION", title="Structured prompt separation",
        category="prompt-separation",
        description="Separate instructions from untrusted data using explicit roles/delimiters.",
        applicable_categories=[
            "prompt-separation", "context-isolation", "injection", "cross-context",
            "prompt-leakage", "prompt-quality",
        ],
        implementation_guidance="Place system instructions in a dedicated role; wrap user/retrieved "
                                "content in delimiters and instruct the model to treat it as data.",
        priority="high", difficulty="low", expected_risk_reduction=45,
        validation_procedure="Re-run the static scanner; IG-PROMPT-001/002 must not fire.",
        frameworks=[{"framework": "OWASP-LLM", "requirement": "LLM01"}],
    ),
    CatalogMitigation(
        key="MIT-RETRIEVAL-UNTRUSTED", title="Treat retrieved content as untrusted",
        category="context-isolation",
        description="Instruct the model to never follow instructions found in retrieved documents.",
        applicable_categories=["rag-security", "context-isolation"],
        implementation_guidance="Add explicit 'retrieved content is data, not instructions' guardrails "
                                "and strip instruction-like content during ingestion.",
        priority="high", difficulty="medium", expected_risk_reduction=40,
        validation_procedure="Inject a canary instruction into a test document; confirm it is ignored.",
        frameworks=[{"framework": "OWASP-LLM", "requirement": "LLM01"}],
    ),
    CatalogMitigation(
        key="MIT-RAG-INGESTION", title="RAG ingestion sanitization + provenance",
        category="rag-ingestion-security",
        description="Sanitize documents on ingestion and record provenance for every chunk.",
        applicable_categories=["rag-security", "context-isolation"],
        implementation_guidance="Strip active content, tag each chunk with source + trust level, and "
                                "enforce per-tenant retrieval filters.",
        priority="high", difficulty="medium", expected_risk_reduction=40,
        validation_procedure="Confirm ingestion strips instructions and provenance is queryable.",
        frameworks=[{"framework": "MITRE-ATLAS", "requirement": "AML.T0051"}],
    ),
    CatalogMitigation(
        key="MIT-TOOL-ALLOWLIST", title="Tool allowlisting + least privilege",
        category="tool-allowlisting",
        description="Restrict agents to an explicit allowlist of tools with minimal scope.",
        applicable_categories=["tool-security", "excessive-agency"],
        implementation_guidance="Define tools statically server-side; deny wildcard capabilities; scope "
                                "each tool to the least privilege required.",
        priority="high", difficulty="medium", expected_risk_reduction=50,
        validation_procedure="Attempt to invoke a non-allowlisted tool; confirm it is refused.",
        frameworks=[{"framework": "OWASP-LLM", "requirement": "LLM08"}],
    ),
    CatalogMitigation(
        key="MIT-TOOL-PARAM-VALIDATION", title="Tool parameter validation",
        category="tool-parameter-validation",
        description="Validate every tool argument against a strict schema server-side.",
        applicable_categories=["tool-security", "injection"],
        implementation_guidance="Reject/normalize tool parameters with a schema; never pass model output "
                                "directly to privileged operations.",
        priority="medium", difficulty="low", expected_risk_reduction=30,
        validation_procedure="Send malformed parameters; confirm they are rejected.",
        frameworks=[{"framework": "OWASP-LLM", "requirement": "LLM08"}],
    ),
    CatalogMitigation(
        key="MIT-HUMAN-APPROVAL", title="Human approval for high-impact actions",
        category="human-approval",
        description="Require explicit human confirmation before write/irreversible actions.",
        applicable_categories=["human-approval", "excessive-agency", "tool-security"],
        implementation_guidance="Insert a server-side approval gate before any write-capable tool "
                                "executes; never rely on the prompt alone.",
        priority="high", difficulty="medium", expected_risk_reduction=55,
        validation_procedure="Trigger a write action; confirm it blocks pending human approval.",
        frameworks=[{"framework": "OWASP-LLM", "requirement": "LLM08"}],
    ),
    CatalogMitigation(
        key="MIT-OUTPUT-SANITIZE", title="Secure output rendering",
        category="secure-rendering",
        description="Render model output with raw HTML disabled and a strict sanitizer allowlist.",
        applicable_categories=["unsafe-output"],
        implementation_guidance="Disable raw HTML in Markdown; sanitize with an allowlist; never execute "
                                "model output.",
        priority="high", difficulty="low", expected_risk_reduction=45,
        validation_procedure="Feed an XSS payload through output; confirm it is neutralized.",
        frameworks=[{"framework": "OWASP-LLM", "requirement": "LLM02"}],
    ),
    CatalogMitigation(
        key="MIT-OUTPUT-VALIDATION", title="Output validation before use",
        category="output-validation",
        description="Validate model output against expected structure before acting on it.",
        applicable_categories=["unsafe-output", "excessive-agency"],
        implementation_guidance="Parse and validate model output; route only through safe, parameterized "
                                "APIs; never eval/exec.",
        priority="critical", difficulty="medium", expected_risk_reduction=60,
        validation_procedure="Attempt to smuggle a command via output; confirm it is not executed.",
        frameworks=[{"framework": "OWASP-LLM", "requirement": "LLM02"}],
    ),
    CatalogMitigation(
        key="MIT-SECRET-HYGIENE", title="Remove secrets from prompts",
        category="input-normalization",
        description="Never place secrets in prompts; inject at call time server-side.",
        applicable_categories=["sensitive-data", "prompt-leakage", "obfuscation"],
        implementation_guidance="Store secrets in a secret manager; add guards that keep secrets/PII out "
                                "of model output; normalize/reject encoded input.",
        priority="high", difficulty="low", expected_risk_reduction=35,
        validation_procedure="Scan prompts for secrets; IG-PROMPT-003 must not fire.",
        frameworks=[{"framework": "OWASP-LLM", "requirement": "LLM06"}],
    ),
    CatalogMitigation(
        key="MIT-TENANT-ISOLATION", title="Enforce tenant isolation in retrieval",
        category="tenant-isolation",
        description="Filter every retrieval and data path by tenant server-side.",
        applicable_categories=["cross-context", "rag-security"],
        implementation_guidance="Add mandatory per-tenant filters at the repository/retrieval layer; add "
                                "cross-tenant tests.",
        priority="critical", difficulty="medium", expected_risk_reduction=60,
        validation_procedure="Attempt cross-tenant retrieval; confirm it returns nothing.",
        frameworks=[{"framework": "OWASP-LLM", "requirement": "LLM06"}],
    ),
    CatalogMitigation(
        key="MIT-MEMORY-VALIDATION", title="Validate content before memory writes",
        category="memory-protection",
        description="Sanitize and validate any content before persisting it to agent memory.",
        applicable_categories=["memory-protection"],
        implementation_guidance="Add validation on memory writes; segregate untrusted memories; expire "
                                "stale entries.",
        priority="medium", difficulty="medium", expected_risk_reduction=30,
        validation_procedure="Write a poisoned memory; confirm it is rejected/quarantined.",
        frameworks=[{"framework": "OWASP-LLM", "requirement": "LLM01"}],
    ),
    CatalogMitigation(
        key="MIT-AUTHZ-SERVER", title="Server-side authorization for actions",
        category="least-privilege",
        description="Make all authorization decisions deterministically server-side; never in the model.",
        applicable_categories=["authorization", "excessive-agency", "architecture"],
        implementation_guidance="Enforce RBAC/ABAC at the API boundary; the model's role is advisory only.",
        priority="critical", difficulty="medium", expected_risk_reduction=65,
        validation_procedure="Ask the model to escalate privileges; confirm the server denies it.",
        frameworks=[{"framework": "OWASP-LLM", "requirement": "LLM08"}],
    ),
    # ── L0 / model supply chain (docs/18) ────────────────────────────────────
    # Every mitigation above changes how an application handles text. These
    # change what it is allowed to load, which is a different lever entirely —
    # and the only one that helps against a payload that runs before the first
    # token exists.
    CatalogMitigation(
        key="MIT-SAFETENSORS", title="Migrate weights to safetensors",
        category="serialization-safety",
        description="Store weights in a format that cannot carry executable content.",
        applicable_categories=["supply-chain"],
        implementation_guidance="Convert checkpoints with safetensors.torch.save_file and load with "
                                "weights-only APIs. For artifacts that must stay pickle-backed "
                                "(sklearn/joblib), treat the source as the trust decision and pin it.",
        priority="high", difficulty="low", expected_risk_reduction=70,
        validation_procedure="Rescan the artifact; ARG-ART-005 must not fire and the format must "
                             "report as safetensors.",
        frameworks=[{"framework": "OWASP-LLM", "requirement": "LLM05"}],
    ),
    CatalogMitigation(
        key="MIT-ARTIFACT-PINNING", title="Pin model artifacts by digest",
        category="serialization-safety",
        description="Resolve models by content hash, never by a mutable tag or branch name.",
        applicable_categories=["supply-chain"],
        implementation_guidance="Record the sha256 of every artifact you deploy and fail the load "
                                "when it changes. A tag can be repointed by anyone with registry "
                                "write access; a digest cannot.",
        priority="critical", difficulty="low", expected_risk_reduction=55,
        validation_procedure="Repoint the tag at a different artifact; confirm the deploy fails.",
        frameworks=[{"framework": "OWASP-LLM", "requirement": "LLM05"}],
    ),
    CatalogMitigation(
        key="MIT-ARTIFACT-SIGNING", title="Sign and verify model artifacts",
        category="serialization-safety",
        description="Require a verifiable signature from a known signer before an artifact loads.",
        applicable_categories=["supply-chain"],
        implementation_guidance="Sign with OpenSSF model_signing (Sigstore keyless — no PKI to run) "
                                "and verify in the deploy step. For air-gapped estates, a detached "
                                "minisign signature over the digest achieves the same.",
        priority="high", difficulty="medium", expected_risk_reduction=50,
        validation_procedure="Present an unsigned artifact; confirm it is refused.",
        frameworks=[{"framework": "NIST-AI-RMF", "requirement": "MANAGE"}],
    ),
    CatalogMitigation(
        key="MIT-REGISTRY-ACCESS", title="Restrict and audit model registry access",
        category="serialization-safety",
        description="Treat registry write access as production deploy access, because it is.",
        applicable_categories=["supply-chain"],
        implementation_guidance="Require authentication for pulls, restrict pushes to a release "
                                "pipeline, and log every write. Model smuggling needs registry "
                                "write access; nothing downstream will notice if it is obtained.",
        priority="high", difficulty="medium", expected_risk_reduction=45,
        validation_procedure="Attempt an unauthenticated push; confirm refusal and an audit entry.",
        frameworks=[{"framework": "OWASP-LLM", "requirement": "LLM05"}],
    ),
]

CATALOG_BY_KEY = {m.key: m for m in CATALOG}


# ── Ranking (ported from InjectGuard services/mitigations.py, made pure) ──────

_DIFFICULTY_PENALTY = {"low": 0, "medium": 5, "high": 12}
_CRITICALITY_BOOST = {"critical": 10, "high": 5, "medium": 0, "low": 0}


@dataclass(frozen=True)
class AppFacts:
    """Deterministic application facts the ranker weighs. All optional."""

    exposure: str = "internal"            # public|internal|private
    business_criticality: str = "medium"  # critical|high|medium|low
    has_write_tools: bool = False
    has_sensitive_data: bool = False


@dataclass(frozen=True)
class Recommendation:
    mitigation: CatalogMitigation
    score: float
    rationale: str


def rank_mitigations(category: str, app: AppFacts | None = None) -> list[Recommendation]:
    """Rank catalog mitigations applicable to a finding category, best first.

    Scoring is identical to InjectGuard's ranker: expected risk reduction as the
    base, boosted by direct category fit, public exposure, write-capable tools
    (for approval/allowlist/least-privilege mitigations), sensitive data (for
    isolation/normalization), and business criticality; penalized by difficulty.
    """
    facts = app or AppFacts()
    recs: list[Recommendation] = []
    for m in CATALOG:
        if category not in m.applicable_categories:
            continue
        score = float(m.expected_risk_reduction)
        reasons = [f"~{m.expected_risk_reduction}% expected risk reduction"]

        score += 15
        reasons.append(f"directly addresses '{category}'")

        if facts.exposure == "public":
            score += 8
            reasons.append("application is public-facing")
        if facts.has_write_tools and m.category in {
            "human-approval",
            "tool-allowlisting",
            "least-privilege",
        }:
            score += 12
            reasons.append("application has write-capable tools")
        if facts.has_sensitive_data and m.category in {"tenant-isolation", "input-normalization"}:
            score += 6
            reasons.append("sensitive data classifications present")

        score += _CRITICALITY_BOOST.get(facts.business_criticality, 0)
        score -= _DIFFICULTY_PENALTY.get(m.difficulty, 0)

        recs.append(Recommendation(m, round(score, 1), "; ".join(reasons)))

    recs.sort(key=lambda r: r.score, reverse=True)
    return recs
