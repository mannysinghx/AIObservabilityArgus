"""Static assessment engine — pre-deployment prompt/architecture risk analysis.

Ported from InjectGuard (Phase 1 of the Argus+InjectGuard merge). Where the
detection layers (L1–L4) judge *live traffic*, this package judges the
*application itself*: its prompt templates, its architecture graph, and the
governance policies around it. Everything here is deterministic and pure —
no DB, no network, no model calls — so it stays independently testable and
can later run inside the worker, the gateway, or a CLI without changes.

Modules:
    scanner/     20 deterministic prompt rules (IG-PROMPT-001..020)
    artifact/    L0 model-artifact rules (ARG-ART-*) — judges the model FILE,
                 not the prompt or the traffic. Opcodes are walked, never
                 executed. See docs/18.
    graph        trust-boundary analysis over an architecture graph
    risk         transparent, versioned 5-factor risk scoring
    mitigations  ranked, architecture-aware mitigation catalog
    policy       fail-closed policy-as-code evaluator
    frameworks   OWASP LLM / MITRE ATLAS / NIST AI RMF registry
    taxonomy     assessment-category → Argus security-event category mapping
    redaction    secret scrubbing for evidence excerpts
"""

from .risk import SCORING_VERSION

__all__ = ["SCORING_VERSION"]
