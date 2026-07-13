# 07 — References

## Standards & taxonomies

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — LLM01 (Prompt Injection) is our primary target; map every detection category to it.
- [MITRE ATLAS](https://atlas.mitre.org/) — adversarial ML tactics/techniques; use its IDs in incident exports.
- [OpenTelemetry GenAI Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) — canonical trace format ([overview article](https://dev.to/x4nent/opentelemetry-genai-semantic-conventions-the-standard-for-llm-observability-1o2a)).
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) — useful vocabulary for compliance-driven buyers.

## Observability platforms (study these)

- [Langfuse](https://github.com/langfuse/langfuse) (MIT) — the architectural reference: ClickHouse + Postgres + Redis + S3, OTel ingestion. Now [acquired by ClickHouse](https://clickhouse.com/blog/clickhouse-acquires-langfuse-open-source-llm-observability); remains MIT for core.
- [ClickHouse: Understanding LLM Observability](https://clickhouse.com/resources/engineering/llm-observability) — why ClickHouse for this workload.
- [Langfuse: Security & Guardrails docs](https://langfuse.com/docs/security-and-guardrails) — how they treat security today (external integrations only) — the gap we fill.
- [Arize Phoenix](https://github.com/Arize-ai/phoenix) (OpenInference conventions), [OpenLLMetry](https://github.com/traceloop/openllmetry) — instrumentation to ingest.
- [SigNoz: LLM observability tools comparison 2026](https://signoz.io/comparisons/llm-observability-tools/), [Self-hosted LLM observability picks 2026](https://futureagi.com/blog/best-self-hosted-llm-observability-2026/) — competitive landscape.
- [MLflow / OTel convergence commentary](https://www.snackonai.com/p/mlflow-made-opentelemetry-the-default-substrate-for-llm-tracing-the-gen-ai-semantic-conventions-are) — evidence GenAI conventions are the substrate.

## Detection engines & guardrails (embed / interop)

- [LLM Guard](https://github.com/protectai/llm-guard) (MIT) — input/output scanner toolkit; [2026 overview](https://appsecsanta.com/llm-guard).
- [Meta Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) — 86M multilingual injection/jailbreak classifier.
- [ProtectAI DeBERTa-v3 prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) (Apache-2.0) — ensemble partner.
- [NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) (Apache-2.0) — programmable rails; interop target, not embedded.
- [Rebuff](https://github.com/protectai/rebuff) — lightly maintained, but the canary-token and self-hardening vector-corpus ideas are adopted in our L4/corpus design.
- [Guardrails AI](https://github.com/guardrails-ai/guardrails) — validator ecosystem; [comparison](https://dev.to/agdex_ai/best-ai-agent-security-guardrails-tools-in-2026-llm-guard-vs-nemo-vs-guardrails-ai-5e5d).
- [Microsoft Presidio](https://github.com/microsoft/presidio) (MIT) — PII detection/redaction.
- [LlamaFirewall paper](https://arxiv.org/pdf/2505.03574) — Meta's open guardrail system for agents (PromptGuard 2 + AlignmentCheck + CodeShield); closest published relative of our L2+L4 combination — read carefully.

## Red-teaming

- [garak](https://github.com/NVIDIA/garak) (Apache-2.0) — LLM vulnerability scanner; probe source for the scheduler and the detection corpus.
- [promptfoo](https://github.com/promptfoo/promptfoo) (MIT) — red-team suites + CI.
- [PyRIT](https://github.com/Azure/PyRIT) — Microsoft's risk-identification toolkit; multi-turn attack orchestration patterns.

## Attack & defense research

- [tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses) — the best living catalog of practical and proposed defenses; mine it for the L1 rule pack.
- [Bypassing LLM Guardrails: Evasion Attacks against Injection/Jailbreak Detectors](https://arxiv.org/pdf/2504.11168) — why we ensemble and why L4 behavioral detection is the backstop.
- [OneShield guardrails paper](https://arxiv.org/pdf/2507.21170) — next-gen guardrail architecture survey.
- Simon Willison's prompt-injection series (simonwillison.net) — the clearest thinking on why detection-only is insufficient and least-privilege design matters; informs our "honest limitations" stance.
- Greshake et al., *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection* (arXiv:2302.12173) — the foundational indirect-injection paper; its attack taxonomy seeds our test corpus.

## Public datasets for the detection corpus

- deepset/prompt-injections (HF) — labeled injection dataset.
- Lakera Gandalf / ignore-instructions datasets (check current licenses).
- jackhhao/jailbreak-classification (HF) — jailbreak samples.
- garak probe outputs — generate labeled attacks per category.
- **Benign hard-negatives matter most:** security blog posts, documentation
  *about* prompt injection, fiction with imperative dialogue, customer-support
  transcripts — the corpus must include content that *talks about* attacks
  without *being* attacks, or the FP rate will sink the product.
