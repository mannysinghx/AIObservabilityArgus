# 03 — Tech Stack (Open-Source Foundations)

Principle: **compose, don't reinvent**. Every layer builds on a proven
open-source project; our code is the integration, the trace-level security
analysis, and the product surface.

## Ingestion & instrumentation

| Choice | Project | License | Rationale |
|---|---|---|---|
| Trace standard | [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) | Apache-2.0 | The industry has converged on `gen_ai.*` attributes as the vendor-neutral format; every major SDK can emit it. Zero-friction adoption. |
| Client instrumentation (reuse, don't build) | [OpenLLMetry](https://github.com/traceloop/openllmetry), [OpenInference](https://github.com/Arize-ai/openinference), Langfuse SDKs, MLflow tracing | Apache-2.0 / MIT | We don't ship 10 SDKs. We ingest what exists. A thin `argus` SDK wrapper comes later only to add taint labels conveniently. |
| Collector | [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector) (optional in front of ingestion) | Apache-2.0 | Buffering, retry, fan-out for enterprises that already run collectors. |

## Backend services

| Choice | Technology | Rationale |
|---|---|---|
| Ingestion API + workers | **TypeScript (Node/Fastify)** for API + queue workers; **Python (FastAPI)** for the detection service | TS matches the Langfuse-ecosystem talent pool and shares types with the UI. Detection must be Python — every ML model, scanner, and security library (LLM Guard, transformers, garak) is Python-native. Two services, clean gRPC/HTTP boundary. |
| Queue | **Redis Streams** ([Redis](https://redis.io/)) | Minimal ops for self-hosters; consumer groups give us independent trace/security lag. Kafka as documented scale-out path. |
| Trace/analytics store | **[ClickHouse](https://github.com/ClickHouse/ClickHouse)** (Apache-2.0) | The de-facto store for LLM observability at scale — validated by [Langfuse running entirely on it](https://clickhouse.com/blog/clickhouse-acquires-langfuse-open-source-llm-observability). |
| Metadata store | **PostgreSQL** | Boring, correct, transactional. |
| Vector similarity | **[pgvector](https://github.com/pgvector/pgvector)** | Attack-corpus similarity (Rebuff-style self-hardening) without a second database. Corpus is thousands–low-millions of vectors; pgvector is ample. |
| Blob storage | **S3 API (MinIO for self-host)** | Raw payload offload; Langfuse-proven pattern. |

## Security detection engines (embedded as libraries/models)

| Layer | Project | License | Role in Argus |
|---|---|---|---|
| L1 heuristics | Own rule pack + patterns curated from [tldrsec/prompt-injection-defenses](https://github.com/tldrsec/prompt-injection-defenses) | — | Microsecond regex/keyword/structural checks (role-play markers, "ignore previous instructions" families, invisible Unicode, base64/hex blobs, markdown-image exfil patterns, zero-width chars). |
| L2 classifier | **[Meta Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)** (86M) | Llama license | Fast multilingual jailbreak/injection classifier; small enough for CPU. |
| L2 classifier (alt/ensemble) | **[ProtectAI DeBERTa-v3 prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2)** | Apache-2.0 | Second opinion; ensemble voting reduces single-model blind spots (see [evasion-attack literature](https://arxiv.org/pdf/2504.11168) — single detectors are bypassable). |
| L2 scanner toolkit | **[LLM Guard](https://github.com/protectai/llm-guard)** (MIT) | MIT | Reuse its input/output scanners: PII (Presidio-based), secrets, toxicity, invisible text, language detection. We wrap it rather than rewrite scanners. |
| L2 output-side | **[Presidio](https://github.com/microsoft/presidio)** (MIT) | MIT | PII detection on model outputs (leak detection) and optional ingestion-time redaction. |
| L3 judge | Any OpenAI-compatible endpoint (self-hosted **vLLM**/**Ollama** or commercial) | Apache-2.0 (vLLM) | Structured LLM-as-judge on escalated content: "does this text contain instructions directed at an AI system?" with rationale, over the span's context. |
| L4 trace analysis | **Argus-original code** | ours | Taint propagation + behavior-deviation scoring across the trace graph. This is the moat — nothing OSS does this today. |
| Guardrail interop | **[NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails)** (Apache-2.0) | Apache-2.0 | Not embedded; we ingest its rail-triggered events as security signals and document side-by-side deployment. |
| Canary tokens | Argus-original (concept from **[Rebuff](https://github.com/protectai/rebuff)**) | — | Platform issues canary strings for system prompts; output scanners watch all egress spans for them. |

## Red-teaming

| Project | License | Role |
|---|---|---|
| **[garak](https://github.com/NVIDIA/garak)** | Apache-2.0 | Probe library for scheduled scans (injection, jailbreak, leakage probes). |
| **[promptfoo](https://github.com/promptfoo/promptfoo)** | MIT | Red-team suites + CI integration; results ingested as scored traces. |

## Frontend

| Choice | Technology | Rationale |
|---|---|---|
| Web app | **Next.js + TypeScript + Tailwind + shadcn/ui** | Ecosystem standard (Langfuse uses the same); fastest path to a polished dashboard. |
| Charts | **ECharts** or **Recharts** | Time-series + histogram heavy dashboards. |
| Trace rendering | Custom tree/waterfall component | The security-annotated trace view is core product; owning this component matters. |

## Infra & delivery

- **Docker Compose** for evaluation, **Helm** for production.
- **CI:** GitHub Actions — lint, typecheck, unit, integration (compose-based),
  plus a *detection-quality gate*: the detection test corpus (labeled attack +
  benign sets) must not regress below threshold precision/recall on any PR
  that touches detection code.

## Build-vs-fork decision (important)

**Considered: forking Langfuse and adding a security module.**

Rejected for the core platform, for three reasons:

1. Langfuse's codebase is optimized for its own roadmap (now under
   ClickHouse's ownership); tracking upstream while carrying a deep
   security-pipeline divergence is a permanent tax.
2. Our security pipeline needs its own processing lane, schema, and Python
   service — architecturally parallel to, not inside, their worker.
3. Differentiation: "Langfuse fork" is a weak identity; "OTel-native
   security-first observability" stands alone.

**But adopted from the Langfuse playbook:** ClickHouse+Postgres+Redis+S3
topology, OTel-first ingestion, MIT license, self-host-first distribution.
And the MVP (see roadmap) deliberately *interoperates* with Langfuse — the
detection sidecar can analyze traces from an existing Langfuse deployment,
which turns their install base into our adoption funnel instead of our
competitor.
