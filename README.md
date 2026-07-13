# Argus — Security-First AI Observability Platform

> Working codename: **Argus** (the hundred-eyed watchman). Rename freely.

Argus is an open-source AI observability platform in the spirit of
[Langfuse](https://github.com/langfuse/langfuse), with one deliberate
differentiator: **LLM security is a first-class citizen, not an afterthought**.
Every trace that flows through the platform is analyzed for prompt injection,
indirect prompt injection, jailbreaks, data exfiltration, and anomalous agent
behavior — with the trace context needed to actually investigate an incident.

## Why this exists

Existing observability tools (Langfuse, Phoenix, Helicone, LangSmith) answer:

- *What did my LLM app do?* (traces, spans, tool calls)
- *How well did it do it?* (evals, scores, latency, cost)

None of them natively answer:

- *Is someone attacking my LLM app right now?*
- *Did a poisoned document in my RAG store hijack my agent?*
- *Did my agent leak data after reading untrusted content?*
- *Which tool output injected instructions into my agent's context?*

Security scanners (LLM Guard, Prompt Guard, NeMo Guardrails) exist, but they
operate on **single messages in isolation**. Indirect prompt injection is a
**cross-span, cross-turn phenomenon** — you can only detect it reliably when
you can see the whole trace: what the model read, what it did next, and whether
its behavior deviated after ingesting untrusted content. That is exactly the
data an observability platform already has. Argus fuses the two.

## Core capabilities

| Pillar | What you get |
|---|---|
| **Observability** | OTel-native tracing (GenAI semantic conventions), token/cost/latency analytics, prompt management, evals & datasets |
| **Security detection** | Multi-layer prompt-injection pipeline: heuristics → ML classifiers → LLM judge → trace-level behavioral analysis |
| **Indirect injection defense** | Taint tracking of untrusted spans (RAG chunks, tool outputs, web content), canary tokens, post-ingestion behavior deviation scoring |
| **Response** | Real-time alerting, security dashboard, incident timelines, optional inline blocking via gateway mode |
| **Continuous red-teaming** | Scheduled attack simulation with garak / promptfoo, regression tracking of your app's attack surface |

## Documentation

| Doc | Contents |
|---|---|
| [01 — Vision & Scope](docs/01-vision-and-scope.md) | Problem statement, differentiators, target users, non-goals |
| [02 — Architecture](docs/02-architecture.md) | System design, components, data flow, deployment modes |
| [03 — Tech Stack](docs/03-tech-stack.md) | Open-source foundations and the rationale for each choice |
| [04 — Security Detection Engine](docs/04-security-detection-engine.md) | The core differentiator: detection layers, indirect-injection design, scoring |
| [05 — Data Model](docs/05-data-model.md) | Trace/span/security-event schemas, ClickHouse table design |
| [06 — Roadmap](docs/06-roadmap.md) | Phased build plan from MVP to full platform |
| [07 — References](docs/07-references.md) | Standards, tools, papers, attack taxonomies |
| [08 — UI Design Spec](docs/08-ui-design-spec.md) | Design system, theming/white-label, configurability, key screens |

## Quick orientation

```
SDKs / OTel instrumentation
        │  (OTLP — GenAI semantic conventions)
        ▼
  Ingestion API ──► Queue ──► Workers ──► ClickHouse (traces + security events)
                               │
                               ├─► Security Detection Pipeline
                               │     heuristics · ML classifiers · LLM judge ·
                               │     taint tracking · behavior deviation
                               │
                               └─► Alerting (webhooks, Slack, PagerDuty)
        ▲
  Web UI (traces, analytics, security dashboard, incident view)
```

## Status

**Phase 1 (Security Sidecar) — implemented and verified end-to-end.** See
[RUNBOOK.md](RUNBOOK.md) to run it and [docs/06-roadmap.md](docs/06-roadmap.md)
for what's next.

What works today:

- **Ingestion** (`apps/ingest`, Fastify): native/Langfuse-style batch endpoint +
  OTLP/HTTP JSON with GenAI-convention mapping → Redis Streams.
- **Workers** (`apps/worker`): trace worker → ClickHouse; security worker →
  detection service → `security_events` + webhook alerts.
- **Detection service** (`services/detection`, FastAPI): L1 heuristic rule pack
  + taint classifier + L4 trace-level behavioral analysis (taint propagation,
  instruction-echo, exfil-flow, behavior deviation, canary egress). L2 classifier
  ensemble is wired and pluggable (opt-in).
- **Detection quality gate**: labeled corpus (attacks + hard negatives) with a
  pytest precision/recall regression gate, enforced in CI.
- **Verified demo**: a poisoned-document trace raises `high indirect_injection`
  (L1) **and** `critical exfiltration` (L4); a benign control raises nothing.

Layout:

```
apps/ingest         TS ingestion API (OTLP + native batch)
apps/worker         TS trace + security workers
services/detection  Python detection pipeline (L1..L4) + corpus + quality gate
packages/shared     TS types, config, ClickHouse/Redis clients, GenAI mapping
deploy/             docker-compose + ClickHouse/Postgres migrations
demo/               end-to-end poisoned-trace demo
```

## License

Intended license: MIT (matches the ecosystem we build on — verify each
dependency's license in [docs/03-tech-stack.md](docs/03-tech-stack.md)).
