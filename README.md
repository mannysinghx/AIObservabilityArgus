<div align="center">

# 🛡️ Argus

### Security-first AI observability for LLM applications

**Langfuse-style tracing + a prompt-injection detection engine that actually understands your traces.**

[![License: MIT](https://img.shields.io/badge/License-MIT-informational.svg)](#license)
[![Status: Phase 1](https://img.shields.io/badge/status-Phase%201%20verified-brightgreen.svg)](#project-status)
[![OTel GenAI](https://img.shields.io/badge/OpenTelemetry-GenAI%20conventions-blueviolet.svg)](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
[![Python](https://img.shields.io/badge/python-3.10+-3776AB.svg?logo=python&logoColor=white)](services/detection)
[![TypeScript](https://img.shields.io/badge/typescript-5.5-3178C6.svg?logo=typescript&logoColor=white)](apps)

</div>

---

Argus is an open-source AI observability platform in the spirit of
[Langfuse](https://github.com/langfuse/langfuse), with one deliberate
difference: **LLM security is a first-class citizen, not an add-on.** Every
trace is analyzed for prompt injection, **indirect** prompt injection,
jailbreaks, data exfiltration, and anomalous agent behavior — with the full
trace context you need to actually investigate an incident.

> **Codename "Argus"** — the hundred-eyed watchman of Greek myth. Rename freely.

## The idea in one paragraph

Existing observability tools tell you *what your LLM app did* and *how well*.
None natively tell you *whether someone is attacking it right now*. And existing
guardrails (LLM Guard, Prompt Guard, NeMo Guardrails) scan **single messages in
isolation** — but indirect prompt injection is a **cross-span** phenomenon: a
poisoned document gets retrieved, the agent reads it, and three steps later it
emails your data to an attacker. You can only catch that if you can see the
whole trace: what the model read, what it did next, and whether its behavior
changed after ingesting untrusted content. **That's exactly the data an
observability platform already owns.** Argus fuses the two.

## Why it's different

|  | Langfuse / Phoenix | LLM Guard / Prompt Guard / NeMo | **Argus** |
|---|:---:|:---:|:---:|
| Full trace observability | ✅ | ❌ | ✅ |
| Per-message injection scanning | ⚠️ eval hooks | ✅ | ✅ |
| **Cross-span indirect-injection detection** | ❌ | ❌ | ✅ |
| Taint tracking through the trace graph | ❌ | ❌ | ✅ |
| Security incidents rendered over traces | ❌ | ❌ | ✅ |
| Continuous red-team regression | ❌ | ❌ | ✅ |

## See it work

The end-to-end demo sends a **poisoned knowledge-base document** — one that tells
a shipping-support agent to email the customer's saved data to an attacker
address — through the live pipeline. Argus produces exactly the right story:

```
$ python3 demo/send_poisoned_trace.py

severity   category             outcome     detected by
────────   ──────────────────   ─────────   ─────────────────────────────────────
high       indirect_injection   attempted   L1 heuristics on the retrieved chunk
critical   exfiltration         succeeded   L4 trace analysis (exfil_flow,
                                            behavior_deviation): outbound to
                                            attacker-controlled target
```

The benign control trace (`--benign`) raises **zero** events. The `critical`
finding is the differentiator — no single-message scanner sees it, because it
only exists in the *relationship between spans*.

## Architecture

```
  Instrumented LLM app
  (Langfuse SDK · OpenLLMetry · OpenInference · raw OTel)
          │  OTLP / native batch  (GenAI semantic conventions)
          ▼
  ┌─────────────────┐     ┌──────────────┐
  │  Ingestion API  │────▶│ Redis Streams│
  │  (Fastify, TS)  │     └──────┬───────┘
  └─────────────────┘            │
                   ┌─────────────┴──────────────┐
                   ▼                            ▼
          ┌────────────────┐          ┌─────────────────────┐
          │  Trace worker  │          │  Security worker    │
          │      (TS)      │          │       (TS)          │
          └───────┬────────┘          └─────────┬───────────┘
                  │                              │  HTTP
                  ▼                              ▼
         ┌──────────────┐          ┌──────────────────────────┐
         │  ClickHouse  │◀─────────│  Detection service (Py)  │
         │ traces ·     │  events  │  L1 heuristics           │
         │ observations │          │  L2 classifier ensemble  │
         │ security_    │          │  L3 LLM judge (opt)      │
         │ events       │          │  L4 trace analysis ⭐    │
         └──────────────┘          └──────────────────────────┘
                  │                              │
                  ▼                              ▼
             Web UI / API                   Webhook · Slack alerts
```

**⭐ L4 trace analysis is the moat** — taint propagation, instruction-echo
detection, exfil-flow analysis, behavior-deviation scoring, and canary-token
egress. Full design in
[docs/04-security-detection-engine.md](docs/04-security-detection-engine.md).

## Quick start

Requires Docker, Python ≥ 3.10, Node ≥ 20. Full details in [RUNBOOK.md](RUNBOOK.md).

```bash
# 1. Infra: ClickHouse, Postgres, Redis, MinIO (migrations auto-apply)
make up

# 2. Detection service (Python) — includes the quality gate
make detection-install
make detection-test        # 15 tests, precision/recall gate must pass
make detection-run         # :8000

# 3. Ingestion + workers (TypeScript)
npm install
npm run ingest             # :3001
npm run worker             # trace + security consumers

# 4. Fire the demo
python3 demo/send_poisoned_trace.py            # poisoned
python3 demo/send_poisoned_trace.py --benign   # clean control
```

Then inspect the events:

```bash
curl -s 'http://localhost:8123/?user=argus&password=argus' --data-binary "
  SELECT severity, category, outcome, arrayStringConcat(l4_signals,',') AS signals
  FROM argus.security_events ORDER BY detected_at DESC LIMIT 10 FORMAT PrettyCompact"
```

## Detection pipeline

Cheap-first, escalating layers — millisecond checks run on everything; expensive
analysis runs only on what earlier layers flag.

| Layer | What it does | Cost | Runs on |
|---|---|---|---|
| **L1 — Heuristics** | Regex/structural rule pack: instruction-override families, obfuscation (zero-width, homoglyphs, encoded blobs), exfil patterns. Downweights quoted/reported speech. | µs | 100% of content |
| **L2 — Classifiers** | Open-model ensemble (Meta Prompt Guard 2 + ProtectAI DeBERTa) with document chunking. *Pluggable, opt-in.* | ~10–50 ms | untrusted + L1 escalations |
| **L3 — LLM judge** | Structured "is this text instructing an AI?" verdict over span context. Any OpenAI-compatible endpoint. *Opt-in.* | ~s | escalations only |
| **L4 — Trace analysis** ⭐ | Taint propagation, instruction-echo, exfil-flow, behavior deviation, canary egress — across the whole trace graph. | ~100 ms | on trace completion |

A **detection quality gate** ([`tests/test_quality_gate.py`](services/detection/tests/test_quality_gate.py))
runs the L1 pipeline over a labeled corpus — attacks **and hard negatives**
(blog posts *about* prompt injection, fiction with imperative dialogue) — and
fails CI if precision/recall regress below their floors. Because the fastest way
to kill this kind of product is false positives, not missed attacks.

## Project structure

```
apps/ingest         TS ingestion API — OTLP/HTTP JSON + native/Langfuse batch
apps/worker         TS trace worker (→ ClickHouse) + security worker (→ detection)
services/detection  Python detection pipeline (L1–L4) + corpus + quality gate
packages/shared     TS types, config, ClickHouse/Redis clients, GenAI mapping
deploy/             docker-compose + ClickHouse/Postgres migrations
demo/               end-to-end poisoned-trace demo
docs/               design docs 01–08 (vision, architecture, detection, UI spec…)
```

## Project status

**Phase 1 (Security Sidecar) — implemented and verified end-to-end.**

- ✅ Ingestion (OTLP + native batch) → Redis → workers → ClickHouse
- ✅ Detection L1 (heuristics) + L4 (trace analysis); L2 wired & pluggable
- ✅ Detection quality gate with hard-negative corpus, enforced in CI
- ✅ Webhook alerting with trace-linked payloads
- ✅ Verified demo (poisoned → 2 correct events; benign → 0)
- 🔜 **Phase 2:** L3 judge, canary tokens end-to-end, pgvector self-hardening corpus, cross-trace RAG-poisoning correlation, Incidents UI
- 🔜 **Live dashboard:** Next.js UI reading ClickHouse (design in [docs/08](docs/08-ui-design-spec.md))
- 🔜 **Phase 3+:** observability parity (analytics, prompts, evals), gateway/blocking mode, scheduled red-teaming

See [docs/06-roadmap.md](docs/06-roadmap.md) for the full plan.

## Documentation

| Doc | Contents |
|---|---|
| [01 — Vision & Scope](docs/01-vision-and-scope.md) | Problem, differentiators, target users, non-goals |
| [02 — Architecture](docs/02-architecture.md) | Components, data flow, deployment modes |
| [03 — Tech Stack](docs/03-tech-stack.md) | Open-source foundations + rationale (incl. build-vs-fork-Langfuse) |
| [04 — Security Detection Engine](docs/04-security-detection-engine.md) | The core: detection layers, indirect-injection design, scoring |
| [05 — Data Model](docs/05-data-model.md) | ClickHouse + Postgres schemas, OTel attribute mapping |
| [06 — Roadmap](docs/06-roadmap.md) | Phased build plan |
| [07 — References](docs/07-references.md) | Standards, tools, papers, datasets |
| [08 — UI Design Spec](docs/08-ui-design-spec.md) | Design system, theming/white-label, key screens |
| [RUNBOOK.md](RUNBOOK.md) | How to run the stack and reproduce the demo |

## Built on

[OpenTelemetry GenAI conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) ·
[ClickHouse](https://github.com/ClickHouse/ClickHouse) ·
PostgreSQL · Redis · MinIO ·
[FastAPI](https://fastapi.tiangolo.com/) ·
[Fastify](https://fastify.dev/) ·
[Meta Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) ·
[ProtectAI DeBERTa](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) ·
[LLM Guard](https://github.com/protectai/llm-guard)

## Contributing

Early-stage and moving fast. The highest-leverage contributions right now:
detection rules for the L1 pack, labeled samples for the corpus (especially
**hard negatives**), and instrumentation adapters. If you touch detection, the
quality gate must stay green — see [docs/04](docs/04-security-detection-engine.md).

## Disclaimer

Argus **reduces and surfaces** prompt-injection risk; it does not make injection
impossible. No detector is complete, and published research shows all
content-level guards can be evaded. Argus's defense-in-depth stance is that L4
watches what the agent *actually did*, which an attacker can't phrase their way
around — but least-privilege tool design and human-in-the-loop for irreversible
actions remain necessary. Treat findings as high-signal leads, not guarantees.

## License

MIT — see [LICENSE](LICENSE). Verify each dependency's license in
[docs/03-tech-stack.md](docs/03-tech-stack.md).
