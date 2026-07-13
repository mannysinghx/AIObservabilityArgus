# 06 — Roadmap

Strategy: **ship the differentiator first, backfill the table stakes.**
Building Langfuse-parity observability first means competing head-on with a
mature, ClickHouse-backed incumbent before having anything unique. Instead,
Phase 1 is a *security analysis layer that works with the observability
people already have* — every Langfuse/OTel user is a prospect on day one.

## Phase 1 — Security Sidecar (MVP)

**Goal:** point it at an existing trace stream; get a security dashboard.

Scope:

- Ingestion: OTLP/HTTP endpoint accepting GenAI-convention spans; adapter
  for Langfuse trace export (their API/exports) and OTel Collector fan-out.
- Taint classification (automatic rules only: retrieval/tool spans =
  untrusted).
- Detection **L1 (heuristics)** + **L2 (Prompt Guard 2 + DeBERTa ensemble,
  LLM Guard scanners)** with document chunking.
- `security_events` in ClickHouse; minimal Postgres (projects, keys, config).
- Dashboard v1: attack feed, event detail with evidence + trace link,
  severity filters, mark-as-false-positive.
- Alerting v1: webhook + Slack.
- Deployment: docker compose.
- **Detection test corpus + CI quality gate from day one.**

Definition of done: a demo RAG app with planted poisoned documents produces
correct, explainable `indirect_injection` events with < agreed FP rate on a
benign corpus, viewable end-to-end in the dashboard.

## Phase 2 — Trace-Level Detection (the moat)

- Own trace store: full trace/observation ingestion & tree UI (waterfall with
  taint tinting, security annotations inline).
- **L4**: taint propagation, instruction-echo, post-ingestion deviation
  scoring, exfil-flow analysis.
- **Canary tokens** end-to-end (issue, embed helper, egress watch).
- **L3 LLM judge** with escalation budget controls.
- pgvector attack corpus + self-hardening loop (confirmed incidents →
  corpus).
- Cross-trace correlation: poisoned-document detection, attacker-session
  clustering; **Incidents** UI with timelines.
- Alert routing: dedup, suppression rules, PagerDuty/email.

## Phase 3 — Observability Parity

- Analytics: cost/tokens/latency dashboards, model usage, sessions & users.
- Prompt management (versions, labels, API fetch).
- Evals: LLM-as-judge eval templates, human annotation queues, datasets,
  scores API (schema already reserved for this in Phase 1).
- Thin `argus` SDK wrappers (Python/TS) — convenience for taint labels and
  canaries, not a required SDK.
- Helm chart; multi-node deployment docs; SSO (OIDC).

## Phase 4 — Prevention & Ecosystem

- **Gateway mode**: OpenAI-compatible inline proxy, sync L1+L2 (<50 ms p99),
  block/redact policies, fail-open/fail-closed configurable.
- **Red-team scheduler**: garak + promptfoo integration, attack-success-rate
  trend charts, CI hooks ("security regression" gate for app teams).
- NeMo Guardrails event ingestion; MCP-server instrumentation guides.
- Compliance exports (audit reports, EU AI Act logging evidence).
- Community: rule-pack contribution format, public benchmark of the
  detection corpus.

## Suggested repo layout (monorepo)

```
argus/
├── apps/
│   ├── web/                 # Next.js UI
│   ├── api/                 # TS ingestion + public API
│   └── worker/              # TS trace workers
├── services/
│   └── detection/           # Python FastAPI: L1–L4 pipeline
│       ├── layers/
│       ├── models/          # classifier serving
│       ├── rules/           # L1 rule pack (yaml)
│       └── corpus/          # labeled eval corpus + quality-gate harness
├── packages/
│   ├── shared/              # TS types, GenAI-attr mapping
│   └── sdk/                 # thin taint/canary helpers (phase 3)
├── deploy/
│   ├── docker-compose.yml
│   └── helm/
└── docs/
```

## Team-of-one build order (first 10 steps)

1. Compose file: ClickHouse + Postgres + Redis + MinIO.
2. ClickHouse migrations for `observations`/`security_events` (from
   [05 — Data Model](05-data-model.md)).
3. OTLP/HTTP ingestion endpoint → Redis Stream → worker → ClickHouse insert.
4. Instrument a demo RAG app (OpenLLMetry) pointing at it; verify spans land.
5. L1 rule engine (yaml rules, tests) in the Python service.
6. L2: serve Prompt Guard 2 + DeBERTa via ONNX/transformers; chunking; ensemble.
7. Security-worker consumer group: scan untrusted spans → `security_events`.
8. Labeled corpus + pytest quality gate (precision/recall report).
9. Dashboard v1 (attack feed + event detail + trace link).
10. Slack/webhook alerter. → Demo: plant a poisoned doc, watch the alert fire.

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| Detection FP rate makes the product noisy → uninstalled | Corpus-gated CI, shadow mode, suppression UX as a first-class feature (see [04](04-security-detection-engine.md)) |
| Langfuse/ClickHouse adds a security module | Our moat is L4 trace-graph analysis + security-analyst UX; move fast on Phase 2, keep sidecar interop so we complement rather than displace |
| Classifier models have restrictive licenses (Prompt Guard = Llama license) | Ensemble includes Apache-2.0 DeBERTa model; classifiers are pluggable; document license implications per model |
| Judge-model cost blowout | Escalation-only triggering + hard budget caps in config |
| Storing attack payloads creates platform risk (stored XSS etc.) | UI output-encoding policy, CSP, security review of trace rendering (see [02](02-architecture.md)) |
