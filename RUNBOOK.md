# Runbook — Phase 1 (Security Sidecar)

How to run the stack locally and reproduce the end-to-end demo.

## Prerequisites

- Docker (for ClickHouse, Postgres, Redis, MinIO)
- Python ≥ 3.10, Node ≥ 20

## Ports

Argus uses these host ports. Two were remapped from the docs defaults to avoid
common local collisions:

| Service | Host port | Note |
|---|---|---|
| ClickHouse HTTP | 8123 | |
| ClickHouse native | 9000 | |
| Postgres | **5433** | remapped from 5432 (local postgres often holds 5432) |
| Redis | 6379 | |
| MinIO S3 / console | 9002 / 9001 | |
| Ingestion API | 3001 | move with `INGEST_PORT` if taken |
| Detection service | 8000 | move with `--port` if taken |

If a port is busy, override via env (`INGEST_PORT`, `DATABASE_URL`,
`DETECTION_URL`) — every service reads them (see `packages/shared/src/config.ts`).

## 1. Infra

```bash
make up          # starts clickhouse, postgres, redis, minio; waits for health
```

Migrations auto-apply on first init:
- ClickHouse tables → `argus` database (traces, observations, security_events, scores + MVs)
- Postgres schema + a dev API key (`pk-dev` / `sk-dev`) and seed project

Verify:
```bash
curl -s 'http://localhost:8123/?user=argus&password=argus' --data-binary 'SHOW TABLES FROM argus'
```

## 2. Detection service (Python)

```bash
make detection-install     # venv + pip install -e ".[dev]"
make detection-test        # unit tests + quality gate (must pass)
make detection-run         # serves on :8000
```

## 3. Ingestion API + workers (TypeScript)

```bash
npm install
# terminal A
DATABASE_URL=postgres://argus:argus@localhost:5433/argus npm run ingest
# terminal B
DATABASE_URL=postgres://argus:argus@localhost:5433/argus \
DETECTION_URL=http://localhost:8000 npm run worker
```

## 4. Run the demo

```bash
python3 demo/send_poisoned_trace.py            # poisoned (indirect injection + exfil)
python3 demo/send_poisoned_trace.py --benign   # clean control
```

Expected security events for the poisoned trace:

| severity | category | outcome | detected by |
|---|---|---|---|
| high | indirect_injection | attempted | L1 heuristics on the retrieved chunk |
| critical | exfiltration | succeeded | L4 trace analysis (`exfil_flow`, `behavior_deviation`) |

The benign control raises **zero** events.

Inspect:
```bash
curl -s 'http://localhost:8123/?user=argus&password=argus' --data-binary "
SELECT severity, category, outcome, round(score,1) score,
       arrayStringConcat(l1_rules,',') l1, arrayStringConcat(l4_signals,',') l4,
       substring(evidence_excerpt,1,70) evidence
FROM argus.security_events ORDER BY detected_at DESC LIMIT 20 FORMAT PrettyCompact"
```

## Sending your own data

- **Native / Langfuse-style batch:** `POST /api/public/ingestion` with
  `{ traces:[], observations:[] }`, HTTP Basic auth `pk-dev:sk-dev`.
- **OTLP/HTTP JSON:** `POST /v1/traces` with OpenTelemetry GenAI spans
  (`gen_ai.*` attributes; set `argus.taint` / `argus.content` where helpful).

Tool/retrieval spans are auto-classified as untrusted; override per tool in the
project's `detection_configs.config.taint.tool_overrides`.

## Optional: enable L2 classifiers

Phase 1 ships heuristics-only. To add the open-model ensemble (Prompt Guard 2 +
DeBERTa injection v2):

```bash
cd services/detection && . .venv/bin/activate && pip install -e ".[l2]"
DETECTION_ENABLE_L2=true uvicorn argus_detection.app:app --port 8000
```

## Stop everything

```bash
make down                 # stop infra (keeps volumes)
make reset                # stop infra AND wipe data
# stop app processes: Ctrl-C the ingest/worker/detection terminals
```
