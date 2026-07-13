# 05 — Data Model

## Conceptual model

```
Organization ─► Project ─► Trace ─► Observation (span / generation / event)
                              │           │
                              │           ├─► Score (eval results)
                              │           └─► SecurityEvent
                              ├─► Session (groups traces; multi-turn)
                              └─► Incident (groups SecurityEvents)
```

- **Trace** — one end-to-end execution (a request, an agent run).
- **Observation** — a node in the trace tree. Types: `span` (generic step),
  `generation` (LLM call), `retrieval`, `tool`, `event`.
- **Score** — a numeric/categorical judgment attached to a trace or
  observation (evals, user feedback, security scores reuse this).
- **SecurityEvent** — a detection hit with layer provenance.
- **Incident** — analyst-facing grouping of related security events
  (same attacker session, same poisoned document, same canary).

## Attribute mapping: OTel GenAI conventions → Argus

We store the canonical `gen_ai.*` attributes and add an `argus.*` namespace
for what the conventions don't cover:

| Attribute | Meaning |
|---|---|
| `gen_ai.operation.name`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `gen_ai.response.finish_reasons` … | Standard GenAI conventions, stored as-is |
| `argus.taint` | `system` \| `user` \| `untrusted-external` \| `model` (see [04](04-security-detection-engine.md)) |
| `argus.taint.source` | Tool/retriever identity that produced untrusted content |
| `argus.content.sha256` | Content hash for cross-trace correlation (poisoned-doc detection) |
| `argus.canary.ids` | Canary tokens known to be present in this span's inputs |

## ClickHouse tables (analytical plane)

Design notes: ClickHouse `ReplacingMergeTree` for observation updates
(spans arrive incrementally), `MergeTree` + TTL for events, all tables
partitioned by month and ordered by `(project_id, …, timestamp)` for
tenant-scoped scans.

```sql
-- traces
CREATE TABLE traces (
    project_id       LowCardinality(String),
    trace_id         String,
    session_id       String DEFAULT '',
    user_id          String DEFAULT '',
    name             String,
    timestamp        DateTime64(3),
    environment      LowCardinality(String) DEFAULT 'default',
    release          String DEFAULT '',
    metadata         Map(String, String),
    tags             Array(String),
    -- security rollups (denormalized for fast dashboard queries)
    sec_max_severity     Enum8('none'=0,'info'=1,'low'=2,'medium'=3,'high'=4,'critical'=5) DEFAULT 'none',
    sec_event_count      UInt32 DEFAULT 0,
    sec_taint_present    Bool DEFAULT false,
    updated_at       DateTime64(3),
    event_ts         DateTime64(3)
) ENGINE = ReplacingMergeTree(event_ts)
PARTITION BY toYYYYMM(timestamp)
ORDER BY (project_id, toDate(timestamp), trace_id);

-- observations (spans / generations / retrievals / tools)
CREATE TABLE observations (
    project_id       LowCardinality(String),
    trace_id         String,
    observation_id   String,
    parent_id        String DEFAULT '',
    type             Enum8('span'=1,'generation'=2,'retrieval'=3,'tool'=4,'event'=5),
    name             String,
    start_time       DateTime64(3),
    end_time         Nullable(DateTime64(3)),
    -- GenAI conventions
    model            LowCardinality(String) DEFAULT '',
    provider         LowCardinality(String) DEFAULT '',
    input_tokens     UInt32 DEFAULT 0,
    output_tokens    UInt32 DEFAULT 0,
    cost_usd         Decimal64(8) DEFAULT 0,
    finish_reason    LowCardinality(String) DEFAULT '',
    -- content: small inline, large via blob pointer
    input_preview    String,          -- truncated
    output_preview   String,          -- truncated
    input_blob_ref   String DEFAULT '',   -- s3 key
    output_blob_ref  String DEFAULT '',
    content_sha256   String DEFAULT '',
    -- security
    taint            Enum8('system'=1,'user'=2,'untrusted_external'=3,'model'=4) DEFAULT 'model',
    taint_source     String DEFAULT '',
    taint_influenced Bool DEFAULT false,   -- downstream of taint frontier
    attributes       Map(String, String),
    event_ts         DateTime64(3)
) ENGINE = ReplacingMergeTree(event_ts)
PARTITION BY toYYYYMM(start_time)
ORDER BY (project_id, toDate(start_time), trace_id, observation_id);

-- security_events
CREATE TABLE security_events (
    project_id       LowCardinality(String),
    event_id         String,
    trace_id         String,
    observation_id   String DEFAULT '',      -- '' = trace-level finding
    detected_at      DateTime64(3),
    category         Enum8('direct_injection'=1,'jailbreak'=2,'indirect_injection'=3,
                           'exfiltration'=4,'excessive_agency'=5,'rag_poisoning'=6,
                           'prompt_leak'=7,'pii_egress'=8,'canary_triggered'=9),
    severity         Enum8('info'=1,'low'=2,'medium'=3,'high'=4,'critical'=5),
    outcome          Enum8('attempted'=1,'succeeded'=2,'blocked'=3,'unknown'=0),
    score            Float32,                 -- 0..100
    -- provenance: which layers fired and why
    l1_rules         Array(String),
    l2_scores        Map(String, Float32),    -- model -> score
    l3_verdict       String DEFAULT '',       -- judge JSON
    l4_signals       Array(String),           -- e.g. ['instruction_echo','exfil_flow']
    evidence_excerpt String,                  -- quoted matched content (truncated)
    content_sha256   String DEFAULT '',
    incident_id      String DEFAULT '',
    analyst_verdict  Enum8('unreviewed'=0,'confirmed'=1,'false_positive'=2) DEFAULT 'unreviewed',
    event_ts         DateTime64(3)
) ENGINE = ReplacingMergeTree(event_ts)
PARTITION BY toYYYYMM(detected_at)
ORDER BY (project_id, toDate(detected_at), severity, event_id);

-- scores (evals, user feedback, security scores)
CREATE TABLE scores (
    project_id      LowCardinality(String),
    score_id        String,
    trace_id        String,
    observation_id  String DEFAULT '',
    name            LowCardinality(String),   -- e.g. 'helpfulness', 'sec.injection_risk'
    value           Float64,
    string_value    String DEFAULT '',
    source          Enum8('api'=1,'eval'=2,'annotation'=3,'security'=4),
    comment         String DEFAULT '',
    timestamp       DateTime64(3),
    event_ts        DateTime64(3)
) ENGINE = ReplacingMergeTree(event_ts)
PARTITION BY toYYYYMM(timestamp)
ORDER BY (project_id, toDate(timestamp), trace_id, score_id);
```

Plus materialized views for dashboard aggregates: hourly
`security_events_by_category`, `cost_by_model_daily`, `trace_latency_daily`.

## PostgreSQL (transactional plane)

```
organizations(id, name, ...)
projects(id, org_id, name, retention_days, ...)
api_keys(id, project_id, public_key, secret_hash, scopes, ...)
users / memberships / roles
prompts(id, project_id, name) / prompt_versions(id, prompt_id, version, content, labels[])
detection_configs(project_id, yaml, version, updated_by)
suppression_rules(id, project_id, rule_id, scope_type, scope_value, reason, created_by)
canaries(id, project_id, token_hash, label, created_at, last_triggered_at)
incidents(id, project_id, title, status, severity, assignee, created_at)
audit_log(id, actor, action, target, at)
attack_corpus(id, project_id NULL=global, embedding vector(768), label, source, content_ref)
```

`attack_corpus` uses pgvector; global rows ship with the product (public
attack datasets), project rows accumulate from confirmed incidents.

## Blob storage layout (S3/MinIO)

```
{project_id}/traces/{yyyy-mm-dd}/{trace_id}/{observation_id}.{input|output}.json.zst
```

Payloads compressed, encrypted at rest, deleted by retention job when the
project TTL expires (ClickHouse TTL and S3 lifecycle must agree).

## Retention & privacy

- Per-project retention (days) applies to blobs + ClickHouse rows.
- Optional ingestion-time PII redaction (Presidio) — store redacted, flag
  `redacted=true`.
- `security_events.evidence_excerpt` is capped and may be redacted while the
  event metadata is retained longer than payloads (security teams often need
  event history beyond content retention).
