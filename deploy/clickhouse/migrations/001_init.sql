-- Argus ClickHouse schema — Phase 1.
-- Mirrors docs/05-data-model.md. Runs on first container init.
-- The server creates database `argus` before init scripts run; the entrypoint
-- executes these against `default`, so target the argus db explicitly.
CREATE DATABASE IF NOT EXISTS argus;
USE argus;

CREATE TABLE IF NOT EXISTS traces
(
    project_id        LowCardinality(String),
    trace_id          String,
    session_id        String DEFAULT '',
    user_id           String DEFAULT '',
    name              String,
    timestamp         DateTime64(3),
    environment       LowCardinality(String) DEFAULT 'default',
    release           String DEFAULT '',
    metadata          Map(String, String),
    tags              Array(String),
    -- security rollups (denormalized for fast dashboard queries)
    sec_max_severity  Enum8('none'=0,'info'=1,'low'=2,'medium'=3,'high'=4,'critical'=5) DEFAULT 'none',
    sec_event_count   UInt32 DEFAULT 0,
    sec_taint_present  UInt8 DEFAULT 0,
    event_ts          DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(event_ts)
PARTITION BY toYYYYMM(timestamp)
ORDER BY (project_id, toDate(timestamp), trace_id);

CREATE TABLE IF NOT EXISTS observations
(
    project_id        LowCardinality(String),
    trace_id          String,
    observation_id    String,
    parent_id         String DEFAULT '',
    type              Enum8('span'=1,'generation'=2,'retrieval'=3,'tool'=4,'event'=5),
    name              String,
    start_time        DateTime64(3),
    end_time          Nullable(DateTime64(3)),
    -- GenAI semantic conventions
    model             LowCardinality(String) DEFAULT '',
    provider          LowCardinality(String) DEFAULT '',
    input_tokens      UInt32 DEFAULT 0,
    output_tokens     UInt32 DEFAULT 0,
    cost_usd          Decimal64(8) DEFAULT 0,
    finish_reason     LowCardinality(String) DEFAULT '',
    -- content: small inline preview, large via blob pointer
    input_preview     String DEFAULT '',
    output_preview    String DEFAULT '',
    input_blob_ref    String DEFAULT '',
    output_blob_ref   String DEFAULT '',
    content_sha256    String DEFAULT '',
    -- security
    taint             Enum8('system'=1,'user'=2,'untrusted_external'=3,'model'=4) DEFAULT 'model',
    taint_source      String DEFAULT '',
    taint_influenced  UInt8 DEFAULT 0,
    attributes        Map(String, String),
    event_ts          DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(event_ts)
PARTITION BY toYYYYMM(start_time)
ORDER BY (project_id, toDate(start_time), trace_id, observation_id);

CREATE TABLE IF NOT EXISTS security_events
(
    project_id        LowCardinality(String),
    event_id          String,
    trace_id          String,
    observation_id    String DEFAULT '',   -- '' = trace-level finding
    detected_at       DateTime64(3),
    category          Enum8('direct_injection'=1,'jailbreak'=2,'indirect_injection'=3,
                            'exfiltration'=4,'excessive_agency'=5,'rag_poisoning'=6,
                            'prompt_leak'=7,'pii_egress'=8,'canary_triggered'=9,
                            'obfuscation'=10),
    severity          Enum8('info'=1,'low'=2,'medium'=3,'high'=4,'critical'=5),
    outcome           Enum8('unknown'=0,'attempted'=1,'succeeded'=2,'blocked'=3),
    score             Float32,             -- 0..100
    -- provenance: which layers fired and why
    l1_rules          Array(String),
    l2_scores         Map(String, Float32),
    l3_verdict        String DEFAULT '',
    l4_signals        Array(String),
    evidence_excerpt  String DEFAULT '',
    content_sha256    String DEFAULT '',
    incident_id       String DEFAULT '',
    analyst_verdict   Enum8('unreviewed'=0,'confirmed'=1,'false_positive'=2) DEFAULT 'unreviewed',
    event_ts          DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(event_ts)
PARTITION BY toYYYYMM(detected_at)
ORDER BY (project_id, toDate(detected_at), severity, event_id);

CREATE TABLE IF NOT EXISTS scores
(
    project_id        LowCardinality(String),
    score_id          String,
    trace_id          String,
    observation_id    String DEFAULT '',
    name              LowCardinality(String),
    value             Float64,
    string_value      String DEFAULT '',
    source            Enum8('api'=1,'eval'=2,'annotation'=3,'security'=4),
    comment           String DEFAULT '',
    timestamp         DateTime64(3),
    event_ts          DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(event_ts)
PARTITION BY toYYYYMM(timestamp)
ORDER BY (project_id, toDate(timestamp), trace_id, score_id);
