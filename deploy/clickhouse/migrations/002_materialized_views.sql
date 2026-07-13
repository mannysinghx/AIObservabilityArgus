-- Dashboard aggregates. Materialized views keep the Threat Center fast.
USE argus;

CREATE TABLE IF NOT EXISTS security_events_by_hour
(
    project_id   LowCardinality(String),
    hour         DateTime,
    category     Enum8('direct_injection'=1,'jailbreak'=2,'indirect_injection'=3,
                       'exfiltration'=4,'excessive_agency'=5,'rag_poisoning'=6,
                       'prompt_leak'=7,'pii_egress'=8,'canary_triggered'=9,'obfuscation'=10),
    severity     Enum8('info'=1,'low'=2,'medium'=3,'high'=4,'critical'=5),
    events       UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (project_id, hour, category, severity);

CREATE MATERIALIZED VIEW IF NOT EXISTS security_events_by_hour_mv
TO security_events_by_hour AS
SELECT
    project_id,
    toStartOfHour(detected_at) AS hour,
    category,
    severity,
    count() AS events
FROM security_events
GROUP BY project_id, hour, category, severity;

CREATE TABLE IF NOT EXISTS cost_by_model_daily
(
    project_id    LowCardinality(String),
    day           Date,
    model         LowCardinality(String),
    input_tokens  UInt64,
    output_tokens UInt64,
    cost_usd      Decimal64(8),
    observations  UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (project_id, day, model);

CREATE MATERIALIZED VIEW IF NOT EXISTS cost_by_model_daily_mv
TO cost_by_model_daily AS
SELECT
    project_id,
    toDate(start_time) AS day,
    model,
    sum(input_tokens)  AS input_tokens,
    sum(output_tokens) AS output_tokens,
    sum(cost_usd)      AS cost_usd,
    count()            AS observations
FROM observations
WHERE type = 'generation'
GROUP BY project_id, day, model;
