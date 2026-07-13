-- Durable, complete storage for future analysis.
-- Previous schema stored only truncated previews inline; this adds full,
-- untruncated content columns and an append-only raw event log so historical
-- traffic can be re-scored by future detector versions.
USE argus;

-- Full (untruncated) content alongside the fast list-view previews.
ALTER TABLE observations ADD COLUMN IF NOT EXISTS input_full  String DEFAULT '';
ALTER TABLE observations ADD COLUMN IF NOT EXISTS output_full String DEFAULT '';

-- Immutable archive of every ingested event, exactly as received. Enables
-- reprocessing history when L2/L3/L4 improve, and forensic replay. No TTL by
-- default (retention is applied per-project by the retention job, not here).
CREATE TABLE IF NOT EXISTS raw_events
(
    project_id   LowCardinality(String),
    event_id     String,
    kind         Enum8('trace'=1,'observation'=2),
    trace_id     String DEFAULT '',
    received_at  DateTime64(3),
    payload      String          -- full JSON envelope as ingested
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(received_at)
ORDER BY (project_id, received_at, event_id);
