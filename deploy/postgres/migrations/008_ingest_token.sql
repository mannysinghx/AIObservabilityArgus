-- Argus: single-value ingest key. Collapses the public/secret pair into one
-- opaque, write-only token (`ak_live_…`) that a customer can paste directly into
-- init() — no environment variables required. Stored hashed; the raw token is
-- shown once at creation. The old public/secret pair still works (back-compat).

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS token_hash TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_token
    ON api_keys(token_hash) WHERE token_hash IS NOT NULL;
