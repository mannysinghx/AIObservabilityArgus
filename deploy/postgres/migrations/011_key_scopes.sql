-- Argus: make api_keys.scopes mean something.
--
-- The column has existed since 001 and was written on every key creation, but
-- never read. Every key was therefore an ingest key in name and an unlimited
-- key in fact — which mattered little while ingest was the only API, and
-- matters a great deal now that there is a read API.
--
-- Scopes:
--   ingest  write telemetry (the zero-config key pasted into init())
--   read    read this project's traces, observations and security events
--
-- An ingest key belongs in application code and gets deployed everywhere; a read
-- key belongs in a dashboard or a SIEM connector. Keeping them separable is what
-- stops a leaked telemetry key — the one with the widest blast radius by
-- deployment count — from also being able to read back everything it ever sent.
--
-- A label so a key can be identified in the UI without revealing it.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS label      TEXT;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

-- Existing keys keep exactly the access they already had. Granting them `read`
-- here would silently widen every key in every deployment during an upgrade —
-- the opposite of what this migration is for.
UPDATE api_keys SET scopes = ARRAY['ingest'] WHERE scopes IS NULL OR cardinality(scopes) = 0;

CREATE INDEX IF NOT EXISTS idx_api_keys_project_active
    ON api_keys(project_id) WHERE revoked_at IS NULL;
