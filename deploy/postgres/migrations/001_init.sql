-- Argus Postgres schema — Phase 1 (transactional metadata).
-- See docs/05-data-model.md.

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
-- pgvector is added in Phase 2 (attack corpus); guarded so init won't fail if absent.
DO $$ BEGIN
  CREATE EXTENSION IF NOT EXISTS vector;
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'pgvector not installed; attack_corpus.embedding disabled until Phase 2';
END $$;

CREATE TABLE IF NOT EXISTS organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    branding    JSONB NOT NULL DEFAULT '{}',      -- white-label token overrides (docs/08)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    retention_days INT NOT NULL DEFAULT 30,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id   UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    public_key   TEXT NOT NULL UNIQUE,       -- pk-...
    secret_hash  TEXT NOT NULL,              -- bcrypt/argon2 of sk-...
    scopes       TEXT[] NOT NULL DEFAULT ARRAY['ingest'],
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);

-- Detection config per project (docs/04 §Detection config). Stored as JSONB so
-- the YAML in the docs maps 1:1 and can evolve without migrations.
CREATE TABLE IF NOT EXISTS detection_configs (
    project_id  UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    config      JSONB NOT NULL,
    version     INT NOT NULL DEFAULT 1,
    updated_by  TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS suppression_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    rule_id     TEXT,                        -- L1 rule id to suppress (nullable)
    scope_type  TEXT NOT NULL,               -- 'tool' | 'source' | 'rule' | 'project'
    scope_value TEXT NOT NULL DEFAULT '',
    reason      TEXT,
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS canaries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,           -- store hash; raw token given once
    label           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_triggered_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS incidents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open',   -- open | ack | resolved
    severity    TEXT NOT NULL DEFAULT 'medium',
    assignee    TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id       BIGSERIAL PRIMARY KEY,
    actor    TEXT,
    action   TEXT NOT NULL,
    target   TEXT,
    at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_suppression_project ON suppression_rules(project_id);
CREATE INDEX IF NOT EXISTS idx_incidents_project ON incidents(project_id, status);

-- (No seed data — the platform holds only real, self-onboarded customer
-- projects. A dev org/project/key used to be seeded here; removed so re-running
-- migrations on deploy can never re-introduce demo data.)
