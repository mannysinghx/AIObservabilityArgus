-- Argus: enrich the audit_log for a real audit trail. The base table (001) has
-- actor/action/target/at; add the columns a viewer needs. org_id is intentionally
-- NOT a foreign key so the trail survives a company deletion. Idempotent.

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS actor_email TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS org_id      UUID;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS target_type TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS metadata    JSONB NOT NULL DEFAULT '{}';
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS ip          TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_log_at  ON audit_log(at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_org ON audit_log(org_id, at DESC);
