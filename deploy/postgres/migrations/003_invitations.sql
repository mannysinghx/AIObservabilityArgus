-- Argus Phase 3: team invitations. A pending invite lets someone join an org
-- with a role; it activates automatically when they sign up / sign in with the
-- invited email (no email delivery required — a shareable link carries the token).

CREATE TABLE IF NOT EXISTS invitations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member',   -- admin | member | viewer
    token       TEXT NOT NULL UNIQUE,
    invited_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    accepted_at TIMESTAMPTZ,
    UNIQUE (org_id, email)
);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(lower(email)) WHERE accepted_at IS NULL;
