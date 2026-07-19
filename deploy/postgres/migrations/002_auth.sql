-- Argus Phase 2: user accounts, sessions, and org membership.
-- Turns the platform multi-tenant: a person signs in, and the dashboard shows
-- only the organizations (customers) they belong to. Idempotent — safe to
-- re-run on every deploy alongside 001_init.

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,             -- scrypt: "<salt-hex>:<derived-hex>"
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- user <-> organization, with a role. An org can have many members; a user can
-- belong to many orgs (agencies, consultants, our own team).
CREATE TABLE IF NOT EXISTS memberships (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'owner',   -- owner | admin | member | viewer
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, org_id)
);
CREATE INDEX IF NOT EXISTS idx_memberships_org ON memberships(org_id);

-- Server-side sessions: the raw token lives only in the user's httpOnly cookie;
-- we store just its sha256 so a DB leak can't be replayed as a login.
CREATE TABLE IF NOT EXISTS user_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);
