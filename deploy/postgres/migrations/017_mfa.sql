-- Argus: two-factor authentication (TOTP, RFC 6238). Idempotent.
--
-- Three tables rather than three columns on `users`, because the values have
-- three different lifetimes: the shared secret is long-lived, a recovery code
-- is single-use, and a login challenge lives for five minutes.
--
-- The secret is the one credential in this schema that CANNOT be hashed.
-- Verifying a TOTP code means recomputing HMAC-SHA1 over the shared secret, so
-- it has to be recoverable. `secret_enc` therefore holds AES-256-GCM ciphertext
-- when ARGUS_MFA_KEY is configured, and the bare base32 secret when it is not
-- (see totp.ts for the format and why the unset case is the default). Recovery
-- codes and challenge tokens are one-way hashed like every other credential
-- here — only the secret gets this exemption, and only because the algorithm
-- requires it.

CREATE TABLE IF NOT EXISTS user_mfa (
    user_id        UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_enc     TEXT NOT NULL,
    -- NULL means enrolment was started but never confirmed with a code. Such a
    -- row must never gate a login: a half-finished setup that locked someone
    -- out would be worse than no MFA at all.
    confirmed_at   TIMESTAMPTZ,
    -- Replay guard. A TOTP code stays valid for its whole 30-second step (and
    -- we accept one step of clock drift either side), so without this the same
    -- six digits work more than once inside that window. Storing the last
    -- accepted step and refusing anything <= it closes that.
    last_used_step BIGINT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    code_hash  TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    used_at    TIMESTAMPTZ,               -- single-use; kept after use as an audit trace
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON mfa_recovery_codes(user_id);

-- The half-authenticated state between "password was correct" and "second
-- factor was correct". Deliberately its own short-lived token rather than an
-- early session cookie: until the second factor lands there is no session, so
-- there is nothing for a stolen password alone to ride on.
CREATE TABLE IF NOT EXISTS mfa_challenges (
    token_hash TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user ON mfa_challenges(user_id);
