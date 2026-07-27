-- Argus: activate canary tokens.
--
-- The table has existed since 001 but nothing ever wrote to it, and nothing
-- read it: the detection service accepted a `canaries` argument that the worker
-- never populated. This migration adds the columns needed to actually run the
-- feature, and to run it without keeping every canary in plaintext.
--
-- Two kinds, because they have genuinely different threat models:
--
--   generated — Argus mints `argus-cnry-<random>`. Because the format is known,
--               detection can extract candidates from span content and compare
--               *hashes*, so the raw value never has to be stored or shipped to
--               the detection service. This is the default and the one to use.
--
--   custom    — the customer plants a string of their own (a fake employee
--               record, a decoy API key already embedded in their docs). There
--               is no way to match an arbitrary string without holding it, so
--               `value` stores it in the clear. The UI says so plainly; the
--               alternative is silently pretending it's protected.
--
-- Idempotent.

ALTER TABLE canaries ADD COLUMN IF NOT EXISTS kind          TEXT NOT NULL DEFAULT 'generated';
ALTER TABLE canaries ADD COLUMN IF NOT EXISTS value         TEXT;      -- raw, custom canaries only
ALTER TABLE canaries ADD COLUMN IF NOT EXISTS trigger_count INT NOT NULL DEFAULT 0;
ALTER TABLE canaries ADD COLUMN IF NOT EXISTS revoked_at    TIMESTAMPTZ;
ALTER TABLE canaries ADD COLUMN IF NOT EXISTS created_by    TEXT;

-- token_hash is NOT NULL from 001, but a custom canary has no generated token.
-- Store the hash of its raw value there instead so the column keeps its meaning
-- ("the identity of this canary") for both kinds.
CREATE INDEX IF NOT EXISTS idx_canaries_project ON canaries(project_id) WHERE revoked_at IS NULL;

-- A canary is only useful if it is unique — two projects sharing one token means
-- an alert can't say whose data leaked.
CREATE UNIQUE INDEX IF NOT EXISTS idx_canaries_token ON canaries(token_hash);
