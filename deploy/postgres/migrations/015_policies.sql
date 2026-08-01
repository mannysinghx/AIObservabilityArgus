-- Argus: governance policies (Phase 4b of the InjectGuard merge).
--
-- The policy *evaluator* has been in the detection service since Phase 1 — a
-- deterministic, fail-closed matcher over dotted-path conditions. What it never
-- had here was anywhere to keep the policies, so nothing could actually be
-- enforced. This is that storage.
--
-- A policy asks a question about the application's current state ("is this
-- public AND does it have open critical findings?") and returns an action. The
-- actions are deliberately advisory-to-gating rather than runtime blocking:
-- this evaluates against a rich, slow-moving picture (findings, architecture,
-- approval state), which is the opposite of what the inline gateway does with
-- one message and a 300ms budget. Gateway blocking is configured separately in
-- detection_configs.gateway; see packages/shared/src/gateway.ts for why the two
-- are not the same mechanism.
CREATE TABLE IF NOT EXISTS assessment_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    -- Stable identifier for the rule, unique per project. Lets a policy be
    -- referenced in an evaluation record or an audit line by something more
    -- durable than a generated UUID.
    policy_key      TEXT NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    -- The condition map, in the evaluator's grammar: dotted path → matcher,
    -- implicit AND. Stored verbatim so the engine remains the single authority
    -- on what it means — Postgres never interprets this.
    conditions      JSONB NOT NULL DEFAULT '{}',
    -- warn | block_deployment | block_assessment_approval
    action          TEXT NOT NULL DEFAULT 'warn',
    result_severity TEXT NOT NULL DEFAULT 'medium',
    message         TEXT NOT NULL DEFAULT '',
    -- Disabled rather than deleted is the common case: a policy that fired at a
    -- bad moment gets switched off, and the team still wants to see it existed.
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, policy_key)
);
CREATE INDEX IF NOT EXISTS idx_assessment_policies_project
    ON assessment_policies(project_id, created_at DESC);
