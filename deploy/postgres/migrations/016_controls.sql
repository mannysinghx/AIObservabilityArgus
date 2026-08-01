-- Argus: governance controls (InjectGuard merge — controls port).
--
-- A control is a standing commitment ("retrieved content is treated as
-- untrusted", "writes require human approval") that an auditor will ask about
-- and someone has to own. Findings say what is wrong today; controls say what
-- you have decided to always be true, who owns it, and when it was last
-- checked. Compliance conversations need both.
--
-- Rows are per project rather than per organization: the answer to "do writes
-- require approval?" is a property of an application, not a company, and one
-- team's shipped control is another team's gap. The baseline catalog is copied
-- in on demand (see controls.ts) so each project can then diverge.
CREATE TABLE IF NOT EXISTS governance_controls (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id       UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    control_key      TEXT NOT NULL,          -- GOV-1, PE-1, … stable across projects
    domain           TEXT NOT NULL DEFAULT '',
    objective        TEXT NOT NULL DEFAULT '',
    description      TEXT NOT NULL DEFAULT '',
    -- not_implemented | in_progress | implemented | not_applicable
    status           TEXT NOT NULL DEFAULT 'not_implemented',
    owner            TEXT NOT NULL DEFAULT '',
    review_frequency TEXT NOT NULL DEFAULT 'quarterly',
    -- Free text rather than a structured evidence table: at this stage the
    -- useful artifact is a link to the PR, runbook or ticket that proves it.
    -- A full evidence-attachment model can come when someone needs one.
    evidence         TEXT NOT NULL DEFAULT '',
    frameworks       JSONB NOT NULL DEFAULT '[]',
    last_reviewed_at TIMESTAMPTZ,
    updated_by       TEXT,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, control_key)
);
CREATE INDEX IF NOT EXISTS idx_governance_controls_project
    ON governance_controls(project_id, domain);
