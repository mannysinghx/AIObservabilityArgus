-- Argus: record which assessment findings are backed by runtime evidence.
--
-- Phase 4 of the InjectGuard merge closes the loop between the two halves of
-- the platform. Until now an assessment finding was a statement about how the
-- application is built; the runtime side separately knew which attacks had
-- actually been attempted against it. When a finding's attack class appears in
-- this project's security events, the finding stops being theoretical — its
-- likelihood factor goes to maximum and the rationale says why.
--
-- Stored as a column rather than inferred from the risk JSON at read time
-- because it is the field worth filtering and sorting a queue by: "show me the
-- weaknesses someone is already probing" is the question this whole merge was
-- meant to be able to answer.
ALTER TABLE assessment_findings
    ADD COLUMN IF NOT EXISTS observed_in_production BOOLEAN NOT NULL DEFAULT false;

-- Partial index: the interesting set is always the true one, and it is small.
CREATE INDEX IF NOT EXISTS idx_assessment_findings_observed
    ON assessment_findings(project_id, created_at DESC)
    WHERE observed_in_production;
