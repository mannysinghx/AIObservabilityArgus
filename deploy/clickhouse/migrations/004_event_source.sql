-- Argus: where a security event came from.
--
-- Until now every row in security_events was produced the same way: the worker
-- scanned content Argus had itself ingested, so provenance was implicit. The
-- Browser Guard extension breaks that assumption. It scans a prompt locally, in
-- someone's browser, and reports only the verdict — no prompt text ever leaves
-- the machine, which is the whole point of it. Those findings are worth having,
-- but they are not the same kind of evidence:
--
--   server            the detection pipeline scanned content Argus holds; the
--                     trace is right there and the finding can be re-derived.
--   browser_extension a client asserted this. There is no content to re-check,
--                     and the report is only as trustworthy as the install.
--
-- An analyst triaging an incident needs to know which they are looking at, and
-- a metadata-only ALTER is cheap on a ReplacingMergeTree. Defaulting to
-- 'server' keeps every existing row and every existing INSERT correct.
ALTER TABLE security_events
    ADD COLUMN IF NOT EXISTS source LowCardinality(String) DEFAULT 'server';
