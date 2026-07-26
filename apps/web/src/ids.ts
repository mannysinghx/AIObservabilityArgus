/**
 * One sanitizer for tenant-scoping identifiers.
 *
 * This exists because the authorization check and the data query MUST agree on
 * exactly which project id they are talking about. They used to sanitize with
 * different character classes (auth stripped `_`, the query kept it), so a
 * crafted `?project=` could be authorized as one id and then queried as a
 * different one. Any divergence there is a cross-tenant read, so both sides now
 * call this and nothing else.
 *
 * It validates rather than merely strips. Stripping alone turns `' OR 1=1 --`
 * into `OR11--`: harmless as a ClickHouse literal, but it is then handed to
 * Postgres as a `uuid` parameter, which raises 22P02 and surfaces as a 500 with
 * the database's own error text in the body. Project ids are `gen_random_uuid()`
 * values and always have been, so anything that isn't a UUID cannot name a real
 * project — returning "" makes every caller fail closed (403, or `AND 1 = 0`)
 * instead of failing loudly with internals attached.
 */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function safeProjectId(projectId: string | undefined | null): string {
  const stripped = String(projectId ?? "").replace(/[^a-zA-Z0-9_-]/g, "");
  return UUID.test(stripped) ? stripped : "";
}

/** True when the value names a syntactically possible project. */
export function isProjectId(projectId: string | undefined | null): boolean {
  return safeProjectId(projectId) !== "";
}
