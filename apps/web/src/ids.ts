/**
 * One sanitizer for tenant-scoping identifiers.
 *
 * This exists because the authorization check and the data query MUST agree on
 * exactly which project id they are talking about. They used to sanitize with
 * different character classes (auth stripped `_`, the query kept it), so a
 * crafted `?project=` could be authorized as one id and then queried as a
 * different one. Any divergence there is a cross-tenant read, so both sides now
 * call this and nothing else.
 */
export function safeProjectId(projectId: string | undefined | null): string {
  return String(projectId ?? "").replace(/[^a-zA-Z0-9_-]/g, "");
}
