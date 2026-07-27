/**
 * Response security headers for the dashboard.
 *
 * Argus renders attacker-authored text by design: a prompt-injection payload is
 * the *content* of the product. Every render path escapes, but "all forty
 * innerHTML call sites remembered to call esc()" is a property maintained by
 * reviewer attention, and reviewer attention is not a security control. CSP is
 * the backstop that makes a missed escape a broken layout instead of a session
 * theft.
 *
 * `script-src 'self'` with no 'unsafe-inline': every page loads external JS
 * only, so injected <script> and injected on*= attributes both fail to run.
 * `style-src` does allow 'unsafe-inline' — the dashboard uses inline style
 * attributes extensively for bar widths and severity colours, and CSS injection
 * is not the threat we are containing here.
 */
import type { FastifyReply, FastifyRequest } from "fastify";

export interface CspOptions {
  /** sha256 hashes ('sha256-…') of inline scripts allowed on this response. */
  scriptHashes?: string[];
}

function csp(opts: CspOptions = {}): string {
  const script = ["'self'", ...(opts.scriptHashes ?? []).map((h) => `'${h}'`)].join(" ");
  return [
    "default-src 'self'",
    `script-src ${script}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    // The dashboard only ever talks to its own origin. This is what stops an
    // injected payload from posting a stolen trace to an attacker's collector.
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'none'",
    "object-src 'none'",
  ].join("; ");
}

/** True when the request reached us over TLS (directly or via a proxy). */
function isHttps(req: FastifyRequest): boolean {
  if (req.protocol === "https") return true;
  const xf = req.headers["x-forwarded-proto"];
  const proto = Array.isArray(xf) ? xf[0] : xf;
  return (proto ?? "").split(",")[0].trim() === "https";
}

/**
 * Apply the standard header set. Call from an onSend/onRequest hook.
 * `scriptHashes` lets one specific page (the marketing demo) keep its inline
 * script without weakening the policy for the pages that hold customer data.
 */
export function applySecurityHeaders(
  req: FastifyRequest,
  reply: FastifyReply,
  opts: CspOptions = {},
): void {
  reply.header("content-security-policy", csp(opts));
  reply.header("x-content-type-options", "nosniff");
  reply.header("x-frame-options", "DENY");
  reply.header("referrer-policy", "no-referrer");
  reply.header("cross-origin-opener-policy", "same-origin");
  reply.header("permissions-policy", "geolocation=(), microphone=(), camera=(), payment=()");
  // Only assert HSTS on connections that are already TLS — sending it over
  // plain HTTP is ignored by browsers and would pin a broken scheme in dev.
  if (isHttps(req)) {
    reply.header("strict-transport-security", "max-age=31536000; includeSubDomains");
  }
}
