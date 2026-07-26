/**
 * The single definition of "what text of a span is security-relevant", and its
 * fingerprint.
 *
 * This used to be copy-pasted in three places (trace worker, detection client,
 * security worker). That mattered more than ordinary duplication: the stored
 * `content_sha256` is the join key for cross-trace poisoned-source correlation,
 * so if the storage side and the scanning side ever disagree about which text
 * they hashed, the correlation silently matches nothing. One function, one hash.
 */
import { createHash } from "node:crypto";

export interface ContentBearing {
  type?: string;
  input?: string;
  output?: string;
}

/**
 * The analyzable body of a span:
 *  - generation/retrieval: the produced text (completion / retrieved chunk)
 *  - tool: BOTH arguments and result — exfiltration lives in the arguments
 *    (recipient, body, URL), which a result-only view misses
 *  - anything else: whatever text is present
 */
export function contentOf(o: ContentBearing): string {
  if (o.type === "generation" || o.type === "retrieval") return o.output || o.input || "";
  return [o.input, o.output].filter(Boolean).join("\n");
}

export function sha256Hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

/** Fingerprint of a span's analyzable content. Empty content hashes to "" so a
 *  contentless span never collides with every other contentless span in the
 *  cross-trace correlation query (which groups by this value). */
export function contentSha256(o: ContentBearing): string {
  const text = contentOf(o);
  return text ? sha256Hex(text) : "";
}
