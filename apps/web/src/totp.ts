/**
 * TOTP (RFC 6238) over HMAC-SHA1, the base32 codec every authenticator app
 * expects (RFC 4648 §6), and at-rest protection for the stored secret.
 *
 * Pure functions over `node:crypto` — no database, no Fastify, no I/O. That
 * split is deliberate: it means the entire code-verification path can be tested
 * against the RFC's own published vectors without standing anything up, and
 * mfa.ts is left holding only storage decisions. Same pure/impure boundary as
 * queryIntent.ts.
 *
 * SHA-1 is not an oversight. RFC 6238's default MAC is HMAC-SHA1 and it is what
 * Google Authenticator, 1Password, Authy and every QR scanner in the wild
 * implement. HMAC's security does not rest on the hash's collision resistance,
 * and picking SHA-256 here would mint QR codes that most authenticator apps
 * cannot read. Interoperability wins, and the RFC agrees.
 */
import { createHmac, createHash, randomBytes, timingSafeEqual, createCipheriv, createDecipheriv, scryptSync } from "node:crypto";

/** RFC 6238's default time step. Every authenticator app assumes 30s. */
export const STEP_SECONDS = 30;
/** Codes are 6 digits by default; the `digits` parameter exists for the RFC's 8-digit test vectors. */
export const DIGITS = 6;
/**
 * How many steps of clock drift to accept either side of now. One step (±30s)
 * is the usual compromise: it forgives a phone whose clock is slightly off
 * without widening the window an attacker can guess into. With the replay guard
 * in mfa.ts, a code accepted at step N also burns every step <= N.
 */
export const DRIFT_STEPS = 1;

// ---------------- base32 (RFC 4648, no padding on output) ----------------

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/**
 * Decode base32. Tolerant of what humans and authenticator apps actually
 * produce: lowercase, spaces, and `=` padding are all accepted. Anything else
 * throws rather than silently decoding to the wrong secret.
 */
export function base32Decode(input: string): Buffer {
  const clean = String(input || "").toUpperCase().replace(/[\s=]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error("invalid base32 character");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/**
 * A fresh secret. 20 bytes (160 bits) is what RFC 4226 §4 recommends and what
 * every authenticator expects; it encodes to 32 base32 characters.
 */
export function generateSecret(bytes = 20): string {
  return base32Encode(randomBytes(bytes));
}

// ---------------- HOTP / TOTP ----------------

function counterBuffer(counter: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(counter));
  return b;
}

/** RFC 4226 HOTP with the standard dynamic-truncation step. */
export function hotp(secret: Buffer, counter: number, digits = DIGITS): string {
  const mac = createHmac("sha1", secret).update(counterBuffer(counter)).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, "0");
}

/** The time step a given moment falls in. Exported so the replay guard can name it. */
export function stepFor(atMs: number = Date.now(), stepSeconds = STEP_SECONDS): number {
  return Math.floor(atMs / 1000 / stepSeconds);
}

/** The code an authenticator would show for this secret at this moment. */
export function totpCode(
  secretB32: string,
  atMs: number = Date.now(),
  digits = DIGITS,
  stepSeconds = STEP_SECONDS,
): string {
  return hotp(base32Decode(secretB32), stepFor(atMs, stepSeconds), digits);
}

/** Length-safe, constant-time string compare. Length itself is not a secret here. */
function sameCode(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

export interface TotpResult {
  ok: boolean;
  /** The time step that matched — the caller stores this to refuse replays. */
  step: number;
}

/**
 * Check a user-supplied code against the secret, allowing ±DRIFT_STEPS of clock
 * drift. Returns the matching step so the caller can enforce monotonicity;
 * without that, every code stays reusable for its full window.
 *
 * `minStep` lets the caller refuse anything at or below an already-used step.
 */
export function verifyTotp(
  secretB32: string,
  code: string,
  opts: { atMs?: number; drift?: number; digits?: number; minStep?: number | null } = {},
): TotpResult {
  const digits = opts.digits ?? DIGITS;
  const drift = opts.drift ?? DRIFT_STEPS;
  const presented = String(code || "").replace(/\s/g, "");
  if (!/^\d+$/.test(presented) || presented.length !== digits) return { ok: false, step: -1 };

  let secret: Buffer;
  try {
    secret = base32Decode(secretB32);
  } catch {
    return { ok: false, step: -1 };
  }

  const now = stepFor(opts.atMs ?? Date.now());
  // Walk oldest-to-newest so a code valid in two windows resolves to the
  // earliest — the conservative choice for the replay guard.
  for (let s = now - drift; s <= now + drift; s++) {
    if (opts.minStep != null && s <= opts.minStep) continue;
    if (sameCode(hotp(secret, s, digits), presented)) return { ok: true, step: s };
  }
  return { ok: false, step: -1 };
}

/**
 * The `otpauth://` URI an authenticator scans. The label carries the account
 * and the issuer appears twice by convention — once in the path (for apps that
 * only read the label) and once as a parameter (for apps that read both).
 */
export function otpauthUrl(email: string, secretB32: string, issuer = "Argus"): string {
  const label = encodeURIComponent(`${issuer}:${email}`);
  const params = new URLSearchParams({
    secret: secretB32,
    issuer,
    algorithm: "SHA1",
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// ---------------- recovery codes ----------------

/**
 * Human-transcribable recovery codes. Base32 alphabet (no 0/1/8/O/I/L to
 * confuse), grouped for readability. These are high-entropy random values, not
 * passwords, so a plain SHA-256 is the right store — key stretching defends
 * against guessing a low-entropy input, which this isn't.
 */
export function generateRecoveryCodes(count = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const raw = base32Encode(randomBytes(10)).slice(0, 10);
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5, 10)}`);
  }
  return codes;
}

/** Normalize then hash. Users retype these, so case and dashes must not matter. */
export function hashRecoveryCode(code: string): string {
  const norm = String(code || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  return createHash("sha256").update(norm).digest("hex");
}

// ---------------- secret at rest ----------------
//
// A TOTP secret cannot be hashed (see 017_mfa.sql), so the only lever left is
// encrypting it. ARGUS_MFA_KEY buys exactly one thing: a database compromise
// that does not also include the application environment — a leaked backup, a
// read-only SQL injection, a snapshot handed to a contractor — yields
// ciphertext instead of live second factors. It does NOT defend against an
// attacker who already has the app's env, and it is not pretending to.
//
// When the key is unset the secret is stored as plain base32. That is the
// deliberate default: a self-hoster who never sets a variable gets working MFA
// rather than a broken install, and rotating or losing the key would lock every
// enrolled user out of their own account. Encrypted rows are tagged so both
// formats can coexist, which is what makes turning the key on later a no-op for
// existing enrolments.

const ENC_PREFIX = "enc.v1.";

function encKey(): Buffer | null {
  const raw = process.env.ARGUS_MFA_KEY;
  if (!raw) return null;
  // Fixed salt: the key material is already a secret, and a random per-secret
  // salt would have to be stored beside the ciphertext for no added strength.
  return scryptSync(raw, "argus.mfa.v1", 32);
}

export function secretEncryptionEnabled(): boolean {
  return encKey() !== null;
}

/** Encrypt if a key is configured, otherwise pass through untouched. */
export function encryptSecret(secretB32: string): string {
  const key = encKey();
  if (!key) return secretB32;
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(secretB32, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ENC_PREFIX + [iv.toString("base64url"), ct.toString("base64url"), tag.toString("base64url")].join(".");
}

/**
 * Reverse encryptSecret. Rows written before a key was configured are stored
 * bare and come back unchanged. Returns null when a row is encrypted but the
 * key is missing or wrong — the caller must treat that as "MFA unavailable"
 * rather than "MFA passed".
 */
export function decryptSecret(stored: string): string | null {
  if (!stored.startsWith(ENC_PREFIX)) return stored;
  const key = encKey();
  if (!key) return null;
  try {
    const [ivB64, ctB64, tagB64] = stored.slice(ENC_PREFIX.length).split(".");
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(ivB64, "base64url"));
    decipher.setAuthTag(Buffer.from(tagB64, "base64url"));
    return Buffer.concat([decipher.update(Buffer.from(ctB64, "base64url")), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}
