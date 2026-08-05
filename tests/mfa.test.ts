/**
 * Unit tests for the TOTP core in apps/web/src/totp.ts.
 *
 * Only the pure half is exercised here — no Postgres. The storage/flow layer
 * (mfa.ts: challenges, replay guard persistence, single-use recovery codes)
 * talks to a real database and belongs in the integration suite, the same split
 * queryIntent.test.ts draws.
 *
 * The load-bearing tests are the RFC 6238 vectors. A homemade TOTP that passes
 * its own round-trip but disagrees with the RFC produces codes no authenticator
 * app can generate, and the failure looks exactly like "user typed it wrong" —
 * which is the worst possible way to find out.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  base32Encode,
  base32Decode,
  generateSecret,
  hotp,
  totpCode,
  verifyTotp,
  stepFor,
  otpauthUrl,
  generateRecoveryCodes,
  hashRecoveryCode,
  encryptSecret,
  decryptSecret,
  secretEncryptionEnabled,
  STEP_SECONDS,
} from "../apps/web/src/totp.js";

// RFC 6238 Appendix B. The published vectors use the ASCII seed
// "12345678901234567890" and 8 digits; we check 8 (matching the RFC exactly)
// and 6 (what Argus actually issues) from the same seed.
const RFC_SEED = Buffer.from("12345678901234567890", "utf8");
const RFC_SECRET = base32Encode(RFC_SEED);

const RFC_VECTORS: Array<{ seconds: number; code8: string }> = [
  { seconds: 59, code8: "94287082" },
  { seconds: 1111111109, code8: "07081804" },
  { seconds: 1111111111, code8: "14050471" },
  { seconds: 1234567890, code8: "89005924" },
  { seconds: 2000000000, code8: "69279037" },
  { seconds: 20000000000, code8: "65353130" },
];

describe("RFC 6238 test vectors", () => {
  for (const { seconds, code8 } of RFC_VECTORS) {
    test(`T=${seconds} produces ${code8}`, () => {
      assert.equal(totpCode(RFC_SECRET, seconds * 1000, 8), code8);
    });
  }

  test("6-digit codes are the low 6 digits of the RFC's 8-digit codes", () => {
    // Dynamic truncation takes `binary % 10^digits`, so the 6-digit code is the
    // 8-digit one's last six characters. If this ever diverges, truncation is wrong.
    for (const { seconds, code8 } of RFC_VECTORS) {
      assert.equal(totpCode(RFC_SECRET, seconds * 1000, 6), code8.slice(-6));
    }
  });

  test("HOTP counter 0 over the RFC seed matches RFC 4226", () => {
    assert.equal(hotp(RFC_SEED, 0, 6), "755224");
    assert.equal(hotp(RFC_SEED, 1, 6), "287082");
    assert.equal(hotp(RFC_SEED, 9, 6), "520489");
  });
});

describe("base32 codec (RFC 4648)", () => {
  test("matches the RFC's own vectors", () => {
    assert.equal(base32Encode(Buffer.from("", "utf8")), "");
    assert.equal(base32Encode(Buffer.from("f", "utf8")), "MY");
    assert.equal(base32Encode(Buffer.from("fo", "utf8")), "MZXQ");
    assert.equal(base32Encode(Buffer.from("foo", "utf8")), "MZXW6");
    assert.equal(base32Encode(Buffer.from("foob", "utf8")), "MZXW6YQ");
    assert.equal(base32Encode(Buffer.from("fooba", "utf8")), "MZXW6YTB");
    assert.equal(base32Encode(Buffer.from("foobar", "utf8")), "MZXW6YTBOI");
  });

  test("round-trips arbitrary bytes", () => {
    for (let len = 1; len <= 32; len++) {
      const buf = Buffer.from(Array.from({ length: len }, (_, i) => (i * 37 + 11) & 0xff));
      assert.deepEqual(base32Decode(base32Encode(buf)), buf);
    }
  });

  test("tolerates lowercase, spaces and padding — what users actually paste", () => {
    assert.deepEqual(base32Decode("mzxw 6ytb oi=="), Buffer.from("foobar", "utf8"));
  });

  test("rejects characters outside the alphabet rather than decoding garbage", () => {
    assert.throws(() => base32Decode("MZXW6YTB0I")); // 0 is not in the base32 alphabet
    assert.throws(() => base32Decode("hello!"));
  });

  test("generateSecret yields a decodable 160-bit secret", () => {
    const s = generateSecret();
    assert.equal(s.length, 32);
    assert.equal(base32Decode(s).length, 20);
  });
});

describe("verifyTotp", () => {
  const secret = generateSecret();
  const now = 1_700_000_000_000; // fixed instant; no wall-clock dependence

  test("accepts the current code", () => {
    const r = verifyTotp(secret, totpCode(secret, now), { atMs: now });
    assert.equal(r.ok, true);
    assert.equal(r.step, stepFor(now));
  });

  test("accepts one step of drift either side", () => {
    const prev = totpCode(secret, now - STEP_SECONDS * 1000);
    const next = totpCode(secret, now + STEP_SECONDS * 1000);
    assert.equal(verifyTotp(secret, prev, { atMs: now }).ok, true);
    assert.equal(verifyTotp(secret, next, { atMs: now }).ok, true);
  });

  test("rejects beyond the drift window", () => {
    const stale = totpCode(secret, now - 3 * STEP_SECONDS * 1000);
    assert.equal(verifyTotp(secret, stale, { atMs: now }).ok, false);
  });

  test("rejects a code from a different secret", () => {
    assert.equal(verifyTotp(secret, totpCode(generateSecret(), now), { atMs: now }).ok, false);
  });

  test("rejects malformed input without throwing", () => {
    for (const bad of ["", "12345", "1234567", "abcdef", "12 34 56", "٠١٢٣٤٥"]) {
      assert.equal(verifyTotp(secret, bad, { atMs: now }).ok, false);
    }
  });

  test("tolerates whitespace inside an otherwise valid code", () => {
    const code = totpCode(secret, now);
    const spaced = `${code.slice(0, 3)} ${code.slice(3)}`;
    assert.equal(verifyTotp(secret, spaced, { atMs: now }).ok, true);
  });

  test("survives a corrupt stored secret rather than throwing", () => {
    assert.equal(verifyTotp("not!valid!base32", "123456", { atMs: now }).ok, false);
  });

  // The replay guard. Without minStep a code stays good for its whole window
  // (plus drift), so the same six digits work more than once.
  test("minStep refuses a code at or below an already-used step", () => {
    const code = totpCode(secret, now);
    const first = verifyTotp(secret, code, { atMs: now });
    assert.equal(first.ok, true);
    const replay = verifyTotp(secret, code, { atMs: now, minStep: first.step });
    assert.equal(replay.ok, false, "the same code must not verify twice");
  });

  test("minStep still admits the next step's code", () => {
    const used = stepFor(now);
    const next = totpCode(secret, now + STEP_SECONDS * 1000);
    const r = verifyTotp(secret, next, { atMs: now + STEP_SECONDS * 1000, minStep: used });
    assert.equal(r.ok, true);
    assert.equal(r.step, used + 1);
  });
});

describe("otpauth URI", () => {
  test("carries the fields an authenticator needs", () => {
    const url = otpauthUrl("alice@example.com", "JBSWY3DPEHPK3PXP");
    assert.match(url, /^otpauth:\/\/totp\//);
    const q = new URL(url).searchParams;
    assert.equal(q.get("secret"), "JBSWY3DPEHPK3PXP");
    assert.equal(q.get("issuer"), "Argus");
    assert.equal(q.get("algorithm"), "SHA1");
    assert.equal(q.get("digits"), "6");
    assert.equal(q.get("period"), "30");
  });

  test("escapes an email that would otherwise break the label", () => {
    const url = otpauthUrl("a+b/c@example.com", "JBSWY3DPEHPK3PXP");
    assert.ok(!url.slice("otpauth://totp/".length).split("?")[0].includes("/"));
  });
});

describe("recovery codes", () => {
  test("issues ten distinct, human-transcribable codes", () => {
    const codes = generateRecoveryCodes();
    assert.equal(codes.length, 10);
    assert.equal(new Set(codes).size, 10);
    for (const c of codes) assert.match(c, /^[A-Z2-7]{5}-[A-Z2-7]{5}$/);
  });

  test("hashing normalizes case and punctuation, so retyping works", () => {
    const [code] = generateRecoveryCodes(1);
    const h = hashRecoveryCode(code);
    assert.equal(hashRecoveryCode(code.toLowerCase()), h);
    assert.equal(hashRecoveryCode(code.replace("-", "")), h);
    assert.equal(hashRecoveryCode(` ${code} `), h);
  });

  test("different codes hash differently", () => {
    const [a, b] = generateRecoveryCodes(2);
    assert.notEqual(hashRecoveryCode(a), hashRecoveryCode(b));
  });
});

describe("secret at rest", () => {
  test("passes through unchanged when no key is configured", () => {
    const prev = process.env.ARGUS_MFA_KEY;
    delete process.env.ARGUS_MFA_KEY;
    try {
      assert.equal(secretEncryptionEnabled(), false);
      const s = generateSecret();
      assert.equal(encryptSecret(s), s);
      assert.equal(decryptSecret(s), s);
    } finally {
      if (prev) process.env.ARGUS_MFA_KEY = prev;
    }
  });

  test("round-trips through AES-256-GCM when a key is set", () => {
    const prev = process.env.ARGUS_MFA_KEY;
    process.env.ARGUS_MFA_KEY = "test-key-material";
    try {
      assert.equal(secretEncryptionEnabled(), true);
      const s = generateSecret();
      const enc = encryptSecret(s);
      assert.notEqual(enc, s);
      assert.match(enc, /^enc\.v1\./);
      assert.equal(decryptSecret(enc), s);
    } finally {
      if (prev) process.env.ARGUS_MFA_KEY = prev;
      else delete process.env.ARGUS_MFA_KEY;
    }
  });

  test("plaintext rows written before the key was set still decrypt", () => {
    // This is what makes turning encryption on later a no-op for existing
    // enrolments instead of a mass lockout.
    const prev = process.env.ARGUS_MFA_KEY;
    const s = generateSecret();
    process.env.ARGUS_MFA_KEY = "turned-on-later";
    try {
      assert.equal(decryptSecret(s), s);
    } finally {
      if (prev) process.env.ARGUS_MFA_KEY = prev;
      else delete process.env.ARGUS_MFA_KEY;
    }
  });

  test("returns null — never a wrong secret — when the key is missing or changed", () => {
    const prev = process.env.ARGUS_MFA_KEY;
    process.env.ARGUS_MFA_KEY = "original-key";
    const enc = encryptSecret(generateSecret());
    try {
      delete process.env.ARGUS_MFA_KEY;
      assert.equal(decryptSecret(enc), null, "missing key must fail closed");
      process.env.ARGUS_MFA_KEY = "a-different-key";
      assert.equal(decryptSecret(enc), null, "wrong key must fail closed");
    } finally {
      if (prev) process.env.ARGUS_MFA_KEY = prev;
      else delete process.env.ARGUS_MFA_KEY;
    }
  });
});
