/**
 * Two-factor enrolment and verification state. All the Postgres this feature
 * needs; the arithmetic lives in totp.ts.
 *
 * Deliberately imports nothing from auth.ts — auth.ts imports *this* to gate
 * login, and a cycle between them would be a real problem rather than a style
 * one. Anything needing both (verify a password, then disable MFA) is composed
 * in the route.
 */
import { randomBytes } from "node:crypto";
import { pool, sha256 } from "./db.js";
import * as Totp from "./totp.js";

export interface MfaError {
  error: string;
}

export interface MfaStatus {
  enabled: boolean;
  /** A secret exists but was never confirmed with a code — setup was abandoned. */
  pendingSetup: boolean;
  recoveryRemaining: number;
  /** Surfaced in Settings so an operator can see whether at-rest encryption is on. */
  secretEncrypted: boolean;
}

/** Five minutes is long enough to open an authenticator app, short enough that
 *  a leaked challenge token is near-worthless. */
const CHALLENGE_TTL_MINUTES = 5;

export async function status(userId: string): Promise<MfaStatus> {
  const r = await pool.query<{ confirmed_at: Date | null }>(
    "SELECT confirmed_at FROM user_mfa WHERE user_id = $1",
    [userId],
  );
  const row = r.rows[0];
  const enabled = !!row?.confirmed_at;
  const codes = enabled
    ? await pool.query<{ n: number }>(
        "SELECT count(*)::int AS n FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
        [userId],
      )
    : null;
  return {
    enabled,
    pendingSetup: !!row && !row.confirmed_at,
    recoveryRemaining: codes?.rows[0]?.n ?? 0,
    secretEncrypted: Totp.secretEncryptionEnabled(),
  };
}

/** Is this account gated on a second factor? The only question login asks. */
export async function isEnabled(userId: string): Promise<boolean> {
  const r = await pool.query(
    "SELECT 1 FROM user_mfa WHERE user_id = $1 AND confirmed_at IS NOT NULL",
    [userId],
  );
  return (r.rowCount ?? 0) > 0;
}

/**
 * Start enrolment: mint a secret and hand back the otpauth URI to render as a
 * QR code. Re-running before confirmation replaces the secret, so a user who
 * abandons setup and comes back gets a clean one rather than resuming a secret
 * that may have been screenshotted.
 *
 * Refuses when MFA is already on: changing the secret out from under a
 * confirmed enrolment must go through disable() and its password check.
 */
export async function beginSetup(
  userId: string,
  email: string,
): Promise<{ secret: string; otpauthUrl: string } | MfaError> {
  if (await isEnabled(userId)) return { error: "Two-factor authentication is already enabled." };
  const secret = Totp.generateSecret();
  await pool.query(
    `INSERT INTO user_mfa (user_id, secret_enc, confirmed_at, last_used_step)
     VALUES ($1, $2, NULL, NULL)
     ON CONFLICT (user_id) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, confirmed_at = NULL, last_used_step = NULL`,
    [userId, Totp.encryptSecret(secret)],
  );
  return { secret, otpauthUrl: Totp.otpauthUrl(email, secret) };
}

/**
 * Finish enrolment by proving the authenticator works. Only on success does the
 * account actually become gated — and only here are recovery codes minted, so a
 * user cannot end up with codes for an enrolment that never completed.
 */
export async function enable(userId: string, code: string): Promise<{ recoveryCodes: string[] } | MfaError> {
  const r = await pool.query<{ secret_enc: string; confirmed_at: Date | null }>(
    "SELECT secret_enc, confirmed_at FROM user_mfa WHERE user_id = $1",
    [userId],
  );
  const row = r.rows[0];
  if (!row) return { error: "Start setup first." };
  if (row.confirmed_at) return { error: "Two-factor authentication is already enabled." };

  const secret = Totp.decryptSecret(row.secret_enc);
  if (!secret) return { error: "Stored secret could not be read. Start setup again." };

  const v = Totp.verifyTotp(secret, code);
  if (!v.ok) return { error: "That code isn't right. Check your authenticator app and try again." };

  const codes = Totp.generateRecoveryCodes();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "UPDATE user_mfa SET confirmed_at = now(), last_used_step = $2 WHERE user_id = $1",
      [userId, v.step],
    );
    await client.query("DELETE FROM mfa_recovery_codes WHERE user_id = $1", [userId]);
    for (const c of codes) {
      await client.query("INSERT INTO mfa_recovery_codes (code_hash, user_id) VALUES ($1, $2)", [
        Totp.hashRecoveryCode(c),
        userId,
      ]);
    }
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
  return { recoveryCodes: codes };
}

/**
 * Turn MFA off and destroy every artefact of it. The caller is responsible for
 * having re-checked the password first — disabling a second factor is exactly
 * the move someone with a stolen session would make.
 */
export async function disable(userId: string, code: string): Promise<{ ok: true } | MfaError> {
  const enabled = await isEnabled(userId);
  if (!enabled) return { error: "Two-factor authentication isn't enabled." };
  const v = await verifyForLogin(userId, code);
  if (!v.ok) return { error: "That code isn't right." };
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("DELETE FROM mfa_recovery_codes WHERE user_id = $1", [userId]);
    await client.query("DELETE FROM mfa_challenges WHERE user_id = $1", [userId]);
    await client.query("DELETE FROM user_mfa WHERE user_id = $1", [userId]);
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
  return { ok: true };
}

/** Discard any unconfirmed enrolment (the user backed out of setup). */
export async function cancelSetup(userId: string): Promise<void> {
  await pool.query("DELETE FROM user_mfa WHERE user_id = $1 AND confirmed_at IS NULL", [userId]);
}

export interface VerifyResult {
  ok: boolean;
  /** True when a single-use recovery code was spent rather than a TOTP code. */
  usedRecoveryCode?: boolean;
}

/**
 * Check a second factor: a TOTP code, or one of the recovery codes. Accepting
 * a TOTP code advances `last_used_step`, which is what stops the same six
 * digits being replayed for the rest of their validity window.
 */
export async function verifyForLogin(userId: string, code: string): Promise<VerifyResult> {
  const r = await pool.query<{ secret_enc: string; last_used_step: string | null }>(
    "SELECT secret_enc, last_used_step FROM user_mfa WHERE user_id = $1 AND confirmed_at IS NOT NULL",
    [userId],
  );
  const row = r.rows[0];
  if (!row) return { ok: false };

  const secret = Totp.decryptSecret(row.secret_enc);
  if (secret) {
    // last_used_step comes back as a string (pg maps BIGINT to string to avoid
    // precision loss); Number is exact here — a step is ~5.8e7 today and won't
    // reach 2^53 for another billion years.
    const minStep = row.last_used_step == null ? null : Number(row.last_used_step);
    const v = Totp.verifyTotp(secret, code, { minStep });
    if (v.ok) {
      await pool.query("UPDATE user_mfa SET last_used_step = $2 WHERE user_id = $1", [userId, v.step]);
      return { ok: true };
    }
  }

  // Fall through to recovery codes. The UPDATE ... WHERE used_at IS NULL is the
  // whole single-use guarantee: two concurrent redemptions of the same code
  // race in Postgres, and exactly one comes back with a row.
  const spent = await pool.query(
    "UPDATE mfa_recovery_codes SET used_at = now() WHERE code_hash = $1 AND user_id = $2 AND used_at IS NULL RETURNING code_hash",
    [Totp.hashRecoveryCode(code), userId],
  );
  if (spent.rowCount) return { ok: true, usedRecoveryCode: true };

  return { ok: false };
}

// ---------------- login challenges ----------------

/** Mint the short-lived token that stands in for "password accepted, factor pending". */
export async function createChallenge(userId: string): Promise<string> {
  const token = randomBytes(32).toString("base64url");
  await pool.query(
    `INSERT INTO mfa_challenges (token_hash, user_id, expires_at)
     VALUES ($1, $2, now() + interval '${CHALLENGE_TTL_MINUTES} minutes')`,
    [sha256(token), userId],
  );
  return token;
}

/** Resolve a challenge token to its user, without consuming it — a mistyped
 *  code should not cost the user their whole challenge. */
export async function challengeUser(token: string): Promise<string | null> {
  if (!token) return null;
  const r = await pool.query<{ user_id: string }>(
    "SELECT user_id FROM mfa_challenges WHERE token_hash = $1 AND expires_at > now()",
    [sha256(token)],
  );
  return r.rows[0]?.user_id ?? null;
}

/** Burn a challenge once the second factor has been accepted. */
export async function consumeChallenge(token: string): Promise<void> {
  await pool.query("DELETE FROM mfa_challenges WHERE token_hash = $1", [sha256(token)]);
}

/** Housekeeping: drop expired challenges. Cheap, and keeps the table bounded. */
export async function purgeExpiredChallenges(): Promise<void> {
  await pool.query("DELETE FROM mfa_challenges WHERE expires_at <= now()");
}
