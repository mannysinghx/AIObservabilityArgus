import nodemailer, { type Transporter } from "nodemailer";

// Pluggable transactional email. Configured entirely from the environment so any
// SMTP provider works (SES, Postmark, Resend SMTP, Gmail, …):
//   SMTP_URL=smtp://user:pass@host:587            (or the discrete vars below)
//   SMTP_HOST= SMTP_PORT= SMTP_USER= SMTP_PASS= SMTP_SECURE=true
//   EMAIL_FROM="Argus <noreply@yourdomain.com>"
// When nothing is configured, email is a no-op that logs the link — so the
// platform keeps working and verification simply activates once SMTP is set.

let cached: Transporter | null | undefined;

function transport(): Transporter | null {
  if (cached !== undefined) return cached;
  const env = process.env;
  try {
    if (env.SMTP_URL) {
      cached = nodemailer.createTransport(env.SMTP_URL);
    } else if (env.SMTP_HOST) {
      cached = nodemailer.createTransport({
        host: env.SMTP_HOST,
        port: Number(env.SMTP_PORT || 587),
        secure: env.SMTP_SECURE === "true",
        auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASS || "" } : undefined,
      });
    } else {
      cached = null;
    }
  } catch {
    cached = null;
  }
  return cached;
}

export function configured(): boolean {
  return transport() !== null;
}

const FROM = () => process.env.EMAIL_FROM || "Argus <noreply@argus.local>";

/** Send the verification email. Never throws; logs and returns on failure. */
export async function sendVerification(to: string, name: string, link: string): Promise<void> {
  const t = transport();
  if (!t) {
    // No provider configured — surface the link in logs so setup/testing works.
    console.log(`[email] (not configured) verification link for ${to}: ${link}`);
    return;
  }
  const hi = name ? `Hi ${name},` : "Hi,";
  try {
    await t.sendMail({
      from: FROM(),
      to,
      subject: "Verify your email for Argus",
      text: `${hi}\n\nConfirm your email address to finish setting up your Argus account:\n${link}\n\nThis link expires in 24 hours. If you didn't create an account, you can ignore this email.`,
      html: `<div style="font-family:system-ui,sans-serif;font-size:14px;line-height:1.6;color:#1b2534">
        <p>${hi}</p>
        <p>Confirm your email address to finish setting up your Argus account:</p>
        <p><a href="${link}" style="display:inline-block;background:#2E9E8F;color:#fff;text-decoration:none;padding:10px 18px;border-radius:8px;font-weight:600">Verify email</a></p>
        <p style="color:#6E8CA8;font-size:12px">Or paste this link: ${link}<br>This link expires in 24 hours. If you didn't create an account, you can ignore this email.</p>
      </div>`,
    });
  } catch (err) {
    console.warn("[email] send failed (non-fatal):", (err as Error).message);
  }
}
