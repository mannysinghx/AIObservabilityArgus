"use strict";
// Password reset page — reached from the emailed link (?token=...). Sets a new
// password, then bounces to the login page with a success flag.

const $ = (s) => document.querySelector(s);
const token = new URLSearchParams(location.search).get("token") || "";
const msg = $("#msg");

function show(text, ok) {
  msg.style.display = "block";
  msg.style.color = ok ? "var(--ok)" : "var(--sev-critical)";
  msg.style.borderColor = `color-mix(in srgb, ${ok ? "var(--ok)" : "var(--sev-critical)"} 40%, var(--line))`;
  msg.style.background = `color-mix(in srgb, ${ok ? "var(--ok)" : "var(--sev-critical)"} 8%, transparent)`;
  msg.textContent = text;
}

if (!token) {
  show("This reset link is missing its token. Request a new one from the sign-in page.", false);
  $("#resetForm").style.display = "none";
}

$("#resetForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pass = $("#rp-pass").value, pass2 = $("#rp-pass2").value;
  if (pass.length < 8) { show("Password must be at least 8 characters.", false); return; }
  if (pass !== pass2) { show("Passwords don't match.", false); return; }
  const btn = $("#resetBtn"); btn.disabled = true; btn.textContent = "Saving…";
  try {
    const res = await fetch("/api/auth/reset", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: pass }) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { show(data.error || "Couldn't reset your password.", false); btn.disabled = false; btn.textContent = "Set new password"; return; }
    location.href = "/login.html?reset=1";
  } catch {
    show("Network error — please try again.", false);
    btn.disabled = false; btn.textContent = "Set new password";
  }
});
