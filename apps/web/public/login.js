"use strict";
// Login / signup. On success the server sets an httpOnly session cookie and we
// redirect into the dashboard, which lands on the Applications catalog.

const $ = (s) => document.querySelector(s);
const errBox = $("#err");
function showErr(msg) {
  errBox.style.color = ""; errBox.style.borderColor = ""; errBox.style.background = ""; // reset any success styling
  if (!msg) { errBox.style.display = "none"; return; }
  errBox.style.display = "block";
  errBox.textContent = msg;
}

// Verification-link outcomes (redirected here from /api/auth/verify).
const params = new URLSearchParams(location.search);
if (params.get("verified") === "1") {
  errBox.style.display = "block";
  errBox.style.color = "var(--ok)";
  errBox.style.borderColor = "color-mix(in srgb, var(--ok) 40%, var(--line))";
  errBox.style.background = "color-mix(in srgb, var(--ok) 8%, transparent)";
  errBox.textContent = "Your email is verified. Sign in to continue.";
} else if (params.get("verify_error") === "1") {
  showErr("That verification link is invalid or has expired. Sign in and resend a new one.");
} else if (params.get("reset") === "1") {
  errBox.style.display = "block";
  errBox.style.color = "var(--ok)";
  errBox.style.borderColor = "color-mix(in srgb, var(--ok) 40%, var(--line))";
  errBox.style.background = "color-mix(in srgb, var(--ok) 8%, transparent)";
  errBox.textContent = "Password changed. Sign in with your new password.";
}

// ---- forgot password ----
function showForgot(on) {
  $("#tabs").style.display = on ? "none" : "flex";
  $("#loginForm").style.display = on ? "none" : "grid";
  $("#signupForm").style.display = "none";
  $("#forgotForm").style.display = on ? "grid" : "none";
  showErr("");
}
$("#forgotLink").addEventListener("click", (e) => { e.preventDefault(); showForgot(true); });
$("#backToLogin").addEventListener("click", (e) => { e.preventDefault(); showForgot(false); document.querySelector('#tabs button[data-tab="login"]').classList.add("on"); });
$("#forgotForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#forgotBtn"); btn.disabled = true; btn.textContent = "Sending…";
  try {
    await fetch("/api/auth/forgot", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: $("#fp-email").value.trim() }) });
    $("#forgotForm").innerHTML = '<p style="font-size:13px;color:var(--ink)">If an account exists for that email, a password-reset link is on its way. Check your inbox (and spam).</p><div style="text-align:center;margin-top:12px"><a href="/login.html" style="font-size:12px;color:var(--accent)">← Back to sign in</a></div>';
  } catch {
    btn.disabled = false; btn.textContent = "Send reset link";
    showErr("Something went wrong — please try again.");
  }
});

// If already signed in, skip straight to the dashboard.
fetch("/api/auth/me").then((r) => { if (r.ok) location.href = "/"; }).catch(() => {});

// Tab toggle
document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => {
  const tab = b.dataset.tab;
  document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("on", x === b));
  $("#loginForm").style.display = tab === "login" ? "grid" : "none";
  $("#signupForm").style.display = tab === "signup" ? "grid" : "none";
  showErr("");
}));

async function submit(url, body, btn, label) {
  showErr("");
  btn.disabled = true; btn.textContent = "Please wait…";
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { showErr(data.error || `Failed (${res.status})`); return; }
    location.href = "/"; // cookie is set; land on the catalog
  } catch (e) {
    showErr("Network error — please try again.");
  } finally {
    btn.disabled = false; btn.textContent = label;
  }
}

$("#loginForm").addEventListener("submit", (e) => {
  e.preventDefault();
  submit("/api/auth/login", { email: $("#li-email").value.trim(), password: $("#li-pass").value }, $("#loginBtn"), "Sign in");
});

$("#signupForm").addEventListener("submit", (e) => {
  e.preventDefault();
  submit("/api/auth/signup", {
    name: $("#su-name").value.trim(),
    email: $("#su-email").value.trim(),
    company: $("#su-company").value.trim(),
    password: $("#su-pass").value,
  }, $("#signupBtn"), "Create account");
});
