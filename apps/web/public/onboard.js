"use strict";
// Argus self-service onboarding: create project -> show key -> copy-paste
// integration snippet -> poll for the first trace -> success.

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

let project = null; // { orgId, projectId, projectName, publicKey, secretKey, ingestUrl }
let pollTimer = null;

function showStep(n) {
  [1, 2, 3].forEach((i) => $(`#step${i}`).classList.toggle("on", i === n));
  document.querySelectorAll(".onb-step-dot").forEach((d) => {
    const i = Number(d.dataset.dot);
    d.classList.toggle("done", i < n);
    d.classList.toggle("active", i === n);
  });
}

function showError(msg) {
  const box = $("#errBox");
  if (!msg) { box.style.display = "none"; return; }
  box.style.display = "block";
  box.textContent = msg;
}

// ---------- Step 1: create project ----------
$("#createBtn").addEventListener("click", async () => {
  const orgName = $("#orgName").value.trim();
  const projectName = $("#projName").value.trim();
  showError("");
  if (!orgName || !projectName) { showError("Please fill in both fields."); return; }

  const btn = $("#createBtn");
  btn.disabled = true;
  btn.textContent = "Creating…";
  try {
    const res = await fetch("/api/onboarding/projects", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ orgName, projectName }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    project = data;
    $("#pubKeyOut").textContent = project.publicKey;
    $("#secKeyOut").textContent = project.secretKey;
    showStep(2);
  } catch (e) {
    showError("Couldn't create your project: " + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Create Project & Get API Key";
  }
});

// ---------- Step 2 -> 3 ----------
$("#savedBtn").addEventListener("click", () => {
  showStep(3);
  renderTab("express");
  startPolling();
});

// ---------- copy buttons (delegated; works for any [data-copy] target id) ----------
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  const target = $(`#${btn.dataset.copy}`);
  if (!target) return;
  navigator.clipboard?.writeText(target.textContent).then(() => flashCopied(btn));
});
function flashCopied(btn) {
  const orig = btn.textContent;
  btn.textContent = "Copied";
  btn.classList.add("copied");
  setTimeout(() => { btn.textContent = orig; btn.classList.remove("copied"); }, 1400);
}

// ---------- Step 3: the real, SDK-first integration ----------
// The drop-in @argus/node SDK is the actual integration — the same two lines
// stay in the app permanently. Each framework tab shows: install, env vars
// (pre-filled with this project's keys), and the code. The "curl" tab is a
// throwaway connectivity check for people who want to see the key light up
// before touching their app.

// Pre-filled environment block, shared by every SDK tab.
function envBlock() {
  return `ARGUS_PUBLIC_KEY=${project.publicKey}
ARGUS_SECRET_KEY=${project.secretKey}
ARGUS_INGEST_URL=${project.ingestUrl}`;
}

const EXPRESS_CODE = `// 1) At the very top of your entry file (app.js / server.js),
//    before you create any LLM clients:
const argus = require("@argus/node").init();

// 2) Right after you create your Express app:
app.use(argus.middleware());

// Done. Every OpenAI / Anthropic / OpenAI-compatible call in a
// request is now captured and grouped into one trace — no per-call code.`;

const NEXT_CODE = `// lib/argus.js — import once so init() runs at startup
const argus = require("@argus/node").init();
module.exports = argus;

// In each route handler, wrap the work and flush before returning
// (serverless functions can freeze the instant they respond):
const argus = require("@argus/node");

export async function POST(req) {
  return argus.trace("chat", async () => {
    const result = await handleRequest(req);
    await argus.flush();
    return Response.json(result);
  });
}`;

const NODE_CODE = `// At startup, before creating LLM clients:
const argus = require("@argus/node").init();

// Wrap each job / request so its LLM calls group into one trace:
await argus.trace("summarize-job", async () => {
  // ...your existing code — LLM calls here are captured automatically
});
// (A standalone call outside any trace() is still captured — one trace each.)`;

// Throwaway connectivity check. Trace/observation IDs are unique per project
// (suffixed with a slice of the project's UUID), never a shared literal — two
// clients' test traces must never collide, since Argus can't assume trace IDs
// are globally unique across tenants.
function curlSnippet() {
  const ts = new Date().toISOString();
  const suffix = project.projectId.replace(/-/g, "").slice(0, 10);
  return `curl -X POST '${project.ingestUrl}' \\
  -u '${project.publicKey}:${project.secretKey}' \\
  -H 'content-type: application/json' \\
  -d '{
    "traces": [{ "traceId": "tr_hello_${suffix}", "name": "smoke-test", "timestamp": "${ts}" }],
    "observations": [{
      "observationId": "obs_hello_${suffix}",
      "traceId": "tr_hello_${suffix}",
      "type": "generation", "name": "greeting", "model": "gpt-4.1",
      "role": "assistant", "output": "Hello from Argus!", "startTime": "${ts}"
    }]
  }'`;
}

const TABS = {
  express: {
    env: true,
    install: "npm install @argus/node",
    codeLabel: "Add two lines to your app",
    code: () => EXPRESS_CODE,
    howto: [
      "In a terminal, in your app's project folder, run the install command below.",
      "Put your keys where your app reads config — a <code>.env</code> file locally, or your host's environment-variable settings (Railway, Vercel, Azure, AWS…). They're pre-filled below.",
      "Add the two lines of code below: the <code>init()</code> line at the very top of your entry file, the <code>middleware()</code> line right after you create your Express app.",
      "Deploy the way you always do (<code>git push</code> / your platform's deploy / a restart), then use your app once for real — watch the status below flip to <b>Connected</b>.",
    ],
  },
  next: {
    env: true,
    install: "npm install @argus/node",
    codeLabel: "Wire it into your route handlers",
    code: () => NEXT_CODE,
    howto: [
      "In your project folder, run the install command below.",
      "Add your keys to your host's <b>Production</b> environment variables (pre-filled below). On Vercel, <b>redeploy after adding them</b> — new vars only apply to a fresh deploy.",
      "Add the <code>init()</code> line once at startup, then wrap each route handler as shown. Keep the <code>argus.flush()</code> before you return — serverless functions can freeze the moment they respond.",
      "Deploy, trigger a real request, and watch the status below.",
    ],
  },
  node: {
    env: true,
    install: "npm install @argus/node",
    codeLabel: "Initialize and wrap your work",
    code: () => NODE_CODE,
    howto: [
      "In your project folder, run the install command below.",
      "Set the environment variables (pre-filled below) wherever your process reads config.",
      "Add the <code>init()</code> line at startup, and wrap each unit of work in <code>argus.trace()</code> as shown.",
      "Run your app for real; watch the status below.",
    ],
  },
  curl: {
    env: false,
    install: "",
    codeLabel: "Paste this into a terminal",
    code: curlSnippet,
    howto: [
      "Open a terminal on <b>any computer with internet access</b> — it doesn't need to be where your app runs.",
      "Copy the command below, paste it, and press <b>Enter</b>. This sends one harmless test message to prove your key works — it touches nothing in your real app. <span class=\"dim\">When you're ready for the real thing, switch to your framework's tab.</span>",
    ],
  },
};

function codeBlock(label, id, text) {
  return `<div class="field">
      <div class="code-label">${label}</div>
      <div class="snippet-wrap">
        <button class="copy-btn snippet-copy" data-copy="${id}" type="button">Copy</button>
        <pre class="snippet" id="${id}">${esc(text)}</pre>
      </div>
    </div>`;
}

function renderTab(tab) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  const cfg = TABS[tab];
  const parts = [];
  parts.push(`<div class="howto"><ol>${cfg.howto.map((s) => `<li>${s}</li>`).join("")}</ol></div>`);
  parts.push(`<div class="tab-block">`);
  if (cfg.install) {
    parts.push(
      `<div class="setup-line"><span class="lbl">Install</span><div class="keybox"><span id="cInstall">${esc(cfg.install)}</span><button class="copy-btn" data-copy="cInstall" type="button">Copy</button></div></div>`,
    );
  }
  if (cfg.env) parts.push(codeBlock("Environment variables", "cEnv", envBlock()));
  parts.push(codeBlock(cfg.codeLabel, "cCode", cfg.code()));
  parts.push(`</div>`);
  $("#tabBody").innerHTML = parts.join("");
}
document.querySelectorAll(".tab-btn").forEach((b) => b.addEventListener("click", () => renderTab(b.dataset.tab)));

// ---------- Step 3: live connection status ----------
function startPolling() {
  poll();
  pollTimer = setInterval(poll, 3000);
}

async function poll() {
  if (!project) return;
  try {
    const res = await fetch(`/api/onboarding/status/${encodeURIComponent(project.projectId)}`);
    const data = await res.json();
    if (data.connected) {
      clearInterval(pollTimer);
      $("#statusDot").classList.remove("pulse");
      $("#statusDot").classList.add("ok");
      $("#statusText").textContent = `Connected — ${data.traceCount} trace(s), ${data.eventCount} security event(s) received.`;
      const link = `${location.origin}/?project=${encodeURIComponent(project.projectId)}`;
      $("#dashLinkOut").textContent = link;
      $("#openDashBtn").href = link;
      $("#successSub").textContent = `Project "${project.projectName}" is live.`;
      $("#successCard").style.display = "";
    }
  } catch {
    // transient — keep polling silently, no need to alarm the user over one failed check
  }
}
