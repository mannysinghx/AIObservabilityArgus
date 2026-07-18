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
  renderSnippet("curl");
  startPolling();
});

// ---------- copy buttons ----------
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  const text = $(`#${btn.dataset.copy}`).textContent;
  navigator.clipboard?.writeText(text).then(() => flashCopied(btn));
});
$("#snippetTabs").parentElement.querySelector(".snippet-copy").addEventListener("click", (e) => {
  const text = $("#snippetOut").textContent;
  navigator.clipboard?.writeText(text).then(() => flashCopied(e.target));
});
function flashCopied(btn) {
  const orig = btn.textContent;
  btn.textContent = "Copied";
  btn.classList.add("copied");
  setTimeout(() => { btn.textContent = orig; btn.classList.remove("copied"); }, 1400);
}

// ---------- snippets ----------
// Kept free of "how to run this" comments on purpose — that explanation lives
// in HOWTO below, rendered as visible numbered steps, not buried in code
// where it's easy to skip past.

// Trace/observation IDs are unique per project (suffixed with a slice of the
// project's own UUID), not a shared literal like "tr_hello_world" — two
// different clients' test traces must never collide, since Argus can't
// assume trace IDs are globally unique across tenants.
function testIds() {
  const suffix = project.projectId.replace(/-/g, "").slice(0, 10);
  return { traceId: `tr_hello_${suffix}`, obsId: `obs_hello_${suffix}` };
}

function curlSnippet() {
  const ts = new Date().toISOString();
  const { traceId, obsId } = testIds();
  return `curl -X POST '${project.ingestUrl}' \\
  -u '${project.publicKey}:${project.secretKey}' \\
  -H 'content-type: application/json' \\
  -d '{
    "traces": [{
      "traceId": "${traceId}",
      "name": "smoke-test",
      "timestamp": "${ts}"
    }],
    "observations": [{
      "observationId": "${obsId}",
      "traceId": "${traceId}",
      "type": "generation",
      "name": "greeting",
      "model": "gpt-4.1",
      "role": "assistant",
      "output": "Hello from Argus!",
      "startTime": "${ts}"
    }]
  }'`;
}

function nodeSnippet() {
  const { traceId, obsId } = testIds();
  return `const INGEST_URL = "${project.ingestUrl}";
const AUTH = "Basic " + Buffer.from("${project.publicKey}:${project.secretKey}").toString("base64");

async function sendTrace() {
  const now = new Date().toISOString();
  await fetch(INGEST_URL, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: AUTH },
    body: JSON.stringify({
      traces: [{ traceId: "${traceId}", name: "smoke-test", timestamp: now }],
      observations: [{
        observationId: "${obsId}",
        traceId: "${traceId}",
        type: "generation",
        name: "greeting",
        model: "gpt-4.1",
        role: "assistant",
        output: "Hello from Argus!",
        startTime: now,
      }],
    }),
  });
}

sendTrace();`;
}

function pythonSnippet() {
  const { traceId, obsId } = testIds();
  return `import base64, json, urllib.request
from datetime import datetime, timezone

INGEST_URL = "${project.ingestUrl}"
AUTH = "Basic " + base64.b64encode(b"${project.publicKey}:${project.secretKey}").decode()

now = datetime.now(timezone.utc).isoformat()
batch = {
    "traces": [{"traceId": "${traceId}", "name": "smoke-test", "timestamp": now}],
    "observations": [{
        "observationId": "${obsId}",
        "traceId": "${traceId}",
        "type": "generation",
        "name": "greeting",
        "model": "gpt-4.1",
        "role": "assistant",
        "output": "Hello from Argus!",
        "startTime": now,
    }],
}

req = urllib.request.Request(
    INGEST_URL,
    data=json.dumps(batch).encode(),
    headers={"content-type": "application/json", "authorization": AUTH},
    method="POST",
)
urllib.request.urlopen(req, timeout=10)`;
}

function otlpSnippet() {
  const otlpUrl = project.ingestUrl.replace(/\/api\/public\/ingestion$/, "/v1/traces");
  return `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=${otlpUrl}
OTEL_EXPORTER_OTLP_TRACES_HEADERS=authorization=Basic ${btoa(`${project.publicKey}:${project.secretKey}`)}`;
}

const SNIPPETS = { curl: curlSnippet, node: nodeSnippet, python: pythonSnippet, otlp: otlpSnippet };

// Plain-language "what do I do with this" steps, shown above the code —
// this is the part that was missing before: a snippet with no instructions
// leaves anyone unsure whether to paste it into a terminal, a file, or
// their app. Each tab spells out exactly where it goes and how to run it.
const HOWTO = {
  curl: [
    "Open a terminal on <b>any computer with internet access</b> — your own laptop is fine, it doesn't need to be where your app runs. <b>Terminal</b> on Mac/Linux, <b>Command Prompt</b> or <b>PowerShell</b> on Windows.",
    "Copy the command below, paste it into the terminal, and press <b>Enter</b>.",
  ],
  node: [
    "This runs as a quick standalone test — it doesn't need to be anywhere near your real app, your own laptop is fine.",
    "Copy the code below.",
    "Save it into a new file named <code>argus-test.js</code> (any folder is fine) using a <b>plain-text or code editor</b> (VS Code, Notepad, nano) — not TextEdit's default Rich Text mode, which will break it. Easiest: in a terminal, run <code>nano argus-test.js</code>, paste, then press <code>Ctrl+O</code>, Enter, <code>Ctrl+X</code>.",
    "Open a terminal in that same folder, then run the command underneath the code.",
    "Requires Node.js 18 or newer — check with <code>node -v</code>.",
  ],
  python: [
    "This runs as a quick standalone test — it doesn't need to be anywhere near your real app, your own laptop is fine.",
    "Copy the code below.",
    "Save it into a new file named <code>argus_test.py</code> (any folder is fine) using a <b>plain-text or code editor</b> (VS Code, Notepad, nano) — not TextEdit's default Rich Text mode, which will break it. Easiest: in a terminal, run <code>nano argus_test.py</code>, paste, then press <code>Ctrl+O</code>, Enter, <code>Ctrl+X</code>.",
    "Open a terminal in that same folder, then run the command underneath the code.",
    "Requires Python 3 — check with <code>python3 --version</code>.",
  ],
  otlp: [
    "Only use this if your app already sends data with OpenTelemetry — otherwise use one of the other tabs.",
    "Add the two lines below to your app's environment configuration (e.g. a <code>.env</code> file, or your hosting platform's environment variable settings).",
    "Restart your application. No code changes needed.",
  ],
};
const RUN_CMD = { curl: "", node: "node argus-test.js", python: "python3 argus_test.py", otlp: "" };

function renderSnippet(tab) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  $("#snippetOut").textContent = SNIPPETS[tab]();
  $("#howtoList").innerHTML = HOWTO[tab].map((step) => `<li>${step}</li>`).join("");
  const runCmd = RUN_CMD[tab];
  const runLine = $("#runLine");
  if (runCmd) {
    $("#runCmdOut").textContent = runCmd;
    runLine.style.display = "flex";
  } else {
    runLine.style.display = "none";
  }
}
document.querySelectorAll(".tab-btn").forEach((b) => b.addEventListener("click", () => renderSnippet(b.dataset.tab)));

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
