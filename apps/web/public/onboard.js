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
function curlSnippet() {
  const ts = new Date().toISOString();
  return `curl -X POST '${project.ingestUrl}' \\
  -u '${project.publicKey}:${project.secretKey}' \\
  -H 'content-type: application/json' \\
  -d '{
    "traces": [{
      "traceId": "tr_hello_world",
      "name": "smoke-test",
      "timestamp": "${ts}"
    }],
    "observations": [{
      "observationId": "obs_hello_world",
      "traceId": "tr_hello_world",
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
  return `// npm install not required — uses global fetch (Node 18+)
const INGEST_URL = "${project.ingestUrl}";
const AUTH = "Basic " + Buffer.from("${project.publicKey}:${project.secretKey}").toString("base64");

async function sendTrace() {
  const now = new Date().toISOString();
  await fetch(INGEST_URL, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: AUTH },
    body: JSON.stringify({
      traces: [{ traceId: "tr_hello_world", name: "smoke-test", timestamp: now }],
      observations: [{
        observationId: "obs_hello_world",
        traceId: "tr_hello_world",
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

sendTrace();

// For a real integration with RAG/tool spans, see the full tracer example:
// docs/10-integration-example-nodejs.md`;
}

function pythonSnippet() {
  return `import base64, json, urllib.request
from datetime import datetime, timezone

INGEST_URL = "${project.ingestUrl}"
AUTH = "Basic " + base64.b64encode(b"${project.publicKey}:${project.secretKey}").decode()

now = datetime.now(timezone.utc).isoformat()
batch = {
    "traces": [{"traceId": "tr_hello_world", "name": "smoke-test", "timestamp": now}],
    "observations": [{
        "observationId": "obs_hello_world",
        "traceId": "tr_hello_world",
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
  return `# Already instrumented with OpenTelemetry? Point your OTLP/HTTP exporter
# here instead of the batch endpoint above — same auth, GenAI semantic
# conventions are mapped automatically.

OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=${otlpUrl}
OTEL_EXPORTER_OTLP_TRACES_HEADERS=authorization=Basic ${btoa(`${project.publicKey}:${project.secretKey}`)}

# Retrieval and tool spans are classified untrusted by default — no manual
# tagging needed. See docs/02-architecture.md for the attribute mapping.`;
}

const SNIPPETS = { curl: curlSnippet, node: nodeSnippet, python: pythonSnippet, otlp: otlpSnippet };

function renderSnippet(tab) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  $("#snippetOut").textContent = SNIPPETS[tab]();
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
