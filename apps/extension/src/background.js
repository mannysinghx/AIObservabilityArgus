/**
 * Argus Browser Guard — background service worker.
 *
 * - aggregates per-session verdict counts, reflects risky count on the toolbar badge
 * - OPT-IN: batches verdicts and reports them to an Argus ingest endpoint.
 *
 * What is sent, when reporting is switched on: which rules fired, how severe,
 * which site, and nothing else. **The prompt text never leaves the browser.**
 * Scanning happens locally in `scanner-core.js`; only the verdict travels. That
 * is the promise this extension makes to the person running it, and it is why
 * there is no content field anywhere in this file.
 *
 * Reporting is off until someone pastes an ingest URL and an Argus API key
 * (`ak_live_…`, created under Manage → API Keys). The key is scoped to one
 * application, so an install can write there and nowhere else.
 */
const session = { seen: 0, risky: 0, byRule: {} };
let queue = [];
let flushTimer = null;

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["mode"], (r) => {
    if (!r || !r.mode) chrome.storage.local.set({ mode: "warn" });
  });
});

function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(flush, 5000);
}

async function flush() {
  flushTimer = null;
  if (!queue.length) return;
  const cfg = await chrome.storage.local.get(["report", "apiUrl", "apiKey"]);
  if (!cfg.report || !cfg.apiUrl || !cfg.apiKey) {
    queue = []; // reporting off / unconfigured — drop the queue
    return;
  }
  const batch = queue.splice(0, 200);
  try {
    // The configured value may be the ingest origin or the full path; accept
    // either, because "which URL exactly?" is the step people get wrong.
    const base = cfg.apiUrl.replace(/\/+$/, "");
    const url = base.endsWith("/api/public/prompt-events")
      ? base
      : base + "/api/public/prompt-events";
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + cfg.apiKey },
      body: JSON.stringify({ events: batch }),
    });
    if (!res.ok) {
      // Do not requeue. A 401 is a bad key and a 400 is a bad payload; both
      // repeat forever if retried, and this runs in someone's browser where a
      // retry loop is a battery and network cost they did not agree to.
      console.warn("[Argus] telemetry post failed:", res.status);
    }
  } catch (e) {
    console.warn("[Argus] telemetry post error:", e);
  }
  if (queue.length) scheduleFlush();
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "argus-verdict") {
    session.seen += 1;
    if (msg.count > 0) session.risky += 1;
    for (const r of msg.rules || []) session.byRule[r] = (session.byRule[r] || 0) + 1;
    chrome.action.setBadgeBackgroundColor({ color: "#ff4d6d" });
    chrome.action.setBadgeText({ text: session.risky ? String(session.risky) : "" });

    queue.push({
      provider: msg.provider || "unknown",
      channel: msg.channel || "fetch",
      severity: msg.level || "ok",
      finding_count: msg.count || 0,
      rule_ids: msg.rules || [],
    });
    if (queue.length >= 20) flush();
    else scheduleFlush();
  } else if (msg && msg.type === "argus-stats") {
    sendResponse(session);
    return true;
  }
});
