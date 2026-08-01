/**
 * Argus content script (isolated world).
 * - injects the page hook so we can observe outgoing LLM requests
 * - receives extracted prompts, evaluates them locally with IGScannerCore (sub-ms)
 * - renders a non-blocking inline badge; in "warn" mode expands on risk
 * - forwards session stats to the background service worker
 *
 * Never blocks the page or the LLM request. Evaluation is local; nothing leaves the browser.
 */
(function () {
  "use strict";

  const SEV_COLOR = {
    critical: "#ff4d6d",
    high: "#ff8c42",
    medium: "#ffd166",
    low: "#7ad1a0",
    ok: "#4cc9f0",
  };
  let mode = "warn"; // off | monitor | warn
  const stats = { seen: 0, risky: 0 };

  // Per-site rule muting: entries are "<hostname>|<rule_id>". Lets a user silence a
  // rule that's a known false positive on a specific site without turning off the guard.
  let allowlist = new Set();
  const hostKey = (ruleId) => location.hostname + "|" + ruleId;
  const isMuted = (ruleId) => allowlist.has(hostKey(ruleId));
  function muteRule(ruleId) {
    chrome.storage?.local.get(["allowlist"], (r) => {
      const list = Array.isArray(r && r.allowlist) ? r.allowlist : [];
      const key = hostKey(ruleId);
      if (!list.includes(key)) list.push(key);
      chrome.storage.local.set({ allowlist: list });
    });
  }

  chrome.storage?.local.get(["mode", "allowlist"], (r) => {
    if (r && r.mode) mode = r.mode;
    if (r && Array.isArray(r.allowlist)) allowlist = new Set(r.allowlist);
  });
  chrome.storage?.onChanged.addListener((c) => {
    if (c.mode) mode = c.mode.newValue;
    if (c.allowlist) allowlist = new Set(Array.isArray(c.allowlist.newValue) ? c.allowlist.newValue : []);
  });

  // Inject the page hook as early as possible (document_start).
  function injectHook() {
    try {
      const s = document.createElement("script");
      s.src = chrome.runtime.getURL("src/page-hook.js");
      s.onload = () => s.remove();
      (document.head || document.documentElement).appendChild(s);
    } catch (_) {}
  }
  injectHook();

  // --- inline badge -------------------------------------------------------------------
  let badge, badgeText, badgeDetail, hideTimer;
  function ensureBadge() {
    if (badge) return;
    badge = document.createElement("div");
    badge.setAttribute("data-argus-guard", "1");
    Object.assign(badge.style, {
      position: "fixed", zIndex: 2147483647, right: "16px", bottom: "16px",
      maxWidth: "340px", fontFamily: "ui-monospace,Menlo,monospace", fontSize: "12px",
      background: "#0b1220", color: "#dbe6f3", border: "1px solid #22304a",
      borderRadius: "10px", boxShadow: "0 6px 24px rgba(0,0,0,.4)", overflow: "hidden",
      transition: "opacity .2s", opacity: "0",
    });
    const head = document.createElement("div");
    Object.assign(head.style, { display: "flex", alignItems: "center", gap: "8px", padding: "8px 10px", cursor: "default" });
    head.innerHTML = '<span style="font-weight:700;color:#4f8cff">🛡 Argus</span>';
    badgeText = document.createElement("span");
    badgeText.style.marginLeft = "auto";
    head.appendChild(badgeText);
    badgeDetail = document.createElement("div");
    Object.assign(badgeDetail.style, { padding: "0 10px 10px", color: "#8098b4", lineHeight: "1.5", display: "none" });
    badgeDetail.addEventListener("click", (ev) => {
      const btn = ev.target.closest && ev.target.closest("[data-mute-rule]");
      if (!btn) return;
      muteRule(btn.getAttribute("data-mute-rule"));
      const row = btn.closest("[data-finding-row]");
      if (row) row.remove();
    });
    badge.appendChild(head);
    badge.appendChild(badgeDetail);
    document.documentElement.appendChild(badge);
  }

  function showVerdict(findings) {
    if (mode === "off") return;
    ensureBadge();
    const s = self.IGScannerCore.summarize(findings);
    const color = SEV_COLOR[s.level] || SEV_COLOR.ok;
    badge.style.borderColor = color;
    badge.style.opacity = "1";
    if (s.count === 0) {
      badgeText.textContent = "prompt ok";
      badgeText.style.color = SEV_COLOR.ok;
      badgeDetail.style.display = "none";
    } else {
      badgeText.innerHTML = `<span style="color:${color};font-weight:700">${s.level.toUpperCase()}</span> · ${s.count} issue${s.count > 1 ? "s" : ""}`;
      if (mode === "warn") {
        badgeDetail.style.display = "block";
        badgeDetail.innerHTML = findings
          .slice(0, 4)
          .map(
            (f) =>
              `<div data-finding-row style="margin-top:4px"><span style="color:${SEV_COLOR[f.severity]}">●</span> <b>${escapeHtml(f.title)}</b>` +
              `<div style="opacity:.8">${escapeHtml(f.evidence)}</div>` +
              `<button data-mute-rule="${escapeHtml(f.rule_id)}" style="margin-top:2px;background:none;border:none;padding:0;font:inherit;font-size:10px;color:#4f8cff;text-decoration:underline;cursor:pointer">mute on this site</button></div>`
          )
          .join("");
      } else {
        badgeDetail.style.display = "none";
      }
    }
    clearTimeout(hideTimer);
    hideTimer = setTimeout(() => { if (badge) badge.style.opacity = "0"; }, s.count ? 9000 : 3500);
  }

  function escapeHtml(x) {
    return String(x).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  // --- receive prompts from the page hook --------------------------------------------
  window.addEventListener("message", (ev) => {
    const d = ev.data;
    if (!d || d.__argusBrowserGuard !== true || d.kind !== "prompt") return;
    if (mode === "off") return;
    const findings = self.IGScannerCore.scan(d.prompt).filter((f) => !isMuted(f.rule_id)); // local, sub-ms
    stats.seen += 1;
    if (findings.length) stats.risky += 1;
    showVerdict(findings);
    // Telemetry to background (counts + redacted verdicts only; never the raw prompt).
    try {
      chrome.runtime.sendMessage({
        type: "argus-verdict",
        provider: d.provider,
        channel: d.channel || "fetch",
        level: findings[0] ? findings[0].severity : "ok",
        count: findings.length,
        rules: findings.map((f) => f.rule_id),
      });
    } catch (_) {}
  });
})();
