(function () {
  "use strict";
  const modeEl = document.getElementById("mode");
  const seenEl = document.getElementById("seen");
  const riskyEl = document.getElementById("risky");

  chrome.storage.local.get(["mode"], (r) => {
    modeEl.value = (r && r.mode) || "warn";
  });
  modeEl.addEventListener("change", () => {
    chrome.storage.local.set({ mode: modeEl.value });
  });

  chrome.runtime.sendMessage({ type: "argus-stats" }, (s) => {
    if (chrome.runtime.lastError || !s) return;
    seenEl.textContent = s.seen || 0;
    riskyEl.textContent = s.risky || 0;
  });

  // Muted rules (per-site allowlist).
  const allowlistEl = document.getElementById("allowlist");
  const allowlistEmptyEl = document.getElementById("allowlistEmpty");
  function renderAllowlist(list) {
    allowlistEl.innerHTML = "";
    allowlistEmptyEl.style.display = list.length ? "none" : "block";
    list.forEach((key) => {
      const [host, ruleId] = key.split("|");
      const row = document.createElement("div");
      row.style.display = "flex";
      row.style.justifyContent = "space-between";
      row.style.gap = "6px";
      const label = document.createElement("span");
      label.textContent = `${host} — ${ruleId}`;
      label.style.overflow = "hidden";
      label.style.textOverflow = "ellipsis";
      label.style.whiteSpace = "nowrap";
      const remove = document.createElement("button");
      remove.textContent = "×";
      remove.title = "Un-mute";
      Object.assign(remove.style, { background: "none", border: "none", color: "#ff8c42", cursor: "pointer", font: "inherit" });
      remove.addEventListener("click", () => {
        chrome.storage.local.get(["allowlist"], (r) => {
          const next = (r.allowlist || []).filter((k) => k !== key);
          chrome.storage.local.set({ allowlist: next });
        });
      });
      row.appendChild(label);
      row.appendChild(remove);
      allowlistEl.appendChild(row);
    });
  }
  chrome.storage.local.get(["allowlist"], (r) => renderAllowlist(r.allowlist || []));
  chrome.storage.onChanged.addListener((c) => {
    if (c.allowlist) renderAllowlist(c.allowlist.newValue || []);
  });

  // Reporting settings.
  const reportEl = document.getElementById("report");
  const fieldsEl = document.getElementById("reportFields");
  const apiUrlEl = document.getElementById("apiUrl");
  const tokenEl = document.getElementById("apiKey");

  chrome.storage.local.get(["report", "apiUrl", "apiKey"], (r) => {
    reportEl.checked = !!(r && r.report);
    fieldsEl.style.display = reportEl.checked ? "block" : "none";
    apiUrlEl.value = (r && r.apiUrl) || "";
    tokenEl.value = (r && r.apiKey) || "";
  });

  reportEl.addEventListener("change", () => {
    fieldsEl.style.display = reportEl.checked ? "block" : "none";
    chrome.storage.local.set({ report: reportEl.checked });
    const v = apiUrlEl.value.trim();
    if (reportEl.checked && v) requestHostAccess(v);
  });
  /**
   * Ask for permission to talk to the Argus the operator just named.
   *
   * The reporting endpoint is whatever URL they paste, so it cannot be a static
   * host permission in the manifest — and without permission for that specific
   * origin the service worker's fetch fails, silently, forever. Requesting it
   * here (from a user gesture, which Chrome requires) turns "reporting quietly
   * never worked" into a prompt they can answer.
   */
  function requestHostAccess(rawUrl) {
    let origin;
    try {
      origin = new URL(rawUrl).origin + "/*";
    } catch {
      return; // not a URL yet — they're still typing
    }
    chrome.permissions.contains({ origins: [origin] }, (has) => {
      if (has) return;
      chrome.permissions.request({ origins: [origin] }, (granted) => {
        if (!granted) {
          console.warn("[Argus] host access declined — verdict reporting will not send.");
        }
      });
    });
  }

  apiUrlEl.addEventListener("change", () => {
    const v = apiUrlEl.value.trim();
    chrome.storage.local.set({ apiUrl: v });
    if (v && reportEl.checked) requestHostAccess(v);
  });
  tokenEl.addEventListener("change", () => chrome.storage.local.set({ apiKey: tokenEl.value.trim() }));
})();
