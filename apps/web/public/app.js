"use strict";
// Argus dashboard client. Fetches /api/* and renders the views.

const SEV_ORDER = { none: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5 };
const SEV_NAME = ["none", "info", "low", "medium", "high", "critical"];

const $ = (sel, el = document) => el.querySelector(sel);
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (n) => Number(n ?? 0).toLocaleString();
const ago = (iso) => {
  const d = new Date((iso || "").replace(" ", "T") + (String(iso).includes("Z") ? "" : "Z"));
  const s = (Date.now() - d.getTime()) / 1000;
  if (!isFinite(s)) return "";
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};
const sevMax = (a, b) => (SEV_ORDER[a] >= SEV_ORDER[b] ? a : b);
const pill = (sev) => `<span class="pill pill-${sev === "info" ? "neutral" : sev}">${sev}</span>`;
const outcomePill = (o) => {
  const cls = o === "succeeded" ? "critical" : o === "attempted" ? "ok" : "neutral";
  return `<span class="pill pill-${cls}">${esc(o)}</span>`;
};

async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json();
}

function banner(msg) {
  const b = $("#statusBanner");
  if (!msg) { b.style.display = "none"; return; }
  b.style.display = "block";
  b.textContent = msg;
}

// ---------- view routing ----------
const VIEWS = ["threat", "traces", "trace", "analytics", "appearance"];
function show(view) {
  VIEWS.forEach((v) => $(`#view-${v}`).classList.toggle("on", v === view));
  document.querySelectorAll(".nav-item[data-nav]").forEach((b) =>
    b.classList.toggle("active", b.dataset.nav === view));
  window.scrollTo({ top: 0 });
}
document.querySelectorAll("[data-nav]").forEach((el) =>
  el.addEventListener("click", () => { const v = el.dataset.nav; show(v); load(v); }));

// ---------- Threat Center ----------
function catIcon(type) { return { retrieval: "R", tool: "T", generation: "G", span: "S", event: "E" }[type] || "S"; }

function layerChips(ev) {
  const chips = [];
  (ev.l1_rules || []).slice(0, 3).forEach((r) => chips.push(`<span class="lchip">${esc(r)}</span>`));
  const l2 = ev.l2_scores || {};
  Object.entries(l2).forEach(([m, s]) => chips.push(`<span class="lchip hot">L2 ${Number(s).toFixed(2)}</span>`));
  (ev.l4_signals || []).forEach((s) => chips.push(`<span class="lchip hot">${esc(s)}</span>`));
  return `<span class="layerchips">${chips.join("") || '<span class="lchip">—</span>'}</span>`;
}

async function loadThreat() {
  try {
    const [ov, attacks] = await Promise.all([api("/api/overview"), api("/api/attacks")]);
    banner("");
    const k = ov.kpis || {};
    $("#threatSub").textContent =
      `${num(k.total)} events · ${num(k.injections)} injections · ${num(k.succeeded)} succeeded`;
    const crit = Number(k.critical || 0);
    const badge = $("#critBadge");
    if (crit > 0) { badge.style.display = ""; badge.textContent = crit; } else badge.style.display = "none";

    const untrusted = ov.obsStats?.untrusted || 0, totalTool = ov.obsStats?.total || 0;
    const cov = totalTool ? Math.round((untrusted / totalTool) * 100) : 0;
    $("#kpis").innerHTML = [
      ["Security events", num(k.total), `${num(k.succeeded)} succeeded`],
      ["Critical", num(k.critical), `${num(k.critical_unreviewed)} unreviewed`, crit > 0],
      ["Injections", num(k.injections), `${num(k.indirect)} indirect`],
      ["Exfiltration", num(k.exfiltration), "data egress"],
      ["Canary triggers", num(k.canaries), "system-prompt canaries"],
      ["Traces", num(ov.traceStats?.traces), `${cov}% taint coverage`],
    ].map(([lab, val, sub, isCrit]) =>
      `<div class="card kpi ${isCrit ? "crit" : ""}"><span class="lab">${lab}</span><span class="val">${val}</span><span class="sub">${sub}</span></div>`
    ).join("");

    renderFeed(attacks);
    renderBreakdown("#bySeverity", (ov.bySeverity || []).map((r) => ({ label: r.severity, n: r.n })), true);
    renderBreakdown("#byCategory", (ov.byCategory || []).map((r) => ({ label: r.category, n: r.n })));
    renderTrend(ov.trend || []);
    $("#lastUpdated").textContent = "updated " + new Date().toLocaleTimeString();
  } catch (e) {
    banner("Can't reach the data layer (ClickHouse). " + e.message);
    $("#kpis").innerHTML = '<div class="empty">No data available.</div>';
  }
}

function renderFeed(rows) {
  const tb = $("#attackFeed").querySelector("tbody") || $("#attackFeed");
  if (!rows || !rows.length) { $("#attackFeed").innerHTML = '<tbody><tr><td class="empty">No security events yet. Send a trace to the ingestion API.</td></tr></tbody>'; return; }
  const head = `<thead><tr><th></th><th>Sev</th><th>Category</th><th>Outcome</th><th>Layers</th><th>Trace</th><th>When</th></tr></thead>`;
  const body = rows.map((ev) => `
    <tr class="evt s-${ev.severity} clickable" data-trace="${esc(ev.trace_id)}">
      <td class="stripe"><i></i></td>
      <td>${pill(ev.severity)}</td>
      <td><span class="cat">${esc(ev.category.replace(/_/g, " "))}</span>${ev.evidence_excerpt ? `<br><span class="faint" style="font-size:11px">${esc(ev.evidence_excerpt.slice(0, 60))}</span>` : ""}</td>
      <td>${outcomePill(ev.outcome)}</td>
      <td>${layerChips(ev)}</td>
      <td><a class="tracelink">${esc(ev.trace_id)}</a></td>
      <td class="dim num">${ago(ev.detected_at)}</td>
    </tr>`).join("");
  $("#attackFeed").innerHTML = head + "<tbody>" + body + "</tbody>";
  $("#attackFeed").querySelectorAll("tr.evt").forEach((tr) =>
    tr.addEventListener("click", () => openTrace(tr.dataset.trace)));
}

function renderBreakdown(sel, items, isSev) {
  const el = $(sel);
  if (!items.length) { el.innerHTML = '<div class="empty">none</div>'; return; }
  const max = Math.max(...items.map((i) => Number(i.n)), 1);
  el.innerHTML = items.map((i) => {
    const color = isSev ? `var(--sev-${i.label === "info" ? "low" : i.label})` : "var(--accent)";
    return `<div class="row"><span>${isSev ? pill(i.label) : esc(String(i.label).replace(/_/g, " "))}</span>
      <span class="barmini"><b style="width:${(Number(i.n) / max) * 100}%;background:${color}"></b></span>
      <span class="mono dim">${num(i.n)}</span></div>`;
  }).join("");
}

function renderTrend(trend) {
  const svg = $("#trendChart");
  const NS = "http://www.w3.org/2000/svg";
  svg.innerHTML = "";
  if (!trend.length) { svg.innerHTML = '<text x="20" y="30" fill="var(--ink-faint)" font-size="12">No events in range yet.</text>'; return; }
  const hours = [...new Set(trend.map((t) => t.hour))].sort();
  const lanes = ["output", "direct", "indirect"];
  const colors = { indirect: "var(--sev-critical)", direct: "var(--sev-high)", output: "var(--sev-low)" };
  const byHour = {};
  hours.forEach((h) => (byHour[h] = { output: 0, direct: 0, indirect: 0 }));
  trend.forEach((t) => { byHour[t.hour][t.lane] = Number(t.n); });
  const maxV = Math.max(...hours.map((h) => lanes.reduce((s, l) => s + byHour[h][l], 0)), 1);
  const W = 960, H = 200, padL = 30, padB = 22, padT = 8;
  const n = hours.length, bw = (W - padL - 8) / Math.max(n, 1);
  const y = (v) => H - padB - (v / maxV) * (H - padB - padT);
  [0, maxV].forEach((v) => {
    const ln = document.createElementNS(NS, "line");
    ln.setAttribute("x1", padL); ln.setAttribute("x2", W - 4); ln.setAttribute("y1", y(v)); ln.setAttribute("y2", y(v));
    ln.setAttribute("stroke", "var(--chart-grid)"); svg.appendChild(ln);
    const tx = document.createElementNS(NS, "text");
    tx.setAttribute("x", padL - 6); tx.setAttribute("y", y(v) + 3); tx.setAttribute("text-anchor", "end");
    tx.setAttribute("fill", "var(--ink-faint)"); tx.setAttribute("font-size", "9.5"); tx.textContent = v;
    svg.appendChild(tx);
  });
  hours.forEach((h, i) => {
    let acc = 0;
    lanes.forEach((l) => {
      const v = byHour[h][l]; if (!v) return;
      const r = document.createElementNS(NS, "rect");
      r.setAttribute("x", padL + i * bw + bw * 0.15); r.setAttribute("width", Math.max(bw * 0.7, 2));
      r.setAttribute("y", y(acc + v)); r.setAttribute("height", Math.max(y(acc) - y(acc + v), 0));
      r.setAttribute("fill", colors[l]); r.setAttribute("rx", "1.5"); r.setAttribute("opacity", ".88");
      svg.appendChild(r); acc += v;
    });
  });
}

// ---------- Traces ----------
async function loadTraces() {
  try {
    const rows = await api("/api/traces"); banner("");
    $("#tracesSub").textContent = `${rows.length} recent traces`;
    const t = $("#tracesTable");
    if (!rows.length) { t.innerHTML = '<tbody><tr><td class="empty">No traces yet.</td></tr></tbody>'; return; }
    t.innerHTML = `<thead><tr><th>Trace</th><th>Name</th><th>Env</th><th>Spans</th><th>Tokens</th><th>Cost</th><th>Security</th><th>When</th></tr></thead><tbody>` +
      rows.map((r) => {
        const sev = r.sec_max_severity && r.sec_events > 0 ? SEV_NAME[r.sec_max_severity] || r.sec_max_severity : null;
        const secCell = r.sec_events > 0 ? `${pill(typeof sev === "string" ? sev : "info")} <span class="dim">${num(r.sec_events)}</span>` : '<span class="dim">—</span>';
        return `<tr class="clickable" data-trace="${esc(r.trace_id)}">
          <td><a class="tracelink">${esc(r.trace_id)}</a></td>
          <td>${esc(r.name || "—")}</td><td class="dim">${esc(r.environment || "")}</td>
          <td class="num">${num(r.observations)}</td><td class="num">${num(r.tokens)}</td>
          <td class="num">$${Number(r.cost || 0).toFixed(4)}</td><td>${secCell}</td>
          <td class="dim num">${ago(r.timestamp)}</td></tr>`;
      }).join("") + "</tbody>";
    t.querySelectorAll("tr.clickable").forEach((tr) => tr.addEventListener("click", () => openTrace(tr.dataset.trace)));
  } catch (e) { banner("Traces query failed: " + e.message); }
}

// ---------- Trace detail ----------
async function openTrace(id) {
  show("trace"); load("__none");
  $("#traceIdLabel").textContent = id;
  $("#waterfall").innerHTML = '<div class="loading">loading trace…</div>';
  $("#traceEvents").innerHTML = "";
  $("#traceSevPill").innerHTML = "";
  try {
    const d = await api("/api/trace/" + encodeURIComponent(id));
    const obs = d.observations || [], events = d.events || [];
    const evByObs = {};
    let maxSev = "none";
    events.forEach((e) => { (evByObs[e.observation_id] = evByObs[e.observation_id] || []).push(e); maxSev = sevMax(maxSev, e.severity); });
    if (maxSev !== "none") $("#traceSevPill").innerHTML = pill(maxSev);

    // meta
    const t = d.trace || {};
    const totTokens = obs.reduce((s, o) => s + Number(o.input_tokens || 0) + Number(o.output_tokens || 0), 0);
    const totCost = obs.reduce((s, o) => s + Number(o.cost || 0), 0);
    $("#traceMeta").innerHTML =
      `<span>name <b>${esc(t.name || "—")}</b></span><span>env <b>${esc(t.environment || "")}</b></span>
       <span>spans <b class="num">${obs.length}</b></span><span>tokens <b class="num">${num(totTokens)}</b></span>
       <span>cost <b class="num">$${totCost.toFixed(4)}</b></span>`;

    // waterfall time base
    const times = obs.map((o) => new Date((o.start_time || "").replace(" ", "T") + "Z").getTime()).filter((n) => isFinite(n));
    const t0 = Math.min(...times);
    const ends = obs.map((o) => new Date((o.end_time || o.start_time || "").replace(" ", "T") + "Z").getTime()).filter((n) => isFinite(n));
    const tEnd = Math.max(...ends, t0 + 1);
    const span = Math.max(tEnd - t0, 1);

    $("#waterfall").innerHTML = obs.map((o) => {
      const st = new Date((o.start_time || "").replace(" ", "T") + "Z").getTime();
      const en = new Date((o.end_time || o.start_time || "").replace(" ", "T") + "Z").getTime();
      const left = isFinite(st) ? ((st - t0) / span) * 100 : 0;
      const width = isFinite(en) && isFinite(st) ? Math.max(((en - st) / span) * 100, 1.5) : 1.5;
      const evs = evByObs[o.observation_id] || [];
      const hasCrit = evs.some((e) => e.severity === "critical" || e.severity === "high");
      let rowCls = "";
      if (o.taint === "untrusted_external") rowCls = "taint";
      else if (Number(o.taint_influenced)) rowCls = "influenced";
      if (hasCrit) rowCls = "canary";
      const dur = isFinite(en) && isFinite(st) ? (en - st) : 0;
      const durTxt = dur >= 1000 ? (dur / 1000).toFixed(2) + " s" : dur + " ms";
      const icoCls = o.type === "generation" ? "g" : o.type === "retrieval" ? "r" : "";
      const barCls = hasCrit ? (evs.some((e) => e.severity === "critical") ? "crit" : "warn") : "";
      const flags = evs.flatMap((e) => [...(e.l4_signals || [])]).slice(0, 2)
        .map((s) => `<span class="lchip hot">${esc(s)}</span>`).join("");
      return `<div class="wf-row ${rowCls}">
        <div class="wf-name"><span class="wf-ind">│</span><span class="tico ${icoCls}">${catIcon(o.type)}</span>
          <span class="wf-label">${esc(o.name || o.type)}</span>
          <span class="wf-flags">${flags}</span></div>
        <div class="wf-track"><span class="wf-bar ${barCls}" style="left:${left}%;width:${width}%"></span>
          <span class="wf-dur" style="left:${Math.min(left + width + 1, 82)}%">${durTxt}</span></div>
      </div>`;
    }).join("") || '<div class="empty">No observations for this trace.</div>';

    // events
    $("#traceEvents").innerHTML = events.length ? events.map((e) => `
      <div class="sec-block">
        <div class="sec-block-head">${pill(e.severity)} ${esc(e.category.replace(/_/g, " "))} · <span class="dim">${esc(e.outcome)}</span></div>
        <div class="sec-block-body">
          ${e.evidence_excerpt ? `<div style="margin-bottom:8px;">${esc(e.evidence_excerpt)}</div>` : ""}
          <dl class="kv">
            <dt>score</dt><dd>${e.score}</dd>
            ${(e.l1_rules || []).length ? `<dt>L1 rules</dt><dd>${esc((e.l1_rules || []).join(", "))}</dd>` : ""}
            ${(e.l4_signals || []).length ? `<dt>L4 signals</dt><dd>${esc((e.l4_signals || []).join(", "))}</dd>` : ""}
            ${Object.keys(e.l2_scores || {}).length ? `<dt>L2</dt><dd>${esc(JSON.stringify(e.l2_scores))}</dd>` : ""}
          </dl>
        </div>
      </div>`).join("") : '<div class="empty">No security events on this trace.</div>';
  } catch (e) { $("#waterfall").innerHTML = '<div class="empty">Failed to load trace: ' + esc(e.message) + "</div>"; }
}
$("#backToTraces").addEventListener("click", () => { show("traces"); load("traces"); });

// ---------- Analytics ----------
async function loadAnalytics() {
  try {
    const a = await api("/api/analytics"); banner("");
    const t = a.totals || {};
    $("#analyticsTiles").innerHTML = [
      ["Observations", num(t.observations)],
      ["Total cost", "$" + Number(t.cost || 0).toFixed(4)],
      ["Tokens", num(t.tokens)],
      ["Avg latency", num(t.avg_latency_ms) + " ms"],
      ["p95 latency", num(t.p95_latency_ms) + " ms"],
    ].map(([lab, val]) => `<div class="card kpi"><span class="lab">${lab}</span><span class="val" style="font-size:20px;">${val}</span></div>`).join("");
    const mt = $("#modelTable");
    const models = a.byModel || [];
    mt.innerHTML = models.length ? `<thead><tr><th>Model</th><th>Calls</th><th>In</th><th>Out</th><th>Cost</th></tr></thead><tbody>` +
      models.map((m) => `<tr><td>${esc(m.model)}</td><td class="num">${num(m.calls)}</td><td class="num">${num(m.input_tokens)}</td><td class="num">${num(m.output_tokens)}</td><td class="num">$${Number(m.cost || 0).toFixed(4)}</td></tr>`).join("") + "</tbody>"
      : '<tbody><tr><td class="empty">No generation spans yet.</td></tr></tbody>';
    renderBreakdown("#byType", (a.byType || []).map((r) => ({ label: r.type, n: r.n })));
  } catch (e) { banner("Analytics query failed: " + e.message); }
}

// ---------- appearance ----------
document.querySelectorAll(".seg[data-set], .swatches[data-set]").forEach((group) => {
  group.addEventListener("click", (e) => {
    const btn = e.target.closest("button"); if (!btn) return;
    group.querySelectorAll("button").forEach((b) => { b.classList.toggle("on", b === btn); if (group.classList.contains("swatches")) b.style.borderColor = b === btn ? "var(--ink)" : "transparent"; });
    const key = group.dataset.set, val = btn.dataset.val;
    if (key === "theme") { val === "system" ? document.documentElement.removeAttribute("data-theme") : document.documentElement.setAttribute("data-theme", val); }
    else { val ? document.documentElement.setAttribute("data-" + key, val) : document.documentElement.removeAttribute("data-" + key); }
  });
});

// ---------- loader dispatch ----------
function load(view) {
  if (view === "threat") loadThreat();
  else if (view === "traces") loadTraces();
  else if (view === "analytics") loadAnalytics();
}
$("#refreshBtn").addEventListener("click", () => {
  const active = document.querySelector(".nav-item.active")?.dataset.nav || "threat";
  load(active);
});

// initial
loadThreat();
