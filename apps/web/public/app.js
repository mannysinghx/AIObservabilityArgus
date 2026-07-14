"use strict";
// Argus dashboard client. Fetches /api/* and renders every view.

const SEV_ORDER = { none: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5 };
const SEV_NAME = ["none", "info", "low", "medium", "high", "critical"];
let RANGE = "";
let TRACE_BACK = "traces";
// A self-onboarded client's personalized link carries ?project=<uuid>, which
// scopes every query to just their data. Absent => default "all projects" view.
const PROJECT = new URLSearchParams(location.search).get("project") || "";
if (PROJECT) {
  document.addEventListener("DOMContentLoaded", () => {
    const el = document.getElementById("projectLabel");
    if (el) el.textContent = PROJECT.slice(0, 8) + "…";
  });
}

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (n) => Number(n ?? 0).toLocaleString();
const money = (n) => "$" + Number(n ?? 0).toFixed(4);
const titleCase = (s) => String(s ?? "").replace(/_/g, " ");
const ago = (iso) => {
  const d = new Date((iso || "").replace(" ", "T") + (String(iso).includes("Z") ? "" : "Z"));
  const s = (Date.now() - d.getTime()) / 1000;
  if (!isFinite(s)) return "";
  if (s < 60) return `${Math.max(0, Math.floor(s))}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};
const sevName = (v) => (typeof v === "number" ? SEV_NAME[v] : v) || "info";
const sevMax = (a, b) => (SEV_ORDER[sevName(a)] >= SEV_ORDER[sevName(b)] ? sevName(a) : sevName(b));
const pill = (sev) => { const s = sevName(sev); return `<span class="pill pill-${s === "info" ? "neutral" : s}">${s}</span>`; };
const outcomePill = (o) => `<span class="pill pill-${o === "succeeded" ? "critical" : o === "attempted" ? "ok" : o === "blocked" ? "medium" : "neutral"}">${esc(o)}</span>`;
const dur = (ms) => (ms >= 1000 ? (ms / 1000).toFixed(2) + " s" : Math.round(ms) + " ms");

async function api(path) {
  const params = new URLSearchParams();
  if (RANGE) params.set("range", RANGE);
  if (PROJECT) params.set("project", PROJECT);
  const qs = params.toString();
  const sep = path.includes("?") ? "&" : "?";
  const r = await fetch(path + (qs ? `${sep}${qs}` : ""));
  if (!r.ok) throw new Error(`${path} → ${r.status}`);
  return r.json();
}
function banner(msg) { const b = $("#statusBanner"); if (!msg) { b.style.display = "none"; return; } b.style.display = "block"; b.textContent = msg; }
function stamp() { $("#lastUpdated").textContent = "updated " + new Date().toLocaleTimeString(); }
function tile(lab, val, sub, crit) {
  return `<div class="card kpi ${crit ? "crit" : ""}"><span class="lab">${lab}</span><span class="val">${val}</span><span class="sub">${sub || ""}</span></div>`;
}
function breakdown(sel, items, isSev) {
  const el = $(sel); if (!el) return;
  if (!items || !items.length) { el.innerHTML = '<div class="empty" style="padding:calc(var(--u)*3)">none</div>'; return; }
  const max = Math.max(...items.map((i) => Number(i.n)), 1);
  el.innerHTML = items.map((i) => {
    const color = isSev ? `var(--sev-${sevName(i.label) === "info" ? "low" : sevName(i.label)})` : "var(--accent)";
    return `<div class="row"><span>${isSev ? pill(i.label) : esc(titleCase(i.label) || "—")}</span><span class="barmini"><b style="width:${(Number(i.n) / max) * 100}%;background:${color}"></b></span><span class="mono dim">${num(i.n)}</span></div>`;
  }).join("");
}

// ---------- routing ----------
const VIEWS = ["overview", "threat", "incidents", "review", "redteam", "traces", "trace", "sessions", "analytics", "prompts", "evals", "appearance", "guide"];
function show(view) {
  VIEWS.forEach((v) => $(`#view-${v}`).classList.toggle("on", v === view));
  document.querySelectorAll(".nav-item[data-nav]").forEach((b) => b.classList.toggle("active", b.dataset.nav === view));
  window.scrollTo({ top: 0 });
}
document.querySelectorAll("[data-nav]").forEach((el) => el.addEventListener("click", () => { const v = el.dataset.nav; show(v); load(v); }));

// ---------- User Guide: table-of-contents scrolling ----------
document.querySelectorAll("[data-scroll]").forEach((el) => el.addEventListener("click", () => {
  const id = el.dataset.scroll;
  // Links inside guide body text (e.g. "see Trace detail below") may live
  // outside the currently-visible view — make sure the guide view is shown first.
  if (!$("#view-guide").classList.contains("on")) { show("guide"); }
  const target = document.getElementById(id);
  if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
  document.querySelectorAll(".guide-toc .toc-link").forEach((b) => b.classList.toggle("active", b.dataset.scroll === id));
}));

// ---------- Overview ----------
async function loadOverview() {
  try {
    const o = await api("/api/overview"); banner("");
    const s = o.sec || {}, ob = o.obs || {}, t = o.tr || {};
    $("#ovSub").textContent = `${num(s.total)} security events · ${num(t.traces)} traces · ${num(ob.observations)} spans`;
    $("#ovSecurity").innerHTML =
      tile("Security events", num(s.total), `${num(s.succeeded)} succeeded`) +
      tile("Critical", num(s.critical), `${num(s.critical_unreviewed)} unreviewed`, Number(s.critical) > 0) +
      tile("Injections", num(s.injections), `${num(s.indirect)} indirect`) +
      tile("Exfiltration", num(s.exfiltration), "data egress") +
      tile("Jailbreaks", num(s.jailbreaks), "") +
      tile("Unreviewed", num(s.unreviewed), "awaiting verdict");
    const cov = Number(ob.tool_spans) ? Math.round((Number(ob.untrusted) / Number(ob.tool_spans)) * 100) : 0;
    $("#ovObs").innerHTML =
      tile("Traces", num(t.traces), `${num(t.sessions)} sessions`) +
      tile("Spans", num(ob.observations), `${num(ob.generations)} generations`) +
      tile("Tokens", num(ob.tokens), "") +
      tile("Cost", money(ob.cost), "") +
      tile("Users", num(t.users), "") +
      tile("Taint coverage", cov + "%", "of tool/retrieval spans");
    breakdown("#ovPosture", [
      { label: "succeeded", n: s.succeeded }, { label: "blocked", n: s.blocked },
      { label: "critical", n: s.critical }, { label: "high", n: s.high }, { label: "canary", n: s.canaries },
    ]);
    breakdown("#ovTraffic", [
      { label: "generations", n: ob.generations }, { label: "tool/retrieval", n: ob.tool_spans },
      { label: "untrusted", n: ob.untrusted }, { label: "sessions", n: t.sessions },
    ]);
    stamp();
  } catch (e) { banner("Can't reach ClickHouse: " + e.message); }
}

// ---------- Threat Center ----------
function layerChips(ev) {
  const c = [];
  (ev.l1_rules || []).slice(0, 3).forEach((r) => c.push(`<span class="lchip">${esc(r)}</span>`));
  Object.entries(ev.l2_scores || {}).forEach(([, s]) => c.push(`<span class="lchip hot">L2 ${Number(s).toFixed(2)}</span>`));
  if (ev.l3_verdict) c.push('<span class="lchip hot">L3</span>');
  (ev.l4_signals || []).forEach((s) => c.push(`<span class="lchip hot">${esc(s)}</span>`));
  return `<span class="layerchips">${c.join("") || '<span class="lchip">—</span>'}</span>`;
}
const tico = (t) => ({ retrieval: "R", tool: "T", generation: "G", span: "S", event: "E" }[t] || "S");

async function loadThreat() {
  try {
    const [ov, th, attacks] = await Promise.all([api("/api/overview"), api("/api/threat"), api("/api/attacks")]);
    banner("");
    const s = ov.sec || {};
    $("#threatSub").textContent = `${num(s.total)} events · ${num(s.injections)} injections · ${num(s.succeeded)} succeeded`;
    const crit = Number(s.critical || 0), badge = $("#critBadge");
    if (crit > 0) { badge.style.display = ""; badge.textContent = crit; } else badge.style.display = "none";
    const f = th.funnel || {};
    const cov = Number(ov.obs?.tool_spans) ? Math.round((Number(ov.obs.untrusted) / Number(ov.obs.tool_spans)) * 100) : 0;
    $("#threatKpis").innerHTML =
      tile("Security events", num(s.total), `${num(s.succeeded)} succeeded`) +
      tile("Critical", num(s.critical), `${num(s.critical_unreviewed)} unreviewed`, crit > 0) +
      tile("Injections", num(s.injections), `${num(s.indirect)} indirect`) +
      tile("Exfiltration", num(s.exfiltration), "data egress") +
      tile("Canary triggers", num(s.canaries), "") +
      tile("Taint coverage", cov + "%", "tool/retrieval spans");
    renderFeed(attacks);
    // layer activity
    const layers = th.layers || [];
    const lmax = Math.max(...layers.map((l) => Number(l.n)), 1);
    $("#layerHealth").innerHTML = layers.map((l) =>
      `<div class="lh-row"><div><div class="lh-name">${esc(l.layer)}</div><div class="lh-sub">${esc(l.scope)}</div></div><div class="bar"><b style="width:${(Number(l.n) / lmax) * 100}%"></b></div><div class="lh-val">${num(l.n)}</div></div>`).join("");
    // funnel
    const steps = [["Spans scanned", f.spans_scanned], ["L1 flags", f.l1_flags], ["L2 escalations", f.l2_escalations], ["L3 judged", f.l3_judged], ["Events raised", f.events]];
    const fmax = Math.max(...steps.map((x) => Number(x[1] || 0)), 1);
    $("#funnel").innerHTML = steps.map(([lab, v]) => `<div class="fn-row"><span class="fn-lab">${lab}</span><div class="fn-bar"><b style="width:${(Number(v || 0) / fmax) * 100}%"></b></div><span class="fn-val">${num(v)}</span></div>`).join("");
    // surfaces
    const surf = th.surfaces || [];
    $("#surfaces").innerHTML = surf.length ? surf.map((x) =>
      `<div style="display:flex;justify-content:space-between"><span>${esc(x.type)} · <span class="dim">${esc(x.name)}</span></span><span class="mono dim">${num(x.events)}</span></div>`).join("") : '<div class="dim">No attributed surfaces yet.</div>';
    breakdown("#bySeverity", (th.bySeverity || []).map((r) => ({ label: r.severity, n: r.n })), true);
    breakdown("#byCategory", (th.byCategory || []).map((r) => ({ label: r.category, n: r.n })));
    renderTrend(th.trend || []);
    stamp();
  } catch (e) { banner("Threat Center query failed: " + e.message); }
}

let feedRows = [];
function renderFeed(rows) {
  feedRows = rows || [];
  const t = $("#attackFeed");
  if (!feedRows.length) { t.innerHTML = '<tbody><tr><td class="empty"><div class="big">No security events</div>Send a trace to the ingestion API to see attacks here.</td></tr></tbody>'; return; }
  const head = `<thead><tr><th></th><th>Sev</th><th>Category</th><th>Outcome</th><th>Layers</th><th>Trace</th><th>When</th></tr></thead>`;
  const body = feedRows.map((ev, i) => `
    <tr class="evt s-${sevName(ev.severity)} clickable" data-i="${i}">
      <td class="stripe"><i></i></td><td>${pill(ev.severity)}</td>
      <td><span class="cat">${esc(titleCase(ev.category))}</span>${ev.analyst_verdict && ev.analyst_verdict !== "unreviewed" ? ` <span class="verdict-tag verdict-${ev.analyst_verdict}">${esc(titleCase(ev.analyst_verdict))}</span>` : ""}</td>
      <td>${outcomePill(ev.outcome)}</td><td>${layerChips(ev)}</td>
      <td><a class="tracelink">${esc(ev.trace_id)}</a></td><td class="dim num">${ago(ev.detected_at)}</td>
    </tr>
    <tr class="evidence" id="ev-${i}" style="display:none"><td colspan="7">
      ${ev.evidence_excerpt ? `<div class="ev-label">Evidence</div><div class="ev-quote">${esc(ev.evidence_excerpt)}</div>` : ""}
      <div class="ev-label" style="margin-top:10px">Provenance</div>
      <dl class="kv" style="max-width:none">
        <dt>score</dt><dd>${ev.score}</dd>
        ${(ev.l1_rules || []).length ? `<dt>L1 rules</dt><dd>${esc((ev.l1_rules || []).join(", "))}</dd>` : ""}
        ${Object.keys(ev.l2_scores || {}).length ? `<dt>L2 scores</dt><dd>${esc(JSON.stringify(ev.l2_scores))}</dd>` : ""}
        ${ev.l3_verdict ? `<dt>L3 verdict</dt><dd>${esc(ev.l3_verdict)}</dd>` : ""}
        ${(ev.l4_signals || []).length ? `<dt>L4 signals</dt><dd>${esc((ev.l4_signals || []).join(", "))}</dd>` : ""}
      </dl>
      <div class="ev-actions">
        <button class="btn btn-primary" data-open="${esc(ev.trace_id)}">Open trace</button>
        <button class="btn" data-verdict="confirmed" data-ev="${esc(ev.event_id)}">Confirm malicious</button>
        <button class="btn" data-verdict="false_positive" data-ev="${esc(ev.event_id)}">False positive</button>
      </div>
    </td></tr>`).join("");
  t.innerHTML = head + "<tbody>" + body + "</tbody>";
  t.querySelectorAll("tr.evt").forEach((tr) => tr.addEventListener("click", (e) => {
    if (e.target.closest("a.tracelink")) { openTrace(feedRows[tr.dataset.i].trace_id, "threat"); return; }
    const row = $(`#ev-${tr.dataset.i}`); row.style.display = row.style.display === "none" ? "" : "none";
  }));
  t.querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", (e) => { e.stopPropagation(); openTrace(b.dataset.open, "threat"); }));
  t.querySelectorAll("[data-verdict]").forEach((b) => b.addEventListener("click", async (e) => {
    e.stopPropagation(); b.disabled = true; b.textContent = "…";
    await postVerdict(b.dataset.ev, b.dataset.verdict); loadThreat();
  }));
}

function renderTrend(trend) {
  const svg = $("#trendChart"), NS = "http://www.w3.org/2000/svg"; svg.innerHTML = "";
  if (!trend.length) { svg.innerHTML = '<text x="20" y="30" fill="var(--ink-faint)" font-size="12">No events in range.</text>'; return; }
  const hours = [...new Set(trend.map((t) => t.hour))].sort();
  const lanes = ["output", "direct", "indirect"], colors = { indirect: "var(--sev-critical)", direct: "var(--sev-high)", output: "var(--sev-low)" };
  const byHour = {}; hours.forEach((h) => (byHour[h] = { output: 0, direct: 0, indirect: 0 }));
  trend.forEach((t) => { byHour[t.hour][t.lane] = Number(t.n); });
  const maxV = Math.max(...hours.map((h) => lanes.reduce((s, l) => s + byHour[h][l], 0)), 1);
  const W = 960, H = 200, padL = 30, padB = 22, padT = 8, n = hours.length, bw = (W - padL - 8) / Math.max(n, 1);
  const y = (v) => H - padB - (v / maxV) * (H - padB - padT);
  [0, maxV].forEach((v) => {
    const ln = document.createElementNS(NS, "line"); ln.setAttribute("x1", padL); ln.setAttribute("x2", W - 4); ln.setAttribute("y1", y(v)); ln.setAttribute("y2", y(v)); ln.setAttribute("stroke", "var(--chart-grid)"); svg.appendChild(ln);
    const tx = document.createElementNS(NS, "text"); tx.setAttribute("x", padL - 6); tx.setAttribute("y", y(v) + 3); tx.setAttribute("text-anchor", "end"); tx.setAttribute("fill", "var(--ink-faint)"); tx.setAttribute("font-size", "9.5"); tx.textContent = v; svg.appendChild(tx);
  });
  hours.forEach((h, i) => { let acc = 0; lanes.forEach((l) => { const v = byHour[h][l]; if (!v) return; const r = document.createElementNS(NS, "rect"); r.setAttribute("x", padL + i * bw + bw * 0.15); r.setAttribute("width", Math.max(bw * 0.7, 2)); r.setAttribute("y", y(acc + v)); r.setAttribute("height", Math.max(y(acc) - y(acc + v), 0)); r.setAttribute("fill", colors[l]); r.setAttribute("rx", "1.5"); r.setAttribute("opacity", ".88"); svg.appendChild(r); acc += v; }); });
}

// ---------- Incidents ----------
async function loadIncidents() {
  try {
    const d = await api("/api/incidents"); banner("");
    const pl = $("#poisonedList");
    pl.innerHTML = (d.poisoned || []).length ? d.poisoned.map((p) => `
      <div class="incident-card">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:5px;">${pill(p.max_sev)}<b>Recurring source</b><span class="mono dim" style="font-size:11px">${esc(String(p.content_sha256).slice(0, 16))}…</span><span style="margin-left:auto" class="dim">${num(p.traces)} traces · ${num(p.events)} events</span></div>
        <div>${(p.categories || []).map((c) => `<span class="tag">${esc(titleCase(c))}</span>`).join("")}</div>
        ${p.evidence ? `<div class="dim" style="font-size:12px;margin-top:6px">${esc(String(p.evidence).slice(0, 140))}</div>` : ""}
      </div>`).join("") : '<div class="empty">No content seen across multiple traces yet.</div>';
    const il = $("#incidentList");
    il.innerHTML = (d.traceIncidents || []).length ? d.traceIncidents.map((t) => `
      <div class="incident-card clickable" data-trace="${esc(t.trace_id)}">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:5px;">${pill(t.max_sev)}<a class="tracelink">${esc(t.trace_id)}</a><span style="margin-left:auto" class="dim">${num(t.events)} events · ${ago(t.last_seen)}</span></div>
        <div>${(t.categories || []).map((c) => `<span class="tag">${esc(titleCase(c))}</span>`).join("")}</div>
        ${t.evidence ? `<div class="dim" style="font-size:12px;margin-top:6px">${esc(String(t.evidence).slice(0, 140))}</div>` : ""}
      </div>`).join("") : '<div class="empty">No high/critical incidents in range.</div>';
    il.querySelectorAll("[data-trace]").forEach((c) => c.addEventListener("click", () => openTrace(c.dataset.trace, "incidents")));
    $("#incidentsSub").textContent = `${(d.traceIncidents || []).length} trace incidents · ${(d.poisoned || []).length} recurring sources`;
    stamp();
  } catch (e) { banner("Incidents query failed: " + e.message); }
}

// ---------- Review Queue ----------
async function loadReview() {
  try {
    const rows = await api("/api/review"); banner("");
    const b = $("#reviewBadge");
    if (rows.length) { b.style.display = ""; b.textContent = rows.length; } else b.style.display = "none";
    $("#reviewSub").textContent = `${rows.length} unreviewed events`;
    const t = $("#reviewTable");
    if (!rows.length) { t.innerHTML = '<tbody><tr><td class="empty"><div class="big">Queue clear 🎉</div>No events awaiting review.</td></tr></tbody>'; return; }
    t.innerHTML = `<thead><tr><th></th><th>Sev</th><th>Category</th><th>Evidence</th><th>Trace</th><th>When</th><th>Action</th></tr></thead><tbody>` +
      rows.map((ev) => `<tr class="evt s-${sevName(ev.severity)}">
        <td class="stripe"><i></i></td><td>${pill(ev.severity)}</td><td><span class="cat">${esc(titleCase(ev.category))}</span></td>
        <td class="dim" style="white-space:normal;max-width:340px">${esc(String(ev.evidence_excerpt || "").slice(0, 120))}</td>
        <td><a class="tracelink" data-open="${esc(ev.trace_id)}">${esc(ev.trace_id)}</a></td><td class="dim num">${ago(ev.detected_at)}</td>
        <td><button class="btn" style="padding:3px 8px" data-verdict="confirmed" data-ev="${esc(ev.event_id)}">Confirm</button> <button class="btn" style="padding:3px 8px" data-verdict="false_positive" data-ev="${esc(ev.event_id)}">Dismiss</button></td>
      </tr>`).join("") + "</tbody>";
    t.querySelectorAll("[data-open]").forEach((a) => a.addEventListener("click", () => openTrace(a.dataset.open, "review")));
    t.querySelectorAll("[data-verdict]").forEach((b2) => b2.addEventListener("click", async () => { b2.disabled = true; b2.textContent = "…"; await postVerdict(b2.dataset.ev, b2.dataset.verdict); loadReview(); }));
    stamp();
  } catch (e) { banner("Review queue failed: " + e.message); }
}
async function postVerdict(eventId, verdict) {
  try { await fetch("/api/verdict", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ eventId, verdict }) }); }
  catch (e) { banner("Verdict failed: " + e.message); }
}

// ---------- Traces ----------
async function loadTraces() {
  try {
    const rows = await api("/api/traces"); banner("");
    $("#tracesSub").textContent = `${rows.length} recent traces`;
    const t = $("#tracesTable");
    if (!rows.length) { t.innerHTML = '<tbody><tr><td class="empty">No traces yet.</td></tr></tbody>'; return; }
    t.innerHTML = `<thead><tr><th>Trace</th><th>Name</th><th>Env</th><th>Spans</th><th>Tokens</th><th>Cost</th><th>Latency</th><th>Security</th><th>When</th></tr></thead><tbody>` +
      rows.map((r) => {
        const sec = Number(r.sec_events) > 0 ? `${pill(sevName(r.sec_max_severity))} <span class="dim">${num(r.sec_events)}</span>` : '<span class="dim">—</span>';
        return `<tr class="clickable" data-trace="${esc(r.trace_id)}"><td><a class="tracelink">${esc(r.trace_id)}</a></td><td>${esc(r.name || "—")}</td><td class="dim">${esc(r.environment || "")}</td><td class="num">${num(r.observations)}</td><td class="num">${num(r.tokens)}</td><td class="num">${money(r.cost)}</td><td class="num dim">${dur(Number(r.latency_ms || 0))}</td><td>${sec}</td><td class="dim num">${ago(r.timestamp)}</td></tr>`;
      }).join("") + "</tbody>";
    t.querySelectorAll("tr.clickable").forEach((tr) => tr.addEventListener("click", () => openTrace(tr.dataset.trace, "traces")));
    stamp();
  } catch (e) { banner("Traces query failed: " + e.message); }
}

// ---------- Trace detail ----------
let curObs = [], curEvByObs = {};
async function openTrace(id, back) {
  TRACE_BACK = back || "traces"; show("trace");
  $("#traceIdLabel").textContent = id; $("#waterfall").innerHTML = '<div class="loading">loading…</div>';
  $("#traceSevPill").innerHTML = ""; drawerReset();
  try {
    const d = await api("/api/trace/" + encodeURIComponent(id));
    const obs = d.observations || [], events = d.events || []; curObs = obs;
    curEvByObs = {}; let maxSev = "none";
    events.forEach((e) => { (curEvByObs[e.observation_id] = curEvByObs[e.observation_id] || []).push(e); maxSev = sevMax(maxSev, e.severity); });
    if (maxSev !== "none") $("#traceSevPill").innerHTML = pill(maxSev);
    const t = d.trace || {};
    const tok = obs.reduce((s, o) => s + Number(o.input_tokens || 0) + Number(o.output_tokens || 0), 0);
    const cost = obs.reduce((s, o) => s + Number(o.cost || 0), 0);
    $("#traceMeta").innerHTML = `<span>name <b>${esc(t.name || "—")}</b></span><span>env <b>${esc(t.environment || "")}</b></span><span>session <b class="mono" style="font-size:11px">${esc(t.session_id || "—")}</b></span><span>spans <b class="num">${obs.length}</b></span><span>tokens <b class="num">${num(tok)}</b></span><span>cost <b class="num">${money(cost)}</b></span>`;
    const times = obs.map((o) => new Date((o.start_time || "").replace(" ", "T") + "Z").getTime()).filter(isFinite);
    const t0 = Math.min(...times);
    const ends = obs.map((o) => new Date((o.end_time || o.start_time || "").replace(" ", "T") + "Z").getTime()).filter(isFinite);
    const span = Math.max(Math.max(...ends, t0 + 1) - t0, 1);
    $("#waterfall").innerHTML = obs.map((o, idx) => {
      const st = new Date((o.start_time || "").replace(" ", "T") + "Z").getTime();
      const en = new Date((o.end_time || o.start_time || "").replace(" ", "T") + "Z").getTime();
      const left = isFinite(st) ? ((st - t0) / span) * 100 : 0;
      const width = isFinite(en) && isFinite(st) ? Math.max(((en - st) / span) * 100, 1.5) : 1.5;
      const evs = curEvByObs[o.observation_id] || [];
      const hasHot = evs.some((e) => ["critical", "high"].includes(sevName(e.severity)));
      let cls = ""; if (o.taint === "untrusted_external") cls = "taint"; else if (Number(o.taint_influenced)) cls = "influenced"; if (hasHot) cls = "canary";
      const barCls = hasHot ? (evs.some((e) => sevName(e.severity) === "critical") ? "crit" : "warn") : "";
      const flags = [...new Set(evs.flatMap((e) => e.l4_signals || []))].slice(0, 2).map((s) => `<span class="lchip hot">${esc(s)}</span>`).join("");
      const d2 = isFinite(en) && isFinite(st) ? en - st : 0;
      return `<div class="wf-row ${cls}" data-idx="${idx}"><div class="wf-name"><span class="wf-ind">│</span><span class="tico ${o.type === "generation" ? "g" : o.type === "retrieval" ? "r" : ""}">${tico(o.type)}</span><span class="wf-label">${esc(o.name || o.type)}</span><span class="wf-flags">${flags}</span></div><div class="wf-track"><span class="wf-bar ${barCls}" style="left:${left}%;width:${width}%"></span><span class="wf-dur" style="left:${Math.min(left + width + 1, 82)}%">${dur(d2)}</span></div></div>`;
    }).join("") || '<div class="empty">No spans.</div>';
    $("#waterfall").querySelectorAll(".wf-row").forEach((r) => r.addEventListener("click", () => selectSpan(Number(r.dataset.idx), r)));
    // auto-select the most severe span
    let sel = 0; obs.forEach((o, i) => { if ((curEvByObs[o.observation_id] || []).some((e) => ["critical", "high"].includes(sevName(e.severity)))) sel = i; });
    const selRow = $(`#waterfall .wf-row[data-idx="${sel}"]`); if (selRow) selectSpan(sel, selRow);
  } catch (e) { $("#waterfall").innerHTML = '<div class="empty">Failed to load: ' + esc(e.message) + "</div>"; }
}
function drawerReset() { $("#drawerTitle").textContent = "Select a span"; $("#drawerId").textContent = ""; $("#drawerBody").innerHTML = '<div class="dim" style="font-size:12px;">Click a span in the waterfall.</div>'; }
let curSpanIdx = 0, curTab = "security";
function selectSpan(idx, rowEl) {
  curSpanIdx = idx;
  document.querySelectorAll("#waterfall .wf-row").forEach((r) => r.classList.remove("sel"));
  if (rowEl) rowEl.classList.add("sel");
  const o = curObs[idx]; if (!o) return;
  $("#drawerTitle").textContent = `${o.type} · ${o.name || ""}`;
  $("#drawerId").textContent = o.observation_id;
  const evs = curEvByObs[o.observation_id] || [];
  document.querySelector('#drawerTabs [data-tab="security"]').textContent = `Security${evs.length ? " · " + evs.length : ""}`;
  renderTab(curTab);
}
function renderTab(tab) {
  curTab = tab;
  document.querySelectorAll("#drawerTabs .dtab").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  const o = curObs[curSpanIdx]; if (!o) return;
  const body = $("#drawerBody");
  if (tab === "input") body.innerHTML = o.input ? `<div class="payload">${esc(o.input)}</div>` : '<div class="dim">No input.</div>';
  else if (tab === "output") body.innerHTML = o.output ? `<div class="payload">${esc(o.output)}</div>` : '<div class="dim">No output.</div>';
  else if (tab === "attributes") {
    const attrs = o.attributes || {};
    const rows = [["type", o.type], ["taint", o.taint], ["taint_source", o.taint_source], ["model", o.model], ["provider", o.provider], ["tokens", `${o.input_tokens} in / ${o.output_tokens} out`], ["cost", money(o.cost)], ["finish", o.finish_reason], ...Object.entries(attrs)];
    body.innerHTML = `<dl class="kv">${rows.filter(([, v]) => v !== "" && v != null).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(String(v))}</dd>`).join("")}</dl>`;
  } else {
    const evs = curEvByObs[o.observation_id] || [];
    body.innerHTML = evs.length ? evs.map((e) => `<div class="sec-block"><div class="sec-block-head">${pill(e.severity)} ${esc(titleCase(e.category))} · <span class="dim">${esc(e.outcome)}</span></div><div class="sec-block-body">${e.evidence_excerpt ? `<div style="margin-bottom:8px">${esc(e.evidence_excerpt)}</div>` : ""}<dl class="kv"><dt>score</dt><dd>${e.score}</dd>${(e.l1_rules || []).length ? `<dt>L1</dt><dd>${esc((e.l1_rules || []).join(", "))}</dd>` : ""}${(e.l4_signals || []).length ? `<dt>L4</dt><dd>${esc((e.l4_signals || []).join(", "))}</dd>` : ""}${Object.keys(e.l2_scores || {}).length ? `<dt>L2</dt><dd>${esc(JSON.stringify(e.l2_scores))}</dd>` : ""}</dl><div class="ev-actions"><button class="btn" data-verdict="confirmed" data-ev="${esc(e.event_id)}">Confirm</button><button class="btn" data-verdict="false_positive" data-ev="${esc(e.event_id)}">False positive</button></div></div>`).join("") : '<div class="dim" style="font-size:12px">No security events on this span.</div>';
    body.querySelectorAll("[data-verdict]").forEach((b) => b.addEventListener("click", async () => { b.disabled = true; b.textContent = "…"; await postVerdict(b.dataset.ev, b.dataset.verdict); }));
  }
}
document.querySelectorAll("#drawerTabs .dtab").forEach((b) => b.addEventListener("click", () => renderTab(b.dataset.tab)));
$("#backLink").addEventListener("click", () => { show(TRACE_BACK); load(TRACE_BACK); });

// ---------- Sessions ----------
async function loadSessions() {
  try {
    const rows = await api("/api/sessions"); banner("");
    $("#sessionsSub").textContent = `${rows.length} sessions`;
    const t = $("#sessionsTable");
    if (!rows.length) { t.innerHTML = '<tbody><tr><td class="empty">No sessions yet.</td></tr></tbody>'; return; }
    t.innerHTML = `<thead><tr><th>Session</th><th>User</th><th>Traces</th><th>Spans</th><th>Tokens</th><th>Cost</th><th>Security</th><th>Last seen</th></tr></thead><tbody>` +
      rows.map((r) => `<tr><td class="mono">${esc(r.session_id)}</td><td class="dim">${esc(r.user_id || "—")}</td><td class="num">${num(r.traces)}</td><td class="num">${num(r.spans)}</td><td class="num">${num(r.tokens)}</td><td class="num">${money(r.cost)}</td><td>${Number(r.events) > 0 ? pill(sevName(r.max_sev)) + ` <span class="dim">${num(r.events)}</span>` : '<span class="dim">—</span>'}</td><td class="dim num">${ago(r.last_seen)}</td></tr>`).join("") + "</tbody>";
    stamp();
  } catch (e) { banner("Sessions query failed: " + e.message); }
}

// ---------- Analytics ----------
async function loadAnalytics() {
  try {
    const a = await api("/api/analytics"); banner("");
    const t = a.totals || {};
    $("#analyticsTiles").innerHTML = [["Observations", num(t.observations)], ["Total cost", money(t.cost)], ["Tokens", num(t.tokens)], ["Input tokens", num(t.input_tokens)], ["Output tokens", num(t.output_tokens)], ["Avg latency", num(t.avg_latency_ms) + " ms"], ["p95 latency", num(t.p95_latency_ms) + " ms"]].map(([l, v]) => `<div class="card kpi"><span class="lab">${l}</span><span class="val" style="font-size:19px">${v}</span></div>`).join("");
    const mt = $("#modelTable"), models = a.byModel || [];
    mt.innerHTML = models.length ? `<thead><tr><th>Model</th><th>Calls</th><th>In</th><th>Out</th><th>Cost</th><th>Avg latency</th></tr></thead><tbody>` + models.map((m) => `<tr><td>${esc(m.model)}</td><td class="num">${num(m.calls)}</td><td class="num">${num(m.input_tokens)}</td><td class="num">${num(m.output_tokens)}</td><td class="num">${money(m.cost)}</td><td class="num dim">${num(m.avg_latency_ms)} ms</td></tr>`).join("") + "</tbody>" : '<tbody><tr><td class="empty">No generation spans yet.</td></tr></tbody>';
    breakdown("#byType", (a.byType || []).map((r) => ({ label: r.type, n: r.n })));
    breakdown("#byProvider", (a.byProvider || []).map((r) => ({ label: r.provider, n: r.n })));
    breakdown("#byEnv", (a.byEnv || []).map((r) => ({ label: r.environment, n: r.n })));
    renderCost(a.costTrend || []);
    stamp();
  } catch (e) { banner("Analytics query failed: " + e.message); }
}
function renderCost(rows) {
  const svg = $("#costChart"), NS = "http://www.w3.org/2000/svg"; svg.innerHTML = "";
  if (!rows.length) { svg.innerHTML = '<text x="20" y="30" fill="var(--ink-faint)" font-size="12">No cost data.</text>'; return; }
  const W = 960, H = 180, padL = 40, padB = 20, padT = 8;
  const vals = rows.map((r) => Number(r.cost)); const maxV = Math.max(...vals, 0.00001);
  const bw = (W - padL - 8) / rows.length, y = (v) => H - padB - (v / maxV) * (H - padB - padT);
  const tx = document.createElementNS(NS, "text"); tx.setAttribute("x", padL - 6); tx.setAttribute("y", y(maxV) + 3); tx.setAttribute("text-anchor", "end"); tx.setAttribute("fill", "var(--ink-faint)"); tx.setAttribute("font-size", "9.5"); tx.textContent = "$" + maxV.toFixed(4); svg.appendChild(tx);
  rows.forEach((r, i) => { const v = Number(r.cost); const rect = document.createElementNS(NS, "rect"); rect.setAttribute("x", padL + i * bw + bw * 0.15); rect.setAttribute("width", Math.max(bw * 0.7, 2)); rect.setAttribute("y", y(v)); rect.setAttribute("height", Math.max(H - padB - y(v), 0)); rect.setAttribute("fill", "var(--accent)"); rect.setAttribute("rx", "1.5"); rect.setAttribute("opacity", ".85"); svg.appendChild(rect); });
}

// ---------- Evals ----------
async function loadEvals() {
  try {
    const d = await api("/api/prompts"); banner("");
    const rows = d.evalScores || [], t = $("#evalsTable");
    t.innerHTML = rows.length ? `<thead><tr><th>Score</th><th>Count</th><th>Avg</th><th>Min</th><th>Max</th></tr></thead><tbody>` + rows.map((r) => `<tr><td>${esc(r.name)}</td><td class="num">${num(r.n)}</td><td class="num">${r.avg_value}</td><td class="num dim">${r.min_value}</td><td class="num dim">${r.max_value}</td></tr>`).join("") + "</tbody>" : '<tbody><tr><td class="empty"><div class="big">No eval scores yet</div>Submit scores via the scores API (LLM-as-judge, human annotation) to track quality here.</td></tr></tbody>';
    stamp();
  } catch (e) { banner("Evals query failed: " + e.message); }
}

// ---------- appearance + range + refresh ----------
document.querySelectorAll(".seg[data-set], .swatches[data-set]").forEach((group) => {
  group.addEventListener("click", (e) => {
    const btn = e.target.closest("button"); if (!btn) return;
    group.querySelectorAll("button").forEach((b) => { b.classList.toggle("on", b === btn); if (group.classList.contains("swatches")) b.style.border = b === btn ? "2px solid var(--ink)" : "2px solid transparent"; });
    const key = group.dataset.set, val = btn.dataset.val;
    if (key === "theme") { val === "system" ? document.documentElement.removeAttribute("data-theme") : document.documentElement.setAttribute("data-theme", val); }
    else { val ? document.documentElement.setAttribute("data-" + key, val) : document.documentElement.removeAttribute("data-" + key); }
  });
});
const rangeMenu = $("#rangeMenu");
$("#rangeBtn").addEventListener("click", (e) => { e.stopPropagation(); rangeMenu.classList.toggle("open"); });
document.addEventListener("click", () => rangeMenu.classList.remove("open"));
rangeMenu.querySelectorAll("[data-range]").forEach((b) => b.addEventListener("click", () => {
  RANGE = b.dataset.range; $("#rangeLabel").textContent = b.textContent;
  rangeMenu.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
  rangeMenu.classList.remove("open");
  load(document.querySelector(".nav-item.active")?.dataset.nav || "overview");
}));
$("#refreshBtn").addEventListener("click", () => load(document.querySelector(".nav-item.active")?.dataset.nav || "overview"));

// ---------- loader dispatch ----------
function load(view) {
  ({ overview: loadOverview, threat: loadThreat, incidents: loadIncidents, review: loadReview, traces: loadTraces, sessions: loadSessions, analytics: loadAnalytics, evals: loadEvals }[view] || (() => {}))();
}

// ---------- deep link from onboarding: ?guide=onboarding opens the User
// Guide straight to the "Connect a new app" section ----------
const GUIDE_DEEP_LINK = new URLSearchParams(location.search).get("guide");
if (GUIDE_DEEP_LINK === "onboarding") {
  show("guide");
  // No need to wait a frame — toggling display:grid via classList.toggle
  // applies synchronously, and scrollIntoView forces layout on demand.
  const target = document.getElementById("g-onboarding");
  if (target) target.scrollIntoView({ behavior: "instant", block: "start" });
  document.querySelectorAll(".guide-toc .toc-link").forEach((b) => b.classList.toggle("active", b.dataset.scroll === "g-onboarding"));
} else {
  loadOverview();
}
