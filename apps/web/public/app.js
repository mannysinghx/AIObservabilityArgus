"use strict";
// Argus dashboard client. Fetches /api/* and renders every view.

const SEV_ORDER = { none: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5 };
const SEV_NAME = ["none", "info", "low", "medium", "high", "critical"];
let RANGE = "";
let TRACE_BACK = "traces";
// A self-onboarded client's personalized link carries ?project=<uuid>, which
// scopes every query to just their data. Absent => default "all projects" view.
const PROJECT = new URLSearchParams(location.search).get("project") || "";
// Header project chip: show the real application name (not a UUID). When scoped
// to one app, resolve its name via /api/project/:id; unscoped, it reads
// "All applications" and links to the catalog.
let PROJECT_ROLE = null;
const ROLE_RANK = { viewer: 0, member: 1, admin: 2, owner: 3 };
document.addEventListener("DOMContentLoaded", async () => {
  const el = document.getElementById("projectLabel");
  const projMenu = document.getElementById("projMenu");
  const ctx = document.getElementById("projectCtx");
  if (ctx) ctx.addEventListener("click", (e) => { e.stopPropagation(); projMenu.classList.toggle("open"); buildSwitcher(); });
  document.addEventListener("click", () => projMenu?.classList.remove("open"));

  if (!PROJECT) { if (el) el.textContent = "All applications"; return; }
  if (el) el.textContent = PROJECT.slice(0, 8) + "…";
  try {
    const m = await (await fetch("/api/project/" + encodeURIComponent(PROJECT))).json();
    if (m && m.projectName) {
      if (el) { el.textContent = m.projectName; el.title = (m.orgName ? m.orgName + " · " : "") + PROJECT; }
      PROJECT_ROLE = m.role || null;
      applyRoleUI();
    }
  } catch { /* keep the truncated id fallback */ }
});

// Header switcher: jump between the user's applications without going to the catalog.
let SWITCHER_BUILT = false;
async function buildSwitcher() {
  if (SWITCHER_BUILT) return;
  SWITCHER_BUILT = true;
  const pop = $("#projPop");
  try {
    const apps = await (await fetch("/api/projects")).json();
    pop.innerHTML =
      `<button data-goto="/">All applications</button>` +
      (apps || []).map((a) => `<button data-goto="/?project=${encodeURIComponent(a.projectId)}"${a.projectId === PROJECT ? ' class="on"' : ""}>${esc(a.projectName)} <span class="dim" style="font-size:10px">${esc(a.orgName)}</span></button>`).join("");
  } catch { pop.innerHTML = `<button data-goto="/">All applications</button>`; }
  pop.querySelectorAll("[data-goto]").forEach((b) => b.addEventListener("click", () => { location.href = b.dataset.goto; }));
}

// Show/hide role-gated management nav. Team = member+, API Keys = admin+.
function applyRoleUI() {
  const r = ROLE_RANK[PROJECT_ROLE] ?? -1;
  if (PROJECT && r >= 1) $("#manageGroup").style.display = "";
  const nk = $("#navKeys"), na = $("#navAudit"), ns = $("#navSettings");
  if (nk) nk.style.display = PROJECT && r >= 2 ? "" : "none";
  if (na) na.style.display = PROJECT && r >= 2 ? "" : "none"; // audit: admin+
  if (ns) ns.style.display = PROJECT && r >= 1 ? "" : "none"; // settings: view member+, save admin+
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
// Severity/outcome/verdict pills all carry their plain-English meaning on hover
// (copy lives in glossary.js).
const pill = (sev) => { const s = sevName(sev); return `<span class="pill pill-${s === "info" ? "neutral" : s}"${tipAttr(SEVERITY_INFO[s])}>${s}</span>`; };
const outcomePill = (o) => `<span class="pill pill-${o === "succeeded" ? "critical" : o === "attempted" ? "ok" : o === "blocked" ? "medium" : "neutral"}"${tipAttr(OUTCOME_INFO[o])}>${esc(o)}</span>`;
const verdictTag = (v) => `<span class="verdict-tag verdict-${esc(v)}"${tipAttr(VERDICT_INFO[v])}>${esc(titleCase(v))}</span>`;
const dur = (ms) => (ms >= 1000 ? (ms / 1000).toFixed(2) + " s" : Math.round(ms) + " ms");

// ---------- glossary fallback ----------
// app.js renders with helpers from glossary.js. If that file is missing, stale,
// or blocked (a partial deploy, a CDN serving a mismatched pair, a failed asset
// fetch), a bare reference would throw ReferenceError on EVERY render and take
// the whole dashboard down. These no-op stubs make the plain-English layer
// degrade to the pre-glossary UI instead: labels still render, tooltips and
// explainers simply don't appear.
//
// `typeof` is safe on an undeclared identifier, and glossary.js's top-level
// `const`s live in the global lexical scope — so when it HAS loaded these
// checks see it and nothing is overwritten.
(function glossaryFallback() {
  const g = globalThis;
  const plain = (s) => String(s ?? "").replace(/_/g, " ");
  if (typeof tipAttr === "undefined") g.tipAttr = () => "";
  if (typeof catLabel === "undefined") g.catLabel = plain;
  if (typeof catTip === "undefined") g.catTip = () => "";
  if (typeof catChip === "undefined") {
    g.catChip = (c, cls = "cat") => `<span class="${cls}">${esc(plain(c))}</span>`;
  }
  if (typeof ruleTip === "undefined") g.ruleTip = () => "";
  if (typeof signalTip === "undefined") g.signalTip = () => "";
  if (typeof anyTip === "undefined") g.anyTip = () => "";
  if (typeof explainBlock === "undefined") g.explainBlock = () => "";
  if (typeof narrativeBlock === "undefined") g.narrativeBlock = () => "";
  if (typeof scoreBlock === "undefined") {
    g.scoreBlock = (n) => `<div class="scorebar"><span class="scorebar-val">${esc(String(n ?? 0))}</span><span class="scorebar-scale">/100</span></div>`;
  }
  // Lookup tables: an empty object yields no tooltip, which is exactly the
  // pre-glossary behaviour.
  if (typeof SEVERITY_INFO === "undefined") g.SEVERITY_INFO = {};
  if (typeof OUTCOME_INFO === "undefined") g.OUTCOME_INFO = {};
  if (typeof VERDICT_INFO === "undefined") g.VERDICT_INFO = {};
  if (typeof LAYER_INFO === "undefined") g.LAYER_INFO = {};
  if (typeof METRIC_INFO === "undefined") g.METRIC_INFO = {};
  if (typeof TAINT_INFO === "undefined") g.TAINT_INFO = {};
  if (typeof BREAKDOWN_INFO === "undefined") g.BREAKDOWN_INFO = {};

  if (typeof CATEGORY_INFO === "undefined") {
    console.warn("Argus: /glossary.js did not load — plain-English tooltips and explainers are disabled, but the dashboard is otherwise fine.");
  }
})();

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
  // Tooltip is looked up by the label itself, so every caller gets the
  // explanation for free without threading an extra argument through.
  return `<div class="card kpi ${crit ? "crit" : ""}"><span class="lab"${tipAttr(METRIC_INFO[lab])}>${lab}</span><span class="val">${val}</span><span class="sub">${sub || ""}</span></div>`;
}
/**
 * An empty state that tells you how to get data, instead of only telling you
 * there isn't any. `steps` entries may contain safe inline markup (<b>/<code>) —
 * they're author-written copy, never user input.
 */
function emptyCta({ title, body, steps = [], action }) {
  return `<div class="empty-cta">
    <div class="big">${title}</div>
    ${body ? `<p>${body}</p>` : ""}
    ${steps.length ? `<div class="empty-steps">${steps.map((s, i) =>
      `<div class="es-row"><span class="es-n">${i + 1}</span><span>${s}</span></div>`).join("")}</div>` : ""}
    ${action ? `<a class="btn btn-primary" href="${esc(action.href)}" style="text-decoration:none">${esc(action.label)}</a>` : ""}
  </div>`;
}

function breakdown(sel, items, isSev) {
  const el = $(sel); if (!el) return;
  if (!items || !items.length) { el.innerHTML = '<div class="empty" style="padding:calc(var(--u)*3)">none</div>'; return; }
  const max = Math.max(...items.map((i) => Number(i.n)), 1);
  el.innerHTML = items.map((i) => {
    const color = isSev ? `var(--sev-${sevName(i.label) === "info" ? "low" : sevName(i.label)})` : "var(--accent)";
    // Non-severity rows get the friendly label plus a hover explanation when we
    // have one (categories, outcomes, span types...).
    const lab = isSev
      ? pill(i.label)
      : `<span class="cat"${tipAttr(anyTip(i.label))}>${esc(catLabel(i.label) || "—")}</span>`;
    return `<div class="row">${lab}<span class="barmini"><b style="width:${(Number(i.n) / max) * 100}%;background:${color}"></b></span><span class="mono dim">${num(i.n)}</span></div>`;
  }).join("");
}

// ---------- routing ----------
const VIEWS = ["apps", "overview", "threat", "incidents", "review", "redteam", "traces", "trace", "sessions", "analytics", "prompts", "evals", "settings", "keys", "team", "audit", "admin", "customers", "adminusers", "auditall", "appearance", "guide"];
function show(view) {
  VIEWS.forEach((v) => $(`#view-${v}`).classList.toggle("on", v === view));
  document.querySelectorAll(".nav-item[data-nav]").forEach((b) => b.classList.toggle("active", b.dataset.nav === view));
  window.scrollTo({ top: 0 });
}
document.querySelectorAll("[data-nav]").forEach((el) => el.addEventListener("click", () => {
  const v = el.dataset.nav;
  // "Applications" is the cross-project catalog — leaving a scoped view means
  // dropping ?project= so we see every app again.
  if (v === "apps" && PROJECT) { location.href = location.pathname; return; }
  show(v); load(v);
}));

// ---------- Applications catalog (customers -> their apps) ----------
// Cross-company listing is opt-in and platform-admin only — the server enforces
// both, this just drives the request.
let SHOW_ALL_COMPANIES = false;
async function loadApps() {
  try {
    const rows = await (await fetch("/api/projects" + (SHOW_ALL_COMPANIES ? "?all=1" : ""))).json(); banner("");
    if (!Array.isArray(rows) || !rows.length) {
      $("#appsSub").textContent = "no applications yet";
      $("#appsCatalog").innerHTML = '<div class="card"><div class="empty" style="padding:calc(var(--u)*4)"><div class="big">No applications connected yet</div><a href="/onboard.html" style="color:var(--accent)">Connect your first app →</a></div></div>';
      return;
    }
    const byOrg = new Map();
    rows.forEach((r) => { if (!byOrg.has(r.orgName)) byOrg.set(r.orgName, []); byOrg.get(r.orgName).push(r); });
    const noun = SHOW_ALL_COMPANIES ? "customers" : "companies";
    const scopeNote = byOrg.size > 1 ? ` across ${byOrg.size} ${noun}` : "";
    $("#appsSub").textContent = `${rows.length} application${rows.length > 1 ? "s" : ""}${scopeNote}`;
    $("#appsCatalog").innerHTML = [...byOrg.entries()].map(([org, apps]) => `
      <div>
        <div style="display:flex;align-items:baseline;gap:8px;margin-bottom:10px">
          <span style="font-weight:650;font-size:14px">${esc(org)}</span>
          <span class="dim" style="font-size:12px">${apps.length} app${apps.length > 1 ? "s" : ""}</span>
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:12px">
          ${apps.map(appCard).join("")}
        </div>
      </div>`).join("");
    stamp();
  } catch (e) { banner("Applications query failed: " + e.message); }
}
function appCard(a) {
  const sec = Number(a.secEvents) > 0
    ? pill(sevName(a.maxSev)) + ` <span class="dim">${num(a.secEvents)} event${Number(a.secEvents) > 1 ? "s" : ""}</span>`
    : '<span class="dim">no security events</span>';
  const activity = a.lastSeen ? "active " + ago(a.lastSeen) : "no traffic yet";
  return `<a class="card clickable" href="/?project=${encodeURIComponent(a.projectId)}" style="text-decoration:none;color:inherit;display:block;padding:calc(var(--u)*2.6)">
    <div style="display:flex;justify-content:space-between;align-items:baseline;gap:8px">
      <span style="font-weight:650;font-size:15px">${esc(a.projectName)}</span>
      ${a.environment ? `<span class="pill pill-neutral">${esc(a.environment)}</span>` : ""}
    </div>
    <div class="dim mono" style="font-size:10.5px;margin:3px 0 12px">${esc(String(a.projectId).slice(0, 13))}… · ${activity}</div>
    <div style="display:flex;gap:16px;flex-wrap:wrap;font-size:12.5px">
      <span><b>${num(a.traces)}</b> <span class="dim">traces</span></span>
      <span><b>${num(a.tokens)}</b> <span class="dim">tokens</span></span>
      <span><b>${money(a.cost)}</b></span>
    </div>
    <div style="margin-top:8px;font-size:12px">${sec}</div>
  </a>`;
}

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
  // Every chip explains itself on hover — a bare "R-OVR-001" means nothing to
  // anyone who hasn't read the rule pack.
  (ev.l1_rules || []).slice(0, 3).forEach((r) =>
    c.push(`<span class="lchip"${tipAttr(ruleTip(r) || LAYER_INFO.L1)}>${esc(r)}</span>`));
  Object.entries(ev.l2_scores || {}).forEach(([, s]) =>
    c.push(`<span class="lchip hot"${tipAttr(LAYER_INFO.L2)}>L2 ${Number(s).toFixed(2)}</span>`));
  if (ev.l3_verdict) c.push(`<span class="lchip hot"${tipAttr(LAYER_INFO.L3)}>L3</span>`);
  (ev.l4_signals || []).forEach((s) =>
    c.push(`<span class="lchip hot"${tipAttr(signalTip(s) || LAYER_INFO.L4)}>${esc(s)}</span>`));
  return `<span class="layerchips">${c.join("") || '<span class="lchip">—</span>'}</span>`;
}

/** Provenance rendered as readable lines instead of a comma-joined id list. */
function whyList(ev) {
  const rows = [];
  (ev.l1_rules || []).forEach((r) => rows.push([r, ruleTip(r) || "Matched an L1 heuristic rule."]));
  (ev.l4_signals || []).forEach((s) => rows.push([s, signalTip(s) || "An L4 trace-analysis signal fired."]));
  Object.entries(ev.l2_scores || {}).forEach(([m, s]) =>
    rows.push([`L2 ${Number(s).toFixed(2)}`, `Classifier “${m}” scored this ${Number(s).toFixed(2)} out of 1.00 for being injection-like.`]));
  if (ev.l3_verdict) rows.push(["L3", `AI judge verdict: ${ev.l3_verdict}`]);
  if (!rows.length) return "";
  return `<div class="why-list">${rows.map(([id, text]) =>
    `<div class="why-row"><span class="why-id">${esc(id)}</span><span class="why-text">${esc(text)}</span></div>`).join("")}</div>`;
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
  if (!feedRows.length) {
    t.innerHTML = `<tbody><tr><td>${emptyCta({
      title: "No security events — that's the good outcome",
      body: "Argus scanned everything it received and found nothing worth flagging. If you expected findings here, the two usual causes are below.",
      steps: [
        "Your time <b>Range</b> (top bar) may be excluding them — try <b>All time</b>.",
        "Your app may not be sending traces yet. Check the Traces page: if it's empty too, the problem is ingestion, not detection.",
        "Want to prove detection works? Send a trace containing a line like <code>Ignore all previous instructions</code> and watch it appear here.",
      ],
    })}</td></tr></tbody>`;
    return;
  }
  const head = `<thead><tr><th></th><th>Sev</th><th>Category</th><th>Outcome</th><th>Layers</th><th>Trace</th><th>When</th></tr></thead>`;
  const body = feedRows.map((ev, i) => `
    <tr class="evt s-${sevName(ev.severity)} clickable" data-i="${i}">
      <td class="stripe"><i></i></td><td>${pill(ev.severity)}</td>
      <td>${catChip(ev.category)}${ev.analyst_verdict && ev.analyst_verdict !== "unreviewed" ? " " + verdictTag(ev.analyst_verdict) : ""}</td>
      <td>${outcomePill(ev.outcome)}</td><td>${layerChips(ev)}</td>
      <td><a class="tracelink">${esc(ev.trace_id)}</a></td><td class="dim num">${ago(ev.detected_at)}</td>
    </tr>
    <tr class="evidence" id="ev-${i}" style="display:none"><td colspan="7">
      ${explainBlock(ev)}
      ${ev.evidence_excerpt ? `<div class="ev-label">Evidence — the text that triggered this</div><div class="ev-quote">${esc(ev.evidence_excerpt)}</div>` : ""}
      <div class="ev-label" style="margin-top:10px">Risk score</div>
      ${scoreBlock(ev.score)}
      <div class="ev-label" style="margin-top:10px">Why this was flagged</div>
      ${whyList(ev) || '<div class="dim" style="font-size:12px">No layer detail recorded.</div>'}
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
        <div>${(p.categories || []).map((c) => catChip(c, "tag")).join("")}</div>
        ${p.evidence ? `<div class="dim" style="font-size:12px;margin-top:6px">${esc(String(p.evidence).slice(0, 140))}</div>` : ""}
      </div>`).join("") : '<div class="empty">No content seen across multiple traces yet.</div>';
    const il = $("#incidentList");
    il.innerHTML = (d.traceIncidents || []).length ? d.traceIncidents.map((t) => `
      <div class="incident-card clickable" data-trace="${esc(t.trace_id)}">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:5px;">${pill(t.max_sev)}<a class="tracelink">${esc(t.trace_id)}</a><span style="margin-left:auto" class="dim">${num(t.events)} events · ${ago(t.last_seen)}</span></div>
        <div>${(t.categories || []).map((c) => catChip(c, "tag")).join("")}</div>
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
        <td class="stripe"><i></i></td><td>${pill(ev.severity)}</td><td>${catChip(ev.category)}</td>
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
  try { await fetch("/api/verdict", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ eventId, verdict, project: PROJECT }) }); }
  catch (e) { banner("Verdict failed: " + e.message); }
}

// ---------- Traces ----------
async function loadTraces() {
  try {
    const rows = await api("/api/traces"); banner("");
    $("#tracesSub").textContent = `${rows.length} recent traces`;
    const t = $("#tracesTable");
    if (!rows.length) {
      t.innerHTML = `<tbody><tr><td>${emptyCta({
        title: "No traces yet",
        body: "A trace is one end-to-end run of your app. Nothing has arrived for this application in the selected range.",
        steps: [
          "Check the <b>Range</b> filter in the top bar — try <b>All time</b>.",
          "Confirm your app is posting to <code>/api/public/ingestion</code> or <code>/v1/traces</code> with this application's API key.",
          "Not connected yet? Walk through the three-step setup and send a test message.",
        ],
        action: { href: "/onboard.html", label: "Connect this app →" },
      })}</td></tr></tbody>`;
      return;
    }
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
    // Plain-English reconstruction of what happened, above the waterfall — the
    // answer to "what am I looking at?" before any span is clicked.
    const narr = $("#narrativeCard");
    if (narr) {
      const html = narrativeBlock(obs, events);
      narr.innerHTML = html ? `<div class="card-head"><span class="card-title">What happened</span><span class="card-hint">reconstructed from this trace</span></div>${html}` : "";
      narr.style.display = html ? "" : "none";
    }
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
      const flags = [...new Set(evs.flatMap((e) => e.l4_signals || []))].slice(0, 2).map((s) => `<span class="lchip hot"${tipAttr(signalTip(s) || LAYER_INFO.L4)}>${esc(s)}</span>`).join("");
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
    // `taint` and `type` are the two rows people ask about — explain them inline.
    const attrTip = (k, v) => (k === "taint" ? TAINT_INFO[v] : k === "type" ? BREAKDOWN_INFO[v] : "");
    body.innerHTML = `<dl class="kv">${rows.filter(([, v]) => v !== "" && v != null).map(([k, v]) => `<dt>${esc(k)}</dt><dd${tipAttr(attrTip(k, v))}>${esc(String(v))}</dd>`).join("")}</dl>`;
  } else {
    const evs = curEvByObs[o.observation_id] || [];
    body.innerHTML = evs.length ? evs.map((e) => `<div class="sec-block"><div class="sec-block-head">${pill(e.severity)} ${catChip(e.category)} · ${outcomePill(e.outcome)}</div><div class="sec-block-body">${explainBlock(e)}${e.evidence_excerpt ? `<div class="ev-label">Evidence</div><div style="margin-bottom:8px">${esc(e.evidence_excerpt)}</div>` : ""}<div class="ev-label">Risk score</div>${scoreBlock(e.score)}${whyList(e) ? `<div class="ev-label" style="margin-top:10px">Why this was flagged</div>${whyList(e)}` : ""}<div class="ev-actions"><button class="btn" data-verdict="confirmed" data-ev="${esc(e.event_id)}">Confirm</button><button class="btn" data-verdict="false_positive" data-ev="${esc(e.event_id)}">False positive</button></div></div></div>`).join("") : '<div class="dim" style="font-size:12px">No security events on this span.</div>';
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
    if (!rows.length) {
      t.innerHTML = `<tbody><tr><td>${emptyCta({
        title: "No sessions yet",
        body: "Sessions group several traces into one conversation. They appear automatically once your traces carry a session ID.",
        steps: [
          "Set a <code>session_id</code> (or <code>sessionId</code>) on the traces your app sends.",
          "Use the same value for every turn of a conversation — that's what links them together.",
          "Add a <code>user_id</code> too if you can: it's what makes the Users count and repeat-offender analysis work.",
        ],
      })}</td></tr></tbody>`;
      return;
    }
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
    t.innerHTML = rows.length ? `<thead><tr><th>Score</th><th>Count</th><th>Avg</th><th>Min</th><th>Max</th></tr></thead><tbody>` + rows.map((r) => `<tr><td>${esc(r.name)}</td><td class="num">${num(r.n)}</td><td class="num">${r.avg_value}</td><td class="num dim">${r.min_value}</td><td class="num dim">${r.max_value}</td></tr>`).join("") + "</tbody>" : `<tbody><tr><td>${emptyCta({
      title: "No eval scores yet",
      body: "Evals track how <i>good</i> your AI's answers are, separately from whether they're safe. Each row here is one score name with its average across every trace.",
      steps: [
        "Decide what to measure — e.g. <code>helpfulness</code>, <code>groundedness</code>, <code>sec.injection_risk</code>.",
        "Score your traces with an LLM-as-judge run or human annotation.",
        "Submit them to the scores API against a trace ID; they'll aggregate here automatically.",
      ],
    })}</td></tr></tbody>`;
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

// ---------- global search ----------
// Deliberately client-side and dumb: a trace ID pasted from a log should open
// that trace, and anything else filters the list you're already looking at.
// The FAQ used to say "you can't look up a trace by ID" — this is that.
const searchInput = $("#globalSearch");
searchInput?.addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  const q = searchInput.value.trim();
  if (!q) return;
  // A trace ID is long and has no spaces — treat it as "open this trace".
  if (!/\s/.test(q) && q.length >= 12) { openTrace(q, "traces"); return; }
  applyFilter(q);
});
searchInput?.addEventListener("input", () => { if (!searchInput.value.trim()) applyFilter(""); });

/** Hides table rows / cards on the current view that don't contain the term. */
function applyFilter(q) {
  const term = q.toLowerCase();
  const view = document.querySelector(".view.on");
  if (!view) return;
  let shown = 0, total = 0;
  // Feed rows come in pairs (row + hidden evidence row); filter the visible one
  // and keep its evidence row collapsed alongside it.
  view.querySelectorAll("table tbody tr:not(.evidence), .incident-card").forEach((row) => {
    total++;
    const hit = !term || row.textContent.toLowerCase().includes(term);
    row.style.display = hit ? "" : "none";
    if (hit) shown++;
    const ev = row.nextElementSibling;
    if (ev && ev.classList.contains("evidence") && !hit) ev.style.display = "none";
  });
  const note = $("#searchNote");
  if (note) note.textContent = term ? `${shown} of ${total} match “${q}”` : "";
}

// ---------- loader dispatch ----------
// Views that only make sense inside a selected application.
const SCOPED_VIEWS = new Set(["overview", "threat", "incidents", "review", "redteam", "traces", "sessions", "analytics", "prompts", "evals", "settings", "keys", "team", "audit"]);
function load(view) {
  // Any re-render replaces the rows the filter was hiding, so drop the stale
  // "N of M match" note rather than leaving it contradicting the screen.
  if (searchInput) { searchInput.value = ""; const n = $("#searchNote"); if (n) n.textContent = ""; }
  if (!PROJECT && SCOPED_VIEWS.has(view)) { banner("Select an application from Applications to view its data."); return; }
  ({ apps: loadApps, overview: loadOverview, threat: loadThreat, incidents: loadIncidents, review: loadReview, traces: loadTraces, sessions: loadSessions, analytics: loadAnalytics, evals: loadEvals, settings: loadSettings, keys: loadKeys, team: loadTeam, audit: loadAudit, admin: loadAdmin, customers: loadCustomers, adminusers: loadAdminUsers, auditall: loadAuditAll }[view] || (() => {}))();
}

// ---------- Audit log ----------
const ACTION_LABELS = {
  "user.signup": "Signed up",
  "apikey.created": "Created API key", "apikey.revoked": "Revoked API key",
  "member.invited": "Invited member", "member.role_changed": "Changed member role",
  "member.removed": "Removed member", "member.invite_revoked": "Revoked invite",
  "event.verdict_set": "Set security verdict", "project.created": "Created application",
  "settings.updated": "Updated settings",
  "admin.platform_admin_changed": "Changed platform-admin", "admin.user_deleted": "Deleted user",
  "admin.company_created": "Created company", "admin.company_renamed": "Renamed company",
  "admin.company_deleted": "Deleted company",
};
const actionLabel = (a) => ACTION_LABELS[a] || a;
function auditDetail(e) {
  const m = e.metadata || {}, bits = [];
  if (m.name) bits.push(esc(m.name));
  if (m.role) bits.push("role: " + esc(m.role));
  if (m.verdict) bits.push(esc(titleCase(m.verdict)));
  if (m.publicKey) bits.push(`<span class="mono">${esc(m.publicKey)}</span>`);
  if (typeof m.value !== "undefined") bits.push(m.value ? "granted" : "revoked");
  if (typeof m.projectsPurged !== "undefined") bits.push(`${m.projectsPurged} app(s) purged`);
  if (e.target && !m.name) {
    const t = String(e.target);
    bits.push(t.includes("@") ? esc(t) : `<span class="mono dim">${esc(t.slice(0, 13))}${t.length > 13 ? "…" : ""}</span>`);
  }
  return bits.join(" · ") || "—";
}
function renderAuditRows(rows, showOrg) {
  if (!rows.length) return '<tbody><tr><td class="empty" style="padding:calc(var(--u)*4)">No activity recorded yet.</td></tr></tbody>';
  return `<thead><tr><th>When</th><th>Who</th><th>Action</th>${showOrg ? "<th>Company</th>" : ""}<th>Details</th></tr></thead><tbody>` +
    rows.map((e) => `<tr><td class="dim">${ago(e.at)}</td><td>${esc(e.actorEmail || "—")}</td><td>${esc(actionLabel(e.action))}</td>${showOrg ? `<td class="dim">${esc(e.orgName || "—")}</td>` : ""}<td class="dim">${auditDetail(e)}</td></tr>`).join("") + "</tbody>";
}
async function loadAudit() {
  if (!PROJECT) { banner("Open an application to view its company's audit log."); return; }
  try {
    const d = await api("/api/audit"); banner("");
    const rows = d.entries || [];
    $("#auditSub").textContent = `${rows.length} recent action${rows.length !== 1 ? "s" : ""} in this company`;
    $("#auditTable").innerHTML = renderAuditRows(rows, false);
    stamp();
  } catch (e) { banner("Audit query failed: " + e.message); }
}
async function loadAuditAll() {
  try {
    const d = await (await fetch("/api/admin/audit")).json(); banner("");
    const rows = d.entries || [];
    $("#auditAllSub").textContent = `${rows.length} recent actions`;
    $("#auditAllTable").innerHTML = renderAuditRows(rows, true);
    stamp();
  } catch (e) { banner("Audit query failed: " + e.message); }
}

// ---------- Platform admin: overview (all customers) ----------
async function loadAdmin() {
  try {
    const d = await (await fetch("/api/admin/overview")).json(); banner("");
    const t = d.totals || {};
    $("#adminKpis1").innerHTML =
      tile("Customers", num(t.orgs), num(t.projects) + " apps") +
      tile("Users", num(t.users), num(t.admins) + " platform admins") +
      tile("Applications", num(t.projects), "") +
      tile("Security events", num(t.securityEvents), num(t.highCritical) + " high/critical", Number(t.highCritical) > 0);
    $("#adminKpis2").innerHTML =
      tile("Traces", num(t.traces), "") +
      tile("Spans", num(t.observations), "") +
      tile("Tokens", num(t.tokens), "") +
      tile("Total cost", money(t.cost), "across all customers") +
      tile("Unreviewed", num(t.unreviewed), "security events");
    const rows = d.topOrgs || [];
    $("#topOrgsTable").innerHTML = `<thead><tr><th>Company</th><th>Apps</th><th>Tokens</th><th>Cost</th><th>Sec events</th></tr></thead><tbody>` +
      (rows.length ? rows.map((o) => `<tr><td>${esc(o.org)}</td><td class="num">${num(o.projects)}</td><td class="num">${num(o.tokens)}</td><td class="num">${money(o.cost)}</td><td class="num">${num(o.secEvents)}</td></tr>`).join("") : '<tr><td class="empty">No customer data yet.</td></tr>') + "</tbody>";
    stamp();
  } catch (e) { banner("Platform overview failed: " + e.message); }
}

// ---------- Platform admin: companies ----------
async function loadCustomers() {
  try {
    const d = await (await fetch("/api/admin/orgs")).json(); banner("");
    const orgs = d.orgs || [];
    $("#customersSub").textContent = `${orgs.length} companies`;
    $("#customersTable").innerHTML = `<thead><tr><th>Company</th><th>Apps</th><th>Members</th><th>Created</th><th></th></tr></thead><tbody>` +
      orgs.map((o) => `<tr><td>${esc(o.name)}</td><td class="num">${num(o.projectCount)}</td><td class="num">${num(o.memberCount)}</td><td class="dim">${o.createdAt ? ago(o.createdAt) : ""}</td><td style="text-align:right"><button class="btn" data-rename="${esc(o.id)}" data-name="${esc(o.name)}" style="padding:3px 9px;font-size:11px">Rename</button> <button class="btn" data-delorg="${esc(o.id)}" data-name="${esc(o.name)}" style="padding:3px 9px;font-size:11px;color:var(--sev-critical)">Delete</button></td></tr>`).join("") + "</tbody>";
    document.querySelectorAll("[data-rename]").forEach((b) => b.addEventListener("click", async () => {
      const name = prompt("Rename company:", b.dataset.name); if (!name || name === b.dataset.name) return;
      const r = await fetch("/api/admin/orgs/" + encodeURIComponent(b.dataset.rename), { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ name }) });
      if (!r.ok) banner((await r.json().catch(() => ({}))).error || "Rename failed");
      loadCustomers();
    }));
    document.querySelectorAll("[data-delorg]").forEach((b) => b.addEventListener("click", async () => {
      if (!confirm(`Delete company "${b.dataset.name}"? This permanently removes its apps, keys, members, and ALL trace + security data. This cannot be undone.`)) return;
      const r = await fetch("/api/admin/orgs/" + encodeURIComponent(b.dataset.delorg), { method: "DELETE" });
      if (!r.ok) banner((await r.json().catch(() => ({}))).error || "Delete failed");
      else { const j = await r.json(); banner(`Deleted "${b.dataset.name}" — purged ${j.projectsPurged} app(s) of data.`); setTimeout(() => banner(""), 4000); }
      loadCustomers();
    }));
    stamp();
  } catch (e) { banner("Companies query failed: " + e.message); }
}
$("#createOrgBtn")?.addEventListener("click", async () => {
  const name = $("#newOrgName").value.trim(); if (!name) return;
  const r = await fetch("/api/admin/orgs", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name }) });
  if (!r.ok) { banner((await r.json().catch(() => ({}))).error || "Create failed"); return; }
  $("#newOrgName").value = ""; loadCustomers();
});

// ---------- Platform admin: users ----------
async function loadAdminUsers() {
  try {
    const d = await (await fetch("/api/admin/users")).json(); banner("");
    const users = d.users || [];
    $("#adminUsersSub").textContent = `${users.length} users`;
    $("#adminUsersTable").innerHTML = `<thead><tr><th>User</th><th>Orgs</th><th>Verified</th><th>Platform admin</th><th></th></tr></thead><tbody>` +
      users.map((u) => {
        const you = u.id === ME_ID;
        return `<tr>
          <td>${esc(u.name || u.email)}${u.name ? ` <span class="dim">${esc(u.email)}</span>` : ""}${you ? ' <span class="dim">(you)</span>' : ""}</td>
          <td class="num">${num(u.orgCount)}</td>
          <td>${u.emailVerified ? '<span style="color:var(--ok);font-size:11.5px">✓ verified</span>' : '<span class="dim" style="font-size:11.5px">unverified</span>'}</td>
          <td><input type="checkbox" data-admin-user="${esc(u.id)}" ${u.isPlatformAdmin ? "checked" : ""} ${you ? "disabled" : ""}></td>
          <td style="text-align:right">${you ? "" : `<button class="btn" data-deluser="${esc(u.id)}" data-email="${esc(u.email)}" style="padding:3px 9px;font-size:11px;color:var(--sev-critical)">Remove</button>`}</td></tr>`;
      }).join("") + "</tbody>";
    document.querySelectorAll("[data-admin-user]").forEach((c) => c.addEventListener("change", async () => {
      const r = await fetch("/api/admin/users/" + encodeURIComponent(c.dataset.adminUser) + "/platform-admin", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ value: c.checked }) });
      if (!r.ok) banner((await r.json().catch(() => ({}))).error || "Update failed");
      loadAdminUsers();
    }));
    document.querySelectorAll("[data-deluser]").forEach((b) => b.addEventListener("click", async () => {
      if (!confirm(`Remove user ${b.dataset.email}? They lose access immediately.`)) return;
      const r = await fetch("/api/admin/users/" + encodeURIComponent(b.dataset.deluser), { method: "DELETE" });
      if (!r.ok) banner((await r.json().catch(() => ({}))).error || "Remove failed");
      loadAdminUsers();
    }));
    stamp();
  } catch (e) { banner("Users query failed: " + e.message); }
}

// ---------- API Keys (admin+) ----------
// ---------- Application settings (detection config) ----------
// Read is member+; save is admin+ (server-enforced). Non-admins see the current
// settings but the controls are disabled.
let SETTINGS_CFG = null;
async function loadSettings() {
  if (!PROJECT) { banner("Open an application to view its settings."); return; }
  try {
    const d = await api("/api/settings"); banner("");
    SETTINGS_CFG = d.config;
    const canEdit = (ROLE_RANK[PROJECT_ROLE] ?? -1) >= 2;
    fillSettings(d.config, canEdit);
    const who = d.updatedBy ? ` · last changed by ${esc(d.updatedBy)}` : "";
    $("#settingsSub").innerHTML = (canEdit ? "Changes apply within ~30s — no redeploy" : "Read-only — admin role required to change") + who;
    $("#saveSettingsBtn").style.display = canEdit ? "" : "none";
    $("#settingsSaveNote").textContent = "";
    stamp();
  } catch (e) { banner("Settings query failed: " + e.message); }
}

function fillSettings(c, canEdit) {
  const pct = Math.round((c.sampling?.trace_sample_rate ?? 1) * 100);
  $("#setSample").value = pct;
  $("#setSampleVal").textContent = pct + "%";
  $("#setRedact").value = c.redaction?.mode || "off";
  $("#setL2").checked = !!c.layers?.classifiers?.enabled;
  $("#setL4").checked = !!c.layers?.trace_analysis?.enabled;
  $("#setAlertSev").value = c.alerting?.min_severity || "high";
  // Disable the editable controls for non-admins (L1/L3 stay disabled always).
  ["setSample", "setRedact", "setL2", "setL4", "setAlertSev"].forEach((id) => { const el = $("#" + id); if (el) el.disabled = !canEdit; });
}

$("#setSample")?.addEventListener("input", () => { $("#setSampleVal").textContent = $("#setSample").value + "%"; });

$("#saveSettingsBtn")?.addEventListener("click", async () => {
  if (!SETTINGS_CFG) return;
  // Start from the loaded config so untouched fields (canaries, thresholds,
  // heuristics ruleset) are preserved, then overlay the controls we expose.
  const cfg = JSON.parse(JSON.stringify(SETTINGS_CFG));
  cfg.sampling = { trace_sample_rate: Number($("#setSample").value) / 100 };
  cfg.redaction = { mode: $("#setRedact").value };
  cfg.layers = cfg.layers || {};
  cfg.layers.classifiers = { ...(cfg.layers.classifiers || {}), enabled: $("#setL2").checked };
  cfg.layers.trace_analysis = { ...(cfg.layers.trace_analysis || {}), enabled: $("#setL4").checked };
  cfg.alerting = { ...(cfg.alerting || {}), min_severity: $("#setAlertSev").value };
  const btn = $("#saveSettingsBtn");
  btn.disabled = true; btn.textContent = "Saving…";
  try {
    const res = await fetch("/api/settings", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ project: PROJECT, config: cfg }) });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { banner(d.error || "Save failed"); return; }
    SETTINGS_CFG = d.config;
    fillSettings(d.config, true);
    $("#settingsSaveNote").textContent = `Saved (v${d.version}) — live within ~30s.`;
  } catch (e) { banner("Save failed: " + e.message); }
  finally { btn.disabled = false; btn.textContent = "Save settings"; }
});

async function loadKeys() {
  if (!PROJECT) { banner("Open an application to manage its API keys."); return; }
  try {
    const d = await api("/api/keys"); banner("");
    const keys = d.keys || [];
    $("#keysSub").textContent = `${keys.length} key${keys.length !== 1 ? "s" : ""} for this application`;
    const t = $("#keysTable");
    t.innerHTML = `<thead><tr><th>Public key</th><th>Created</th><th>Last used</th><th></th></tr></thead><tbody>` +
      keys.map((k) => `<tr><td class="mono">${esc(k.publicKey)}</td><td class="dim">${k.createdAt ? ago(k.createdAt) : "—"}</td><td class="dim">${k.lastUsedAt ? ago(k.lastUsedAt) : "never"}</td><td style="text-align:right"><button class="btn" data-revoke="${esc(k.id)}" style="padding:3px 9px;font-size:11px;color:var(--sev-critical)">Revoke</button></td></tr>`).join("") + "</tbody>";
    t.querySelectorAll("[data-revoke]").forEach((b) => b.addEventListener("click", () => revokeKey(b.dataset.revoke)));
    stamp();
  } catch (e) { banner("Keys query failed: " + e.message); }
}
$("#createKeyBtn")?.addEventListener("click", async () => {
  try {
    const res = await fetch("/api/keys", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ project: PROJECT }) });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { banner(d.error || "Create failed"); return; }
    $("#newKeyBox").innerHTML = `<div style="margin:calc(var(--u)*2) calc(var(--u)*3);padding:12px 14px;border:1px solid var(--accent);border-radius:var(--radius);background:color-mix(in srgb,var(--accent) 8%,transparent)">
      <div style="font-weight:600;margin-bottom:6px">New key created — copy it now, it won't be shown again</div>
      <div class="mono" style="font-size:12px;line-height:1.7">${esc(d.token || "")}</div>
      <div class="dim" style="font-size:11.5px;margin-top:8px">Drop it straight into your app: <span class="mono">argus.init("${esc(d.token || "")}")</span> — no environment variables needed.</div>
      <details style="font-size:11.5px;margin-top:8px"><summary style="cursor:pointer">Legacy public/secret pair</summary>
        <div class="mono" style="font-size:12px;line-height:1.7;padding-top:6px">public: ${esc(d.publicKey)}<br>secret: ${esc(d.secretKey)}</div></details></div>`;
    loadKeys();
  } catch (e) { banner("Create failed: " + e.message); }
});
async function revokeKey(id) {
  if (!confirm("Revoke this key? Any app using it will stop sending data.")) return;
  try {
    const res = await fetch(`/api/keys/${encodeURIComponent(id)}?project=${encodeURIComponent(PROJECT)}`, { method: "DELETE" });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { banner(d.error || "Revoke failed"); return; }
    $("#newKeyBox").innerHTML = ""; loadKeys();
  } catch (e) { banner("Revoke failed: " + e.message); }
}

// ---------- Team & roles ----------
async function loadTeam() {
  if (!PROJECT) { banner("Open an application to manage its team."); return; }
  try {
    const d = await api("/api/members"); banner("");
    const members = d.members || [], myRole = d.myRole, myId = d.myUserId;
    const canManage = myRole === "admin" || myRole === "owner";
    $("#inviteCard").style.display = canManage ? "" : "none";
    $("#teamSub").textContent = `${members.length} member${members.length !== 1 ? "s" : ""}`;
    const t = $("#teamTable");
    t.innerHTML = `<thead><tr><th>Member</th><th>Role</th><th></th></tr></thead><tbody>` +
      members.map((m) => memberRow(m, canManage, myId)).join("") + "</tbody>";
    wireTeam();
    stamp();
  } catch (e) { banner("Team query failed: " + e.message); }
}
function memberRow(m, canManage, myId) {
  const you = m.userId && m.userId === myId;
  const who = m.pending
    ? `<span class="dim">${esc(m.email)}</span> <span class="pill pill-neutral">invited</span>`
    : `${esc(m.name || m.email)}${m.name ? ` <span class="dim">${esc(m.email)}</span>` : ""}${you ? ' <span class="dim">(you)</span>' : ""}`;
  let role;
  if (canManage && !m.pending && !you) {
    role = `<select data-role-user="${esc(m.userId)}" style="font:inherit;font-size:12px;padding:3px 6px;border:1px solid var(--line);border-radius:5px;background:var(--surface);color:var(--ink)">` +
      ["owner", "admin", "member", "viewer"].map((r) => `<option value="${r}"${m.role === r ? " selected" : ""}>${r}</option>`).join("") + "</select>";
  } else { role = `<span class="pill pill-neutral">${esc(m.role)}</span>`; }
  const action = canManage && (m.pending || !you)
    ? `<button class="btn" data-remove-user="${esc(m.userId || "")}" data-remove-email="${esc(m.pending ? m.email : "")}" style="padding:3px 9px;font-size:11px;color:var(--sev-critical)">Remove</button>`
    : "";
  return `<tr><td>${who}</td><td>${role}</td><td style="text-align:right">${action}</td></tr>`;
}
function wireTeam() {
  document.querySelectorAll("[data-role-user]").forEach((s) => s.addEventListener("change", async () => {
    try {
      const res = await fetch("/api/members/role", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ project: PROJECT, userId: s.dataset.roleUser, role: s.value }) });
      const d = await res.json().catch(() => ({}));
      if (!res.ok) banner(d.error || "Role change failed");
    } catch (e) { banner(e.message); }
    loadTeam();
  }));
  document.querySelectorAll("[data-remove-user]").forEach((b) => b.addEventListener("click", async () => {
    if (!confirm("Remove this member from the organization?")) return;
    try {
      const res = await fetch("/api/members/remove", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ project: PROJECT, userId: b.dataset.removeUser || undefined, email: b.dataset.removeEmail || undefined }) });
      const d = await res.json().catch(() => ({}));
      if (!res.ok) banner(d.error || "Remove failed");
    } catch (e) { banner(e.message); }
    loadTeam();
  }));
}
$("#inviteBtn")?.addEventListener("click", async () => {
  const email = $("#inviteEmail").value.trim(), role = $("#inviteRole").value;
  const out = $("#inviteResult");
  if (!email) { out.innerHTML = ""; return; }
  try {
    const res = await fetch("/api/members/invite", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ project: PROJECT, email, role }) });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { out.innerHTML = `<span style="color:var(--sev-critical);font-size:12px">${esc(d.error || "Invite failed")}</span>`; return; }
    if (d.added) out.innerHTML = `<span style="color:var(--ok);font-size:12px">Added — they already had an Argus account.</span>`;
    else out.innerHTML = `<span style="font-size:12px">Invitation created. Tell them to sign up at <b>${esc(location.origin)}/login.html</b> with <b>${esc(email)}</b> — they'll join this organization automatically.</span>`;
    $("#inviteEmail").value = "";
    loadTeam();
  } catch (e) { out.innerHTML = `<span style="color:var(--sev-critical);font-size:12px">${esc(e.message)}</span>`; }
});

// ---------- auth gate + user menu ----------
let EMAIL_CONFIGURED = true;
async function requireAuth() {
  try {
    const r = await fetch("/api/auth/me");
    if (r.ok) { const d = await r.json(); EMAIL_CONFIGURED = d.emailConfigured !== false; return d.user; }
  } catch { /* fall through */ }
  location.href = "/login.html";
  return null;
}
let ME_ID = null;
function renderUser(u) {
  ME_ID = u.id;
  const initial = (u.name || u.email || "?").trim().charAt(0).toUpperCase() || "?";
  const btn = $("#userBtn"); if (btn) { btn.textContent = initial; btn.title = u.email; }
  const em = $("#userEmail"); if (em) em.textContent = u.email;
  if (u.emailVerified === false) showVerifyBanner();
  if (u.isPlatformAdmin) {
    const g = $("#adminGroup"); if (g) g.style.display = "";
    // Operators can still reach every company's apps — but only by asking.
    const t = $("#allCompaniesToggle"); if (t) t.style.display = "flex";
  }
}
$("#allCompaniesChk")?.addEventListener("change", (e) => {
  SHOW_ALL_COMPANIES = e.target.checked;
  SWITCHER_BUILT = false; // rebuild the header switcher against the new scope
  loadApps();
});
function showVerifyBanner() {
  const bar = $("#verifyBanner"), msg = $("#verifyMsg");
  if (!bar) return;
  msg.textContent = EMAIL_CONFIGURED
    ? "Please verify your email address — check your inbox for the confirmation link."
    : "Email verification is pending — your admin hasn't configured email delivery yet, so no action is needed right now.";
  bar.style.display = "flex";
  $("#resendBtn").style.display = EMAIL_CONFIGURED ? "" : "none";
}
$("#resendBtn")?.addEventListener("click", async () => {
  const btn = $("#resendBtn"); btn.disabled = true; btn.textContent = "Sending…";
  try {
    const r = await fetch("/api/auth/resend", { method: "POST" });
    const d = await r.json().catch(() => ({}));
    $("#verifyMsg").textContent = d.alreadyVerified ? "Your email is already verified." : "Verification email sent — check your inbox.";
    if (d.alreadyVerified) $("#verifyBanner").style.display = "none";
  } catch { $("#verifyMsg").textContent = "Couldn't resend right now — try again shortly."; }
  finally { btn.textContent = "Resend email"; btn.disabled = false; }
});
$("#userBtn")?.addEventListener("click", (e) => { e.stopPropagation(); $("#userMenu").classList.toggle("open"); });
document.addEventListener("click", () => $("#userMenu")?.classList.remove("open"));
$("#logoutBtn")?.addEventListener("click", async () => {
  try { await fetch("/api/auth/logout", { method: "POST" }); } catch { /* redirect regardless */ }
  location.href = "/login.html";
});

// ---------- boot (gated on auth) ----------
const GUIDE_DEEP_LINK = new URLSearchParams(location.search).get("guide");
(async function boot() {
  const user = await requireAuth();
  if (!user) return; // redirected to /login.html
  renderUser(user);
  // Per-app views (Overview, Security, Observability, Engineering) only make
  // sense with an application selected. On the unscoped "All applications" view,
  // hide them so you can't land on a data page with nothing to show.
  if (!PROJECT) {
    document.querySelectorAll(".app-nav").forEach((g) => { g.style.display = "none"; });
    const ov = document.getElementById("navOverview");
    if (ov) ov.style.display = "none";
  }
  if (GUIDE_DEEP_LINK === "onboarding") {
    show("guide");
    const target = document.getElementById("g-onboarding");
    if (target) target.scrollIntoView({ behavior: "instant", block: "start" });
    document.querySelectorAll(".guide-toc .toc-link").forEach((b) => b.classList.toggle("active", b.dataset.scroll === "g-onboarding"));
  } else if (!PROJECT) {
    // No app selected -> the Applications catalog (only this user's orgs).
    show("apps"); load("apps");
  } else {
    loadOverview();
  }
})();
