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
  const nk = $("#navKeys"), na = $("#navAudit"), ns = $("#navSettings"), nc = $("#navCanaries");
  if (nc) nc.style.display = PROJECT && r >= 1 ? "" : "none"; // canaries: view member+, manage admin+
  const nal = $("#navAlerts");
  if (nal) nal.style.display = PROJECT && r >= 1 ? "" : "none"; // alerts: view member+, manage admin+
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
const VIEWS = ["apps", "overview", "threat", "incidents", "review", "assess", "redteam", "traces", "trace", "sessions", "analytics", "prompts", "evals", "settings", "keys", "canaries", "alerts", "team", "audit", "admin", "customers", "adminusers", "auditall", "appearance", "guide"];
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
const SCOPED_VIEWS = new Set(["overview", "threat", "incidents", "review", "assess", "redteam", "traces", "sessions", "analytics", "prompts", "evals", "settings", "keys", "team", "audit"]);
function load(view) {
  // Any re-render replaces the rows the filter was hiding, so drop the stale
  // "N of M match" note rather than leaving it contradicting the screen.
  if (searchInput) { searchInput.value = ""; const n = $("#searchNote"); if (n) n.textContent = ""; }
  if (!PROJECT && SCOPED_VIEWS.has(view)) { banner("Select an application from Applications to view its data."); return; }
  ({ apps: loadApps, overview: loadOverview, threat: loadThreat, incidents: loadIncidents, review: loadReview, assess: loadAssess, traces: loadTraces, sessions: loadSessions, analytics: loadAnalytics, evals: loadEvals, settings: loadSettings, keys: loadKeys, canaries: loadCanaries, alerts: loadAlerts, team: loadTeam, audit: loadAudit, admin: loadAdmin, customers: loadCustomers, adminusers: loadAdminUsers, auditall: loadAuditAll }[view] || (() => {}))();
}

// ---------- Canaries ----------
// The highest-signal detector in the product, so the screen leans on plain
// language: what it is, where you put it, and what it means when it fires.
async function loadCanaries() {
  if (!PROJECT) { banner("Open an application to manage its canaries."); return; }
  try {
    const d = await api("/api/canaries"); banner("");
    const rows = d.canaries || [];
    const fired = rows.filter((c) => c.triggerCount > 0).length;
    $("#canariesSub").textContent = rows.length
      ? `${rows.length} planted${fired ? ` · ${fired} triggered` : " · none triggered"}`
      : "none planted yet";
    // Creating requires admin; viewing only needs member. Hide the form rather
    // than let someone fill it in and be refused on submit.
    const canManage = (ROLE_RANK[PROJECT_ROLE] ?? -1) >= 2;
    $("#canaryCreateCard").style.display = canManage ? "" : "none";

    const t = $("#canariesTable");
    if (!rows.length) {
      t.innerHTML = `<tbody><tr><td class="empty" style="padding:calc(var(--u)*4)">
        <div class="big">No canaries planted</div>
        <p>Generate one above, then paste it somewhere it should never leave — the end of your system prompt is the
        usual first choice. If it ever shows up in something your app sends, you'll get a critical incident here.</p>
      </td></tr></tbody>`;
      return;
    }
    t.innerHTML = `<thead><tr><th>Label</th><th>Kind</th><th>Planted</th><th>Status</th><th></th></tr></thead><tbody>` +
      rows.map((c) => {
        const hit = c.triggerCount > 0;
        const status = hit
          ? `<span class="pill sev-critical">triggered ${c.triggerCount}×</span> <span class="dim">${c.lastTriggeredAt ? ago(c.lastTriggeredAt) : ""}</span>`
          : '<span class="dim">quiet</span>';
        const kind = c.kind === "custom"
          ? '<span class="cat" title="You supplied this value, so Argus stores it as-is">your marker</span>'
          : '<span class="cat" title="Generated by Argus and stored only as a hash">generated</span>';
        return `<tr><td>${esc(c.label || "—")}${c.kind === "custom" && c.value ? `<div class="mono dim" style="font-size:11px">${esc(c.value)}</div>` : ""}</td>` +
          `<td>${kind}</td><td class="dim">${c.createdAt ? ago(c.createdAt) : "—"}</td><td>${status}</td>` +
          `<td style="text-align:right">${canManage ? `<button class="btn" data-revoke-canary="${esc(c.id)}" style="padding:3px 9px;font-size:11px;color:var(--sev-critical)">Revoke</button>` : ""}</td></tr>`;
      }).join("") + "</tbody>";
    t.querySelectorAll("[data-revoke-canary]").forEach((b) =>
      b.addEventListener("click", () => revokeCanary(b.dataset.revokeCanary)));
    stamp();
  } catch (e) { banner("Canaries query failed: " + e.message); }
}

async function createCanary(custom) {
  const label = $("#canaryLabel").value.trim();
  const value = custom ? $("#canaryCustom").value.trim() : "";
  try {
    const res = await fetch("/api/canaries", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ project: PROJECT, label, value }),
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { banner(d.error || "Could not create the canary."); return; }
    // A generated canary exists in exactly one place after this response is
    // rendered: the customer's clipboard. Say so, unmistakably.
    $("#newCanaryBox").innerHTML = `<div style="margin:0 calc(var(--u)*3) calc(var(--u)*3);padding:12px 14px;border:1px solid var(--accent);border-radius:var(--radius);background:color-mix(in srgb,var(--accent) 8%,transparent)">
      <div style="font-weight:600;margin-bottom:6px">${d.kind === "generated" ? "Canary created — copy it now, it will never be shown again" : "Marker registered"}</div>
      <div class="mono" style="font-size:12px;line-height:1.7;word-break:break-all">${esc(d.value || "")}</div>
      <div class="dim" style="font-size:11.5px;margin-top:8px">Paste this into <b>${esc(d.label || "the place you chose")}</b>.
      ${d.kind === "generated" ? "Argus stored only a hash of it, so this page cannot show it to you again." : ""}</div>
    </div>`;
    $("#canaryLabel").value = ""; if (custom) $("#canaryCustom").value = "";
    loadCanaries();
  } catch (e) { banner("Could not create the canary: " + e.message); }
}
$("#createCanaryBtn")?.addEventListener("click", () => createCanary(false));
$("#createCustomCanaryBtn")?.addEventListener("click", () => createCanary(true));

async function revokeCanary(id) {
  if (!confirm("Revoke this canary? Argus will stop watching for it. Past incidents that reference it are kept.")) return;
  try {
    const res = await fetch(`/api/canaries/${encodeURIComponent(id)}?project=${encodeURIComponent(PROJECT)}`, { method: "DELETE" });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { banner(d.error || "Revoke failed"); return; }
    loadCanaries();
  } catch (e) { banner("Revoke failed: " + e.message); }
}

// ---------- Assessments (static analysis: prompts + architecture) ----------
// The other half of the platform. L1–L4 judge live traffic; this judges the
// application as built — its prompts and its topology — before an attacker
// sends anything. Deterministic by design: same input, same findings, so a fix
// stays fixed and every score can explain itself.
//
// Severity note: the engine's lowest band is "informational", which has no pill
// style and no glossary entry (the runtime taxonomy calls that band "info").
// Every finding also carries `argus_severity` in the runtime spelling, so pills
// are always rendered from THAT field. Rendering the native label would emit a
// `pill-informational` class that doesn't exist and silently lose the styling.
let ASSESS_TAB = "runs";
let ASSESS_GRAPH = { nodes: [], edges: [], updatedAt: null };
let ASSESS_GRAPH_LOADED = false;

const ASSESS_NODE_TYPES = ["user", "model", "tool", "code_interpreter", "memory_store", "document_source", "vector_database", "external_website", "email_system", "file_upload", "other"];
const ASSESS_EDGE_TYPES = ["sends_prompt", "invokes", "retrieves_data", "reads_data", "writes_data"];
const ASSESS_DOC_KINDS = ["system", "developer", "tool_description", "memory_instruction", "output_instruction", "user"];
const ASSESS_STATUSES = ["open", "resolved", "accepted"];

// Running an assessment and saving a graph are member+ on the server; reflect
// that here so a viewer gets a readable page instead of a button that 403s.
const assessCanWrite = () => (ROLE_RANK[PROJECT_ROLE] ?? -1) >= 1;

const assessOptions = (opts, current) => opts.map((o) => `<option value="${esc(o)}"${o === current ? " selected" : ""}>${esc(titleCase(o))}</option>`).join("");
const assessInput = "font:inherit;font-size:12.5px;padding:7px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--surface);color:var(--ink)";

/**
 * The Phase-4 badge: this weakness's attack class has actually been recorded
 * against this application. Deliberately loud — it is the difference between
 * "this could be exploited" and "someone is trying this", and it is the whole
 * argument for running observability and assessment in one product.
 */
const assessObservedTag = () =>
  `<span class="pill pill-critical" title="This attack class has been recorded against this application in production, so its likelihood is scored at maximum.">seen in production</span>`;

async function loadAssess() {
  if (!PROJECT) { banner("Open an application from Applications to assess it."); return; }
  banner("");
  // The graph is read once per session and reused: the Runs tab derives its
  // default context facts from it, which is what makes findings architecture-
  // aware rather than generic.
  if (!ASSESS_GRAPH_LOADED) {
    try {
      const g = await api("/api/assessment-graph");
      ASSESS_GRAPH = { nodes: g?.nodes || [], edges: g?.edges || [], updatedAt: g?.updatedAt || null };
      ASSESS_GRAPH_LOADED = true;
    } catch { /* a missing graph is not an error — the editor starts empty */ }
  }
  renderAssessTab();
}

$("#assessTabs")?.addEventListener("click", (e) => {
  const b = e.target.closest("[data-atab]");
  if (!b) return;
  ASSESS_TAB = b.dataset.atab;
  document.querySelectorAll("#assessTabs .dtab").forEach((x) => x.classList.toggle("active", x === b));
  renderAssessTab();
});

function renderAssessTab() {
  if (ASSESS_TAB === "findings") return renderAssessFindings();
  if (ASSESS_TAB === "arch") return renderAssessArch();
  if (ASSESS_TAB === "policies") return renderAssessPolicies();
  if (ASSESS_TAB === "controls") return renderAssessControls();
  return renderAssessRuns();
}

const assessPane = () => $("#assessPane");
const assessLoading = () => { assessPane().innerHTML = '<div class="card"><div class="dim" style="padding:calc(var(--u)*4)">loading…</div></div>'; };
const assessError = (e) => { assessPane().innerHTML = `<div class="card"><div class="empty" style="padding:calc(var(--u)*4)">${esc(String(e && e.message ? e.message : e))}</div></div>`; };

/** Facts we can prove from the saved graph, so the run form starts truthful. */
function assessFactsFromGraph() {
  const n = ASSESS_GRAPH.nodes || [];
  const tools = n.filter((x) => x.node_type === "tool");
  return {
    has_write_capable_tools: tools.some((t) => t.can_write),
    human_approval_enabled: tools.length > 0 && tools.filter((t) => t.can_write).every((t) => t.requires_approval),
    has_retrieval: n.some((x) => x.node_type === "document_source" || x.node_type === "vector_database"),
  };
}

// ---- Runs tab -------------------------------------------------------------
async function renderAssessRuns() {
  assessLoading();
  try {
    const d = await api("/api/assessments");
    const rows = d.assessments || [];
    assessPane().innerHTML = assessRunFormHtml() + assessRunsTableHtml(rows);
    wireAssessRunForm();
  } catch (e) { assessError(e); }
}

function assessRunFormHtml() {
  if (!assessCanWrite()) {
    return '<div class="card"><div class="pad dim" style="padding:calc(var(--u)*3);font-size:12.5px">Running an assessment needs the <b>member</b> role. You can read past runs and findings below.</div></div>';
  }
  const f = assessFactsFromGraph();
  const derived = ASSESS_GRAPH.nodes.length
    ? '<span class="dim" style="font-size:11.5px">· pre-filled from your Architecture tab</span>'
    : '<span class="dim" style="font-size:11.5px">· describe your app in the Architecture tab to pre-fill these</span>';
  const check = (id, label, on) =>
    `<label style="display:flex;gap:7px;align-items:center;font-size:12.5px;cursor:pointer"><input type="checkbox" id="${id}"${on ? " checked" : ""}> ${esc(label)}</label>`;
  return `<div class="card">
    <div class="card-head"><span class="card-title">Run an assessment</span></div>
    <div class="pad" style="padding:calc(var(--u)*3);display:grid;gap:calc(var(--u)*2.5)">
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <div class="field" style="flex:1;min-width:200px">
          <label for="assessDocName" style="font-size:12px;font-weight:600;display:block;margin-bottom:5px">Name this prompt</label>
          <input id="assessDocName" type="text" placeholder="e.g. support agent system prompt" style="${assessInput};width:100%">
        </div>
        <div class="field" style="min-width:170px">
          <label for="assessDocKind" style="font-size:12px;font-weight:600;display:block;margin-bottom:5px">Kind</label>
          <select id="assessDocKind" style="${assessInput};width:100%">${assessOptions(ASSESS_DOC_KINDS, "system")}</select>
        </div>
      </div>
      <div class="field">
        <label for="assessDocContent" style="font-size:12px;font-weight:600;display:block;margin-bottom:5px">Paste the prompt template</label>
        <textarea id="assessDocContent" rows="9" placeholder="You are a helpful assistant. …" style="${assessInput};width:100%;font-family:var(--font-mono);line-height:1.6"></textarea>
        <div class="dim" style="font-size:11.5px;margin-top:5px">Not stored. Only the name, the facts below, and redacted evidence excerpts are kept.</div>
      </div>
      <div class="field">
        <div style="font-size:12px;font-weight:600;margin-bottom:7px">Facts about this application ${derived}</div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:8px">
          ${check("assessCtxPublic", "Reachable by the public", false)}
          ${check("assessCtxWrite", "Has write-capable tools", f.has_write_capable_tools)}
          ${check("assessCtxApproval", "Human approval before writes", f.human_approval_enabled)}
          ${check("assessCtxRetrieval", "Uses retrieval / RAG", f.has_retrieval)}
          ${check("assessCtxSensitive", "Handles sensitive data", false)}
          ${check("assessCtxControls", "Has compensating controls", false)}
        </div>
        <div style="margin-top:10px;display:flex;gap:8px;align-items:center">
          <label for="assessCtxCrit" style="font-size:12.5px">Business criticality</label>
          <select id="assessCtxCrit" style="${assessInput}">${assessOptions(["low", "medium", "high", "critical"], "medium")}</select>
        </div>
      </div>
      <div><button class="btn btn-primary" id="assessRunBtn" type="button" style="padding:8px 16px;font-size:12.5px">Run assessment</button></div>
    </div>
  </div>`;
}

function wireAssessRunForm() {
  $("#assessRunBtn")?.addEventListener("click", runAssessment);
  assessPane().querySelectorAll("[data-arun]").forEach((r) =>
    r.addEventListener("click", () => openAssessRun(r.dataset.arun)));
}

function assessRunsTableHtml(rows) {
  if (!rows.length) {
    return `<div class="card" style="margin-top:calc(var(--u)*3)"><div class="empty-cta">
      <div class="big">No assessments yet</div>
      <p>Paste a prompt above and run one. It takes about a second — the rules are deterministic, so nothing is queued and nothing is sent to a model.</p>
    </div></div>`;
  }
  return `<div class="card" style="margin-top:calc(var(--u)*3)">
    <div class="card-head"><span class="card-title">Past runs</span></div>
    <div class="tablewrap"><table class="feed"><tbody>
      <tr><th>When</th><th>Kind</th><th>Findings</th><th>Worst</th><th>Risk</th><th></th></tr>
      ${rows.map((r) => `<tr class="evt" data-arun="${esc(r.id)}" style="cursor:pointer">
        <td class="mono dim">${esc(ago(r.created_at))}</td>
        <td>${esc(titleCase(r.kind))}</td>
        <td class="mono">${num(r.finding_count)}</td>
        <td>${r.max_severity ? pill(r.max_severity === "informational" ? "info" : r.max_severity) : '<span class="dim">clean</span>'}</td>
        <td class="mono">${r.overall_risk ? num(r.overall_risk) : "—"}</td>
        <td class="dim" style="text-align:right">open →</td>
      </tr>`).join("")}
    </tbody></table></div>
  </div>`;
}

async function runAssessment() {
  const content = $("#assessDocContent").value.trim();
  if (!content) { banner("Paste a prompt to assess."); return; }
  const btn = $("#assessRunBtn");
  btn.disabled = true; btn.textContent = "Running…";
  try {
    const res = await fetch("/api/assess/prompt", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        project: PROJECT,
        documents: [{ kind: $("#assessDocKind").value, name: $("#assessDocName").value.trim(), content }],
        context: {
          is_public: $("#assessCtxPublic").checked,
          has_write_capable_tools: $("#assessCtxWrite").checked,
          human_approval_enabled: $("#assessCtxApproval").checked,
          has_retrieval: $("#assessCtxRetrieval").checked,
          has_sensitive_data: $("#assessCtxSensitive").checked,
          has_compensating_controls: $("#assessCtxControls").checked,
          business_criticality: $("#assessCtxCrit").value,
        },
      }),
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { banner(d.error || "Could not run the assessment."); return; }
    banner("");
    openAssessRun(d.id);
  } catch (e) {
    banner("Could not run the assessment: " + e.message);
  } finally {
    btn.disabled = false; btn.textContent = "Run assessment";
  }
}

// ---- One run, in full -----------------------------------------------------
async function openAssessRun(id) {
  assessLoading();
  try {
    const a = await api("/api/assessment/" + encodeURIComponent(id));
    const findings = a.findings || [];
    const docs = Array.isArray(a.documents) ? a.documents : [];
    assessPane().innerHTML = `
      <div class="card">
        <div class="card-head" style="display:flex;justify-content:space-between;align-items:center">
          <span class="card-title">${esc(titleCase(a.kind))} assessment · ${esc(ago(a.created_at))}</span>
          <button class="btn" id="assessBackBtn" type="button" style="padding:6px 12px;font-size:12px">← All runs</button>
        </div>
        <div class="pad" style="padding:calc(var(--u)*3);display:flex;gap:calc(var(--u)*5);flex-wrap:wrap;font-size:12.5px">
          <div><div class="dim" style="font-size:11px">Findings</div><div class="mono" style="font-size:18px">${num(a.finding_count)}</div></div>
          <div><div class="dim" style="font-size:11px">Worst</div><div>${a.max_severity ? pill(a.max_severity === "informational" ? "info" : a.max_severity) : '<span class="dim">clean</span>'}</div></div>
          <div><div class="dim" style="font-size:11px">Highest risk</div><div class="mono" style="font-size:18px">${a.overall_risk ? num(a.overall_risk) : "—"}</div></div>
          ${docs.length ? `<div><div class="dim" style="font-size:11px">Assessed</div><div>${docs.map((d) => esc(d.name || d.kind || "prompt")).join(", ")}</div></div>` : ""}
          ${a.scoring_version ? `<div><div class="dim" style="font-size:11px">Scoring</div><div class="mono">v${esc(a.scoring_version)}</div></div>` : ""}
        </div>
      </div>
      ${findings.length
        ? findings.map(assessFindingCard).join("")
        : `<div class="card" style="margin-top:calc(var(--u)*3)"><div class="empty-cta"><div class="big">No findings</div><p>Nothing in this ${esc(a.kind)} tripped a rule. That is a real result, not an empty screen — the same input will always produce the same answer.</p></div></div>`}`;
    $("#assessBackBtn").addEventListener("click", renderAssessRuns);
    wireAssessStatusControls();
  } catch (e) { assessError(e); }
}

/**
 * One finding. Everything interpolated here is engine output derived from
 * customer prompts — i.e. attacker-authored text can reach `evidence` — so every
 * field goes through esc(). The CSP is the backstop, not the control.
 */
function assessFindingCard(f) {
  const risk = f.risk || {};
  const mits = Array.isArray(f.mitigations) ? f.mitigations : [];
  const fws = Array.isArray(f.frameworks) ? f.frameworks : [];
  const factors = risk.factors || {};
  return `<div class="card" style="margin-top:calc(var(--u)*3)">
    <div class="card-head" style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">
      <span class="card-title" style="display:flex;gap:9px;align-items:center;flex-wrap:wrap">
        ${pill(f.argus_severity || "info")}
        <span class="mono dim" style="font-size:11.5px">${esc(f.rule_id)}</span>
        ${esc(f.title)}
        ${f.observed_in_production ? assessObservedTag() : ""}
      </span>
      ${risk.final_score != null ? `<span class="mono" style="font-size:13px">risk ${num(risk.final_score)}</span>` : ""}
    </div>
    <div class="pad" style="padding:calc(var(--u)*3);font-size:12.5px;color:var(--ink-muted);display:grid;gap:10px">
      <div class="dim" style="font-size:11.5px">
        ${esc(titleCase(f.category))}${f.confidence ? " · " + esc(f.confidence) + " confidence" : ""}${f.document_name ? " · " + esc(f.document_name) : ""}${Array.isArray(f.affected_lines) && f.affected_lines.length ? " · line " + esc(f.affected_lines.join(", ")) : ""}
      </div>
      <div>${esc(f.explanation)}</div>
      ${f.evidence ? `<div class="mono" style="font-size:11.5px;background:var(--surface-2);border-radius:var(--radius);padding:9px 11px;word-break:break-word">${esc(f.evidence)}</div>` : ""}
      ${f.recommendation ? `<div><b style="color:var(--ink)">Fix:</b> ${esc(f.recommendation)}</div>` : ""}
      ${fws.length ? `<div class="dim" style="font-size:11.5px">${fws.map((x) => esc((x.framework || "") + " " + (x.requirement || ""))).join(" · ")}</div>` : ""}
      ${risk.rationale ? `<details><summary style="cursor:pointer;font-size:12px">Why this score?</summary>
        <div style="margin-top:8px">${esc(risk.rationale)}</div>
        <div style="margin-top:8px;display:flex;gap:14px;flex-wrap:wrap;font-size:11.5px" class="mono dim">
          ${Object.keys(factors).map((k) => `<span>${esc(titleCase(k))} ${esc(factors[k])}/5</span>`).join("")}
        </div></details>` : ""}
      ${mits.length ? `<details><summary style="cursor:pointer;font-size:12px">${mits.length} recommended fix${mits.length > 1 ? "es" : ""}, best first</summary>
        <div style="margin-top:8px;display:grid;gap:10px">
          ${mits.map((m) => `<div style="border-left:2px solid var(--accent);padding-left:10px">
            <div style="color:var(--ink);font-weight:600">${esc(m.title)}</div>
            <div class="dim" style="font-size:11.5px;margin:2px 0 4px">${esc(m.priority)} priority · ${esc(m.difficulty)} effort · ~${esc(m.expected_risk_reduction)}% risk reduction</div>
            <div>${esc(m.implementation_guidance)}</div>
            ${m.validation_procedure ? `<div class="dim" style="font-size:11.5px;margin-top:4px"><b>Check it worked:</b> ${esc(m.validation_procedure)}</div>` : ""}
          </div>`).join("")}
        </div></details>` : ""}
      ${f.id ? assessStatusControl(f) : ""}
    </div>
  </div>`;
}

function assessStatusControl(f) {
  if (!assessCanWrite()) return `<div class="dim" style="font-size:11.5px">Status: ${esc(f.analyst_status || "open")}</div>`;
  return `<div style="display:flex;gap:8px;align-items:center;font-size:12px">
    <label for="st-${esc(f.id)}">Status</label>
    <select id="st-${esc(f.id)}" data-astatus="${esc(f.id)}" style="${assessInput}">${assessOptions(ASSESS_STATUSES, f.analyst_status || "open")}</select>
  </div>`;
}

function wireAssessStatusControls() {
  assessPane().querySelectorAll("[data-astatus]").forEach((s) =>
    s.addEventListener("change", () => setAssessFindingStatus(s.dataset.astatus, s.value)));
}

async function setAssessFindingStatus(findingId, status) {
  try {
    const res = await fetch("/api/assessment/finding/status", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ project: PROJECT, findingId, status }),
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { banner(d.error || "Could not update the finding."); return; }
    banner("");
  } catch (e) { banner("Could not update the finding: " + e.message); }
}

// ---- Findings tab (across every run) --------------------------------------
async function renderAssessFindings() {
  assessLoading();
  try {
    const d = await api("/api/assessment-findings");
    const rows = d.findings || [];
    if (!rows.length) {
      assessPane().innerHTML = `<div class="card"><div class="empty-cta">
        <div class="big">No findings yet</div>
        <p>Findings appear here once you run an assessment. This view collects them across every run, so you can work through them without opening each run in turn.</p>
      </div></div>`;
      return;
    }
    assessPane().innerHTML = `<div class="card">
      <div class="card-head"><span class="card-title">${num(rows.length)} finding${rows.length > 1 ? "s" : ""} across all runs</span></div>
      <div class="tablewrap"><table class="feed"><tbody>
        <tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Category</th><th>Risk</th><th>Status</th></tr>
        ${rows.map((f) => `<tr class="evt">
          <td>${pill(f.argus_severity || "info")}</td>
          <td class="mono dim" style="font-size:11.5px">${esc(f.rule_id)}</td>
          <td>${esc(f.title)} ${f.observed_in_production ? assessObservedTag() : ""}${f.document_name ? `<div class="dim" style="font-size:11px">${esc(f.document_name)}</div>` : ""}</td>
          <td class="dim">${esc(titleCase(f.category))}</td>
          <td class="mono">${f.risk && f.risk.final_score != null ? num(f.risk.final_score) : "—"}</td>
          <td>${assessStatusControl(f)}</td>
        </tr>`).join("")}
      </tbody></table></div>
    </div>`;
    wireAssessStatusControls();
  } catch (e) { assessError(e); }
}

// ---- Architecture tab -----------------------------------------------------
function renderAssessArch() {
  const editable = assessCanWrite();
  const n = ASSESS_GRAPH.nodes || [];
  const e = ASSESS_GRAPH.edges || [];
  assessPane().innerHTML = `
    <div class="card">
      <div class="card-head"><span class="card-title">How this application is put together</span></div>
      <div class="pad dim" style="padding:calc(var(--u)*3) calc(var(--u)*3) 0;font-size:12.5px">
        Describe the parts of your app and how data moves between them. Risk here comes from <b>shape</b>, not wording:
        untrusted input reaching a trusted component, model output reaching an interpreter, a tool that can write without
        anyone approving it. Filling this in also pre-fills the facts on the Runs tab.
        ${ASSESS_GRAPH.updatedAt ? `<div style="margin-top:6px">Last saved ${esc(ago(ASSESS_GRAPH.updatedAt))}.</div>` : ""}
      </div>
      <div class="pad" style="padding:calc(var(--u)*3)">
        <div style="font-size:12px;font-weight:600;margin-bottom:8px">Components</div>
        <div class="tablewrap"><table class="feed"><tbody id="assessNodeRows">
          <tr><th>Name</th><th>Type</th><th>Trust</th><th>Can write</th><th>Needs approval</th><th></th></tr>
          ${n.map(assessNodeRow).join("")}
        </tbody></table></div>
        ${editable ? '<button class="btn" id="assessAddNode" type="button" style="margin-top:9px;padding:6px 12px;font-size:12px">+ Add component</button>' : ""}

        <div style="font-size:12px;font-weight:600;margin:calc(var(--u)*4) 0 8px">Connections</div>
        <div class="tablewrap"><table class="feed"><tbody id="assessEdgeRows">
          <tr><th>From</th><th>To</th><th>What flows</th><th>Crosses tenants</th><th></th></tr>
          ${e.map(assessEdgeRow).join("")}
        </tbody></table></div>
        ${editable ? '<button class="btn" id="assessAddEdge" type="button" style="margin-top:9px;padding:6px 12px;font-size:12px">+ Add connection</button>' : ""}

        ${editable ? `<div style="margin-top:calc(var(--u)*4);display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-primary" id="assessSaveGraph" type="button" style="padding:8px 16px;font-size:12.5px">Save</button>
          <button class="btn" id="assessAnalyzeGraph" type="button" style="padding:8px 16px;font-size:12.5px">Save &amp; analyze</button>
          <button class="btn" id="assessDeriveGraph" type="button" style="padding:8px 16px;font-size:12.5px" title="Build a starting point from the traces Argus has already recorded">Suggest from traces</button>
        </div>
        <div class="dim" style="margin-top:8px;font-size:11.5px">“Suggest from traces” reads what your app has actually done and proposes components and connections. It replaces what's on screen but saves nothing until you press Save — and it can't tell whether a write needs human approval, so check those boxes yourself.</div>` : '<div class="dim" style="margin-top:calc(var(--u)*3);font-size:12.5px">Editing needs the <b>member</b> role.</div>'}
      </div>
    </div>
    <div id="assessArchResult"></div>`;
  wireAssessArch();
}

function assessNodeRow(node, i) {
  const idx = typeof i === "number" ? i : 0;
  const dis = assessCanWrite() ? "" : " disabled";
  return `<tr data-nrow="${idx}">
    <td><input type="text" data-nfield="label" value="${esc(node.label || "")}" placeholder="e.g. support agent" style="${assessInput};width:100%"${dis}></td>
    <td><select data-nfield="node_type" style="${assessInput}"${dis}>${assessOptions(ASSESS_NODE_TYPES, node.node_type || "other")}</select></td>
    <td><select data-nfield="trust_level" style="${assessInput}"${dis}>${assessOptions(["trusted", "untrusted"], node.trust_level || "trusted")}</select></td>
    <td style="text-align:center"><input type="checkbox" data-nfield="can_write"${node.can_write ? " checked" : ""}${dis}></td>
    <td style="text-align:center"><input type="checkbox" data-nfield="requires_approval"${node.requires_approval ? " checked" : ""}${dis}></td>
    <td style="text-align:right">${assessCanWrite() ? `<button class="btn" type="button" data-ndel="${idx}" style="padding:3px 8px;font-size:11px">remove</button>` : ""}</td>
  </tr>`;
}

function assessEdgeRow(edge, i) {
  const idx = typeof i === "number" ? i : 0;
  const dis = assessCanWrite() ? "" : " disabled";
  // Node ids are internal join keys, never shown — an unnamed row reads
  // "(unnamed)" rather than leaking a generated id into the picker.
  const opts = (cur) => (ASSESS_GRAPH.nodes || []).map((n) => `<option value="${esc(n.id)}"${n.id === cur ? " selected" : ""}>${esc(n.label || "(unnamed)")}</option>`).join("");
  return `<tr data-erow="${idx}">
    <td><select data-efield="source" style="${assessInput}"${dis}>${opts(edge.source)}</select></td>
    <td><select data-efield="target" style="${assessInput}"${dis}>${opts(edge.target)}</select></td>
    <td><select data-efield="edge_type" style="${assessInput}"${dis}>${assessOptions(ASSESS_EDGE_TYPES, edge.edge_type || "sends_prompt")}</select></td>
    <td style="text-align:center"><input type="checkbox" data-efield="tenant_boundary"${edge.tenant_boundary ? " checked" : ""}${dis}></td>
    <td style="text-align:right">${assessCanWrite() ? `<button class="btn" type="button" data-edel="${idx}" style="padding:3px 8px;font-size:11px">remove</button>` : ""}</td>
  </tr>`;
}

function wireAssessArch() {
  $("#assessAddNode")?.addEventListener("click", () => {
    harvestAssessGraph();
    // Ids are internal join keys for the analyzer, never shown; the label is
    // what the user names. Generated here so a new row can be referenced by an
    // edge immediately, before anything is saved.
    ASSESS_GRAPH.nodes.push({ id: "n" + Date.now().toString(36) + ASSESS_GRAPH.nodes.length, label: "", node_type: "other", trust_level: "trusted", can_write: false, requires_approval: false, attributes: {} });
    renderAssessArch();
  });
  $("#assessAddEdge")?.addEventListener("click", () => {
    harvestAssessGraph();
    if (ASSESS_GRAPH.nodes.length < 2) { banner("Add at least two components before connecting them."); return; }
    banner("");
    ASSESS_GRAPH.edges.push({ source: ASSESS_GRAPH.nodes[0].id, target: ASSESS_GRAPH.nodes[1].id, edge_type: "sends_prompt", tenant_boundary: false });
    renderAssessArch();
  });
  assessPane().querySelectorAll("[data-ndel]").forEach((b) => b.addEventListener("click", () => {
    harvestAssessGraph();
    const gone = ASSESS_GRAPH.nodes[Number(b.dataset.ndel)];
    ASSESS_GRAPH.nodes.splice(Number(b.dataset.ndel), 1);
    // Drop edges that pointed at it, or the analyzer would read them as dangling.
    if (gone) ASSESS_GRAPH.edges = ASSESS_GRAPH.edges.filter((e) => e.source !== gone.id && e.target !== gone.id);
    renderAssessArch();
  }));
  assessPane().querySelectorAll("[data-edel]").forEach((b) => b.addEventListener("click", () => {
    harvestAssessGraph();
    ASSESS_GRAPH.edges.splice(Number(b.dataset.edel), 1);
    renderAssessArch();
  }));
  $("#assessSaveGraph")?.addEventListener("click", () => saveAssessGraph(false));
  $("#assessAnalyzeGraph")?.addEventListener("click", () => saveAssessGraph(true));
  $("#assessDeriveGraph")?.addEventListener("click", deriveAssessGraph);
}

/** Replace the on-screen graph with one proposed from observed traces. Nothing
 *  is written — the user reviews, fixes the approval flags, then saves. */
async function deriveAssessGraph() {
  const btn = $("#assessDeriveGraph");
  btn.disabled = true; btn.textContent = "Reading traces…";
  try {
    const res = await fetch("/api/assessment/graph/derive", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ project: PROJECT }),
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { banner(d.error || "Could not read traces."); return; }
    if (!d.nodes || !d.nodes.length) {
      banner("No components could be derived yet — Argus hasn't recorded enough traffic from this app.");
      return;
    }
    ASSESS_GRAPH = { nodes: d.nodes, edges: d.edges || [], updatedAt: ASSESS_GRAPH.updatedAt };
    banner("");
    renderAssessArch();
    $("#assessArchResult").innerHTML = `<div class="card" style="margin-top:calc(var(--u)*3)"><div class="pad" style="padding:calc(var(--u)*3);font-size:12.5px;color:var(--ink-muted)">
      Proposed <b>${num(d.nodes.length)}</b> component${d.nodes.length === 1 ? "" : "s"} and <b>${num((d.edges || []).length)}</b> connection${(d.edges || []).length === 1 ? "" : "s"} from ${num(d.observations || 0)} recorded spans.
      <b>Nothing is saved yet.</b> Check the trust levels and tick “needs approval” where a human really does confirm the action — that flag can't be read from a trace, and it's the one the highest-severity rules turn on.
    </div></div>`;
  } catch (e) {
    banner("Could not read traces: " + e.message);
  } finally {
    btn.disabled = false; btn.textContent = "Suggest from traces";
  }
}

/** Read the DOM back into ASSESS_GRAPH so edits survive a re-render. */
function harvestAssessGraph() {
  const rows = assessPane().querySelectorAll("#assessNodeRows [data-nrow]");
  rows.forEach((tr) => {
    const n = ASSESS_GRAPH.nodes[Number(tr.dataset.nrow)];
    if (!n) return;
    tr.querySelectorAll("[data-nfield]").forEach((el) => {
      n[el.dataset.nfield] = el.type === "checkbox" ? el.checked : el.value;
    });
  });
  assessPane().querySelectorAll("#assessEdgeRows [data-erow]").forEach((tr) => {
    const e = ASSESS_GRAPH.edges[Number(tr.dataset.erow)];
    if (!e) return;
    tr.querySelectorAll("[data-efield]").forEach((el) => {
      e[el.dataset.efield] = el.type === "checkbox" ? el.checked : el.value;
    });
  });
}

async function saveAssessGraph(thenAnalyze) {
  harvestAssessGraph();
  if (ASSESS_GRAPH.nodes.some((n) => !String(n.label || "").trim())) { banner("Give every component a name."); return; }
  try {
    const res = await fetch("/api/assessment/graph", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ project: PROJECT, nodes: ASSESS_GRAPH.nodes, edges: ASSESS_GRAPH.edges }),
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { banner(d.error || "Could not save the architecture."); return; }
    banner("");
    ASSESS_GRAPH.updatedAt = new Date().toISOString();
    if (thenAnalyze) return analyzeAssessGraph();
    renderAssessArch();
  } catch (e) { banner("Could not save the architecture: " + e.message); }
}

async function analyzeAssessGraph() {
  try {
    const res = await fetch("/api/assessment/graph/analyze", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ project: PROJECT }),
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { banner(d.error || "Could not analyze the architecture."); return; }
    banner("");
    const findings = d.findings || [];
    $("#assessArchResult").innerHTML = findings.length
      ? `<div class="card" style="margin-top:calc(var(--u)*3)">
           <div class="card-head"><span class="card-title">${num(findings.length)} architectural weakness${findings.length > 1 ? "es" : ""}</span></div>
           <div class="pad" style="padding:calc(var(--u)*3);display:grid;gap:12px;font-size:12.5px">
             ${findings.map((i) => `<div style="display:flex;gap:10px;align-items:flex-start">
               ${pill(i.argus_severity || "info")}
               <div><div style="color:var(--ink)">${esc(i.message)}</div>
               <div class="dim" style="font-size:11.5px">${esc(titleCase(i.rule))}</div></div>
             </div>`).join("")}
           </div>
           <div class="pad dim" style="padding:0 calc(var(--u)*3) calc(var(--u)*3);font-size:11.5px">Saved as a run — it appears under Runs and its findings under Findings.</div>
         </div>`
      : `<div class="card" style="margin-top:calc(var(--u)*3)"><div class="empty-cta"><div class="big">No architectural weaknesses found</div><p>Nothing in the shape of this application tripped a rule.</p></div></div>`;
  } catch (e) { banner("Could not analyze the architecture: " + e.message); }
}

// ---- Policies tab ---------------------------------------------------------
// A policy asks a question about the application's current state and returns an
// action. The conditions are authored here as rows rather than raw JSON: the
// engine's grammar is a dotted-path map, which is fine to store and hostile to
// type. Every field offered below is one `buildContext` can actually prove —
// there is no way to author a condition Argus cannot answer, because a policy
// that silently never matches is worse than no policy.
const POLICY_FIELDS = [
  { path: "application.has_write_capable_tools", label: "Has write-capable tools", type: "bool" },
  { path: "application.human_approval_enabled", label: "Every write needs human approval", type: "bool" },
  { path: "application.has_retrieval", label: "Uses retrieval / RAG", type: "bool" },
  { path: "application.has_untrusted_component", label: "Has an untrusted component", type: "bool" },
  { path: "application.crosses_tenant_boundary", label: "Data crosses a tenant boundary", type: "bool" },
  { path: "application.described", label: "Architecture has been described", type: "bool" },
  { path: "application.open_critical_findings", label: "Open critical findings", type: "num" },
  { path: "application.open_high_findings", label: "Open high findings", type: "num" },
  { path: "application.open_findings", label: "Open findings (any severity)", type: "num" },
  { path: "application.observed_in_production_findings", label: "Open findings seen in production", type: "num" },
  { path: "application.component_count", label: "Number of components", type: "num" },
];
const POLICY_ACTIONS = [
  ["warn", "Warn only"],
  ["block_deployment", "Block deployment"],
  ["block_assessment_approval", "Block assessment sign-off"],
];
const FIELD_BY_PATH = Object.fromEntries(POLICY_FIELDS.map((f) => [f.path, f]));
let POLICY_DRAFT = [{ path: POLICY_FIELDS[0].path, op: "true", value: 1 }];

async function renderAssessPolicies() {
  assessLoading();
  try {
    const d = await api("/api/policies");
    assessPane().innerHTML = policyIntroHtml() + policyBuilderHtml() + policyListHtml(d.policies || []);
    wireAssessPolicies();
  } catch (e) { assessError(e); }
}

function policyIntroHtml() {
  return `<div class="card"><div class="pad dim" style="padding:calc(var(--u)*3);font-size:12.5px">
    A policy is a rule about how this application is allowed to be built — "don't ship while a critical finding is open",
    "a public app must have human approval on writes". Argus checks them against what it actually knows: the architecture
    you described and the findings your assessments produced. Every condition is joined with <b>and</b>, and a condition
    Argus can't answer never matches, so a rule fails safe rather than firing on a guess.
    <div style="margin-top:8px">These are <b>governance</b> rules, checked when you ask. They are not the inline gateway —
    that blocks single messages in milliseconds and is configured per application in Settings.</div>
  </div></div>`;
}

function policyBuilderHtml() {
  if (!assessCanWrite()) return "";
  const row = (r, i) => {
    const f = FIELD_BY_PATH[r.path] || POLICY_FIELDS[0];
    const ops = f.type === "bool"
      ? [["true", "is yes"], ["false", "is no"]]
      : [["gte", "is at least"], ["lte", "is at most"], ["gt", "is more than"], ["lt", "is fewer than"]];
    return `<div class="prow" data-prow="${i}" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
      <select data-pfield="path" style="${assessInput};flex:1;min-width:220px">
        ${POLICY_FIELDS.map((x) => `<option value="${esc(x.path)}"${x.path === r.path ? " selected" : ""}>${esc(x.label)}</option>`).join("")}
      </select>
      <select data-pfield="op" style="${assessInput}">
        ${ops.map(([v, l]) => `<option value="${esc(v)}"${v === r.op ? " selected" : ""}>${esc(l)}</option>`).join("")}
      </select>
      ${f.type === "num" ? `<input type="number" min="0" data-pfield="value" value="${esc(r.value ?? 1)}" style="${assessInput};width:90px">` : ""}
      ${POLICY_DRAFT.length > 1 ? `<button class="btn" type="button" data-pdel="${i}" style="padding:3px 9px;font-size:11px">remove</button>` : ""}
    </div>`;
  };
  return `<div class="card" style="margin-top:calc(var(--u)*3)">
    <div class="card-head"><span class="card-title">New policy</span></div>
    <div class="pad" style="padding:calc(var(--u)*3);display:grid;gap:calc(var(--u)*2.5)">
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <div style="flex:1;min-width:220px">
          <label for="policyName" style="font-size:12px;font-weight:600;display:block;margin-bottom:5px">Name it</label>
          <input id="policyName" type="text" placeholder="e.g. no shipping with open criticals" style="${assessInput};width:100%">
        </div>
        <div style="min-width:190px">
          <label for="policyAction" style="font-size:12px;font-weight:600;display:block;margin-bottom:5px">If it matches</label>
          <select id="policyAction" style="${assessInput};width:100%">${POLICY_ACTIONS.map(([v, l]) => `<option value="${esc(v)}">${esc(l)}</option>`).join("")}</select>
        </div>
        <div style="min-width:140px">
          <label for="policySeverity" style="font-size:12px;font-weight:600;display:block;margin-bottom:5px">Severity</label>
          <select id="policySeverity" style="${assessInput};width:100%">${assessOptions(["critical", "high", "medium", "low"], "medium")}</select>
        </div>
      </div>
      <div>
        <div style="font-size:12px;font-weight:600;margin-bottom:7px">When all of these are true</div>
        <div id="policyRows">${POLICY_DRAFT.map(row).join("")}</div>
        <button class="btn" id="policyAddRow" type="button" style="padding:5px 11px;font-size:11.5px">+ Add condition</button>
      </div>
      <div>
        <label for="policyMessage" style="font-size:12px;font-weight:600;display:block;margin-bottom:5px">What should someone do about it? <span class="dim" style="font-weight:400">(optional)</span></label>
        <input id="policyMessage" type="text" placeholder="e.g. resolve the critical findings or record an exception before release" style="${assessInput};width:100%">
      </div>
      <div><button class="btn btn-primary" id="policyCreate" type="button" style="padding:8px 16px;font-size:12.5px">Create policy</button></div>
    </div>
  </div>`;
}

function policyListHtml(rows) {
  const head = `<div class="card-head" style="display:flex;justify-content:space-between;align-items:center">
      <span class="card-title">Policies</span>
      <button class="btn" id="policyEvaluate" type="button" style="padding:6px 12px;font-size:12px">Check against this app now</button>
    </div>`;
  if (!rows.length) {
    return `<div class="card" style="margin-top:calc(var(--u)*3)">${head}<div class="empty-cta">
      <div class="big">No policies yet</div>
      <p>Nothing is enforced until you write a rule. A good first one: block deployment when an open critical finding exists.</p>
    </div></div><div id="policyResult"></div>`;
  }
  return `<div class="card" style="margin-top:calc(var(--u)*3)">${head}
    <div class="tablewrap"><table class="feed"><tbody>
      <tr><th>Policy</th><th>When</th><th>Action</th><th>Severity</th><th>Enabled</th><th></th></tr>
      ${rows.map((p) => `<tr class="evt">
        <td>${esc(p.name)}${p.message ? `<div class="dim" style="font-size:11px">${esc(p.message)}</div>` : ""}</td>
        <td class="dim" style="font-size:11.5px">${esc(describeConditions(p.conditions))}</td>
        <td>${esc(titleCase(p.action))}</td>
        <td>${pill(p.result_severity === "informational" ? "info" : p.result_severity)}</td>
        <td>${assessCanWrite()
          ? `<input type="checkbox" data-ptoggle="${esc(p.id)}"${p.enabled ? " checked" : ""}>`
          : (p.enabled ? "yes" : "no")}</td>
        <td style="text-align:right">${assessCanWrite() ? `<button class="btn" type="button" data-pdelete="${esc(p.id)}" style="padding:3px 9px;font-size:11px">delete</button>` : ""}</td>
      </tr>`).join("")}
    </tbody></table></div>
  </div><div id="policyResult"></div>`;
}

/** Render a stored condition map back into the language the builder speaks. */
function describeConditions(conds) {
  const parts = [];
  for (const [path, matcher] of Object.entries(conds || {})) {
    const label = FIELD_BY_PATH[path]?.label || path;
    if (matcher === true) parts.push(`${label} is yes`);
    else if (matcher === false) parts.push(`${label} is no`);
    else if (matcher && typeof matcher === "object") {
      const [op, v] = Object.entries(matcher)[0] || [];
      const word = { gte: "at least", lte: "at most", gt: "more than", lt: "fewer than" }[op] || op;
      parts.push(`${label} ${word} ${v}`);
    } else parts.push(`${label} = ${matcher}`);
  }
  return parts.join(" and ") || "—";
}

function harvestPolicyDraft() {
  const rows = assessPane().querySelectorAll("#policyRows [data-prow]");
  POLICY_DRAFT = [...rows].map((tr) => {
    const get = (n) => tr.querySelector(`[data-pfield="${n}"]`);
    return { path: get("path").value, op: get("op").value, value: Number(get("value")?.value ?? 1) };
  });
}

/** Builder rows → the engine's condition map. */
function draftToConditions() {
  const out = {};
  for (const r of POLICY_DRAFT) {
    if (r.op === "true") out[r.path] = true;
    else if (r.op === "false") out[r.path] = false;
    else out[r.path] = { [r.op]: Number.isFinite(r.value) ? r.value : 1 };
  }
  return out;
}

function wireAssessPolicies() {
  $("#policyAddRow")?.addEventListener("click", () => {
    harvestPolicyDraft();
    POLICY_DRAFT.push({ path: POLICY_FIELDS[0].path, op: "true", value: 1 });
    renderAssessPolicies();
  });
  assessPane().querySelectorAll("[data-pdel]").forEach((b) => b.addEventListener("click", () => {
    harvestPolicyDraft();
    POLICY_DRAFT.splice(Number(b.dataset.pdel), 1);
    renderAssessPolicies();
  }));
  // Switching field type changes which operators make sense, so re-render.
  assessPane().querySelectorAll('[data-pfield="path"]').forEach((s) => s.addEventListener("change", () => {
    harvestPolicyDraft();
    POLICY_DRAFT.forEach((r) => {
      const t = FIELD_BY_PATH[r.path]?.type;
      if (t === "bool" && !["true", "false"].includes(r.op)) r.op = "true";
      if (t === "num" && ["true", "false"].includes(r.op)) r.op = "gte";
    });
    renderAssessPolicies();
  }));
  $("#policyCreate")?.addEventListener("click", createPolicy);
  $("#policyEvaluate")?.addEventListener("click", evaluatePolicies);
  assessPane().querySelectorAll("[data-ptoggle]").forEach((c) => c.addEventListener("change", () =>
    togglePolicy(c.dataset.ptoggle, c.checked)));
  assessPane().querySelectorAll("[data-pdelete]").forEach((b) => b.addEventListener("click", () =>
    deletePolicy(b.dataset.pdelete)));
}

async function createPolicy() {
  harvestPolicyDraft();
  const name = $("#policyName").value.trim();
  if (!name) { banner("Give the policy a name."); return; }
  try {
    const res = await fetch("/api/policies", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        project: PROJECT, name,
        conditions: draftToConditions(),
        action: $("#policyAction").value,
        resultSeverity: $("#policySeverity").value,
        message: $("#policyMessage").value.trim(),
      }),
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { banner(d.error || "Could not create the policy."); return; }
    banner("");
    POLICY_DRAFT = [{ path: POLICY_FIELDS[0].path, op: "true", value: 1 }];
    renderAssessPolicies();
  } catch (e) { banner("Could not create the policy: " + e.message); }
}

async function togglePolicy(id, enabled) {
  try {
    const res = await fetch(`/api/policies/${encodeURIComponent(id)}/enabled`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ project: PROJECT, enabled }),
    });
    if (!res.ok) banner("Could not update the policy.");
  } catch (e) { banner("Could not update the policy: " + e.message); }
}

async function deletePolicy(id) {
  if (!confirm("Delete this policy? Past evaluations are not affected.")) return;
  try {
    const res = await fetch(`/api/policies/${encodeURIComponent(id)}?project=${encodeURIComponent(PROJECT)}`, { method: "DELETE" });
    if (!res.ok) { banner("Could not delete the policy."); return; }
    renderAssessPolicies();
  } catch (e) { banner("Could not delete the policy: " + e.message); }
}

async function evaluatePolicies() {
  const btn = $("#policyEvaluate");
  btn.disabled = true; btn.textContent = "Checking…";
  try {
    const d = await api("/api/policies/evaluate");
    const decisions = d.decisions || [];
    const app = (d.context && d.context.application) || {};
    const matched = decisions.filter((x) => x.matched);
    $("#policyResult").innerHTML = `<div class="card" style="margin-top:calc(var(--u)*3)">
      <div class="card-head"><span class="card-title">${matched.length ? `${num(matched.length)} of ${num(decisions.length)} policies match right now` : "No policies match right now"}</span></div>
      <div class="pad" style="padding:calc(var(--u)*3);display:grid;gap:10px;font-size:12.5px">
        ${decisions.length ? decisions.map((x) => `<div style="display:flex;gap:10px;align-items:flex-start">
          ${x.matched ? pill(x.severity === "informational" ? "info" : x.severity) : '<span class="pill pill-neutral">ok</span>'}
          <div><div style="color:var(--ink)">${esc(x.name)}</div>
          <div class="dim" style="font-size:11.5px">${x.matched ? esc(x.message || titleCase(x.action)) : "not matching"}</div></div>
        </div>`).join("") : '<div class="dim">No enabled policies to check.</div>'}
        <details style="margin-top:6px"><summary style="cursor:pointer;font-size:12px">What Argus knows about this app</summary>
          <div class="mono dim" style="font-size:11.5px;margin-top:8px;display:grid;gap:3px">
            ${Object.keys(app).map((k) => `<span>${esc(titleCase(k))}: ${esc(String(app[k]))}</span>`).join("")}
          </div>
          <div class="dim" style="font-size:11.5px;margin-top:8px">These are the only facts a condition can test. Anything missing here can never match.</div>
        </details>
      </div>
    </div>`;
  } catch (e) {
    banner("Could not check policies: " + e.message);
  } finally {
    btn.disabled = false; btn.textContent = "Check against this app now";
  }
}

// ---- Controls tab ---------------------------------------------------------
// Findings say what is wrong today; controls are the commitments you've made
// and will be asked to evidence. Status changes stamp last_reviewed_at server
// side, so "when did anyone last look at this?" has an answer.
const CONTROL_STATUS_LABELS = [
  ["not_implemented", "Not implemented"],
  ["in_progress", "In progress"],
  ["implemented", "Implemented"],
  ["not_applicable", "Not applicable"],
];

/**
 * Report downloads. Plain links rather than fetch-and-blob: the endpoint sets
 * Content-Disposition, so the browser's own download handling is both simpler
 * and better behaved than anything reimplemented here.
 */
function reportLinksHtml() {
  const kinds = [
    ["executive", "Executive summary", "For someone who needs the position in one page."],
    ["technical", "Technical findings", "Every open finding with evidence and fixes."],
    ["governance", "Governance report", "Controls, ownership and outstanding risk."],
  ];
  const link = (kind, fmt, label) =>
    `<a class="btn" href="/api/reports/${kind}?project=${encodeURIComponent(PROJECT)}&format=${fmt}" style="padding:4px 10px;font-size:11.5px;text-decoration:none">${esc(label)}</a>`;
  return `<div class="card" style="margin-top:calc(var(--u)*3)">
    <div class="card-head"><span class="card-title">Reports</span></div>
    <div class="pad" style="padding:calc(var(--u)*3);display:grid;gap:calc(var(--u)*2.5);font-size:12.5px">
      <div class="dim">Built from this application's <b>open</b> findings and its controls — a report is a statement about outstanding risk, so resolved items are left out. Secrets are stripped from every format.</div>
      ${kinds.map(([k, title, blurb]) => `<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <div style="flex:1;min-width:220px"><div style="color:var(--ink)">${esc(title)}</div><div class="dim" style="font-size:11.5px">${esc(blurb)}</div></div>
        ${link(k, "pdf", "PDF")}${link(k, "md", "Markdown")}${link(k, "csv", "CSV")}${link(k, "json", "JSON")}
      </div>`).join("")}
    </div>
  </div>`;
}

async function renderAssessControls() {
  assessLoading();
  try {
    const d = await api("/api/controls");
    const rows = d.controls || [];
    if (!rows.length) {
      assessPane().innerHTML = `<div class="card"><div class="empty-cta">
        <div class="big">No controls adopted yet</div>
        <p>A control is a commitment you intend to hold — "retrieved content is treated as untrusted", "writes need human approval" — with an owner and a review date. Argus ships a baseline of ${num(d.catalogSize || 0)} covering the domains that matter for an LLM application, each mapped to the framework requirement an auditor will cite.</p>
        <p>Adopting copies them into this application so you can set status and ownership per control. Nothing is adopted automatically — that would be Argus deciding what your team has committed to.</p>
        ${assessCanWrite() ? '<button class="btn btn-primary" id="controlsAdopt" type="button">Adopt the baseline</button>' : '<p class="dim">Adopting needs the <b>member</b> role.</p>'}
      </div></div>` + reportLinksHtml();
      $("#controlsAdopt")?.addEventListener("click", adoptControls);
      return;
    }
    const cov = d.coverage || {};
    const total = Object.values(cov).reduce((a, b) => a + Number(b), 0) || rows.length;
    const done = Number(cov.implemented || 0);
    const na = Number(cov.not_applicable || 0);
    // "Not applicable" is a decision, not a gap, so it counts toward a settled
    // position — but it is shown separately so nobody games coverage with it.
    assessPane().innerHTML = `<div class="card">
      <div class="card-head" style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">
        <span class="card-title">${num(done)} of ${num(total)} implemented${na ? ` · ${num(na)} not applicable` : ""}</span>
        ${assessCanWrite() && rows.length < (d.catalogSize || 0) ? '<button class="btn" id="controlsAdopt" type="button" style="padding:6px 12px;font-size:12px">Add new baseline controls</button>' : ""}
      </div>
      <div class="tablewrap"><table class="feed"><tbody>
        <tr><th>Control</th><th>Domain</th><th>Status</th><th>Owner</th><th>Evidence</th><th>Reviewed</th></tr>
        ${rows.map((c) => `<tr class="evt">
          <td><span class="mono dim" style="font-size:11px">${esc(c.control_key)}</span> ${esc(c.objective)}
            <div class="dim" style="font-size:11px">${esc(c.description)}</div>
            ${(c.frameworks || []).length ? `<div class="dim" style="font-size:10.5px;margin-top:2px">${(c.frameworks || []).map((f) => esc(`${f.framework} ${f.requirement}`)).join(" · ")}</div>` : ""}
          </td>
          <td class="dim">${esc(titleCase(c.domain))}</td>
          <td>${assessCanWrite()
            ? `<select data-cstatus="${esc(c.id)}" style="${assessInput}">${CONTROL_STATUS_LABELS.map(([v, l]) => `<option value="${esc(v)}"${v === c.status ? " selected" : ""}>${esc(l)}</option>`).join("")}</select>`
            : esc(titleCase(c.status))}</td>
          <td>${assessCanWrite()
            ? `<input type="text" data-cowner="${esc(c.id)}" value="${esc(c.owner)}" placeholder="who owns it" style="${assessInput};width:130px">`
            : esc(c.owner || "—")}</td>
          <td>${assessCanWrite()
            ? `<input type="text" data-cevidence="${esc(c.id)}" value="${esc(c.evidence)}" placeholder="link or note" style="${assessInput};width:160px">`
            : esc(c.evidence || "—")}</td>
          <td class="mono dim" style="font-size:11px">${c.last_reviewed_at ? esc(ago(c.last_reviewed_at)) : "never"}</td>
        </tr>`).join("")}
      </tbody></table></div>
      <div class="pad dim" style="padding:0 calc(var(--u)*3) calc(var(--u)*3);font-size:11.5px">Changes save as you make them. Setting a status stamps the review date.</div>
    </div>` + reportLinksHtml();
    wireAssessControls();
  } catch (e) { assessError(e); }
}

function wireAssessControls() {
  $("#controlsAdopt")?.addEventListener("click", adoptControls);
  const save = (id, patch) => saveControl(id, patch);
  assessPane().querySelectorAll("[data-cstatus]").forEach((s) =>
    s.addEventListener("change", () => save(s.dataset.cstatus, { status: s.value })));
  // Owner/evidence save on blur rather than per keystroke — a request per
  // character would be silly, and blur is when the user has finished thinking.
  assessPane().querySelectorAll("[data-cowner]").forEach((i) =>
    i.addEventListener("blur", () => save(i.dataset.cowner, { owner: i.value })));
  assessPane().querySelectorAll("[data-cevidence]").forEach((i) =>
    i.addEventListener("blur", () => save(i.dataset.cevidence, { evidence: i.value })));
}

async function adoptControls() {
  const btn = $("#controlsAdopt");
  if (btn) { btn.disabled = true; btn.textContent = "Adopting…"; }
  try {
    const res = await fetch("/api/controls/adopt", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ project: PROJECT }),
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { banner(d.error || "Could not adopt the baseline."); return; }
    banner("");
    renderAssessControls();
  } catch (e) {
    banner("Could not adopt the baseline: " + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Adopt the baseline"; }
  }
}

async function saveControl(id, patch) {
  try {
    const res = await fetch(`/api/controls/${encodeURIComponent(id)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ project: PROJECT, ...patch }),
    });
    if (!res.ok) { const d = await res.json().catch(() => ({})); banner(d.error || "Could not save the control."); return; }
    banner("");
  } catch (e) { banner("Could not save the control: " + e.message); }
}

// ---------- Data governance (retention + erasure) ----------
// Owner-only, and every control here destroys data, so the flow is: show the
// current state, make the consequence explicit, require a second action.
async function loadGovernance() {
  const card = $("#governanceCard");
  if (!card) return;
  const isOwner = (ROLE_RANK[PROJECT_ROLE] ?? -1) >= 3;
  card.style.display = isOwner ? "" : "none";
  if (!isOwner) return;
  try {
    const r = await api("/api/retention");
    $("#setRetention").value = r.retentionDays;
    $("#retentionNote").textContent = r.keepForever ? "keeping everything forever" : "";
  } catch { /* the settings page still works without this */ }
}

$("#saveRetentionBtn")?.addEventListener("click", async () => {
  const days = Number($("#setRetention").value);
  const msg = days <= 0
    ? "Keep all data forever? Nothing will be deleted automatically."
    : `Keep data for ${days} days? Anything older than that will be deleted permanently, starting now.`;
  if (!confirm(msg)) return;
  const note = $("#retentionNote");
  note.textContent = "applying…";
  try {
    const res = await fetch("/api/retention", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ project: PROJECT, retentionDays: days }),
    });
    const d = await res.json().catch(() => ({}));
    note.textContent = res.ok
      ? (d.keepForever ? "keeping everything forever" : `applied — keeping ${d.retentionDays} days`)
      : (d.error || "could not update");
  } catch (e) { note.textContent = "could not update: " + e.message; }
});

$("#previewEraseBtn")?.addEventListener("click", async () => {
  const userId = $("#eraseUserId").value.trim();
  const note = $("#eraseNote"), btn = $("#eraseBtn");
  btn.style.display = "none";
  if (!userId) { note.textContent = "enter a user id first"; return; }
  note.textContent = "checking…";
  try {
    const d = await api(`/api/erasure/preview?userId=${encodeURIComponent(userId)}`);
    if (!d.traces) {
      // The important case: no match looks exactly like a successful erasure
      // unless we say so before anything is deleted.
      note.textContent = "no traces match that user id — check the value your app sends";
      return;
    }
    note.textContent = `${d.traces} trace${d.traces === 1 ? "" : "s"} will be permanently deleted`;
    btn.style.display = "";
  } catch (e) { note.textContent = "check failed: " + e.message; }
});

$("#eraseBtn")?.addEventListener("click", async () => {
  const userId = $("#eraseUserId").value.trim();
  if (!confirm(`Permanently erase all data for "${userId}"? This cannot be undone.`)) return;
  const note = $("#eraseNote");
  note.textContent = "erasing…";
  try {
    const res = await fetch("/api/erasure", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ project: PROJECT, userId }),
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { note.textContent = d.error || "erasure failed"; return; }
    note.textContent = `erased ${d.tracesMatched} trace(s) — recorded in the audit log`;
    $("#eraseBtn").style.display = "none";
    $("#eraseUserId").value = "";
  } catch (e) { note.textContent = "erasure failed: " + e.message; }
});

// ---------- Alerts (destinations + suppression) ----------
const CHANNEL_HELP = {
  slack:     { label: "Slack incoming-webhook URL", ph: "https://hooks.slack.com/services/…" },
  pagerduty: { label: "PagerDuty Events v2 routing key", ph: "your integration routing key" },
  webhook:   { label: "HTTPS endpoint", ph: "https://your-service.example.com/argus" },
};
$("#chKind")?.addEventListener("change", () => {
  const h = CHANNEL_HELP[$("#chKind").value] || CHANNEL_HELP.webhook;
  $("#chTargetLabel").textContent = h.label;
  $("#chTarget").placeholder = h.ph;
});

async function loadAlerts() {
  if (!PROJECT) { banner("Open an application to manage its alerts."); return; }
  const canManage = (ROLE_RANK[PROJECT_ROLE] ?? -1) >= 2;
  $("#channelCreateCard").style.display = canManage ? "" : "none";
  $("#suppCreate").style.display = canManage ? "flex" : "none";
  try {
    const [ch, sup] = await Promise.all([api("/api/alerts/channels"), api("/api/alerts/suppressions")]);
    banner("");
    const channels = ch.channels || [], rules = sup.rules || [];
    const failing = channels.filter((c) => c.consecutiveFailures > 0).length;
    $("#alertsSub").textContent =
      `${channels.length} destination${channels.length === 1 ? "" : "s"}` +
      (failing ? ` · ${failing} failing` : "") +
      (rules.length ? ` · ${rules.length} suppression rule${rules.length === 1 ? "" : "s"}` : "");

    const t = $("#channelsTable");
    if (!channels.length) {
      t.innerHTML = `<tbody><tr><td class="empty" style="padding:calc(var(--u)*4)">
        <div class="big">No destinations yet</div>
        <p>Findings are recorded and visible here regardless — but nobody is being told about them.
        Add Slack or PagerDuty above so a critical incident reaches a person.</p></td></tr></tbody>`;
    } else {
      t.innerHTML = `<thead><tr><th>Type</th><th>Label</th><th>Destination</th><th>Sends at</th><th>Health</th><th></th></tr></thead><tbody>` +
        channels.map((c) => {
          // A channel that has been failing quietly must not look like one that
          // has simply had nothing to report.
          const health = c.consecutiveFailures > 0
            ? `<span class="pill sev-high">failing ×${c.consecutiveFailures}</span><div class="dim" style="font-size:11px">${esc(c.lastError || "")}</div>`
            : c.lastSuccessAt
              ? `<span class="dim">delivered ${ago(c.lastSuccessAt)}</span>`
              : '<span class="dim">nothing sent yet</span>';
          return `<tr><td><span class="cat">${esc(c.kind)}</span></td><td>${esc(c.label || "—")}</td>` +
            `<td class="mono dim" style="font-size:11px">${esc(c.targetHint)}${c.signed ? ' <span class="cat" title="Deliveries are HMAC-signed">signed</span>' : ""}</td>` +
            `<td class="dim">${esc(c.minSeverity)}+</td><td>${health}</td>` +
            `<td style="text-align:right">${canManage ? `<button class="btn" data-test-ch="${esc(c.id)}" style="padding:3px 9px;font-size:11px">Test</button> <button class="btn" data-del-ch="${esc(c.id)}" style="padding:3px 9px;font-size:11px;color:var(--sev-critical)">Remove</button>` : ""}</td></tr>`;
        }).join("") + "</tbody>";
      t.querySelectorAll("[data-test-ch]").forEach((b) => b.addEventListener("click", () => testChannel(b, b.dataset.testCh)));
      t.querySelectorAll("[data-del-ch]").forEach((b) => b.addEventListener("click", () => removeChannel(b.dataset.delCh)));
    }

    const st = $("#suppTable");
    st.innerHTML = rules.length
      ? `<thead><tr><th>Silences</th><th>Reason</th><th>Added</th><th>Expires</th><th></th></tr></thead><tbody>` +
        rules.map((r) => `<tr><td class="mono" style="font-size:11.5px">${esc(r.ruleId || r.category || r.scopeValue || "—")}</td>` +
          `<td>${esc(r.reason || "—")}<div class="dim" style="font-size:11px">${esc(r.createdBy || "")}</div></td>` +
          `<td class="dim">${r.createdAt ? ago(r.createdAt) : "—"}</td>` +
          `<td class="dim">${r.expiresAt ? ago(r.expiresAt) : "never"}</td>` +
          `<td style="text-align:right">${canManage ? `<button class="btn" data-del-sup="${esc(r.id)}" style="padding:3px 9px;font-size:11px">Remove</button>` : ""}</td></tr>`).join("") + "</tbody>"
      : '<tbody><tr><td class="empty" style="padding:calc(var(--u)*3)">Nothing suppressed — every finding above your threshold is being sent.</td></tr></tbody>';
    st.querySelectorAll("[data-del-sup]").forEach((b) => b.addEventListener("click", () => removeSuppression(b.dataset.delSup)));
    stamp();
  } catch (e) { banner("Alerts query failed: " + e.message); }
}

$("#addChannelBtn")?.addEventListener("click", async () => {
  const body = {
    project: PROJECT,
    kind: $("#chKind").value,
    target: $("#chTarget").value.trim(),
    label: $("#chLabel").value.trim(),
    minSeverity: $("#chSeverity").value,
  };
  try {
    const res = await fetch("/api/alerts/channels", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { $("#channelResult").innerHTML = `<span style="color:var(--sev-high)">${esc(d.error || "Could not add it.")}</span>`; return; }
    // The signing secret exists so the receiver can prove a delivery came from
    // us. It is shown once, like every other credential here.
    $("#channelResult").innerHTML = d.signingSecret
      ? `<div style="padding:10px 12px;border:1px solid var(--accent);border-radius:var(--radius);background:color-mix(in srgb,var(--accent) 8%,transparent)">
           <div style="font-weight:600;margin-bottom:4px">Added. Signing secret — copy it now, it won't be shown again</div>
           <div class="mono" style="font-size:12px;word-break:break-all">${esc(d.signingSecret)}</div>
           <div class="dim" style="font-size:11.5px;margin-top:6px">Verify deliveries with
           <span class="mono">HMAC-SHA256(secret, "&lt;x-argus-timestamp&gt;.&lt;body&gt;")</span> against the
           <span class="mono">x-argus-signature</span> header. Reject anything whose timestamp is old.</div>
         </div>`
      : '<span class="dim">Added. Use <b>Test</b> to confirm it works before you rely on it.</span>';
    $("#chTarget").value = ""; $("#chLabel").value = "";
    loadAlerts();
  } catch (e) { $("#channelResult").textContent = "Could not add it: " + e.message; }
});

async function testChannel(btn, id) {
  const original = btn.textContent;
  btn.disabled = true; btn.textContent = "sending…";
  try {
    const res = await fetch("/api/alerts/channels/test", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ project: PROJECT, id }) });
    const d = await res.json().catch(() => ({}));
    btn.textContent = d.ok ? "sent ✓" : "failed";
    if (!d.ok) banner("Test delivery failed: " + (d.error || "unknown error"));
    setTimeout(() => { btn.disabled = false; btn.textContent = original; loadAlerts(); }, 1500);
  } catch (e) { btn.disabled = false; btn.textContent = original; banner("Test failed: " + e.message); }
}

async function removeChannel(id) {
  if (!confirm("Remove this destination? Alerts will stop being sent to it.")) return;
  const res = await fetch(`/api/alerts/channels/${encodeURIComponent(id)}?project=${encodeURIComponent(PROJECT)}`, { method: "DELETE" });
  if (!res.ok) { const d = await res.json().catch(() => ({})); banner(d.error || "Remove failed"); return; }
  loadAlerts();
}

$("#addSuppBtn")?.addEventListener("click", async () => {
  const body = {
    project: PROJECT,
    ruleId: $("#supRule").value.trim(),
    category: $("#supCategory").value,
    scopeType: "rule",
    reason: $("#supReason").value.trim(),
    expiresInDays: Number($("#supExpiry").value),
  };
  const res = await fetch("/api/alerts/suppressions", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const d = await res.json().catch(() => ({}));
  if (!res.ok) { banner(d.error || "Could not add the rule."); return; }
  $("#supRule").value = ""; $("#supReason").value = "";
  loadAlerts();
});

async function removeSuppression(id) {
  const res = await fetch(`/api/alerts/suppressions/${encodeURIComponent(id)}?project=${encodeURIComponent(PROJECT)}`, { method: "DELETE" });
  if (!res.ok) { const d = await res.json().catch(() => ({})); banner(d.error || "Remove failed"); return; }
  loadAlerts();
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
    loadGovernance(); // retention + erasure live on this page, owner-gated
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
  $("#setGwMode").value = c.gateway?.mode || "inherit";
  $("#setGwThreshold").value = c.gateway?.block_threshold ?? 75;
  // Disable the editable controls for non-admins (L1/L3 stay disabled always).
  ["setSample", "setRedact", "setL2", "setL4", "setAlertSev", "setGwMode", "setGwThreshold"].forEach((id) => { const el = $("#" + id); if (el) el.disabled = !canEdit; });
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
  // block_categories is intentionally not exposed: the only honest choice is
  // the built-in set, and mergeConfig drops anything else anyway. Preserved
  // from the stored config so an API-set value survives a UI save.
  cfg.gateway = { ...(cfg.gateway || {}), mode: $("#setGwMode").value, block_threshold: Number($("#setGwThreshold").value) };
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
    const scopeChip = (sc) => (sc || []).length
      ? sc.map((x) => `<span class="cat">${esc(x)}</span>`).join(" ")
      : '<span class="dim">—</span>';
    t.innerHTML = `<thead><tr><th>Label</th><th>Access</th><th>Public key</th><th>Created</th><th>Last used</th><th></th></tr></thead><tbody>` +
      keys.map((k) => `<tr><td>${esc(k.label || "—")}</td><td>${scopeChip(k.scopes)}</td><td class="mono">${esc(k.publicKey)}</td><td class="dim">${k.createdAt ? ago(k.createdAt) : "—"}</td><td class="dim">${k.lastUsedAt ? ago(k.lastUsedAt) : "never"}</td><td style="text-align:right"><button class="btn" data-revoke="${esc(k.id)}" style="padding:3px 9px;font-size:11px;color:var(--sev-critical)">Revoke</button></td></tr>`).join("") + "</tbody>";
    t.querySelectorAll("[data-revoke]").forEach((b) => b.addEventListener("click", () => revokeKey(b.dataset.revoke)));
    stamp();
  } catch (e) { banner("Keys query failed: " + e.message); }
}
$("#createKeyBtn")?.addEventListener("click", async () => {
  try {
    const scopes = ($("#keyScope")?.value || "ingest").split(",");
    const label = $("#keyLabel")?.value.trim() || "";
    const res = await fetch("/api/keys", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ project: PROJECT, scopes, label }) });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { banner(d.error || "Create failed"); return; }
    const canRead = (d.scopes || []).includes("read");
    const canIngest = (d.scopes || []).includes("ingest");
    const usage = canIngest
      ? `<div class="dim" style="font-size:11.5px;margin-top:8px">Set that environment variable where your app runs, then call <span class="mono">argus.init()</span> — the key stays out of your source. <span style="opacity:.8">Can't set env vars? Pass it directly: <span class="mono">argus.init("${esc(d.token || "")}")</span>.</span></div>`
      : "";
    const readUsage = canRead
      ? `<div class="dim" style="font-size:11.5px;margin-top:8px">Read the <span class="mono">/v1</span> API with it:<br>
         <span class="mono">curl -H "Authorization: Bearer ${esc(d.token || "")}" ${esc(location.origin)}/v1/security-events?severity=critical</span></div>`
      : "";
    $("#newKeyBox").innerHTML = `<div style="margin:calc(var(--u)*2) calc(var(--u)*3);padding:12px 14px;border:1px solid var(--accent);border-radius:var(--radius);background:color-mix(in srgb,var(--accent) 8%,transparent)">
      <div style="font-weight:600;margin-bottom:6px">New key created — copy it now, it won't be shown again</div>
      <div class="mono" style="font-size:12px;line-height:1.7">ARGUS_KEY=${esc(d.token || "")}</div>
      ${usage}${readUsage}
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

// Delegated navigation for [data-href] buttons. These used to be inline
// onclick="location.href=..." attributes, which force `script-src
// 'unsafe-inline'` in the CSP and thereby disable the single control that most
// reliably contains a stored-XSS bug. The dashboard renders attacker-authored
// prompt-injection payloads, so that trade was not worth one line of HTML.
document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-href]");
  if (el) location.href = el.dataset.href;
});
