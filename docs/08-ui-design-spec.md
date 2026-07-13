# 08 — UI Design Specification

Goal: a **professional, analyst-grade, deeply configurable** interface.
"Professional" here means the standard set by Linear, Grafana, and Datadog:
calm, dense, fast, keyboard-friendly, and consistent — not decorative.
"Configurable" means theming, layout, and data views are all user- and
tenant-adjustable without forking the frontend.

An interactive mockup of this spec exists as an HTML artifact
(security overview, trace explorer with taint overlay, and the appearance
panel) — use it as the visual reference for everything below.

## 1. Design principles

1. **Severity reads before text.** An analyst triages by scanning; state is
   encoded in form (severity stripes, pills, tinted spans) before numbers.
2. **Summary above detail, always.** Every screen opens with a KPI band;
   every row expands to full context; every alert links to its trace.
3. **Density is a feature.** Security and observability users want more rows
   per screen, not more whitespace. Comfortable/compact density is a global
   token switch, not a per-component hack.
4. **The trace view is the hero component.** It is custom-built, not a
   library table: waterfall bars, taint tinting, inline detection flags.
5. **Dark theme is co-primary.** SOC/ops users live in dark mode; both themes
   ship pixel-equal, driven by the same semantic tokens.
6. **Nothing hardcoded that a tenant might brand.** Accent, logo, radius,
   density defaults are all tokens resolvable per organization (white-label).

## 2. Design system

### 2.1 Token architecture (three layers)

```
primitive tokens   →  semantic tokens        →  component tokens
(--teal-500)          (--accent, --bg,          (--table-row-height,
(--red-500)           --surface, --ink,          --severity-critical)
                      --line, --ink-muted)
```

- All styling goes through **semantic tokens** (CSS custom properties).
- Themes = alternate semantic-token sets. Light/dark ship built-in; tenants
  can register additional theme packs (JSON → CSS variables) without code.
- Implementation: Tailwind configured against CSS variables
  (`colors: { accent: 'var(--accent)' }`), shadcn/ui components inherit.

### 2.2 Color

**Neutrals (blue-biased, deliberately not pure grey):**

| Token | Light | Dark |
|---|---|---|
| `--bg` | `#F6F7F9` | `#0D131D` |
| `--surface` | `#FFFFFF` | `#141C2A` |
| `--surface-2` (nested) | `#F0F2F5` | `#1B2534` |
| `--line` | `#E2E6EB` | `#263248` |
| `--ink` | `#1B2534` | `#E8EDF4` |
| `--ink-muted` | `#5C6B80` | `#8DA0B8` |

**Brand accent (interaction, selection, links, primary buttons):**
`--accent: #35B5A4` (radar teal), `--accent-ink` for on-accent text.
Tenant-overridable; the UI must remain coherent under any accent because
severity color never derives from accent.

**Semantic severity ramp (fixed, never themed away):**

| Token | Value | Use |
|---|---|---|
| `--sev-critical` | `#E5484D` | critical events, blocked states |
| `--sev-high` | `#F76B15` | high |
| `--sev-medium` | `#DFA30E` | medium |
| `--sev-low` | `#6E8CA8` | low |
| `--sev-info` | `--ink-muted` | info |
| `--ok` | `#3BA55D` | healthy/pass |

**Taint tinting (trace view):** untrusted spans get a `--sev-high`-hued left
edge + 6–8% background wash; taint-*influenced* spans a fainter wash; canary
hits use `--sev-critical`. Tint is a wash, not a fill — content stays legible.

### 2.3 Typography

| Role | Face | Notes |
|---|---|---|
| UI & headings | Avenir Next → Inter var (self-hosted) → system-ui | Geometric, professional; headings `text-wrap: balance` |
| Data/mono | `ui-monospace` (SF Mono / Cascadia / JetBrains Mono self-hosted) | trace IDs, hashes, latencies, token counts, payloads |
| Scale | 12 / 13 / 14 / 16 / 20 / 28 px | body 13px in compact, 14px comfortable |

All numeric columns: `font-variant-numeric: tabular-nums`. Uppercase
micro-labels (eyebrows, table headers) get `letter-spacing: 0.06em`.
Self-host fonts (no CDN) — the platform may run air-gapped.

### 2.4 Spacing, radius, elevation

- 4px base unit; density multiplier token `--space-unit` (4px compact /
  5px comfortable) scales paddings and row heights globally.
- Radius token `--radius` (default 6px; tenant-overridable 0–10px).
- Elevation: borders first, shadows minimal (one popover shadow). Data apps
  read better with hairlines than drop shadows.

### 2.5 Motion

- 120–160ms ease-out on hover/expand; no entrance animations on data.
- Live feeds: new rows slide in subtly + unread marker, never flash.
- `prefers-reduced-motion` honored globally.

## 3. Configurability specification

### 3.1 User-level (persisted per user, instant apply)

| Setting | Options |
|---|---|
| Theme | system / light / dark / tenant theme packs |
| Accent | tenant palette or custom hex (contrast-checked) |
| Density | comfortable / compact |
| Sidebar | expanded / collapsed (icon rail) |
| Home screen | which dashboard loads on login |
| Timezone & clock | local / UTC (critical for incident forensics) |
| Number format | locale |
| Keyboard shortcuts | on/off + cheat-sheet (`?`) |

### 3.2 Table & view configurability (every data table)

- Column picker (show/hide/reorder/pin), sort, per-column filters.
- **Saved views**: name + share to project (e.g. "Critical exfil, prod, 7d").
- Row density inherits global; per-table override.
- Export CSV/JSON of current view.
- Implementation: TanStack Table v8; view state serialized to URL (deep
  links) and to Postgres (saved views).

### 3.3 Dashboard builder (Phase 3)

- Grid canvas (12-col, drag/resize — `react-grid-layout` or `gridstack`).
- Widget library: stat tile, time series, top-N table, severity histogram,
  detection-layer health, attack map, markdown/note, saved-view embed.
- Each widget = saved query (filters + aggregation) + visualization config.
- Dashboards are JSON documents (versioned, in Postgres) → importable/
  exportable → shareable as templates; ship defaults: "Security Overview",
  "Cost & Usage", "Model Performance", "Incident Review".
- Scoping: personal / project / org; RBAC controls edit vs. view.

### 3.4 Tenant/white-label (org-level)

- Logo (light+dark), accent, radius, default theme, default dashboards,
  custom links in nav footer (runbooks, on-call).
- Delivered as an org `branding` JSON → semantic-token overrides at runtime.
  No rebuild required.

### 3.5 RBAC-aware UI

Roles: `viewer / analyst / editor / admin / security-admin`.
The UI renders capability-aware (no dead buttons): e.g. only `security-admin`
sees detection-config editing; `analyst` can verdict events but not change
suppression rules. Capability matrix lives in Postgres; frontend consumes a
`capabilities[]` claim.

## 4. Information architecture

```
◐ Argus  [Project ▾] [env: prod ▾] [time: 24h ▾]        ⌘K  🔔  ⚙  👤
├── Overview            – configurable home dashboard
├── SECURITY
│   ├── Threat Center   – KPI band, attack feed, layer health, trends
│   ├── Incidents       – grouped events, timeline, assignee, status
│   ├── Review Queue    – unverdicted events (analyst workflow)
│   └── Red Team        – scheduled scans, attack-success trend
├── OBSERVABILITY
│   ├── Traces          – table + trace explorer (waterfall)
│   ├── Sessions        – multi-turn grouping
│   └── Analytics       – cost, tokens, latency, models
├── ENGINEERING
│   ├── Prompts         – versions, labels, diff
│   ├── Evals           – judges, datasets, scores
│   └── Datasets
└── Settings            – project, detection config, alerting,
                          appearance, API keys, members
```

- **⌘K command palette**: navigate, switch project/env, search trace ID,
  run actions ("mute rule R-014…"). Power-user backbone.
- Global context bar (project / environment / time range) applies to every
  screen and serializes into the URL.

## 5. Key screens

### 5.1 Threat Center (security overview)

- KPI band: events 24h (Δ vs prior), critical count, injections blocked/
  detected, canary triggers, mean-time-to-verdict.
- Attack feed (⅔ width): severity stripe + pill, category, outcome
  (attempted/succeeded/blocked), source span type, model, trace link,
  sparkline of layer scores. Row expand = evidence excerpt with the matched
  content highlighted + "open trace" / "verdict" actions.
- Detection-layer health (⅓): per-layer hit rate, p95 scan latency,
  escalation funnel (L1→L2→L3→L4 counts).
- Trend: stacked area of events by category over time range.

### 5.2 Trace Explorer (hero)

- Left: filterable trace table (saved views apply).
- Main: **waterfall tree** — one row per observation: type icon, name,
  duration bar on shared time axis, tokens/cost, taint tint, detection flags
  as inline chips (e.g. `L2 0.94`, `echo`, `canary`).
- Right drawer (span detail): tabs Input / Output / Attributes / Security.
  Security tab shows every event on that span with layer provenance
  (L1 rules matched, per-model L2 scores, L3 judge verdict JSON, L4 signals).
- Taint legend pinned; "jump to taint frontier" button.
- Payload viewer renders **content as escaped text only** — stored attack
  strings must never execute in the analyst's browser (see hardening note
  in [02 — Architecture](02-architecture.md)).

### 5.3 Incident view

- Header: severity, status (open/ack/resolved), assignee, MITRE/OWASP tags.
- Timeline: correlated events in order, each linking to its trace/span.
- For RAG-poisoning incidents: the offending document (hash, source,
  first-seen), affected-session list, "suppress / confirm corpus" actions.

### 5.4 Review Queue

- Keyboard-first triage: `j/k` navigate, `c` confirm, `f` false-positive,
  `o` open trace. Verdicts feed the corpus (see
  [04 — Security Detection Engine](04-security-detection-engine.md)).

### 5.5 Appearance settings

- Live-preview panel for theme / accent / density / radius; org branding
  editor for admins. (Demonstrated in the mockup artifact.)

## 6. Component stack

| Concern | Choice |
|---|---|
| Framework | Next.js (App Router) + TypeScript |
| Styling | Tailwind CSS mapped to CSS-variable tokens |
| Primitives | shadcn/ui (Radix under the hood — a11y for free) |
| Tables | TanStack Table v8 + TanStack Virtual (100k-row feeds) |
| Charts | ECharts (canvas; dense time series) with token-fed theme |
| Trace waterfall | custom component (owns the differentiator UX) |
| Command palette | cmdk |
| State/URL | TanStack Query + `nuqs` (filters in URL = shareable views) |
| Forms | react-hook-form + zod |

## 7. Quality bars

- **Accessibility:** WCAG 2.1 AA; severity never encoded by color alone
  (stripe + icon + label); full keyboard traversal of trace tree; visible
  focus rings; `aria-live` on the attack feed.
- **Performance:** virtualize all long lists; charts down-sample server-side
  (ClickHouse aggregates); p95 route transition < 200ms on cached data;
  trace with 1k spans renders < 500ms.
- **i18n-ready:** all strings through a message catalog from day one;
  RTL-safe layout (logical CSS properties).
- **Visual regression tests** (Playwright screenshots) on both themes ×
  both densities for the five key screens.
