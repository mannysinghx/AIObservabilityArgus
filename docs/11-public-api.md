# 11 — Public API (v1)

The read API. This is what your own dashboards, SIEM connectors, scheduled
exports and scripts talk to. It is separate from the `/api/*` endpoints the
Argus dashboard uses for itself — those authenticate a browser session and are
shaped for the screens that consume them.

Base URL: wherever you host the Argus web service, e.g.
`https://argus.yourcompany.com`.

## Authentication

```
Authorization: Bearer ak_live_…
```

Keys are created under **API Keys** for an application, and carry scopes:

| Scope | Grants |
|---|---|
| `ingest` | Send telemetry. Cannot read anything. |
| `read` | Read this application's traces, spans and security events. |

**Keep them separate.** An ingest key ships inside your application and is
deployed to every host that runs it — by deployment count it is the most exposed
credential you hold. A read key belongs in one dashboard or one connector. If
the ingest key leaks, it should not also be able to download everything it ever
sent.

A key names exactly one application. There is no `project` parameter on any
endpoint, so there is nothing to point at someone else's data.

Revoking a key takes effect immediately, not when a cache expires.

## Rate limits

600 requests per minute per key by default (`READ_RATE_LIMIT`). Over the limit
you get `429` with a `Retry-After` header in seconds.

## Pagination

Cursor-based. Pass the `nextCursor` from the previous response:

```bash
curl -H "Authorization: Bearer $ARGUS_READ_KEY" \
  "$ARGUS_URL/v1/security-events?limit=100"
# → { "data": [...], "nextCursor": "MjAyNi0wNy0yNi…", "hasMore": true }

curl -H "Authorization: Bearer $ARGUS_READ_KEY" \
  "$ARGUS_URL/v1/security-events?limit=100&cursor=MjAyNi0wNy0yNi…"
```

`hasMore: false` and `nextCursor: null` mean you have reached the end.

Cursors are keyset, not offset, which matters for exports: with `OFFSET`, a row
arriving between two pages shifts everything down and the reader silently never
sees the row that slid across the boundary. Walking with cursors visits every
row exactly once even while data is being written.

`limit` defaults to 100 and is capped at 1000.

## Endpoints

All list endpoints accept `limit`, `cursor`, `since` and `until`.
`since`/`until` take `YYYY-MM-DD HH:MM:SS[.mmm]` in UTC.

### `GET /v1/me`

Which application this key belongs to, and its scopes. Useful as a connectivity
check.

### `GET /v1/traces`

One row per trace: `trace_id`, `name`, `environment`, `release`, `timestamp`,
`session_id`, `user_id`, `tags`, `metadata`.

### `GET /v1/traces/:id`

One trace in full — the trace, all its observations (with complete `input` and
`output`), and every security event raised against it.

### `GET /v1/observations`

Spans. Extra filters: `traceId`, `type`
(`span` | `generation` | `retrieval` | `tool` | `event`).

### `GET /v1/security-events`

The endpoint most integrations want. Extra filters:

| Filter | Values |
|---|---|
| `severity` | `info` `low` `medium` `high` `critical` |
| `category` | `direct_injection` `jailbreak` `indirect_injection` `exfiltration` `excessive_agency` `rag_poisoning` `prompt_leak` `pii_egress` `canary_triggered` `obfuscation` |
| `outcome` | `unknown` `attempted` `succeeded` `blocked` |
| `verdict` | `unreviewed` `confirmed` `false_positive` |

An unrecognised filter value returns `400`, not an empty page. This is
deliberate: a monitoring query filtered on a typo'd severity would otherwise
report "no critical events" indefinitely and look like good news.

### `GET /v1/summary`

Counters for a window — cheap enough to poll from a status board.

```json
{
  "security": { "total": 42, "critical": 2, "high": 7, "succeeded": 1, "unreviewed": 12 },
  "usage":    { "observations": 9310, "tokens": 1840221, "cost_usd": 21.44 },
  "traffic":  { "traces": 1204, "sessions": 310, "users": 88 }
}
```

## Errors

| Status | Meaning |
|---|---|
| `400` | A filter value wasn't recognised. |
| `401` | Missing, unknown, or revoked key. |
| `403` | The key lacks the `read` scope. |
| `404` | No such trace in this application. |
| `429` | Rate limited — see `Retry-After`. |
| `503` | The query store is unavailable. |

Bodies are `{ "error": "<code>", "message": "<human readable>" }`. Internal
failures never include database detail.

## Example: pull new critical events into your SIEM

```bash
#!/usr/bin/env bash
set -euo pipefail
SINCE="${1:-$(date -u -d '1 hour ago' '+%Y-%m-%d %H:%M:%S')}"
cursor=""
while :; do
  url="$ARGUS_URL/v1/security-events?severity=critical&limit=500&since=$(printf %s "$SINCE" | jq -sRr @uri)"
  [ -n "$cursor" ] && url="$url&cursor=$cursor"
  page=$(curl -sS -H "Authorization: Bearer $ARGUS_READ_KEY" "$url")
  echo "$page" | jq -c '.data[]'          # → your SIEM
  cursor=$(echo "$page" | jq -r '.nextCursor // empty')
  [ -z "$cursor" ] && break
done
```

## Stability

`/v1` is additive-only: new fields may appear, existing ones will not change
type or disappear. A breaking change would ship as `/v2`.
