# 12 — Gateway mode

An OpenAI-compatible proxy that can **refuse** a prompt injection instead of
reporting it afterwards. Point your SDK's base URL at Argus:

```python
client = OpenAI(
    base_url="https://argus-gateway.yourcompany.com/v1",
    api_key=OPENAI_API_KEY,                       # yours; forwarded untouched
    default_headers={"x-argus-key": "ak_live_…"}, # identifies the application
)
```

Two credentials on purpose. Your provider key is forwarded verbatim and never
stored — Argus has no business holding your OpenAI billing credential. The
Argus key identifies which application the traffic belongs to.

Pointing at the gateway also gives you tracing with **no SDK change at all**:
every call through it emits a trace, so `/v1/chat/completions` becomes
instrumented by virtue of the base URL.

## The operating principle

This is the only part of Argus on your critical path. Everything else observes
and reports; if it breaks, your app is unaffected. The gateway sits between your
app and your model provider, which makes every property here an availability
property.

**It fails open.** If detection is slow, down, or throwing, the request goes
through unscanned and the response says so. A security tool that takes your
product offline when it has a bad day gets removed the same week, and then it
protects nothing.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `GATEWAY_MODE` | `observe` | `observe` scores and records; `block` refuses. |
| `GATEWAY_BLOCK_THRESHOLD` | `75` | Score (0–100) at or above which a request is refused. |
| `GATEWAY_LATENCY_BUDGET_MS` | `300` | Detection gets this long. Past it, the request proceeds. |
| `GATEWAY_ON_FAILURE` | `open` | `open` allows on detection failure; `closed` refuses. |
| `GATEWAY_UPSTREAM` | `https://api.openai.com` | Where to forward. |
| `GATEWAY_PORT` | `3004` | |

Anything other than the exact strings `block` and `closed` is treated as
`observe` and `open`. A typo must never be what enables blocking.

**Start in `observe`.** Run it for a week, look at what *would* have been
blocked in the Threat Center, then switch. Turning on an inline blocker you
haven't watched first is how you find out about your false positives from a
customer.

## What it blocks, and what it deliberately doesn't

Only **`direct_injection`** and **`jailbreak`**, and only on the user's own
message.

This layer sees one message with no trace context. It cannot judge indirect
injection, exfiltration flows or behavioural deviation — those are cross-span
phenomena and they are Argus's actual speciality, detected by L4 with the whole
trace in view. Blocking on them here would mean refusing real users to catch
attacks this code is not equipped to see.

The system prompt is never scanned. A system prompt is by nature a list of
imperative instructions, so scanning it would match injection heuristics on
every single request.

Everything the gateway allows is still scanned by the full async pipeline
seconds later, with all four layers and the complete trace. Gateway mode adds a
fast, narrow, high-confidence veto in front of that; it does not replace it.

## Where the threshold comes from

Measured against the labelled corpus (20 attacks, 20 hard negatives — blog posts
about prompt injection, fiction quoting it, support text that legitimately
mentions previous instructions):

| Threshold | Attacks blocked | Benign wrongly blocked |
|---:|---:|---:|
| 90 | 2/20 | 0/20 |
| 85 | 4/20 | 0/20 |
| **75** | **7/20** | **0/20** |
| 70 | 10/20 | 0/20 |

Every benign item scores 0.0, so the corpus alone would justify going lower. It
doesn't justify it in production: 20 negatives is thin evidence and real traffic
contains phrasings this corpus has never seen. 75 is the point where at least
two independent rules must fire — one heuristic is a hint, two is a pattern.

The asymmetry that sets it: a false block is a user who cannot use your product;
a missed detection is still caught, recorded and alerted on moments later. Those
costs are nowhere near equal.

`services/detection/tests/test_quality_gate.py` fails CI if this threshold would
start refusing benign traffic, or if it drifts so high it blocks nothing.

## What a blocked request looks like

HTTP 403, in the provider's own error shape, so an OpenAI SDK raises it as a
normal API error you can catch:

```json
{
  "error": {
    "message": "Blocked by Argus: direct_injection. …ignore all previous instructions…",
    "type": "argus_blocked",
    "code": "prompt_injection_detected"
  }
}
```

Blocked requests are traced too, with `finish_reason: "argus_blocked"`, so
they appear in the Threat Center alongside everything else.

## Streaming

`stream: true` is passed through untouched. The *request* is still scanned and
can still be blocked; the response is not, because scanning a streamed response
means buffering it, which removes the only reason anyone streams. The async
pipeline scans the completion afterwards.

## Metrics

`/metrics` exposes `gateway_blocked_total`, `gateway_allowed_total`,
`gateway_scan_duration_ms`, `gateway_scan_degraded_total` and
`gateway_upstream_errors_total`.

Watch `gateway_scan_degraded_total`. It is the number that tells you the gateway
is failing open — that is, that it is currently protecting nothing.
