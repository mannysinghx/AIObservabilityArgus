# @argus/node

Drop-in auto-instrumenting tracer for [Argus](../../README.md) — security-first AI observability. One line captures every LLM call your app makes; a second groups them per request. No per-call code.

## Install

```bash
npm install @argus/node
```

## Use

```js
// Once, at the very top of your app's entry file — before your LLM clients are created.
const argus = require("@argus/node").init();
// reads ARGUS_PUBLIC_KEY, ARGUS_SECRET_KEY, ARGUS_INGEST_URL from the environment

// Express: one trace per request, so every LLM call in a request is grouped.
app.use(argus.middleware());
```

That's the whole integration. From here, every OpenAI, Anthropic, and OpenAI-compatible call (DeepSeek, Gemini, GLM/Z.ai, Groq, Mistral, …) made via the official SDKs or raw `fetch` is captured automatically — prompt, completion, model, token counts, cost (auto-estimated), and latency — and scanned by Argus's detection pipeline.

### Configuration

`init()` reads these environment variables, or takes them as options:

| Env var | Option | Default |
| --- | --- | --- |
| `ARGUS_PUBLIC_KEY` | `publicKey` | — (required) |
| `ARGUS_SECRET_KEY` | `secretKey` | — (required) |
| `ARGUS_INGEST_URL` | `ingestUrl` | `http://localhost:3001/api/public/ingestion` |
| `ARGUS_ENV` | `environment` | `production` |
| `ARGUS_DEBUG=1` | `debug` | `false` |

If the keys aren't set, the SDK logs one warning and stays completely inert — it never sends anything and never affects your app.

### Optional one-liners

Retrieval and tool spans can't be auto-detected, but they're one line each and attach to the active request trace automatically — no trace object to pass around:

```js
argus.retrieval("governance-kb", retrievedDocText, { source: docId });
argus.tool("send_notification", { input: args, output: result });
```

Both default to the `untrusted_external` taint class — exactly what indirect-injection detection keys off.

### Outside Express (workers, queues, scripts)

Wrap any async scope so calls inside it group into one trace:

```js
await argus.trace("nightly.summarize", { userId }, async () => {
  await openai.chat.completions.create({ /* ... */ }); // auto-captured, grouped
});
```

A captured call with no surrounding scope still records — as its own single-span trace.

### Serverless (Vercel, Lambda)

Delivery is async and batched. In a serverless function that may freeze the instant it responds, flush before returning:

```js
await argus.flush(); // or argus.shutdown() on teardown
```

## How it works

- **Capture** — global `fetch` is patched as the universal choke point (both official SDKs dispatch through it on Node 18+), with defensive SDK-level patches for `openai` / `@anthropic-ai/sdk` as belt-and-suspenders for custom transports. A guard ensures a call is never counted twice.
- **Grouping** — an `AsyncLocalStorage` context started by `middleware()` (or `trace()`) binds every call in a request to one trace.
- **Safety** — everything is fire-and-forget: captures run off the caller's path (streaming responses are never buffered on your behalf), nothing here ever throws into your request, and an Argus outage is silently skipped. Zero runtime dependencies.

## Requirements

Node.js ≥ 18 (for global `fetch` and `AsyncLocalStorage`).

## Test

```bash
npm test
```

Spins up fake ingestion + LLM endpoints and asserts capture across raw fetch, streaming, Anthropic, request grouping, the dedup guard, and disabled-mode safety.
