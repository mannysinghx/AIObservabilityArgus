# argus (Python)

Drop-in auto-instrumenting tracer for [Argus](../../README.md) — security-first AI observability. One line captures every LLM call your Python app makes; a middleware groups them per request. No per-call code. Stdlib-only, zero dependencies.

## Install

```bash
pip install argus-tracer
```

## Use (FastAPI / Starlette)

```python
import argus
argus.init()                          # reads ARGUS_PUBLIC_KEY / ARGUS_SECRET_KEY / ARGUS_INGEST_URL

app = FastAPI()
app.add_middleware(argus.Middleware)  # one trace per request; groups every LLM call in it
```

From here, every `openai` / `anthropic` call — including OpenAI-compatible providers (DeepSeek, Kimi, Qwen) via `AsyncOpenAI(base_url=...)` — is captured automatically: prompt, completion, tokens, cost (auto-estimated), latency, provider. Both async and sync clients are covered.

### Workers, Temporal activities, scripts (no request context)

Group a unit of work explicitly:

```python
async with argus.trace("nightly.summarize", user_id=uid):
    await client.chat.completions.create(...)   # captured + grouped
```

A captured call with no surrounding scope still records — as its own single-span trace. Just call `argus.init()` once in the worker process.

### Optional one-liners

```python
argus.retrieval("policy-kb", retrieved_text, source=doc_id)
argus.tool("send_email", input=args, output=result)
```

Both default to the `untrusted_external` taint class — what indirect-injection detection keys off.

## How it works

- **Capture** — patches the async/sync `create` methods of the OpenAI and Anthropic resource classes, so every client instance is covered. Non-streaming calls are captured; streaming passes through untouched.
- **Grouping** — a `contextvars`-based trace context, set by a pure-ASGI middleware (not `BaseHTTPMiddleware`, which would break contextvar propagation to the endpoint).
- **Safety** — a daemon thread batches and POSTs via the stdlib (`urllib`), never on the request's event loop; nothing here raises into your app; an Argus outage is silently skipped. Inert until the API keys are set.

## Config

`init()` reads `ARGUS_PUBLIC_KEY`, `ARGUS_SECRET_KEY`, `ARGUS_INGEST_URL`, `ARGUS_ENV` from the environment (or pass as kwargs). Set `ARGUS_DEBUG=1` to log each capture.

## Test

```bash
python3 test/run.py
```
