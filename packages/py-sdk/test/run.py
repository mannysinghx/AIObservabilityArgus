"""Self-contained test harness for the argus Python tracer. No pytest, no network
beyond localhost. Injects fake `openai`/`anthropic` modules matching the real SDK
resource shape, drives them through the auto-instrumentation, and asserts the
batches that reach a fake ingest endpoint are correct.

Run:  python3 test/run.py   (from packages/py-sdk)
"""
import asyncio
import json
import os
import sys
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---- fake ingest endpoint ----
RECEIVED = {"traces": [], "observations": []}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n)
        try:
            b = json.loads(body)
            RECEIVED["traces"] += b.get("traces", [])
            RECEIVED["observations"] += b.get("observations", [])
        except Exception:
            pass
        self.send_response(202)
        self.end_headers()
        self.wfile.write(b"{}")


def start_ingest():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# ---- fake openai / anthropic SDK modules ----
def ns(**kw):
    return types.SimpleNamespace(**kw)


def inject_fake_sdks():
    # openai.resources.chat.completions.AsyncCompletions.create
    class AsyncCompletions:
        def __init__(self):
            self._client = ns(base_url="https://api.openai.com/v1")

        async def create(self, **kwargs):
            return ns(
                model=kwargs.get("model", ""),
                choices=[ns(message=ns(content="Hello there"), finish_reason="stop")],
                usage=ns(prompt_tokens=11, completion_tokens=3),
            )

    for name, mod in {
        "openai": types.ModuleType("openai"),
        "openai.resources": types.ModuleType("openai.resources"),
        "openai.resources.chat": types.ModuleType("openai.resources.chat"),
        "openai.resources.chat.completions": types.ModuleType("openai.resources.chat.completions"),
    }.items():
        sys.modules[name] = mod
    sys.modules["openai.resources.chat.completions"].AsyncCompletions = AsyncCompletions

    class AsyncMessages:
        def __init__(self):
            self._client = ns(base_url="https://api.anthropic.com")

        async def create(self, **kwargs):
            return ns(
                model=kwargs.get("model", ""),
                content=[ns(text="Hi from Claude")],
                usage=ns(input_tokens=9, output_tokens=4),
                stop_reason="end_turn",
            )

    for name, mod in {
        "anthropic": types.ModuleType("anthropic"),
        "anthropic.resources": types.ModuleType("anthropic.resources"),
        "anthropic.resources.messages": types.ModuleType("anthropic.resources.messages"),
    }.items():
        sys.modules[name] = mod
    sys.modules["anthropic.resources.messages"].AsyncMessages = AsyncMessages
    return AsyncCompletions, AsyncMessages


def wait_for(pred, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.03)
    return pred()


FAILS = 0


def check(name, fn):
    global FAILS
    try:
        fn()
        print("  ✓ " + name)
    except Exception as e:
        FAILS += 1
        print("  ✗ " + name + "\n      " + repr(e))


def reset():
    RECEIVED["traces"].clear()
    RECEIVED["observations"].clear()


def main():
    srv, port = start_ingest()
    ingest_url = f"http://127.0.0.1:{port}/api/public/ingestion"

    AsyncCompletions, AsyncMessages = inject_fake_sdks()

    import argus
    argus.init(public_key="pk", secret_key="sk", ingest_url=ingest_url, flush_interval=0.1)

    print("argus Python tracer tests\n")

    def t_openai():
        reset()
        oc = AsyncCompletions()

        async def run():
            async with argus.trace("job.openai", session_id="s1"):
                r = await oc.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}])
                assert r.choices[0].message.content == "Hello there"  # caller unaffected
        asyncio.run(run())
        assert wait_for(lambda: RECEIVED["observations"] and RECEIVED["traces"]), "nothing ingested"
        g = next(o for o in RECEIVED["observations"] if o["type"] == "generation")
        assert g["model"] == "gpt-4o-mini", g
        assert g["provider"] == "openai"
        assert "hi" in g["input"] and g["output"] == "Hello there"
        assert g["inputTokens"] == 11 and g["outputTokens"] == 3
        assert g["costUsd"] > 0, "cost not auto-estimated"
        tr = next(t for t in RECEIVED["traces"] if t["traceId"] == g["traceId"])
        assert tr["name"] == "job.openai" and tr["sessionId"] == "s1"

    check("captures an OpenAI chat completion, grouped + costed", t_openai)

    def t_anthropic():
        reset()
        am = AsyncMessages()

        async def run():
            async with argus.trace("job.claude"):
                await am.create(model="claude-3-5-sonnet-20241022", system="be brief",
                                messages=[{"role": "user", "content": "hello"}])
        asyncio.run(run())
        assert wait_for(lambda: any(o["type"] == "generation" for o in RECEIVED["observations"]))
        g = next(o for o in RECEIVED["observations"] if o["type"] == "generation")
        assert g["provider"] == "anthropic" and g["output"] == "Hi from Claude"
        assert g["inputTokens"] == 9 and "be brief" in g["input"]

    check("captures an Anthropic message", t_anthropic)

    def t_standalone():
        reset()
        oc = AsyncCompletions()
        asyncio.run(oc.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "x"}]))
        assert wait_for(lambda: any(o["type"] == "generation" for o in RECEIVED["observations"]))
        g = next(o for o in RECEIVED["observations"] if o["type"] == "generation")
        assert any(t["traceId"] == g["traceId"] for t in RECEIVED["traces"]), "no standalone trace summary"

    check("a call outside any scope emits its own standalone trace", t_standalone)

    def t_grouping():
        reset()
        oc = AsyncCompletions()

        async def run():
            async with argus.trace("multi"):
                await oc.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "a"}])
                argus.retrieval("kb", "some doc", source="doc-1")
                await oc.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "b"}])
                argus.tool("send_email", input={"to": "x"}, output="ok")
        asyncio.run(run())
        assert wait_for(lambda: len(RECEIVED["observations"]) >= 4)
        types_ = sorted(o["type"] for o in RECEIVED["observations"])
        assert types_ == ["generation", "generation", "retrieval", "tool"], types_
        ids = {o["traceId"] for o in RECEIVED["observations"]}
        assert len(ids) == 1, "spans not grouped under one trace"

    check("groups generations + retrieval + tool under one trace", t_grouping)

    def t_middleware():
        reset()
        oc = AsyncCompletions()

        async def app(scope, receive, send):
            await oc.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}])
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = argus.Middleware(app)
        scope = {"type": "http", "method": "POST", "path": "/api/chat",
                 "headers": [(b"authorization", b"Bearer tok123")]}

        async def receive():
            return {"type": "http.request", "body": b""}

        async def send(msg):
            pass

        asyncio.run(mw(scope, receive, send))
        assert wait_for(lambda: RECEIVED["traces"] and RECEIVED["observations"])
        tr = RECEIVED["traces"][0]
        assert tr["name"] == "POST /api/chat", tr["name"]
        assert tr["sessionId"].startswith("s_"), "session not derived from auth header"
        g = next(o for o in RECEIVED["observations"] if o["type"] == "generation")
        assert g["traceId"] == tr["traceId"], "middleware didn't group the call"

    check("FastAPI/ASGI middleware groups a request's calls into one trace", t_middleware)

    def t_empty():
        reset()

        async def run():
            async with argus.trace("no-llm"):
                await asyncio.sleep(0.001)
        asyncio.run(run())
        time.sleep(0.3)
        assert not RECEIVED["traces"] and not RECEIVED["observations"], "emitted an empty trace"

    check("a scope with no LLM calls emits nothing", t_empty)

    def t_shape():
        # required IngestBatch fields present on a generation observation
        reset()
        oc = AsyncCompletions()
        asyncio.run(oc.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "x"}]))
        assert wait_for(lambda: any(o["type"] == "generation" for o in RECEIVED["observations"]))
        g = next(o for o in RECEIVED["observations"] if o["type"] == "generation")
        for k in ("observationId", "traceId", "type", "name", "startTime", "model",
                  "provider", "input", "output", "inputTokens", "outputTokens", "costUsd"):
            assert k in g, f"missing field {k}"
        assert isinstance(g["attributes"], dict)

    check("observation matches the Argus IngestBatch field shape", t_shape)

    argus.flush()
    srv.shutdown()
    print("\n" + (f"FAILED ({FAILS})" if FAILS else "ALL PASSED"))
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
