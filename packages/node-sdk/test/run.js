"use strict";
// Self-contained test harness — no test framework, no network beyond localhost.
// Spins up a fake ingestion endpoint and a fake multi-provider LLM endpoint,
// drives the SDK the way a real app would (raw fetch + streaming + Anthropic +
// grouped-request), and asserts the batches that reach ingestion are correct.
//
// Run: node test/run.js   (from packages/node-sdk)

const http = require("http");
const assert = require("assert");
const { runGuarded } = require("../src/guard");

let failures = 0;
function check(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => console.log("  ✓ " + name))
    .catch((err) => {
      failures++;
      console.log("  ✗ " + name + "\n      " + (err && err.message));
    });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- fake ingestion server: records every batch it receives ----------
const received = { traces: [], observations: [], auth: null };
function startIngest() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        received.auth = req.headers.authorization || null;
        try {
          const batch = JSON.parse(body || "{}");
          for (const t of batch.traces || []) received.traces.push(t);
          for (const o of batch.observations || []) received.observations.push(o);
        } catch {}
        res.writeHead(202, { "content-type": "application/json" });
        res.end(JSON.stringify({ accepted: true }));
      });
    });
    srv.listen(0, "127.0.0.1", () => resolve(srv));
  });
}

// ---------- fake LLM server: OpenAI-compatible + Anthropic + streaming ----------
function startLlm() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const b = JSON.parse(body || "{}");
        if (req.url.includes("/messages")) {
          // Anthropic
          res.writeHead(200, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              content: [{ type: "text", text: "Hi from Claude" }],
              usage: { input_tokens: 9, output_tokens: 4 },
              stop_reason: "end_turn",
            }),
          );
          return;
        }
        // OpenAI chat completions
        if (b.stream) {
          res.writeHead(200, { "content-type": "text/event-stream" });
          const chunk = (o) => res.write("data: " + JSON.stringify(o) + "\n\n");
          chunk({ choices: [{ delta: { content: "Hel" } }] });
          chunk({ choices: [{ delta: { content: "lo!" }, finish_reason: "stop" }] });
          chunk({ choices: [{ delta: {} }], usage: { prompt_tokens: 5, completion_tokens: 2 } });
          res.write("data: [DONE]\n\n");
          res.end();
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            choices: [{ message: { role: "assistant", content: "Hello there" }, finish_reason: "stop" }],
            usage: { prompt_tokens: 11, completion_tokens: 3 },
          }),
        );
      });
    });
    srv.listen(0, "127.0.0.1", () => resolve(srv));
  });
}

async function main() {
  const ingest = await startIngest();
  const llm = await startLlm();
  const ingestUrl = `http://127.0.0.1:${ingest.address().port}/api/public/ingestion`;
  const llmBase = `http://127.0.0.1:${llm.address().port}`;

  // init AFTER servers are up; patches global fetch.
  const argus = require("../src/index.js").init({
    publicKey: "pk_test",
    secretKey: "sk_test",
    ingestUrl,
    flushIntervalMs: 50,
  });

  async function chat(bodyExtra = {}) {
    const r = await fetch(`${llmBase}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
        ...bodyExtra,
      }),
    });
    return r;
  }

  const reset = () => {
    received.traces.length = 0;
    received.observations.length = 0;
  };
  const settle = async () => {
    await argus.flush();
    await sleep(60);
    await argus.flush();
    await sleep(40);
  };

  console.log("@argus/node SDK tests\n");

  await check("captures a raw-fetch OpenAI-compatible call as a generation", async () => {
    reset();
    const r = await chat();
    // caller still gets a fully readable body
    const json = await r.json();
    assert.strictEqual(json.choices[0].message.content, "Hello there");
    await settle();
    const gen = received.observations.find((o) => o.type === "generation");
    assert.ok(gen, "no generation observation reached ingestion");
    assert.strictEqual(gen.model, "gpt-4o-mini");
    assert.ok(gen.input.includes("hi"), "input transcript missing");
    assert.strictEqual(gen.output, "Hello there");
    assert.strictEqual(gen.inputTokens, 11);
    assert.strictEqual(gen.outputTokens, 3);
    assert.ok(gen.costUsd > 0, "cost was not auto-estimated");
  });

  await check("accumulates a streaming response", async () => {
    reset();
    const r = await chat({ stream: true });
    // drain the caller's stream to prove it wasn't consumed by capture
    const text = await r.text();
    assert.ok(text.includes("Hello!") || text.includes("Hel"), "caller lost the stream");
    await settle();
    const gen = received.observations.find((o) => o.type === "generation");
    assert.ok(gen, "streaming call not captured");
    assert.strictEqual(gen.output, "Hello!");
    assert.strictEqual(gen.finishReason, "stop");
  });

  await check("captures an Anthropic /v1/messages call", async () => {
    reset();
    const r = await fetch(`${llmBase}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-20241022",
        system: "be brief",
        messages: [{ role: "user", content: "hello" }],
      }),
    });
    await r.json();
    await settle();
    const gen = received.observations.find((o) => o.type === "generation");
    assert.ok(gen, "anthropic call not captured");
    assert.strictEqual(gen.output, "Hi from Claude");
    assert.strictEqual(gen.inputTokens, 9);
    assert.ok(gen.input.includes("be brief"), "system prompt missing from input");
  });

  await check("groups multiple calls in a trace() scope under one traceId", async () => {
    reset();
    await argus.trace("job.multi", { sessionId: "sess-1", userId: "user-1" }, async () => {
      await chat();
      await chat();
    });
    await settle();
    const gens = received.observations.filter((o) => o.type === "generation");
    assert.strictEqual(gens.length, 2, `expected 2 generations, got ${gens.length}`);
    assert.strictEqual(gens[0].traceId, gens[1].traceId, "generations not grouped");
    const summary = received.traces.find((t) => t.traceId === gens[0].traceId);
    assert.ok(summary, "no trace summary emitted for the group");
    assert.strictEqual(summary.sessionId, "sess-1");
    assert.strictEqual(summary.name, "job.multi");
  });

  await check("emits a standalone trace for a call outside any scope", async () => {
    reset();
    await chat();
    await settle();
    const gen = received.observations.find((o) => o.type === "generation");
    assert.ok(gen, "standalone call not captured");
    const summary = received.traces.find((t) => t.traceId === gen.traceId);
    assert.ok(summary, "standalone call did not get its own trace summary");
  });

  await check("does NOT double-capture a guarded (SDK-layer) call", async () => {
    reset();
    await runGuarded(async () => {
      await chat();
    });
    await settle();
    const gens = received.observations.filter((o) => o.type === "generation");
    assert.strictEqual(gens.length, 0, "guarded call was captured by the fetch layer");
  });

  await check("optional retrieval() and tool() one-liners attach to the trace", async () => {
    reset();
    await argus.trace("job.rag", async () => {
      argus.retrieval("governance-kb", "policy text here", { source: "doc-42" });
      await chat();
      argus.tool("flag_for_review", { input: "{}", output: "ok" });
    });
    await settle();
    const types = received.observations.map((o) => o.type).sort();
    assert.deepStrictEqual(types, ["generation", "retrieval", "tool"], `got ${types}`);
    const ret = received.observations.find((o) => o.type === "retrieval");
    assert.strictEqual(ret.taintSource, "doc-42");
  });

  await check("SDK-level openai patch records once (guard prevents double-count)", async () => {
    reset();
    // A minimal stand-in for the `openai` package whose create() dispatches
    // through global fetch — exactly how the real SDK behaves on Node 18+.
    const Module = require("module");
    const fakeOpenAI = (() => {
      class Completions {
        constructor(base) {
          this._base = base;
        }
        async create(params) {
          const r = await fetch(this._base + "/chat/completions", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(params),
          });
          return r.json();
        }
      }
      class OpenAI {
        constructor(opts = {}) {
          this.baseURL = opts.baseURL || "https://api.openai.com/v1";
          this.chat = { completions: new Completions(this.baseURL) };
        }
      }
      return { OpenAI };
    })();

    // Intercept require('openai') just while install() runs.
    const origLoad = Module._load;
    Module._load = function (request) {
      if (request === "openai") return fakeOpenAI;
      return origLoad.apply(this, arguments);
    };
    try {
      require("../src/instrument/openai").install();
    } finally {
      Module._load = origLoad;
    }

    const client = new fakeOpenAI.OpenAI({ baseURL: `${llmBase}/v1` });
    const completion = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "hi" }],
    });
    // Caller still receives the real completion object.
    assert.strictEqual(completion.choices[0].message.content, "Hello there");
    await settle();
    const gens = received.observations.filter((o) => o.type === "generation");
    assert.strictEqual(gens.length, 1, `expected exactly 1 capture, got ${gens.length}`);
    assert.strictEqual(gens[0].output, "Hello there");
    assert.strictEqual(gens[0].model, "gpt-4o-mini");
  });

  await check("a trace scope with no LLM calls emits nothing (no empty traces)", async () => {
    reset();
    await argus.trace("request.no-llm", async () => {
      // simulate a plain request that never touches an LLM
      await sleep(1);
    });
    await settle();
    assert.strictEqual(received.traces.length, 0, "emitted an empty trace summary");
    assert.strictEqual(received.observations.length, 0, "emitted stray observations");
  });

  await check('zero-config: init("ak_live_…") sends Bearer auth', async () => {
    reset();
    const cfgMod = require("../src/config");
    const saved = cfgMod.getConfig();
    // Re-init the way a customer would: one key, no env vars, no URL.
    argus.init({ key: "ak_live_TESTTOKEN123", ingestUrl, flushIntervalMs: 50 });
    await chat();
    await settle();
    assert.strictEqual(received.auth, "Bearer ak_live_TESTTOKEN123", `got ${received.auth}`);
    const gen = received.observations.find((o) => o.type === "generation");
    assert.ok(gen, "no generation captured on the token path");
    assert.strictEqual(gen.output, "Hello there");
    cfgMod.setConfig(saved); // restore the pair-based config for later tests
  });

  await check("legacy public/secret pair still sends Basic auth", async () => {
    reset();
    await chat();
    await settle();
    assert.ok(String(received.auth || "").startsWith("Basic "), `expected Basic, got ${received.auth}`);
  });

  await check("does not send anything when keys are absent", async () => {
    // Re-init disabled in a child-like fashion: flip config to disabled.
    const cfg = require("../src/config");
    const saved = cfg.getConfig();
    cfg.setConfig({ ...saved, enabled: false });
    reset();
    await chat();
    await sleep(60);
    cfg.setConfig(saved); // restore
    assert.strictEqual(received.observations.length, 0, "sent data while disabled");
  });

  await argus.shutdown();
  ingest.close();
  llm.close();

  console.log("\n" + (failures ? `FAILED (${failures})` : "ALL PASSED"));
  process.exit(failures ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
