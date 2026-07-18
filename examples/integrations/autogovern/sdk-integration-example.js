"use strict";
/**
 * Worked example: the SAME "Contract Risk Review" workflow as
 * express-integration-example.js, but wired with the drop-in @argus/node SDK
 * instead of the hand-rolled tracer.
 *
 * Compare the two files side by side. With the SDK:
 *   - setup is two lines for the whole app (init + middleware), not a tracer
 *     file copied into your repo;
 *   - the multi-provider LLM call is captured AUTOMATICALLY — no
 *     recordGeneration(), no token/cost bookkeeping, no startedAt plumbing;
 *   - only retrieval and tool spans (which can't be auto-detected) remain, as
 *     optional one-liners that attach to the request's trace on their own —
 *     there's no trace object to thread through your functions.
 *
 * This is the recommended integration for autogovern.io. The manual tracer in
 * argus-tracer.js stays supported as a zero-dependency alternative.
 */

const express = require("express");

// 1) One line, at the top of your entry file — reads ARGUS_PUBLIC_KEY /
//    ARGUS_SECRET_KEY / ARGUS_INGEST_URL from the environment.
const argus = require("@argus/node").init();

const app = express();
app.use(express.json());

// 2) One line — every request becomes a trace, and every LLM call made during
//    that request is grouped into it automatically. The getters below map
//    autogovern.io's session/user onto the trace; both are optional.
app.use(
  argus.middleware({
    getSessionId: (req) => req.session && req.session.id,
    getUserId: (req) => req.user && req.user.id,
  }),
);

// ---- stand-ins for autogovern.io's real helpers (unchanged from the manual
//      example, so the diff is purely the tracer wiring) -------------------

async function fetchPolicyDocument(pool, contractType) {
  const { rows } = await pool.query(
    "SELECT id, body FROM governance_policies WHERE contract_type = $1 ORDER BY updated_at DESC LIMIT 1",
    [contractType],
  );
  return rows[0]; // { id, body }
}

async function callLlmChain(prompt) {
  // GLM/Z.ai -> DeepSeek -> Gemini -> OpenAI -> Anthropic fallback chain via
  // plain fetch to OpenAI-compatible endpoints. Argus captures this call
  // automatically — no tracer code here at all.
  const res = await fetch("https://api.z.ai/v1/chat/completions", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${process.env.GLM_API_KEY}`,
    },
    body: JSON.stringify({
      model: "glm-4",
      messages: [{ role: "user", content: prompt }],
    }),
  });
  const data = await res.json();
  return { text: data.choices[0].message.content };
}

async function runWorkbenchTool(toolName, args) {
  if (toolName === "flag_for_review") {
    return { flagged: true, reviewer: "compliance-team@autogovern.io" };
  }
  throw new Error(`unknown tool ${toolName}`);
}

// ---- the route, instrumented with the SDK ------------------------------

app.post("/api/workbench/contract-review", async (req, res) => {
  const { contractType, contractText, contractId } = req.body;

  try {
    // RAG retrieval — the highest-risk step. Retrieval can't be auto-detected,
    // so this optional one-liner records it. It attaches to THIS request's
    // trace on its own (via async context), and defaults to untrusted_external
    // taint — exactly what indirect-injection detection watches.
    const policy = await fetchPolicyDocument(req.db, contractType);
    argus.retrieval("governance-policy-kb", policy.body, {
      source: `policy:${policy.id}`,
    });

    // The LLM call. NOTE: there is no tracer call here — the fetch() inside
    // callLlmChain is captured automatically, with model, prompt, completion,
    // token counts and (auto-estimated) cost.
    const prompt = `Policy:\n${policy.body}\n\nContract:\n${contractText}\n\nAssess risk level and recommend an action.`;
    const result = await callLlmChain(prompt);

    // Tool call — its result is untrusted content too. Optional one-liner.
    const toolArgs = { contractId, riskAssessment: result.text };
    const toolResult = await runWorkbenchTool("flag_for_review", toolArgs);
    argus.tool("flag_for_review", { input: toolArgs, output: toolResult });

    res.json({ risk: result.text, action: toolResult });
    // No trace.finish() — argus.middleware() closes the trace when the response
    // finishes. (On serverless, add `await argus.flush()` before responding.)
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = app;
