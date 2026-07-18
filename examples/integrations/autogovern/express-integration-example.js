"use strict";
/**
 * Worked example: wiring the Argus tracer into autogovern.io's "Contract Risk
 * Review" workflow — one route in the 20-tool Governance Workbench.
 *
 * This mirrors the real shape of the app as described:
 *   - Express 5 route handler
 *   - RAG: fetches a governance/compliance policy document from Postgres
 *   - Multi-provider LLM chain: tries GLM/Z.ai first, falls back through
 *     DeepSeek -> Gemini -> OpenAI -> Anthropic, called via plain fetch to
 *     OpenAI-compatible endpoints (Anthropic via @anthropic-ai/sdk)
 *   - Governance Workbench tool call: flag_for_review (one of the 20 tools)
 *
 * Only the tracer calls are new; everything else is a plausible stand-in for
 * autogovern.io's actual server.js logic so you can see exactly where the
 * three recordX() calls slot into code that already exists.
 *
 * NOTE: This is the manual, zero-dependency approach. For most apps the drop-in
 * @argus/node SDK is simpler — it captures LLM calls automatically, so you only
 * write the retrieval/tool one-liners. See sdk-integration-example.js for the
 * same workflow wired that way. This file remains supported for teams who'd
 * rather not add a dependency.
 */

const express = require("express");
const { startTrace } = require("./argus-tracer");

const router = express.Router();

// ---- stand-ins for autogovern.io's real helpers -----------------------
// In the real app these live in server.js / engines/*.js. Signatures shown
// so the tracer calls below line up with real return values.

async function fetchPolicyDocument(pool, contractType) {
  // Real app: raw parameterized SQL against the governance policy table.
  const { rows } = await pool.query(
    "SELECT id, body FROM governance_policies WHERE contract_type = $1 ORDER BY updated_at DESC LIMIT 1",
    [contractType],
  );
  return rows[0]; // { id, body }
}

async function callLlmChain(prompt) {
  // Real app: GLM/Z.ai -> DeepSeek -> Gemini -> OpenAI -> Anthropic fallback
  // chain via fetch()/@anthropic-ai/sdk. Whichever provider actually answers
  // is what you report to the tracer, not the whole attempted list.
  const started = new Date();
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
  return {
    provider: "zhipu",
    model: "glm-4",
    text: data.choices[0].message.content,
    inputTokens: data.usage.prompt_tokens,
    outputTokens: data.usage.completion_tokens,
    startedAt: started,
  };
}

async function runWorkbenchTool(toolName, args) {
  // Real app: dispatches into one of the 20 Governance Workbench tool
  // handlers (flag_for_review, approve_contract, send_notification, ...).
  if (toolName === "flag_for_review") {
    // e.g. writes an audit_log row + notifies a reviewer.
    return { flagged: true, reviewer: "compliance-team@autogovern.io" };
  }
  throw new Error(`unknown tool ${toolName}`);
}

// ---- the actual route, instrumented ------------------------------------

router.post("/api/workbench/contract-review", async (req, res) => {
  const { contractType, contractText } = req.body;

  const trace = startTrace("workbench.contract_review", {
    sessionId: req.session?.id,
    userId: req.user?.id,
    environment: process.env.NODE_ENV || "production",
    tags: ["governance-workbench", "contract-review"],
  });

  try {
    // 1. RAG: retrieve the governing compliance policy. This is the
    //    highest-risk step in the whole flow — the policy text comes from
    //    your database, but if anything upstream (an admin UI, a bulk
    //    import, a compromised editor account) ever wrote attacker content
    //    into a policy row, this is where it enters the trace. Argus
    //    classifies retrieval spans as untrusted_external by default, so it
    //    watches this step even though your own DB "should" be trusted.
    const policy = await fetchPolicyDocument(req.db, contractType);
    trace.recordRetrieval("governance-policy-kb", policy.body, {
      source: `policy:${policy.id}`,
    });

    // 2. Multi-provider LLM call: ask the model to assess risk against the
    //    retrieved policy + the submitted contract text.
    const prompt = `Policy:\n${policy.body}\n\nContract:\n${contractText}\n\nAssess risk level and recommend an action.`;
    const result = await callLlmChain(prompt);
    trace.recordGeneration("risk_assessment", {
      model: result.model,
      provider: result.provider,
      promptText: prompt,
      outputText: result.text,
      inputTokens: result.inputTokens,
      outputTokens: result.outputTokens,
      startedAt: result.startedAt,
    });

    // 3. Governance Workbench tool call: act on the model's recommendation.
    //    This is the second high-risk step — if the policy document
    //    (untrusted) managed to steer the model's output (step 2), this is
    //    where that influence turns into a real side effect.
    const toolArgs = { contractId: req.body.contractId, riskAssessment: result.text };
    const toolResult = await runWorkbenchTool("flag_for_review", toolArgs);
    trace.recordTool("flag_for_review", {
      input: JSON.stringify(toolArgs),
      output: JSON.stringify(toolResult),
    });

    await trace.finish();
    res.json({ risk: result.text, action: toolResult });
  } catch (err) {
    await trace.finish(); // still send whatever we captured before the error
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
