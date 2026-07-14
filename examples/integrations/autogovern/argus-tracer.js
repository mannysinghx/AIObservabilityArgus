"use strict";
/**
 * Argus tracer for autogovern.io — a Node/Express monolith with:
 *   - a multi-provider LLM chain (GLM/Z.ai -> DeepSeek -> Gemini -> OpenAI ->
 *     Anthropic) called via plain fetch to OpenAI-compatible endpoints, plus
 *     @anthropic-ai/sdk for Claude directly
 *   - RAG retrieval over governance/compliance/policy documents
 *   - the 20-tool Governance Workbench (agent actions: flag_for_review,
 *     approve_contract, send_notification, write_audit_log, ...)
 *
 * This module has ZERO dependencies (matches the codebase's no-ORM,
 * raw-SQL, minimal-deps style) and never throws into your request path —
 * if Argus is unreachable, tracing is silently skipped so autogovern.io's
 * own availability is never affected by the observability layer.
 *
 * Usage (see express-integration-example.js for the full flow):
 *
 *   const { startTrace } = require('./argus-tracer');
 *
 *   app.post('/api/workbench/contract-review', async (req, res) => {
 *     const trace = startTrace('workbench.contract_review', {
 *       sessionId: req.session.id,
 *       userId: req.user?.id,
 *       environment: process.env.NODE_ENV,
 *     });
 *
 *     const policy = await fetchPolicyDoc(contractType);
 *     trace.recordRetrieval('governance-kb', policy.text, { source: policy.docId });
 *
 *     const verdict = await callLlmChain(prompt);
 *     trace.recordGeneration('risk_assessment', { model, provider, promptText: prompt, outputText: verdict.text, inputTokens, outputTokens, costUsd });
 *
 *     const toolResult = await runWorkbenchTool('flag_for_review', args);
 *     trace.recordTool('flag_for_review', { input: JSON.stringify(args), output: JSON.stringify(toolResult) });
 *
 *     await trace.finish();
 *     res.json(verdict);
 *   });
 */

const crypto = require("crypto");

const ARGUS_INGEST_URL =
  process.env.ARGUS_INGEST_URL || "http://localhost:3001/api/public/ingestion";
const ARGUS_PUBLIC_KEY = process.env.ARGUS_PUBLIC_KEY || "";
const ARGUS_SECRET_KEY = process.env.ARGUS_SECRET_KEY || "";
const ARGUS_ENABLED = Boolean(ARGUS_PUBLIC_KEY && ARGUS_SECRET_KEY);

if (!ARGUS_ENABLED) {
  // Warn once at load time rather than silently dropping every trace —
  // fire-and-forget should be quiet about *transient* failures (Argus is
  // down), not about a *permanent* misconfiguration (no keys set), which is
  // almost always a mistake worth surfacing immediately.
  console.warn(
    "[argus-tracer] ARGUS_PUBLIC_KEY/ARGUS_SECRET_KEY not set — tracing is disabled, no traces will be sent.",
  );
}

function authHeader() {
  const raw = `${ARGUS_PUBLIC_KEY}:${ARGUS_SECRET_KEY}`;
  return "Basic " + Buffer.from(raw).toString("base64");
}

function newId(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

/** Fire-and-forget POST — never rejects, never delays the caller. */
async function postBatch(batch) {
  if (!ARGUS_ENABLED) return; // tracing disabled until keys are configured
  try {
    await fetch(ARGUS_INGEST_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: authHeader(),
      },
      body: JSON.stringify(batch),
    });
  } catch (err) {
    // Never let an Argus outage affect autogovern.io. Log and move on.
    console.warn("[argus-tracer] ingestion failed (non-fatal):", err.message);
  }
}

class ArgusTrace {
  constructor(name, meta = {}) {
    this.traceId = newId("tr");
    this.name = name;
    this.meta = meta;
    this.startedAt = new Date();
    this.observations = [];
  }

  /**
   * Record a RAG retrieval. `sourceName` identifies the knowledge base or
   * document store (e.g. "governance-kb", "sec-filings-index"). `text` is the
   * full retrieved content — Argus classifies retrieval spans as untrusted
   * ("untrusted_external") by default, which is exactly right here: a policy
   * document is data your app fetched, not an instruction you trust.
   */
  recordRetrieval(sourceName, text, opts = {}) {
    const t = new Date();
    this.observations.push({
      observationId: newId("obs"),
      traceId: this.traceId,
      type: "retrieval",
      name: sourceName,
      startTime: t.toISOString(),
      endTime: t.toISOString(),
      output: text,
      taintSource: opts.source || sourceName,
      attributes: opts.attributes || {},
    });
  }

  /**
   * Record one call in the multi-provider LLM chain. Pass whichever provider
   * actually answered (after your fallback chain resolves), so cost/latency
   * analytics reflect what really happened, not just the first attempt.
   */
  recordGeneration(name, opts) {
    const t = new Date();
    this.observations.push({
      observationId: newId("obs"),
      traceId: this.traceId,
      type: "generation",
      name,
      startTime: (opts.startedAt || t).toISOString(),
      endTime: t.toISOString(),
      model: opts.model || "",
      provider: opts.provider || "",
      role: "assistant",
      input: opts.promptText || "",
      output: opts.outputText || "",
      inputTokens: opts.inputTokens || 0,
      outputTokens: opts.outputTokens || 0,
      costUsd: opts.costUsd || 0,
      finishReason: opts.finishReason || "",
    });
  }

  /**
   * Record one Governance Workbench tool invocation. `toolName` should match
   * the tool's identity in your workbench registry (e.g. "flag_for_review",
   * "approve_contract", "send_notification"). Like retrieval spans, tool
   * spans default to untrusted — this matters because a tool's *result* can
   * carry attacker content just as easily as a retrieved document can.
   */
  recordTool(toolName, opts = {}) {
    const t = new Date();
    this.observations.push({
      observationId: newId("obs"),
      traceId: this.traceId,
      type: "tool",
      name: toolName,
      startTime: (opts.startedAt || t).toISOString(),
      endTime: t.toISOString(),
      input: opts.input || "",
      output: opts.output || "",
      taintSource: toolName,
    });
  }

  /**
   * Record a generic step (e.g. the top-level request handler) if you want
   * it to show up as the root row in the trace waterfall.
   */
  recordSpan(name, opts = {}) {
    const t = new Date();
    this.observations.push({
      observationId: newId("obs"),
      traceId: this.traceId,
      type: "span",
      name,
      startTime: (opts.startedAt || this.startedAt).toISOString(),
      endTime: t.toISOString(),
      input: opts.input || "",
      output: opts.output || "",
      role: opts.role || "",
    });
  }

  /**
   * Send the trace + all buffered observations to Argus. Call this once, at
   * the end of the request — the trace-summary event is also what triggers
   * Argus's L4 trace-level behavioral analysis (taint propagation,
   * instruction-echo, exfil-flow detection across the whole request).
   */
  async finish() {
    const trace = {
      traceId: this.traceId,
      name: this.name,
      sessionId: this.meta.sessionId || "",
      userId: this.meta.userId || "",
      environment: this.meta.environment || "production",
      timestamp: this.startedAt.toISOString(),
      tags: this.meta.tags || [],
    };
    // Observations first, then the trace summary — the summary event is
    // what tells Argus's security worker "this trace is complete, run L4."
    await postBatch({ traces: [], observations: this.observations });
    await postBatch({ traces: [trace], observations: [] });
  }
}

function startTrace(name, meta) {
  return new ArgusTrace(name, meta);
}

module.exports = { startTrace, ARGUS_ENABLED };
