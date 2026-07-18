"use strict";
// The Trace object: an in-memory buffer of observations for one logical run
// (usually one HTTP request), plus the metadata for the trace summary. Field
// names and shapes here match packages/shared IngestBatch exactly — this is the
// contract the ingestion endpoint validates against.

const crypto = require("crypto");
const { getConfig } = require("./config");
const { estimateCost } = require("./pricing");
const { enqueueTrace, enqueueObservations } = require("./transport");

function newId(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

function iso(d) {
  return (d instanceof Date ? d : new Date(d)).toISOString();
}

/** Coerce an arbitrary value to the string the content fields expect. */
function toText(v) {
  if (v == null) return "";
  if (typeof v === "string") return v;
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

/** attributes must be Record<string,string> per the ingestion schema. */
function stringMap(obj) {
  const out = {};
  if (!obj || typeof obj !== "object") return out;
  for (const [k, v] of Object.entries(obj)) {
    if (v == null) continue;
    out[k] = typeof v === "string" ? v : toText(v);
  }
  return out;
}

class Trace {
  constructor(name, meta = {}) {
    const cfg = getConfig();
    this.traceId = meta.traceId || newId("tr");
    this.name = name || "request";
    this.meta = meta;
    this.startedAt = new Date();
    this.observations = [];
    this.finished = false;
    this.environment =
      meta.environment || (cfg && cfg.environment) || "production";
  }

  /**
   * Record a retrieval (RAG fetch, search result, any external content).
   * Defaults to untrusted_external taint via the observation type — exactly the
   * classification indirect-injection detection depends on.
   */
  retrieval(name, text, opts = {}) {
    const t = new Date();
    this.observations.push({
      observationId: newId("obs"),
      traceId: this.traceId,
      parentId: opts.parentId || "",
      type: "retrieval",
      name: name || "retrieval",
      startTime: iso(opts.startTime || t),
      endTime: iso(opts.endTime || t),
      output: toText(text),
      taintSource: opts.source || name || "retrieval",
      attributes: stringMap(opts.attributes),
    });
    return this;
  }

  /** Record one LLM call. Cost is auto-estimated from model+tokens if omitted. */
  generation(name, opts = {}) {
    const end = opts.endTime ? new Date(opts.endTime) : new Date();
    const inputTokens = opts.inputTokens || 0;
    const outputTokens = opts.outputTokens || 0;
    const model = opts.model || "";
    const costUsd =
      opts.costUsd != null
        ? opts.costUsd
        : estimateCost(model, inputTokens, outputTokens);
    this.observations.push({
      observationId: newId("obs"),
      traceId: this.traceId,
      parentId: opts.parentId || "",
      type: "generation",
      name: name || "generation",
      startTime: iso(opts.startTime || end),
      endTime: iso(end),
      model,
      provider: opts.provider || "",
      role: "assistant",
      input: toText(opts.input),
      output: toText(opts.output),
      inputTokens,
      outputTokens,
      costUsd,
      finishReason: opts.finishReason || "",
      attributes: stringMap(opts.attributes),
    });
    return this;
  }

  /** Record a tool / function-call result. Tool output is untrusted by default. */
  tool(name, opts = {}) {
    const t = new Date();
    this.observations.push({
      observationId: newId("obs"),
      traceId: this.traceId,
      parentId: opts.parentId || "",
      type: "tool",
      name: name || "tool",
      startTime: iso(opts.startTime || t),
      endTime: iso(opts.endTime || t),
      input: toText(opts.input),
      output: toText(opts.output),
      taintSource: opts.source || name || "tool",
      attributes: stringMap(opts.attributes),
    });
    return this;
  }

  /** A generic step — e.g. the top-level request handler as the root row. */
  span(name, opts = {}) {
    const t = new Date();
    this.observations.push({
      observationId: newId("obs"),
      traceId: this.traceId,
      parentId: opts.parentId || "",
      type: "span",
      name: name || "span",
      startTime: iso(opts.startTime || this.startedAt),
      endTime: iso(opts.endTime || t),
      input: toText(opts.input),
      output: toText(opts.output),
      role: opts.role || "",
      attributes: stringMap(opts.attributes),
    });
    return this;
  }

  /**
   * Push whatever has been buffered so far without ending the trace. Auto-called
   * incrementally so long-running requests still stream data; the observations
   * go out immediately, the trace summary waits for finish().
   */
  flushObservations() {
    if (!this.observations.length) return;
    const pending = this.observations;
    this.observations = [];
    enqueueObservations(pending);
  }

  /**
   * Emit the trace summary. This is the signal that triggers Argus's L4
   * trace-level analysis. Safe to call more than once (idempotent) — the
   * middleware calls it on response finish; a manual caller may also call it.
   */
  finish(extra = {}) {
    this.flushObservations();
    if (this.finished) return;
    this.finished = true;
    const meta = this.meta;
    enqueueTrace({
      traceId: this.traceId,
      name: this.name,
      sessionId: meta.sessionId || "",
      userId: meta.userId || "",
      timestamp: iso(this.startedAt),
      environment: this.environment,
      release: meta.release || "",
      metadata: stringMap(meta.metadata),
      tags: Array.isArray(meta.tags) ? meta.tags : [],
      ...extra,
    });
  }
}

module.exports = { Trace, newId };
