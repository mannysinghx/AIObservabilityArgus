"use strict";
// Wire-shape parsers. These turn a provider's HTTP request/response — OpenAI
// chat completions, OpenAI Responses, Anthropic Messages — into the neutral
// generation record the tracer stores. Everything here is defensive: a malformed
// or unexpected body must return best-effort partial data, never throw.

// ---------- provider / endpoint detection ----------

const HOST_PROVIDER = [
  [/(^|\.)openai\.com$/, "openai"],
  [/(^|\.)anthropic\.com$/, "anthropic"],
  [/(^|\.)deepseek\.com$/, "deepseek"],
  [/generativelanguage\.googleapis\.com$/, "google"],
  [/(^|\.)z\.ai$/, "zhipu"],
  [/(^|\.)bigmodel\.cn$/, "zhipu"],
  [/(^|\.)mistral\.ai$/, "mistral"],
  [/(^|\.)groq\.com$/, "groq"],
  [/(^|\.)perplexity\.ai$/, "perplexity"],
  [/(^|\.)x\.ai$/, "xai"],
];

function providerFromUrl(url) {
  try {
    const host = new URL(url).host.toLowerCase();
    for (const [re, name] of HOST_PROVIDER) if (re.test(host)) return name;
    return host.split(":")[0];
  } catch {
    return "";
  }
}

/**
 * Classify a request by URL + parsed body. Returns one of:
 *   "openai-chat" | "openai-responses" | "anthropic-messages" | null
 * null means "not an LLM call we know how to capture" — pass it through.
 */
function classify(url, body) {
  const u = String(url || "");
  if (/\/chat\/completions\b/.test(u)) return "openai-chat";
  if (/\/responses\b/.test(u)) return "openai-responses";
  if (/\/v1\/messages\b/.test(u) || /\/messages\b/.test(u) && looksAnthropic(body))
    return "anthropic-messages";
  // Fall back to body shape for OpenAI-compatible endpoints on nonstandard paths.
  if (body && Array.isArray(body.messages) && body.model) {
    // Anthropic bodies also have messages+model; disambiguate on max_tokens +
    // the absence of an OpenAI-only field. Default to openai-chat, which is by
    // far the more common raw-fetch case.
    return "openai-chat";
  }
  return null;
}

function looksAnthropic(body) {
  return Boolean(
    body && Array.isArray(body.messages) && (body.system !== undefined || body.anthropic_version),
  );
}

// ---------- content flattening ----------

/** Turn a message's `content` (string | array of parts) into plain text. */
function contentToText(content) {
  if (content == null) return "";
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((p) => {
        if (typeof p === "string") return p;
        if (p == null) return "";
        if (typeof p.text === "string") return p.text;
        if (p.type === "image_url" || p.type === "image") return "[image]";
        if (p.type === "input_text" && typeof p.text === "string") return p.text;
        return "";
      })
      .filter(Boolean)
      .join("\n");
  }
  if (typeof content === "object" && typeof content.text === "string")
    return content.text;
  return "";
}

/** Serialize an array of chat messages into a readable transcript string. */
function messagesToText(messages, system) {
  const lines = [];
  if (system) lines.push("system: " + (typeof system === "string" ? system : contentToText(system)));
  for (const m of messages || []) {
    if (!m) continue;
    lines.push((m.role || "user") + ": " + contentToText(m.content));
  }
  return lines.join("\n");
}

// ---------- request parsers ----------

function parseRequest(kind, body) {
  try {
    if (kind === "anthropic-messages") {
      return {
        model: body.model || "",
        input: messagesToText(body.messages, body.system),
        stream: body.stream === true,
      };
    }
    if (kind === "openai-responses") {
      const input =
        typeof body.input === "string"
          ? body.input
          : messagesToText(Array.isArray(body.input) ? body.input : [], body.instructions);
      return { model: body.model || "", input, stream: body.stream === true };
    }
    // openai-chat (and OpenAI-compatible)
    return {
      model: body.model || "",
      input: messagesToText(body.messages),
      stream: body.stream === true,
    };
  } catch {
    return { model: (body && body.model) || "", input: "", stream: false };
  }
}

// ---------- non-streaming response parsers ----------

function parseResponse(kind, json) {
  try {
    if (kind === "anthropic-messages") {
      const output = Array.isArray(json.content)
        ? json.content.map((b) => (b && typeof b.text === "string" ? b.text : "")).filter(Boolean).join("\n")
        : "";
      const u = json.usage || {};
      return {
        output,
        inputTokens: u.input_tokens || 0,
        outputTokens: u.output_tokens || 0,
        finishReason: json.stop_reason || "",
      };
    }
    if (kind === "openai-responses") {
      const u = json.usage || {};
      let output = json.output_text || "";
      if (!output && Array.isArray(json.output)) {
        output = json.output
          .map((item) => (item && Array.isArray(item.content) ? contentToText(item.content) : ""))
          .filter(Boolean)
          .join("\n");
      }
      return {
        output,
        inputTokens: u.input_tokens || 0,
        outputTokens: u.output_tokens || 0,
        finishReason: "",
      };
    }
    // openai-chat
    const choice = (json.choices && json.choices[0]) || {};
    const msg = choice.message || {};
    let output = contentToText(msg.content);
    if (!output && msg.tool_calls) output = JSON.stringify(msg.tool_calls);
    const u = json.usage || {};
    return {
      output,
      inputTokens: u.prompt_tokens || 0,
      outputTokens: u.completion_tokens || 0,
      finishReason: choice.finish_reason || "",
    };
  } catch {
    return { output: "", inputTokens: 0, outputTokens: 0, finishReason: "" };
  }
}

// ---------- streaming (SSE) accumulation ----------

/**
 * Fold a full SSE stream body (as one decoded string) into a response record.
 * Handles OpenAI chat deltas and Anthropic message deltas. Token counts appear
 * only if the caller enabled usage in the stream; otherwise they stay 0.
 */
function parseStream(kind, sseText) {
  const events = sseText
    .split(/\n\n/)
    .map((block) =>
      block
        .split(/\n/)
        .filter((l) => l.startsWith("data:"))
        .map((l) => l.slice(5).trim())
        .join(""),
    )
    .filter((d) => d && d !== "[DONE]");

  let output = "";
  let inputTokens = 0;
  let outputTokens = 0;
  let finishReason = "";

  for (const raw of events) {
    let json;
    try {
      json = JSON.parse(raw);
    } catch {
      continue;
    }
    if (kind === "anthropic-messages") {
      if (json.type === "message_start" && json.message && json.message.usage)
        inputTokens = json.message.usage.input_tokens || inputTokens;
      if (json.type === "content_block_delta" && json.delta && typeof json.delta.text === "string")
        output += json.delta.text;
      if (json.type === "message_delta") {
        if (json.usage && json.usage.output_tokens) outputTokens = json.usage.output_tokens;
        if (json.delta && json.delta.stop_reason) finishReason = json.delta.stop_reason;
      }
    } else {
      // openai chat/completions streaming
      const choice = (json.choices && json.choices[0]) || {};
      const delta = choice.delta || {};
      if (typeof delta.content === "string") output += delta.content;
      if (choice.finish_reason) finishReason = choice.finish_reason;
      if (json.usage) {
        inputTokens = json.usage.prompt_tokens || inputTokens;
        outputTokens = json.usage.completion_tokens || outputTokens;
      }
    }
  }
  return { output, inputTokens, outputTokens, finishReason };
}

module.exports = {
  providerFromUrl,
  classify,
  parseRequest,
  parseResponse,
  parseStream,
  contentToText,
  messagesToText,
};
