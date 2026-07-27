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
 *   "openai-chat" | "openai-responses" | "anthropic-messages" |
 *   "google-generate" | null
 * null means "not an LLM call we know how to capture" — pass it through.
 */
function classify(url, body) {
  const u = String(url || "");
  if (/\/chat\/completions\b/.test(u)) return "openai-chat";
  if (/\/responses\b/.test(u)) return "openai-responses";
  if (/\/v1\/messages\b/.test(u) || /\/messages\b/.test(u) && looksAnthropic(body))
    return "anthropic-messages";
  // Google Gemini's native API — `@google/generative-ai` and raw fetch both hit
  // /v1beta/models/<model>:generateContent. Nothing about it looks like the
  // OpenAI shape: the model is in the path, and the turns live in `contents`
  // rather than `messages`, so the body-shape fallback below never matches it.
  if (/:(stream)?generateContent\b/i.test(u) || (body && Array.isArray(body.contents)))
    return "google-generate";
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

/**
 * Gemini's `parts` are the equivalent of OpenAI's content array: an array of
 * {text} objects, possibly with inline media we summarize rather than store.
 */
function googlePartsToText(parts) {
  if (!Array.isArray(parts)) return contentToText(parts);
  return parts
    .map((p) => {
      if (typeof p === "string") return p;
      if (p == null) return "";
      if (typeof p.text === "string") return p.text;
      if (p.inlineData || p.fileData) return "[media]";
      if (p.functionCall) return JSON.stringify(p.functionCall);
      if (p.functionResponse) return JSON.stringify(p.functionResponse);
      return "";
    })
    .filter(Boolean)
    .join("\n");
}

/**
 * Serialize Gemini's `contents` into the same transcript format the other
 * providers produce. `systemInstruction` is a bare Content (or plain string)
 * that sits outside the turn list, so it's prefixed the way `system:` is for
 * Anthropic — detection reads these transcripts, and it must not have to care
 * which provider produced one.
 */
function googleContentsToText(contents, systemInstruction) {
  const lines = [];
  if (systemInstruction) {
    const sys =
      typeof systemInstruction === "string"
        ? systemInstruction
        : googlePartsToText(systemInstruction.parts);
    if (sys) lines.push("system: " + sys);
  }
  for (const c of contents || []) {
    if (!c) continue;
    lines.push((c.role || "user") + ": " + googlePartsToText(c.parts));
  }
  return lines.join("\n");
}

/** Gemini puts the model in the path: /v1beta/models/<model>:generateContent */
function modelFromGoogleUrl(url) {
  const m = /\/models\/([^/:?#]+)/.exec(String(url || ""));
  return m ? m[1] : "";
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

/**
 * `url` is optional and only consulted for providers that put the model in the
 * path (Gemini). Callers that already hold a parsed request body — the SDK-level
 * openai/anthropic patches — can keep passing two arguments.
 */
function parseRequest(kind, body, url) {
  try {
    if (kind === "google-generate") {
      return {
        model: modelFromGoogleUrl(url) || body.model || "",
        input: googleContentsToText(body.contents, body.systemInstruction),
        // Gemini signals streaming in the path, not the body.
        stream: /:streamGenerateContent\b/i.test(String(url || "")),
      };
    }
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
    if (kind === "google-generate") {
      const cand = (json.candidates && json.candidates[0]) || {};
      const u = json.usageMetadata || {};
      return {
        output: googlePartsToText(cand.content && cand.content.parts),
        inputTokens: u.promptTokenCount || 0,
        outputTokens: u.candidatesTokenCount || 0,
        finishReason: cand.finishReason || "",
      };
    }
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
    } else if (kind === "google-generate") {
      // Each SSE event is a whole GenerateContentResponse carrying the next
      // slice of text (only present with ?alt=sse, which is what the Google SDK
      // uses; the bare JSON-array streaming form yields no events here).
      const cand = (json.candidates && json.candidates[0]) || {};
      output += googlePartsToText(cand.content && cand.content.parts);
      if (cand.finishReason) finishReason = cand.finishReason;
      if (json.usageMetadata) {
        inputTokens = json.usageMetadata.promptTokenCount || inputTokens;
        outputTokens = json.usageMetadata.candidatesTokenCount || outputTokens;
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
  googlePartsToText,
  googleContentsToText,
  modelFromGoogleUrl,
};
