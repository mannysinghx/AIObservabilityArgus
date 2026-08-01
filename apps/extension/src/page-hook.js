/**
 * Argus page hook (runs in the PAGE context).
 *
 * Patches fetch, XHR, and WebSocket to observe outgoing LLM requests, extracts the prompt
 * via a provider registry, and posts it to the content script. It NEVER blocks or modifies
 * the request — the original call is forwarded immediately (zero added latency). Evaluation
 * happens asynchronously and locally in the content script.
 *
 * Coverage: OpenAI/ChatGPT, Anthropic/Claude, Google (Gemini/AI Studio), Microsoft Copilot,
 * Perplexity, Mistral (Le Chat), DeepSeek, Meta AI, Poe, Grok, HuggingChat, Groq, You.com,
 * Cohere, Pi — plus a generic deep-search fallback for anything else with a JSON/text body.
 */
(function () {
  "use strict";
  if (window.__argusBrowserGuardHooked) return;
  window.__argusBrowserGuardHooked = true;

  // ---- extraction helpers -----------------------------------------------------------
  function messagesText(msgs) {
    if (!Array.isArray(msgs)) return null;
    const out = [];
    for (const m of msgs) {
      const c = m && m.content;
      if (typeof c === "string") out.push(c);
      else if (c && Array.isArray(c.parts)) out.push(c.parts.filter((p) => typeof p === "string").join("\n"));
      else if (Array.isArray(c)) out.push(c.map((x) => (x && (x.text || x.content)) || "").join("\n"));
    }
    const t = out.join("\n").trim();
    return t || null;
  }

  function deepFindPrompt(obj, depth) {
    depth = depth || 0;
    if (!obj || depth > 7) return null;
    if (typeof obj === "string") return obj.length > 12 ? obj : null;
    if (Array.isArray(obj)) {
      let longest = null;
      for (const v of obj) {
        const r = deepFindPrompt(v, depth + 1);
        if (r && (!longest || r.length > longest.length)) longest = r;
      }
      return longest;
    }
    if (typeof obj === "object") {
      if (typeof obj.prompt === "string" && obj.prompt.length > 1) return obj.prompt;
      if (typeof obj.inputs === "string" && obj.inputs.length > 1) return obj.inputs;
      if (typeof obj.text === "string" && obj.text.length > 1 && Object.keys(obj).length <= 3) return obj.text;
      if (Array.isArray(obj.messages)) { const t = messagesText(obj.messages); if (t) return t; }
      let longest = null;
      for (const k in obj) {
        const r = deepFindPrompt(obj[k], depth + 1);
        if (r && (!longest || r.length > longest.length)) longest = r;
      }
      return longest;
    }
    return null;
  }

  // ---- provider registry: { name, match(url), extract(body, url) } -------------------
  const PROVIDERS = [
    { name: "openai", match: (u) => /(chatgpt\.com|openai\.com)\/backend-api\/.*conversation/.test(u),
      extract: (b) => messagesText(b && b.messages) },
    { name: "anthropic", match: (u) => /claude\.ai\/api\/.*(completion|append_message|messages|retry)/.test(u),
      extract: (b) => (b && typeof b.prompt === "string" ? b.prompt : messagesText(b && b.messages)) },
    { name: "huggingchat", match: (u) => /huggingface\.co\/chat\/conversation/.test(u),
      extract: (b) => (b && typeof b.inputs === "string" ? b.inputs : deepFindPrompt(b)) },
    { name: "deepseek", match: (u) => /deepseek\.com\/api\/.*(chat|completion)/.test(u),
      extract: (b) => deepFindPrompt(b) },
    { name: "mistral", match: (u) => /mistral\.ai\/(api|chat)\//.test(u),
      extract: (b) => messagesText(b && b.messages) || deepFindPrompt(b) },
    { name: "groq", match: (u) => /groq\.com\/.*(chat|completions)/.test(u),
      extract: (b) => messagesText(b && b.messages) || deepFindPrompt(b) },
    { name: "cohere", match: (u) => /cohere\.com\/.*(chat|generate)/.test(u),
      extract: (b) => (b && typeof b.message === "string" ? b.message : deepFindPrompt(b)) },
    { name: "poe", match: (u) => /poe\.com\/api/.test(u), extract: (b) => deepFindPrompt(b) },
    { name: "meta", match: (u) => /meta\.ai\//.test(u), extract: (b) => deepFindPrompt(b) },
    { name: "perplexity", match: (u) => /perplexity\.ai\//.test(u), extract: (b) => deepFindPrompt(b) },
    { name: "copilot", match: (u) => /copilot\.microsoft\.com\//.test(u), extract: (b) => deepFindPrompt(b) },
    { name: "you", match: (u) => /you\.com\//.test(u), extract: (b) => deepFindPrompt(b) },
    { name: "pi", match: (u) => /pi\.ai\//.test(u), extract: (b) => deepFindPrompt(b) },
    { name: "openai-compatible", match: (u) => /(chat\/completions|\/v1\/chat|\/api\/chat)/.test(u),
      extract: (b) => messagesText(b && b.messages) || deepFindPrompt(b) },
    { name: "google", match: (u) => /(gemini\.google\.com|aistudio\.google\.com)/.test(u),
      extract: (b) => deepFindPrompt(b) }, // Gemini uses form-encoded f.req; parseBody handles it
    { name: "generic", match: () => true, extract: (b) => deepFindPrompt(b) },
  ];

  function parseBody(bodyStr) {
    if (!bodyStr || typeof bodyStr !== "string") return null;
    try { return JSON.parse(bodyStr); } catch (_) {}
    // form-encoded (Gemini batchexecute f.req, some others)
    if (bodyStr.indexOf("=") !== -1) {
      try {
        const freq = new URLSearchParams(bodyStr).get("f.req");
        if (freq) { try { return JSON.parse(freq); } catch (_) { return { __raw: freq }; } }
      } catch (_) {}
    }
    return null;
  }

  // Public (also used by the node test): returns { provider, prompt } | null
  function extractPrompt(url, bodyStr) {
    const parsed = parseBody(bodyStr);
    if (!parsed) return null;
    for (const p of PROVIDERS) {
      if (p.match(url || "")) {
        const prompt = p.extract(parsed, url || "");
        if (prompt && String(prompt).trim().length > 1) return { provider: p.name, prompt: String(prompt) };
      }
    }
    return null;
  }

  // ---- emit with lightweight dedup --------------------------------------------------
  let lastKey = "";
  let lastAt = 0;
  function emit(url, bodyStr, channel) {
    try {
      const hit = extractPrompt(url, bodyStr);
      if (!hit) return;
      const now = Date.now();
      const key = channel + "|" + hit.prompt.slice(0, 200);
      if (key === lastKey && now - lastAt < 1500) return; // dedup rapid repeats
      lastKey = key;
      lastAt = now;
      window.postMessage(
        { __argusBrowserGuard: true, kind: "prompt", provider: hit.provider, channel: channel, url: url, prompt: hit.prompt.slice(0, 20000) },
        "*"
      );
    } catch (_) {}
  }

  // ---- patch fetch (observe only, forward unchanged) --------------------------------
  const origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function (input, init) {
      try {
        const url = typeof input === "string" ? input : input && input.url;
        const body = init && init.body;
        if (url && typeof body === "string") emit(url, body, "fetch");
      } catch (_) {}
      return origFetch.apply(this, arguments);
    };
  }

  // ---- patch XHR --------------------------------------------------------------------
  const XP = window.XMLHttpRequest && window.XMLHttpRequest.prototype;
  if (XP) {
    const origOpen = XP.open;
    const origSend = XP.send;
    XP.open = function (method, url) { this.__ig_url = url; return origOpen.apply(this, arguments); };
    XP.send = function (body) {
      try { if (this.__ig_url && typeof body === "string") emit(this.__ig_url, body, "xhr"); } catch (_) {}
      return origSend.apply(this, arguments);
    };
  }

  // ---- patch WebSocket (many chat apps stream the prompt over WS) --------------------
  const WS = window.WebSocket;
  if (WS && WS.prototype && WS.prototype.send) {
    const origWsSend = WS.prototype.send;
    WS.prototype.send = function (data) {
      try {
        if (typeof data === "string" && data.length < 100000) {
          const stripped = data.replace(/^\d+/, ""); // socket.io numeric prefix
          emit(this.url || "", stripped, "ws");
        }
      } catch (_) {}
      return origWsSend.apply(this, arguments);
    };
  }

  // Expose the pure extractor for tests (harmless in the page).
  self.__IGProviders = { extractPrompt, deepFindPrompt, parseBody };
})();
