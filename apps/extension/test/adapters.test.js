/* Tests the provider adapters in page-hook.js without a browser.
   Run: node test/adapters.test.js */
const fs = require("fs");
const path = require("path");
const vm = require("vm");

// Mock the page globals page-hook.js touches.
function XHR() {}
XHR.prototype = { open() {}, send() {} };
function WS() {}
WS.prototype = { send() {} };
const win = {
  __argusBrowserGuardHooked: false,
  fetch: function () {},
  XMLHttpRequest: XHR,
  WebSocket: WS,
  postMessage: function () {},
};
const sandbox = { window: win, self: win, URLSearchParams, Date, console };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "src", "page-hook.js"), "utf8"), sandbox);
const { extractPrompt } = win.__IGProviders;

let pass = 0, fail = 0;
function check(name, cond, got) {
  if (cond) { pass++; console.log("  ✓", name); }
  else { fail++; console.error("  ✗", name, "→ got:", JSON.stringify(got)); }
}
function ex(url, bodyObjOrStr) {
  const body = typeof bodyObjOrStr === "string" ? bodyObjOrStr : JSON.stringify(bodyObjOrStr);
  return extractPrompt(url, body);
}

console.log("adapters:");

let r = ex("https://chatgpt.com/backend-api/f/conversation", {
  messages: [{ author: { role: "user" }, content: { parts: ["hello from chatgpt"] } }],
});
check("openai extracts parts", r && r.provider === "openai" && r.prompt.includes("hello from chatgpt"), r);

r = ex("https://claude.ai/api/organizations/o/chat_conversations/c/completion", { prompt: "claude prompt text" });
check("anthropic extracts prompt", r && r.provider === "anthropic" && r.prompt.includes("claude prompt text"), r);

r = ex("https://claude.ai/api/organizations/o/chat_conversations/c/completion", {
  messages: [{ role: "user", content: "claude via messages array" }],
});
check("anthropic extracts messages[]", r && r.prompt.includes("claude via messages array"), r);

r = ex("https://huggingface.co/chat/conversation/abc", { inputs: "huggingchat inputs prompt" });
check("huggingchat extracts inputs", r && r.provider === "huggingchat" && r.prompt.includes("huggingchat inputs"), r);

r = ex("https://chat.deepseek.com/api/v0/chat/completion", { messages: [{ role: "user", content: "deepseek question here" }] });
check("deepseek extracts", r && r.provider === "deepseek" && r.prompt.includes("deepseek question"), r);

r = ex("https://api.groq.com/openai/v1/chat/completions", { messages: [{ role: "user", content: "groq playground prompt" }] });
check("groq extracts", r && r.provider === "groq" && r.prompt.includes("groq playground"), r);

r = ex("https://www.perplexity.ai/socket.io/query", { query: "perplexity long research question" });
check("perplexity extracts (ws-style body)", r && r.provider === "perplexity" && r.prompt.includes("perplexity long research"), r);

r = ex("https://chat.mistral.ai/api/chat", { messages: [{ role: "user", content: "mistral le chat prompt" }] });
check("mistral extracts", r && r.prompt.includes("mistral le chat"), r);

r = ex("https://coral.cohere.com/api/chat", { message: "cohere coral message prompt" });
check("cohere extracts message", r && r.provider === "cohere" && r.prompt.includes("cohere coral message"), r);

// Gemini: form-encoded f.req containing the prompt as nested JSON string.
const freq = JSON.stringify([null, JSON.stringify([["my gemini prompt goes here"]])]);
r = ex("https://gemini.google.com/_/BardChatUi/data/assistant/StreamGenerate", "f.req=" + encodeURIComponent(freq) + "&at=x");
check("google/gemini extracts form-encoded f.req", r && r.provider === "google" && r.prompt.includes("gemini prompt"), r);

r = ex("https://unknown.example/api/chat", { messages: [{ role: "user", content: "generic fallback works too" }] });
check("generic fallback extracts", r && r.prompt.includes("generic fallback works"), r);

r = ex("https://chatgpt.com/backend-api/me", { name: "x" });
check("non-chat request → null", r === null, r);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
