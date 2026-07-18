"use strict";
// Approximate per-token pricing so the SDK can fill in costUsd automatically —
// the client shouldn't have to compute it. Prices are USD per 1M tokens and are
// intentionally approximate: cost analytics is for spotting the expensive model,
// not for billing. Unknown models fall back to 0 (shown as "—" in the dashboard)
// rather than a wrong guess.
//
// Matched by longest known prefix, so "gpt-4.1-mini-2025-xx" resolves to the
// "gpt-4.1-mini" entry. Update as providers change pricing.

// [inputPerMillion, outputPerMillion]
const TABLE = {
  // OpenAI
  "gpt-4.1-mini": [0.4, 1.6],
  "gpt-4.1-nano": [0.1, 0.4],
  "gpt-4.1": [2.0, 8.0],
  "gpt-4o-mini": [0.15, 0.6],
  "gpt-4o": [2.5, 10.0],
  "o4-mini": [1.1, 4.4],
  "o3-mini": [1.1, 4.4],
  "o3": [2.0, 8.0],
  "gpt-4-turbo": [10.0, 30.0],
  "gpt-4": [30.0, 60.0],
  "gpt-3.5-turbo": [0.5, 1.5],
  // Anthropic
  "claude-3-5-haiku": [0.8, 4.0],
  "claude-3-haiku": [0.25, 1.25],
  "claude-3-5-sonnet": [3.0, 15.0],
  "claude-3-7-sonnet": [3.0, 15.0],
  "claude-sonnet-4": [3.0, 15.0],
  "claude-3-opus": [15.0, 75.0],
  "claude-opus-4": [15.0, 75.0],
  // DeepSeek (OpenAI-compatible)
  "deepseek-chat": [0.27, 1.1],
  "deepseek-reasoner": [0.55, 2.19],
  // Google Gemini (via OpenAI-compatible endpoints)
  "gemini-2.5-pro": [1.25, 10.0],
  "gemini-2.5-flash": [0.3, 2.5],
  "gemini-2.0-flash": [0.1, 0.4],
  "gemini-1.5-pro": [1.25, 5.0],
  "gemini-1.5-flash": [0.075, 0.3],
  // Zhipu / GLM (Z.ai, OpenAI-compatible)
  "glm-4.6": [0.6, 2.2],
  "glm-4.5": [0.6, 2.2],
  "glm-4": [0.5, 1.5],
};

// Sort keys once, longest first, so prefix matching prefers the most specific.
const KEYS = Object.keys(TABLE).sort((a, b) => b.length - a.length);

/**
 * Estimate cost in USD for a call. Returns 0 for unknown models so the SDK
 * never invents a number. Tokens default to 0 if the provider didn't report
 * usage.
 */
function estimateCost(model, inputTokens = 0, outputTokens = 0) {
  if (!model) return 0;
  const m = String(model).toLowerCase();
  const key = KEYS.find((k) => m.startsWith(k) || m.includes(k));
  if (!key) return 0;
  const [inP, outP] = TABLE[key];
  return (inputTokens / 1e6) * inP + (outputTokens / 1e6) * outP;
}

module.exports = { estimateCost, TABLE };
