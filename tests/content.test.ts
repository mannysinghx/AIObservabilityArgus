/**
 * `content_sha256` is the join key for cross-trace poisoned-source correlation
 * ("this same document has now hit N traces"). It is written by the trace worker
 * and by the security worker, from what the detection client sent for scanning.
 * If any of those three disagree about which text they hashed, the Incidents
 * view matches nothing and reports "no recurring sources" — a silent false
 * negative that looks exactly like good news. One shared function; these tests
 * pin its contract.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { contentOf, contentSha256, sha256Hex } from "@argus/shared";

test("generation and retrieval hash the produced text", () => {
  assert.equal(contentOf({ type: "generation", input: "prompt", output: "completion" }), "completion");
  assert.equal(contentOf({ type: "retrieval", input: "query", output: "chunk" }), "chunk");
});

test("generation falls back to input when there is no output", () => {
  assert.equal(contentOf({ type: "generation", input: "prompt", output: "" }), "prompt");
});

test("tool spans include arguments as well as results", () => {
  // Exfiltration lives in the *arguments* — the recipient address, the URL, the
  // body. A result-only view of a send_email span sees "ok" and nothing else.
  const span = { type: "tool", input: "to=attacker@evil.com", output: "sent" };
  assert.equal(contentOf(span), "to=attacker@evil.com\nsent");
  assert.match(contentOf(span), /attacker@evil\.com/);
});

test("identical content produces identical hashes across span shapes", () => {
  // The correlation query groups by this value, so two retrievals of the same
  // poisoned document must collide regardless of surrounding metadata.
  const a = { type: "retrieval", input: "q1", output: "POISONED DOCUMENT BODY" };
  const b = { type: "retrieval", input: "totally different query", output: "POISONED DOCUMENT BODY" };
  assert.equal(contentSha256(a), contentSha256(b));
});

test("different content produces different hashes", () => {
  const a = { type: "retrieval", output: "doc one" };
  const b = { type: "retrieval", output: "doc two" };
  assert.notEqual(contentSha256(a), contentSha256(b));
});

test("empty content hashes to the empty string, not to a shared constant", () => {
  // The Incidents query filters `content_sha256 != ''`. If contentless spans all
  // hashed to sha256("") they would form one enormous fake "recurring source"
  // group and bury the real ones.
  assert.equal(contentSha256({ type: "span" }), "");
  assert.equal(contentSha256({ type: "span", input: "", output: "" }), "");
  assert.notEqual(contentSha256({ type: "span" }), sha256Hex(""));
});

test("hash is a stable lowercase hex sha256", () => {
  assert.equal(
    sha256Hex("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
  assert.match(contentSha256({ type: "tool", input: "x" }), /^[0-9a-f]{64}$/);
});
