# What Argus Is

Argus is an AI security platform built around one idea: **the same data that
lets you debug an LLM application is the data you need to tell whether it's
being attacked.** Most tools pick one side of that — an observability tool that
records everything and understands none of it, or a guardrail that judges one
message in isolation and can't see the three steps that came before it. Argus
is both halves in one product, because the interesting attacks live in the gap
between them.

It answers two different questions, and answering both is the whole point:

- **Is this application being attacked right now?** (runtime)
- **Could this application be attacked, and can I prove I've reduced that risk?** (static)

---

## The runtime half: observability with security built in

Argus records every trace an LLM application produces — every prompt, tool
call, retrieved document, and model response — the way a conventional
observability tool (Langfuse, Datadog) would. On top of that, a layered
detection pipeline analyzes the content flowing through the application:

- **L1 — heuristics.** Eighteen deterministic rules (instruction-override
  phrasing, jailbreak patterns, role-delimiter spoofing, invisible Unicode,
  encoded blobs, homoglyph mixing) with a false-positive suppressor that
  down-weights *reported speech* — a blog post describing an attack scores
  lower than the attack itself.
- **L4 — trace analysis, the actual differentiator.** Most guardrails scan a
  single message and stop. Indirect prompt injection doesn't live in one
  message: a poisoned document gets retrieved, the agent reads it, and three
  steps later it emails your data to an attacker. Catching that requires
  seeing the *whole trace* — what was read, what happened next, whether
  behavior changed after ingesting untrusted content. L4 tracks taint
  propagation across spans, detects when a later span echoes an earlier
  untrusted instruction, and flags exfiltration flows where a side-effect
  tool's destination traces back to something the model wasn't supposed to
  trust.
- **Canary tokens** — plant a unique marker in a system prompt or document;
  if it ever appears in an output or outbound tool call, that's not a
  judgment call, it's proof.
- **An inline gateway** — an OpenAI-compatible proxy that can block
  high-confidence attacks synchronously, with a hard latency budget and
  fail-open semantics, because a security layer that takes production down
  protects nothing.
- **The Browser Guard extension** — the one piece that protects a person
  rather than an application: it scans what someone is about to paste into
  ChatGPT, Claude, Gemini and similar tools *in the browser*, before it's
  sent, and can optionally report the verdict (never the prompt text) back
  into Argus as an ordinary trace.

Findings land in Threat Center, Incidents, and a Review Queue for analyst
triage, with alerting (Slack/PagerDuty/webhook), suppression rules, and
per-project retention.

## The static half: assessing how an application is built

This is the half absorbed from a separate product (InjectGuard) that Argus
merged in whole. Where the runtime side judges live traffic, this judges the
application *as built* — before an attacker sends anything:

- **A 20-rule prompt scanner** that reads your prompt templates for
  instruction/data mixing, secrets, model-controlled authorization, and
  direct execution of model output.
- **An architecture graph analyzer** that reasons about *topology* —
  untrusted input reaching a trusted component, model output reaching an
  interpreter, a write-capable tool with no human approval gate.
- **A transparent, versioned risk score** (five factors, stored rationale,
  fully recomputable) rather than a black-box number.
- **A ranked mitigation catalog**, a **policy engine** for governance rules
  ("don't ship with an open critical finding"), **controls** tracking with
  owner and review cadence, and **downloadable reports** (executive,
  technical, governance) in PDF/Markdown/CSV/JSON.

All of it lives under one **Assessments** page with five tabs: Architecture,
Runs, Findings, Policies, Controls.

## Where the two halves meet

This is the part that only exists because both halves live in one product:

- **Traces build the architecture graph.** Instead of a human drawing the
  application's topology by hand, Argus can propose it from observed spans —
  which components exist, which handle untrusted content, how they call each
  other. (It deliberately won't guess whether a write needs human approval —
  no trace can prove that, so a person confirms it.)
- **Production evidence sharpens the risk score.** If Argus has actually
  recorded an attack class being attempted against an application, any static
  finding of that same class gets marked "seen in production" and scored at
  maximum likelihood — the difference between "this could be exploited" and
  "someone is already trying."

## What it looks like

Argus's chrome — steel ground, thin borders, squared corners — matches
ThreatClaw's own design system, so the two read as one family. Severity,
though, is deliberately loud rather than tonal: critical is red, high is
orange, medium is amber, and a critical finding carries three stacked visual
cues (a bordered pill, a thicker stripe, a faint row tint) so it's the thing
your eye catches while scrolling a long feed. Theme (light/dark/system) and
text size are both user preferences, persisted per device.

## In one sentence

Argus watches what your AI application actually does, judges how it's built,
and lets each of those inform the other — so "is this a real risk" stops being
a guess.
