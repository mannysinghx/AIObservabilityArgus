# 01 — Vision & Scope

## Problem statement

LLM applications in production face two intertwined problems:

1. **Opacity.** Multi-step agents, RAG pipelines, and tool-calling chains fail
   in ways that are invisible without tracing. This is largely solved by the
   observability ecosystem (Langfuse, Phoenix, OpenLLMetry, LangSmith).

2. **A new attack surface.** Prompt injection is the #1 risk in the
   [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
   (LLM01), and **indirect** prompt injection — malicious instructions hidden
   in content the model *reads* (web pages, retrieved documents, emails, tool
   outputs, MCP results) — is the hardest variant because the attacker never
   touches the chat interface. Existing guardrail tools inspect single
   messages; they cannot see the *sequence* of events that constitutes an
   indirect attack.

**The insight:** the data needed to detect indirect prompt injection —
complete traces of what the model read and what it did next — already lives in
the observability layer. A platform that owns the trace store can do security
analysis no standalone guardrail can.

## What Argus is

An open-source, self-hostable platform that provides:

### Observability (table stakes — parity with Langfuse core)

- Distributed tracing of LLM apps: traces, spans, generations, tool calls,
  retrievals, agent steps.
- Ingestion via **OpenTelemetry GenAI semantic conventions** (OTLP), so any
  existing instrumentation (Langfuse SDKs, OpenLLMetry/Traceloop, OpenInference,
  MLflow, vendor SDKs) works with zero or minimal changes.
- Token usage, cost, and latency analytics.
- Prompt management (versioned prompts, deployment labels).
- Evaluations: LLM-as-judge, human annotation queues, datasets, scores.

### Security (the differentiator)

- **Detection pipeline** that scores every ingested span and trace:
  - Direct prompt injection & jailbreak detection (user inputs).
  - Indirect prompt injection detection (retrieved chunks, tool/function
    outputs, web content, MCP tool results).
  - Output-side detection: data leakage, canary-token exfiltration, PII
    egress, insecure output patterns.
  - **Trace-level behavioral analysis**: did the agent's actions deviate
    after ingesting untrusted content? (See
    [04 — Security Detection Engine](04-security-detection-engine.md).)
- **Taint tracking**: spans carrying untrusted content are marked at
  instrumentation time or inferred at ingestion; taint propagates through the
  trace graph.
- **Security dashboard**: attack feed, severity triage, incident timelines
  rendered over the trace view, attacker session clustering.
- **Alerting**: webhooks, Slack, email, PagerDuty on high-severity events.
- **Optional gateway mode**: an inline proxy that can *block* (not just
  observe) using the same detection engines, for teams that want prevention.
- **Continuous red-teaming**: scheduled garak/promptfoo scans against your
  app with results tracked as security regressions over time.

## Differentiators vs. the field

| | Langfuse / Phoenix | LLM Guard / Prompt Guard / NeMo Guardrails | **Argus** |
|---|---|---|---|
| Full trace observability | ✅ | ❌ | ✅ |
| Per-message injection scanning | ❌ (basic eval hooks only) | ✅ | ✅ |
| **Cross-span indirect-injection detection** | ❌ | ❌ | ✅ |
| Taint tracking through trace graph | ❌ | ❌ | ✅ |
| Security incident UI over traces | ❌ | ❌ | ✅ |
| Continuous red-team regression | ❌ | ❌ | ✅ |
| Inline blocking (optional) | ❌ | ✅ | ✅ (gateway mode) |

Note: Langfuse documents [security & guardrails integrations](https://langfuse.com/docs/security-and-guardrails)
— but as external tools the developer wires up and logs scores from. Argus
inverts this: detection runs inside the platform, on every trace, by default.

## Target users

1. **AI platform / MLOps engineers** operating LLM apps who need one pane of
   glass for behavior *and* threats.
2. **Security engineers / AppSec teams** who are being asked to "secure the
   AI stuff" and have no tooling that speaks their language (alerts,
   severities, incidents, MITRE ATLAS mapping).
3. **Compliance-driven teams** (EU AI Act, SOC 2, internal AI governance)
   needing audit trails of model inputs/outputs plus evidence of security
   monitoring.

## Non-goals (v1)

- **Not a model-training or fine-tuning platform.**
- **Not a general APM.** We consume OTel but only model GenAI workloads.
- **Not a replacement for application-level authorization.** We detect and
  alert; least-privilege tool design remains the app's job. (We *surface*
  over-privileged tool usage, we don't enforce it in v1.)
- **No proprietary detection models in the core.** Everything in the OSS core
  must run on open weights / open code. (A future cloud offering may add
  proprietary models — standard open-core play.)
- **Gateway (blocking) mode is optional and later-phase.** The async
  observe-and-alert pipeline is the MVP; inline blocking adds latency and
  failure-mode risk and comes after detection quality is proven.

## Guiding principles

1. **OTel-native or bust.** Never invent a proprietary trace format. Ingest
   OTLP with GenAI semantic conventions; extend via `argus.*` attributes only
   where the conventions have no equivalent (e.g., taint labels).
2. **Detection is layered and cheap-first.** Millisecond heuristics run on
   everything; expensive LLM-judge analysis runs only on what earlier layers
   escalate. Cost of detection must stay a small fraction of the cost of the
   traffic being observed.
3. **Every alert links to a trace.** No context-free alerts. An analyst must
   be able to go from "injection detected" to the exact span, the offending
   content, and everything the agent did afterward, in two clicks.
4. **False-positive budget is a product feature.** Tunable thresholds,
   per-source suppression rules, and feedback loops (analyst marks
   false-positive → threshold/corpus updates) are designed in from day one.
5. **Self-hosting is first-class.** Single `docker compose up` for
   evaluation; Helm chart for production. Same as Langfuse's playbook.
