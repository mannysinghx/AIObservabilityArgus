# Argus Browser Guard

A browser extension that checks what you're about to paste into ChatGPT, Claude,
Gemini, Copilot and a dozen other AI chat apps — **before** it leaves your
machine — and warns you if it contains a secret, personal data, or a prompt
someone else planted.

It is the one part of Argus that protects a *person* rather than an
*application*. Everything else on the platform watches your own AI product; this
watches your team's use of everyone else's.

## The rule that shapes everything here

**Prompt text never leaves the browser.** Scanning happens locally, in
`src/scanner-core.js`, in under a millisecond. If reporting is switched on, what
travels is the verdict only: which rules fired, how severe, which site. There is
no content field anywhere in the reporting path, and
`tests/promptEvents.test.ts` in the main repo asserts that a report built from
nothing but sensitive strings still carries none of them.

That constraint is why the extension is useful at all — nobody will install a
thing that ships their prompts to a server, least of all the security team that
would have to approve it.

## What it detects

Six deterministic rules, each an exact-match pattern rather than a judgement:

| Rule | Catches |
|---|---|
| `IG-SECRET-001` | API keys, tokens, private keys pasted into a chat box |
| `IG-PII-001` | Card numbers (Luhn-checked), and other personal identifiers |
| `IG-INJECT-001` | Instruction-override phrasing |
| `IG-EXFIL-001` | Requests to send data somewhere |
| `IG-INDIRECT-001` | Instructions embedded in pasted third-party content |
| `IG-ENCODE-001` | Base64/hex blobs hiding their contents |

The `IG-` prefix is InjectGuard's, kept deliberately: these ids are stable
identifiers that the server maps onto Argus attack categories
(`packages/shared/src/promptEvents.ts`). Renaming them would orphan every
already-stored finding.

## Installing it

1. Chrome → Extensions → enable **Developer mode** → **Load unpacked** → pick
   this folder.
2. Click the toolbar icon. It works immediately, locally, with no configuration.

## Sending verdicts to Argus (optional)

Off by default. To turn it on you need an API key from the Argus application you
want these to land under — **Manage → API Keys**, then:

1. Open the extension popup, tick **Report verdicts to Argus**.
2. Paste your ingest URL (e.g. `https://ingest.your-argus.com`).
3. Paste the key (`ak_live_…`).
4. Chrome will ask permission to talk to that host — say yes, or reporting
   silently won't send.

Reports arrive as traces in the `browser-extension` environment, with a security
event per rule that fired. They show up in Threat Center, Traces and Analytics
like anything else, and are marked `source: browser_extension` so an analyst can
tell a client's assertion from something Argus detected and can re-derive.

Verdicts batch and flush every 5 seconds (or at 20 queued). A failed post is
dropped rather than retried — a retry loop in someone's browser is a battery and
bandwidth cost they didn't agree to, and the common failures (bad key, bad
payload) repeat forever anyway.

## Layout

```
manifest.json        MV3 manifest; host permissions per supported chat site
src/scanner-core.js  the rules — pure, no I/O, unit-tested
src/page-hook.js     runs in page context; captures the outgoing prompt
src/content.js       isolated world; renders the warning badge
src/background.js    session counters, badge, optional batched reporting
src/popup.js/.html   settings: mode, muted rules, reporting
test/                node --test, run in CI via `npm run test:extension`
```

## Tests

```bash
npm run test:extension   # from the repo root
```
