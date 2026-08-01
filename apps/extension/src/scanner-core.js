/**
 * Argus Browser Guard — deterministic evaluator (MVP).
 *
 * A framework-neutral port of Argus's deterministic rules, focused on the risks that
 * matter when a *user* sends a prompt to an external LLM: leaking secrets, leaking PII, and
 * prompt-injection / jailbreak / indirect-injection patterns. Pure functions, sub-millisecond.
 *
 * Runs in the content-script isolated world (shared scope with content.js). In v1 this
 * becomes packages/scanner-core, shared with the Python backend so verdicts stay in lockstep.
 */
(function () {
  "use strict";

  const REDACTED = "«redacted»";
  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };

  // Redact secret-shaped substrings from evidence so we never surface a live secret.
  const SECRET_SCRUB = [
    /sk-[A-Za-z0-9]{12,}/g,
    /AKIA[0-9A-Z]{16}/g,
    /ghp_[A-Za-z0-9]{20,}/g,
    /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  ];
  function redact(text) {
    let out = String(text || "");
    for (const re of SECRET_SCRUB) out = out.replace(re, REDACTED);
    return out;
  }
  function snippet(text, index, len) {
    const start = Math.max(0, index - 24);
    return redact(text.slice(start, Math.min(text.length, index + (len || 24) + 24))).trim().slice(0, 160);
  }

  // Standard Luhn checksum — filters random digit runs out of the credit-card rule.
  function luhnValid(digits) {
    let sum = 0, alt = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let n = digits.charCodeAt(i) - 48;
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n;
      alt = !alt;
    }
    return sum % 10 === 0;
  }
  function looksLikeCard(match) {
    const d = match.replace(/[^0-9]/g, "");
    if (d.length < 13 || d.length > 19) return false;
    if (!/^(4|5[1-5]|3[47]|6(?:011|5))/.test(d)) return false; // Visa/MC/Amex/Discover BIN prefixes
    return luhnValid(d);
  }

  // Each rule: { id, title, category, severity, test(text) -> match|null }
  const RULES = [
    {
      id: "IG-SECRET-001",
      title: "Secret or credential in prompt",
      category: "sensitive-data",
      severity: "critical",
      res: [
        /\bsk-[A-Za-z0-9]{16,}\b/,
        /\bAKIA[0-9A-Z]{16}\b/,
        /\bghp_[A-Za-z0-9]{20,}\b/,
        /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
        /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,
        /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
        /\b(password|passwd|api[_-]?key|secret|access[_-]?token|bearer)\b\s*[:=]\s*\S+/i,
      ],
    },
    {
      id: "IG-PII-001",
      title: "Personal / sensitive data in prompt",
      category: "sensitive-data",
      severity: "high",
      res: [
        { re: /\b\d(?:[ -]?\d){12,18}\b/, validate: looksLikeCard }, // Visa/MC/Amex/Discover, Luhn-checked
        /\b\d{3}-\d{2}-\d{4}\b/, // US SSN pattern
        /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, // email
        /\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]?\d{4}\b/, // NANP phone, requires a real separator
        /\+\d{1,3}[\s.-]\d{2,4}[\s.-]?\d{2,4}[\s.-]?\d{2,4}\b/, // international phone, requires leading +country code
      ],
    },
    {
      id: "IG-INJECT-001",
      title: "Prompt-injection / jailbreak pattern",
      category: "prompt-injection",
      severity: "medium",
      res: [
        /\bignore (all )?(previous|prior|above) (instructions|prompts?)\b/i,
        /\byou are now\b/i,
        /\bdeveloper mode\b/i,
        /\bdo anything now\b|\bDAN\b/,
        /\bdisregard (the )?(system|earlier) (prompt|message)\b/i,
        /\bpretend (you|to be)\b/i,
      ],
    },
    {
      id: "IG-EXFIL-001",
      title: "System-prompt / instruction disclosure attempt",
      category: "prompt-leakage",
      severity: "medium",
      res: [
        /\b(reveal|print|show|repeat|output)\b.{0,30}\b(system prompt|your instructions|hidden|above)\b/i,
        /\bwhat (are|were) your (initial|system) instructions\b/i,
      ],
    },
    {
      id: "IG-INDIRECT-001",
      title: "Retrieved / pasted text treated as instructions",
      category: "rag-security",
      severity: "medium",
      res: [
        /\b(follow|obey|execute|comply with|do what)\b.{0,30}\b(the (document|text|note|content|below|following)|instructions? in)\b/i,
      ],
    },
    {
      id: "IG-ENCODE-001",
      title: "Encoding / obfuscation passthrough",
      category: "obfuscation",
      severity: "low",
      res: [/\b(base64|rot13|hex(adecimal)?)\b.{0,20}\b(decode|interpret|run|execute)\b/i, /\bdecode (and|then) (run|execute|follow)\b/i],
    },
  ];

  function scan(text) {
    const findings = [];
    const s = String(text || "");
    if (!s) return findings;
    for (const rule of RULES) {
      for (const item of rule.res) {
        const re = item instanceof RegExp ? item : item.re;
        const m = re.exec(s);
        if (m) {
          if (!(item instanceof RegExp) && typeof item.validate === "function" && !item.validate(m[0])) continue;
          findings.push({
            rule_id: rule.id,
            title: rule.title,
            category: rule.category,
            severity: rule.severity,
            evidence: snippet(s, m.index, m[0].length),
          });
          break; // one hit per rule
        }
      }
    }
    findings.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
    return findings;
  }

  function summarize(findings) {
    if (!findings.length) return { level: "ok", top: null, count: 0 };
    return { level: findings[0].severity, top: findings[0], count: findings.length };
  }

  // Expose on the shared isolated-world global for content.js.
  self.IGScannerCore = { scan, summarize, redact, RULE_COUNT: RULES.length };
})();
