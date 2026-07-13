"""L1 — heuristics & signatures.

Microsecond, deterministic, explainable checks. Two rule kinds:
  * regex rules  — compiled case-insensitive/multiline patterns
  * structural `kind` rules — code checks for things regex handles poorly
    (invisible unicode, bidi controls, encoded blobs, mixed-script density)

The engine returns a LayerResult with per-rule matches and an aggregate score in
0..1. Aggregation is a saturating sum of matched-rule weights so multiple weak
signals combine but no single rule pins the score to 1.0.
"""
from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from ..models import Category, LayerResult, Observation, RuleMatch, TaintClass

_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

# Unicode ranges we treat as invisible/format control (subset that matters).
_INVISIBLE = {
    "​", "‌", "‍", "⁠", "﻿",  # zero-width family
    "­",  # soft hyphen
}
_BIDI_CONTROL = {
    "‪", "‫", "‬", "‭", "‮",  # LRE RLE PDF LRO RLO
    "⁦", "⁧", "⁨", "⁩",            # isolates
}
_ENCODED_BLOB = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2}|(?:[0-9a-fA-F]{2}){24,})")


@dataclass
class _Rule:
    rule_id: str
    description: str
    category: Category
    weight: float
    applies_to: str
    regex: re.Pattern | None
    kind: str | None
    mitigable: bool


@lru_cache(maxsize=8)
def load_rules(ruleset: str = "default-v1") -> tuple[_Rule, ...]:
    path = _RULES_DIR / f"{ruleset}.yaml"
    data = yaml.safe_load(path.read_text())
    rules: list[_Rule] = []
    for r in data.get("rules", []):
        pattern = None
        if r.get("regex"):
            pattern = re.compile(r["regex"], re.IGNORECASE | re.MULTILINE)
        rules.append(
            _Rule(
                rule_id=r["id"],
                description=r["description"],
                category=Category(r["category"]),
                weight=float(r["weight"]),
                applies_to=r.get("applies_to", "any"),
                regex=pattern,
                kind=r.get("kind"),
                mitigable=r.get("mitigable", True),
            )
        )
    return tuple(rules)


def _excerpt(text: str, start: int, end: int, radius: int = 48) -> str:
    a = max(0, start - radius)
    b = min(len(text), end + radius)
    snippet = text[a:b].replace("\n", " ").strip()
    return ("…" + snippet + "…") if (a > 0 or b < len(text)) else snippet


# Report-speech markers: text that *describes* or *quotes* an instruction rather
# than issuing one. The design principle (docs/04): "documents describe;
# injections command." A match near these is downweighted to cut the classic
# hard-negative false positives (blogs about prompt injection, fiction, docs).
_REPORT_MARKERS = re.compile(
    r"\b(like|such as|e\.?g\.?|for example|example of|called|the (word|phrase|term)s?|"
    r"instructions? like|says?|said|typed?|writes?|wrote|quote[ds]?|"
    r"explains?|describes?|attackers?|hackers?|in the (novel|story|film|movie|book|game))\b",
    re.IGNORECASE,
)
_QUOTE_CHARS = "\"'“”‘’`"
_MITIGATION_FACTOR = 0.35


def _is_reported(text: str, start: int, end: int) -> bool:
    """True if the match at [start,end) looks quoted or is reported speech."""
    window_before = text[max(0, start - 40) : start]
    window_after = text[end : min(len(text), end + 8)]
    if _REPORT_MARKERS.search(window_before):
        return True
    # Quote immediately before the match and a closing quote nearby after.
    before_stripped = window_before.rstrip()
    if before_stripped and before_stripped[-1] in _QUOTE_CHARS:
        return True
    if any(q in window_after for q in _QUOTE_CHARS) and any(
        q in window_before for q in _QUOTE_CHARS
    ):
        return True
    return False


# ---- structural `kind` checks --------------------------------------------

def _check_invisible(text: str) -> tuple[bool, str]:
    hits = [c for c in text if c in _INVISIBLE]
    if hits:
        return True, f"{len(hits)} zero-width/invisible char(s)"
    return False, ""


def _check_bidi(text: str) -> tuple[bool, str]:
    hits = [c for c in text if c in _BIDI_CONTROL]
    if hits:
        return True, f"{len(hits)} bidi control char(s)"
    return False, ""


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _check_encoded_blob(text: str) -> tuple[bool, str]:
    for m in _ENCODED_BLOB.finditer(text):
        blob = m.group(0)
        # Require high entropy to avoid flagging long hashes/ids that are benign
        # context (still suspicious, but only if entropy says "packed data").
        if _shannon_entropy(blob) >= 4.0:
            return True, f"encoded blob len={len(blob)} entropy={_shannon_entropy(blob):.1f}"
    return False, ""


def _check_mixed_script(text: str) -> tuple[bool, str]:
    # Flag words mixing Latin with Cyrillic/Greek lookalikes (homoglyph attacks).
    scripts_seen = 0
    suspicious_words = 0
    for word in re.findall(r"\w{4,}", text):
        blocks = set()
        for ch in word:
            if not ch.isalpha():
                continue
            try:
                name = unicodedata.name(ch)
            except ValueError:
                continue
            if "LATIN" in name:
                blocks.add("latin")
            elif "CYRILLIC" in name:
                blocks.add("cyrillic")
            elif "GREEK" in name:
                blocks.add("greek")
        if len(blocks) >= 2:
            suspicious_words += 1
        scripts_seen |= len(blocks)
    if suspicious_words:
        return True, f"{suspicious_words} mixed-script word(s)"
    return False, ""


_KIND_CHECKS = {
    "invisible_unicode": _check_invisible,
    "bidi_control": _check_bidi,
    "encoded_blob": _check_encoded_blob,
    "mixed_script": _check_mixed_script,
}


def _rule_applies(rule: _Rule, taint: TaintClass) -> bool:
    if rule.applies_to == "any":
        return True
    return rule.applies_to == taint.value


def scan(obs: Observation, taint: TaintClass, ruleset: str = "default-v1") -> LayerResult:
    """Run all L1 rules against an observation's content."""
    text = obs.content or ""
    matches: list[RuleMatch] = []

    for rule in load_rules(ruleset):
        if not _rule_applies(rule, taint):
            continue

        if rule.regex is not None:
            m = rule.regex.search(text)
            if m:
                weight = rule.weight
                # Downweight quoted/reported matches ("documents describe;
                # injections command"). Skipped for structural obfuscation rules
                # and rules flagged mitigable:false (jailbreak-intrinsic phrases).
                if (
                    rule.mitigable
                    and rule.category != Category.obfuscation
                    and _is_reported(text, m.start(), m.end())
                ):
                    weight *= _MITIGATION_FACTOR
                matches.append(
                    RuleMatch(
                        rule_id=rule.rule_id,
                        description=rule.description,
                        weight=weight,
                        category=rule.category,
                        excerpt=_excerpt(text, m.start(), m.end()),
                    )
                )
        elif rule.kind is not None:
            check = _KIND_CHECKS.get(rule.kind)
            if check is None:
                continue
            hit, detail = check(text)
            if hit:
                matches.append(
                    RuleMatch(
                        rule_id=rule.rule_id,
                        description=rule.description,
                        weight=rule.weight,
                        category=rule.category,
                        excerpt=detail,
                    )
                )

    # Saturating aggregate: 1 - Π(1 - w_i). Combines independent signals without
    # any single rule pinning the score, and stays in [0,1).
    prod = 1.0
    for mt in matches:
        prod *= (1.0 - min(max(mt.weight, 0.0), 0.99))
    score = 1.0 - prod

    return LayerResult(layer="L1", score=score, matches=matches)
