"""Tests for the credential-shape redactor (assessment/redaction.py).

test_evidence_redacts_secrets in test_assessment_scanner.py already covers
"the secret doesn't survive" for the scanner's own evidence extraction. These
add the case that surfaced while wiring blast-radius into the JSON report
format (docs/15 §5, phase 2): redact_text is applied to an already-serialized
JSON string in the json report path, and the original pattern's bare `\\S+`
consumed the JSON value's closing quote along with the secret, corrupting the
document. Not a blast-radius bug — a pre-existing defect in a code path
nothing had exercised with `.json()` assertions before.
"""

from __future__ import annotations

import json

from argus_detection.assessment.redaction import redact_text


def test_redacts_a_bare_api_key_assignment():
    assert "sk-ABCD1234EFGH5678IJKL" not in redact_text("api_key=sk-ABCD1234EFGH5678IJKL")


def test_does_not_consume_the_closing_quote_of_a_json_string():
    """The regression case: a secret-shaped value sitting right before a JSON
    string's closing quote must not eat that quote — doing so turns valid JSON
    into a string that never terminates."""
    payload = json.dumps({"evidence": "api_key=sk-ABCD1234EFGH5678IJKL", "next": "field"})
    redacted = redact_text(payload)
    # Must still be parseable...
    parsed = json.loads(redacted)
    # ...and the secret must still be gone.
    assert "sk-ABCD1234EFGH5678IJKL" not in redacted
    assert parsed["next"] == "field"


def test_does_not_consume_a_trailing_comma_or_closing_brace():
    assert redact_text('{"token=abc123",').endswith(",")
    assert redact_text('{"secret=abc123"}').endswith("}")


def test_redacts_within_plain_prose_unaffected_by_the_narrower_charset():
    # The fix narrows what counts as part of the value; ordinary secret shapes
    # (letters, digits, dashes, dots, underscores) must still redact in full.
    text = "the password=Sup3r-Secret.Value_99 was in the log"
    redacted = redact_text(text)
    assert "Sup3r-Secret.Value_99" not in redacted
    assert "was in the log" in redacted  # nothing past the value is eaten


def test_other_secret_shapes_still_redact():
    assert "sk-ABCD1234EFGH5678IJKL" not in redact_text("key is sk-ABCD1234EFGH5678IJKL")
    assert "ghp_ABCDEFGHIJ0123456789" not in redact_text("ghp_ABCDEFGHIJ0123456789")
    assert "AKIAABCDEFGHIJKLMNOP" not in redact_text("AKIAABCDEFGHIJKLMNOP")
