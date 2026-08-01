"""Framework requirement registry (data-driven, not hard-coded into UI).

Covers OWASP LLM Top 10, a subset of MITRE ATLAS techniques, and NIST AI RMF functions.
Extend by adding rows here or via the API; UI reads them from the registry.
"""

from __future__ import annotations

FRAMEWORK_REQUIREMENTS: list[dict] = [
    # OWASP LLM Top 10 (2025)
    {"framework": "OWASP-LLM", "version": "2025", "requirement_id": "LLM01", "title": "Prompt Injection",
     "source_reference": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"},
    {"framework": "OWASP-LLM", "version": "2025", "requirement_id": "LLM02", "title": "Insecure Output Handling"},
    {"framework": "OWASP-LLM", "version": "2025", "requirement_id": "LLM03", "title": "Training Data Poisoning"},
    {"framework": "OWASP-LLM", "version": "2025", "requirement_id": "LLM04", "title": "Model Denial of Service"},
    {"framework": "OWASP-LLM", "version": "2025", "requirement_id": "LLM05", "title": "Supply Chain Vulnerabilities"},
    {"framework": "OWASP-LLM", "version": "2025", "requirement_id": "LLM06",
     "title": "Sensitive Information Disclosure"},
    {"framework": "OWASP-LLM", "version": "2025", "requirement_id": "LLM07", "title": "Insecure Plugin/Prompt Design"},
    {"framework": "OWASP-LLM", "version": "2025", "requirement_id": "LLM08", "title": "Excessive Agency"},
    {"framework": "OWASP-LLM", "version": "2025", "requirement_id": "LLM09", "title": "Overreliance"},
    {"framework": "OWASP-LLM", "version": "2025", "requirement_id": "LLM10", "title": "Model Theft"},
    # MITRE ATLAS (subset)
    {"framework": "MITRE-ATLAS", "version": "4.5", "requirement_id": "AML.T0051", "title": "LLM Prompt Injection",
     "source_reference": "https://atlas.mitre.org/"},
    {"framework": "MITRE-ATLAS", "version": "4.5", "requirement_id": "AML.T0054", "title": "LLM Jailbreak"},
    {"framework": "MITRE-ATLAS", "version": "4.5", "requirement_id": "AML.T0057", "title": "LLM Data Leakage"},
    # NIST AI RMF functions
    {"framework": "NIST-AI-RMF", "version": "1.0", "requirement_id": "GOVERN", "title": "Govern",
     "source_reference": "https://www.nist.gov/itl/ai-risk-management-framework"},
    {"framework": "NIST-AI-RMF", "version": "1.0", "requirement_id": "MAP", "title": "Map"},
    {"framework": "NIST-AI-RMF", "version": "1.0", "requirement_id": "MEASURE", "title": "Measure"},
    {"framework": "NIST-AI-RMF", "version": "1.0", "requirement_id": "MANAGE", "title": "Manage"},
    # NIST Generative AI Profile (subset)
    {"framework": "NIST-GENAI", "version": "1.0", "requirement_id": "GV-1.1", "title": "GenAI governance policy"},
    {"framework": "NIST-GENAI", "version": "1.0", "requirement_id": "MS-2.6", "title": "Adversarial testing"},
]
