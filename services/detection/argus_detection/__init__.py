"""Argus security detection service.

Layered detection pipeline (see docs/04-security-detection-engine.md):
    L1  heuristics / signatures   (this package: layers.heuristics)
    L2  ML classifier ensemble    (layers.classifiers — pluggable, optional)
    L3  LLM-as-judge              (layers.judge — optional)
    L4  trace-level analysis      (layers.trace_analysis)
"""

__version__ = "0.1.0"
