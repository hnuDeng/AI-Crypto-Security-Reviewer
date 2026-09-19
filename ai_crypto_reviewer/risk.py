"""Risk scoring utilities for aggregating security findings."""

from __future__ import annotations

from typing import Sequence

from ai_crypto_reviewer.types import Finding, Severity

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

RISK_LEVEL_THRESHOLDS = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (20, "Low"),
]


def compute_risk_score(findings: Sequence[Finding], cap: int = 100) -> int:
    """Compute a weighted 0-100 risk score from findings.

    The score grows with the count and severity of findings.
    It is intentionally simple and deterministic so tests can assert it.
    """
    total = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    return min(cap, total)


def risk_level(score: int) -> str:
    """Map a numeric risk score to a human-friendly level."""
    for threshold, level in RISK_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "Informational"
