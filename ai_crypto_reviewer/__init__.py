"""AI Crypto Security Reviewer - Multi-agent code review and auto-remediation system.

An advanced system optimized for deep logical vulnerabilities in C++ and Python
codebases, with specialized focus on cryptographic implementations.
"""

__version__ = "1.0.0"

from ai_crypto_reviewer.config import PipelineConfig
from ai_crypto_reviewer.orchestrator import SecurityReviewPipeline
from ai_crypto_reviewer.types import Finding, Severity, Patch, ReviewReport

__all__ = [
    "PipelineConfig",
    "SecurityReviewPipeline",
    "Finding",
    "Severity",
    "Patch",
    "ReviewReport",
]
