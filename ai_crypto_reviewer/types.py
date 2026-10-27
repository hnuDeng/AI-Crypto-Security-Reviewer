"""Data types and models used across the AI Crypto Security Reviewer pipeline."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class Severity(enum.Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __ge__(self, other: Severity) -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) >= order.index(other)

    def __gt__(self, other: Severity) -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) > order.index(other)


@dataclass
class Finding:
    """A single security finding discovered during analysis."""
    rule_id: str
    severity: Severity
    message: str
    file_path: str
    line_number: int = 0
    end_line: int = 0
    category: str = ""
    tool: str = ""
    code_snippet: str = ""
    recommendation: str = ""
    cwe_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_crypto_related(self) -> bool:
        crypto_keywords = [
            "rsa", "aes", "sha", "md5", "encrypt", "decrypt", "hash",
            "prime", "modular", "key", "cipher", "nonce", "iv", "hmac",
            "dsa", "ecdsa", "diffie", "elliptic", "padding", "pkcs",
        ]
        text = f"{self.rule_id} {self.message} {self.category} {self.code_snippet}".lower()
        return any(kw in text for kw in crypto_keywords)


@dataclass
class Patch:
    """A proposed code patch to fix a security finding."""
    file_path: str
    original_code: str
    patched_code: str
    description: str
    finding: Finding | None = None
    start_line: int = 0
    end_line: int = 0
    kind: str = "fix"

    @property
    def diff(self) -> str:
        """Generate a unified diff of the patch."""
        import difflib
        original_lines = self.original_code.splitlines(keepends=True)
        patched_lines = self.patched_code.splitlines(keepends=True)
        return "".join(difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile=f"a/{self.file_path}",
            tofile=f"b/{self.file_path}",
        ))

    @property
    def is_empty(self) -> bool:
        return self.original_code == self.patched_code


@dataclass
class RunResult:
    """Result of running tests on a patched codebase."""
    passed: bool
    test_name: str
    output: str = ""
    exit_code: int = 0
    duration_seconds: float = 0.0


@dataclass
class ReviewReport:
    """Complete report from the security review pipeline."""
    target_path: str
    findings: list[Finding] = field(default_factory=list)
    patches: list[Patch] = field(default_factory=list)
    test_results: list[RunResult] = field(default_factory=list)
    agent_outputs: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    summary: str = ""

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]

    @property
    def crypto_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.is_crypto_related]

    @property
    def all_tests_passed(self) -> bool:
        return all(r.passed for r in self.test_results) if self.test_results else True

    @property
    def test_status(self) -> str:
        return self.sandbox_test_status

    @property
    def validation_status(self) -> str:
        if not self.test_results:
            return "not_run"
        return "passed" if self.all_tests_passed else "failed"

    def _status_for(self, prefixes: tuple[str, ...]) -> str:
        matching = [result for result in self.test_results if result.test_name.startswith(prefixes)]
        if not matching:
            return "not_run"
        return "passed" if all(result.passed for result in matching) else "failed"

    @property
    def sandbox_test_status(self) -> str:
        return self._status_for(("sandbox_test_suite",))

    @property
    def fix_verification_status(self) -> str:
        return self._status_for(("fix_verify:",))

    @property
    def patch_application_status(self) -> str:
        return self._status_for(("apply_patch:",))

    def to_dict(self) -> dict[str, Any]:
        from ai_crypto_reviewer.risk import compute_risk_score, risk_level

        score = compute_risk_score(self.findings)
        return {
            "target_path": self.target_path,
            "total_findings": len(self.findings),
            "critical_count": len(self.critical_findings),
            "high_count": len(self.high_findings),
            "crypto_count": len(self.crypto_findings),
            "patches_generated": len(self.patches),
            "tests_passed": None if self.test_status == "not_run" else self.test_status == "passed",
            "test_status": self.test_status,
            "validation_status": self.validation_status,
            "sandbox_test_status": self.sandbox_test_status,
            "fix_verification_status": self.fix_verification_status,
            "patch_application_status": self.patch_application_status,
            "patches": [
                {
                    "file": patch.file_path,
                    "description": patch.description,
                    "kind": patch.kind,
                    "rule_id": patch.finding.rule_id if patch.finding else None,
                }
                for patch in self.patches
            ],
            "test_results": [
                {
                    "name": result.test_name,
                    "passed": result.passed,
                    "output": result.output,
                    "exit_code": result.exit_code,
                    "duration_seconds": result.duration_seconds,
                }
                for result in self.test_results
            ],
            "summary": self.summary,
            "errors": self.errors,
            "risk_score": score,
            "risk_level": risk_level(score),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "message": f.message,
                    "file": f.file_path,
                    "line": f.line_number,
                    "category": f.category,
                    "tool": f.tool,
                    "crypto_related": f.is_crypto_related,
                }
                for f in self.findings
            ],
        }
