"""Tests for ai_crypto_reviewer.types module."""

import pytest
from ai_crypto_reviewer.types import Finding, Severity, Patch, RunResult, ReviewReport


class TestSeverity:
    def test_comparison_ge(self):
        assert Severity.CRITICAL >= Severity.HIGH
        assert Severity.HIGH >= Severity.MEDIUM
        assert Severity.MEDIUM >= Severity.LOW
        assert Severity.LOW >= Severity.INFO
        assert not Severity.INFO >= Severity.CRITICAL

    def test_comparison_gt(self):
        assert Severity.CRITICAL > Severity.LOW
        assert not Severity.LOW > Severity.LOW
        assert not Severity.INFO > Severity.CRITICAL

    def test_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


class TestFinding:
    def test_basic_creation(self):
        f = Finding(
            rule_id="TEST001",
            severity=Severity.HIGH,
            message="Test finding",
            file_path="test.py",
            line_number=10,
        )
        assert f.rule_id == "TEST001"
        assert f.severity == Severity.HIGH
        assert f.line_number == 10

    def test_crypto_detection(self):
        f = Finding(
            rule_id="CRYPTO001",
            severity=Severity.HIGH,
            message="Weak RSA key size",
            file_path="crypto.py",
            line_number=5,
            category="weak_crypto",
        )
        assert f.is_crypto_related

    def test_non_crypto_detection(self):
        f = Finding(
            rule_id="STYLE001",
            severity=Severity.LOW,
            message="Line too long",
            file_path="format.py",
            line_number=1,
        )
        assert not f.is_crypto_related

    def test_crypto_keyword_in_code(self):
        f = Finding(
            rule_id="GENERIC001",
            severity=Severity.MEDIUM,
            message="Generic issue",
            file_path="code.py",
            line_number=3,
            code_snippet="def encrypt_data(key, plaintext):",
        )
        assert f.is_crypto_related


class TestPatch:
    def test_diff_generation(self):
        p = Patch(
            file_path="test.py",
            original_code="x = 1\ny = 2\n",
            patched_code="x = 1\ny = 3\n",
            description="Fix value",
        )
        diff = p.diff
        assert "-y = 2" in diff
        assert "+y = 3" in diff

    def test_empty_patch(self):
        p = Patch(
            file_path="test.py",
            original_code="same",
            patched_code="same",
            description="No change",
        )
        assert p.is_empty

    def test_non_empty_patch(self):
        p = Patch(
            file_path="test.py",
            original_code="old",
            patched_code="new",
            description="Changed",
        )
        assert not p.is_empty


class TestRunResult:
    def test_passed(self):
        r = RunResult(passed=True, test_name="test_ok", output="all good")
        assert r.passed
        assert r.test_name == "test_ok"

    def test_failed(self):
        r = RunResult(passed=False, test_name="test_fail", output="error", exit_code=1)
        assert not r.passed
        assert r.exit_code == 1


class TestReviewReport:
    def test_empty_report(self):
        r = ReviewReport(target_path="/tmp/test")
        assert len(r.findings) == 0
        assert r.all_tests_passed  # No tests = vacuously true

    def test_critical_findings_filter(self):
        r = ReviewReport(target_path="/tmp/test", findings=[
            Finding("A", Severity.CRITICAL, "crit", "f.py", 1),
            Finding("B", Severity.LOW, "low", "f.py", 2),
            Finding("C", Severity.HIGH, "high", "f.py", 3),
        ])
        assert len(r.critical_findings) == 1
        assert len(r.high_findings) == 2  # CRITICAL + HIGH

    def test_crypto_findings_filter(self):
        r = ReviewReport(target_path="/tmp/test", findings=[
            Finding("RSA001", Severity.HIGH, "Weak RSA key", "f.py", 1),
            Finding("STYLE001", Severity.LOW, "Line too long", "f.py", 2),
        ])
        assert len(r.crypto_findings) == 1

    def test_to_dict(self):
        r = ReviewReport(target_path="/tmp/test", summary="Test summary")
        d = r.to_dict()
        assert d["target_path"] == "/tmp/test"
        assert d["summary"] == "Test summary"
        assert isinstance(d["findings"], list)

    def test_test_results(self):
        r = ReviewReport(
            target_path="/tmp/test",
            test_results=[
                RunResult(True, "test1"),
                RunResult(False, "test2"),
            ],
        )
        assert not r.all_tests_passed

        r2 = ReviewReport(
            target_path="/tmp/test",
            test_results=[
                RunResult(True, "test1"),
                RunResult(True, "test2"),
            ],
        )
        assert r2.all_tests_passed
