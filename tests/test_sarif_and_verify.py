"""Tests for SARIF report generation and fix verification."""

import json
import pytest
from pathlib import Path
from ai_crypto_reviewer.types import Finding, Severity, Patch, RunResult, ReviewReport
from ai_crypto_reviewer.sarif_report import report_to_sarif, save_sarif_report, finding_to_sarif_result


class TestSarifReport:
    def test_basic_sarif_generation(self):
        report = ReviewReport(
            target_path="/test",
            findings=[
                Finding("SEC101", Severity.CRITICAL, "eval() usage", "test.py", 5),
                Finding("SEC113", Severity.MEDIUM, "MD5 usage", "crypto.py", 10),
            ],
        )
        sarif = report_to_sarif(report)

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) == 2
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 2

    def test_sarif_severity_mapping(self):
        for sev, expected in [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFO, "note"),
        ]:
            f = Finding("TEST", sev, "msg", "f.py", 1)
            result = finding_to_sarif_result(f)
            assert result["level"] == expected, f"Severity {sev} should map to {expected}"

    def test_sarif_with_cwe(self):
        f = Finding("CRYPTO001", Severity.HIGH, "Weak key", "rsa.py", 10, cwe_id="CWE-326")
        result = finding_to_sarif_result(f)
        assert result["properties"]["cwe"] == "CWE-326"

    def test_sarif_with_recommendation(self):
        f = Finding("SEC101", Severity.CRITICAL, "eval()", "test.py", 5, recommendation="Use ast.literal_eval")
        result = finding_to_sarif_result(f)
        assert result["fixes"][0]["description"]["text"] == "Use ast.literal_eval"

    def test_sarif_file_path_normalization(self):
        f = Finding("TEST", Severity.LOW, "msg", "path\\to\\file.py", 1)
        result = finding_to_sarif_result(f)
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "path/to/file.py"

    def test_sarif_properties(self):
        report = ReviewReport(
            target_path="/test",
            findings=[Finding("A", Severity.CRITICAL, "c", "f.py", 1)],
            patches=[Patch("f.py", "old", "new", "fix")],
            summary="Test summary",
        )
        sarif = report_to_sarif(report)
        props = sarif["runs"][0]["properties"]
        assert props["totalFindings"] == 1
        assert props["criticalCount"] == 1
        assert props["patchesGenerated"] == 1

    def test_sarif_rules_deduplication(self):
        report = ReviewReport(
            target_path="/test",
            findings=[
                Finding("SEC101", Severity.CRITICAL, "eval()", "a.py", 1),
                Finding("SEC101", Severity.CRITICAL, "eval()", "b.py", 5),
            ],
        )
        sarif = report_to_sarif(report)
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
        assert len(sarif["runs"][0]["results"]) == 2

    def test_save_sarif(self, tmp_path):
        report = ReviewReport(
            target_path="/test",
            findings=[Finding("TEST", Severity.LOW, "msg", "f.py", 1)],
        )
        path = str(tmp_path / "test.sarif")
        save_sarif_report(report, path)
        assert Path(path).exists()
        with open(path) as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"

    def test_sarif_empty_report(self):
        report = ReviewReport(target_path="/test")
        sarif = report_to_sarif(report)
        assert len(sarif["runs"][0]["results"]) == 0
        assert sarif["runs"][0]["properties"]["totalFindings"] == 0


class TestFixVerification:
    def test_fix_verification_resolves_finding(self):
        """Test that the fix verification correctly identifies resolved findings."""
        from ai_crypto_reviewer.agents.tester import ValidationAgent
        from ai_crypto_reviewer.agents.base import AgentContext

        # Create a patch that fixes eval
        source = 'result = eval(input())\n'
        patched = 'import ast\nresult = ast.literal_eval(input())\n'
        finding = Finding("SEC101", Severity.CRITICAL, "eval()", "test.py", 1)

        patch = Patch(
            file_path="test.py",
            original_code=source,
            patched_code=patched,
            description="Fix eval",
            finding=finding,
        )

        context = AgentContext(target_path="/tmp/test")
        context.patches = [patch]

        agent = ValidationAgent(config={"skip_sandbox": True, "skip_fix_verification": False})
        context = agent.execute(context)

        fix_results = [r for r in context.test_results if "fix_verify" in r.test_name]
        assert len(fix_results) == 1
        assert fix_results[0].passed  # eval should be resolved

    def test_fix_verification_detects_unresolved(self):
        """Test that fix verification catches unresolved findings."""
        from ai_crypto_reviewer.agents.tester import ValidationAgent
        from ai_crypto_reviewer.agents.base import AgentContext

        source = 'result = eval(input())\n'
        patched = 'result = eval(input())  # still here\n'
        finding = Finding("SEC101", Severity.CRITICAL, "eval()", "test.py", 1)

        patch = Patch(
            file_path="test.py",
            original_code=source,
            patched_code=patched,
            description="No real fix",
            finding=finding,
        )

        context = AgentContext(target_path="/tmp/test")
        context.patches = [patch]

        agent = ValidationAgent(config={"skip_sandbox": True, "skip_fix_verification": False})
        context = agent.execute(context)

        fix_results = [r for r in context.test_results if "fix_verify" in r.test_name]
        assert len(fix_results) == 1
        assert not fix_results[0].passed  # eval should still be present
