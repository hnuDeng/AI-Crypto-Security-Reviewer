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
        assert result["properties"]["recommendation"] == "Use ast.literal_eval"

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

    @pytest.mark.parametrize(
        "original,patched,line_number",
        [
            ('value = eval(input())\n', '# header\nvalue = eval(input())\n', 1),
            ('# header\nvalue = eval(input())\n', 'value = eval(input())\n', 2),
        ],
    )
    def test_shifted_vulnerability_is_not_reported_resolved(self, original, patched, line_number):
        from ai_crypto_reviewer.agents.tester import ValidationAgent
        from ai_crypto_reviewer.agents.base import AgentContext

        finding = Finding("SEC101", Severity.CRITICAL, "eval()", "example.py", line_number)
        patch = Patch("example.py", original, patched, "Shift lines only", finding=finding)
        context = AgentContext(target_path="example.py", patches=[patch])

        results = ValidationAgent(config={"skip_sandbox": True}).execute(context).test_results
        verification = next(result for result in results if result.test_name.startswith("fix_verify:"))

        assert not verification.passed
        assert "resolved" not in verification.output.lower()

    def test_fix_one_of_two_same_rule_findings(self):
        from ai_crypto_reviewer.agents.tester import ValidationAgent
        from ai_crypto_reviewer.agents.base import AgentContext

        original = 'first = eval("1")\nsecond = eval("2")\n'
        patched = 'first = 1\nsecond = eval("2")\n'
        finding = Finding("SEC101", Severity.CRITICAL, "eval()", "example.py", 1)
        patch = Patch("example.py", original, patched, "Fix first finding", finding=finding)

        results = ValidationAgent(config={"skip_sandbox": True}).execute(
            AgentContext(target_path="example.py", patches=[patch])
        ).test_results
        verification = next(result for result in results if result.test_name.startswith("fix_verify:"))

        assert verification.passed
        assert "no longer detected" in verification.output.lower()

    def test_unmapped_finding_is_not_reported_resolved(self):
        from ai_crypto_reviewer.agents.tester import ValidationAgent
        from ai_crypto_reviewer.agents.base import AgentContext

        original = 'value = eval(input())\n'
        patched = 'other = eval(input())\n'
        finding = Finding("SEC101", Severity.CRITICAL, "eval()", "example.py", 1)
        patch = Patch("example.py", original, patched, "Ambiguous modification", finding=finding)

        results = ValidationAgent(config={"skip_sandbox": True}).execute(
            AgentContext(target_path="example.py", patches=[patch])
        ).test_results
        verification = next(result for result in results if result.test_name.startswith("fix_verify:"))

        assert not verification.passed
        assert "resolved" not in verification.output.lower()

    def test_rule_not_supported_by_verifier_is_unverified(self):
        from ai_crypto_reviewer.agents.tester import ValidationAgent
        from ai_crypto_reviewer.agents.base import AgentContext

        original = 'value = random.random()\n'
        patched = 'value = secrets.randbelow(10)\n'
        finding = Finding("WEAK-RANDOM", Severity.HIGH, "weak randomness", "example.py", 1)
        patch = Patch("example.py", original, patched, "Change random source", finding=finding)

        results = ValidationAgent(config={"skip_sandbox": True}).execute(
            AgentContext(target_path="example.py", patches=[patch])
        ).test_results
        verification = next(result for result in results if result.test_name.startswith("fix_verify:"))

        assert not verification.passed
        assert "unverified" in verification.output.lower()

    def test_warning_only_patch_is_not_a_verified_fix(self):
        from ai_crypto_reviewer.agents.base import AgentContext
        from ai_crypto_reviewer.agents.coder import CoderAgent
        from ai_crypto_reviewer.agents.tester import ValidationAgent

        source = 'value = eval(input())\n'
        finding = Finding("SEC101", Severity.CRITICAL, "eval()", "example.py", 1)
        patch = CoderAgent()._add_warning_comment(finding, source)
        context = AgentContext(target_path="example.py", patches=[patch])

        results = ValidationAgent(config={"skip_sandbox": True}).execute(context).test_results
        verification = next(result for result in results if result.test_name.startswith("fix_verify:"))

        assert patch.kind == "warning"
        assert not verification.passed
        assert "warning" in verification.output.lower()

    def test_invalid_python_cannot_be_reported_as_resolved(self):
        from ai_crypto_reviewer.agents.tester import ValidationAgent
        from ai_crypto_reviewer.agents.base import AgentContext

        finding = Finding("SEC101", Severity.CRITICAL, "eval()", "example.py", 1)
        patch = Patch("example.py", 'value = eval(input())\n', 'def broken(\n', "Broken code", finding=finding)
        results = ValidationAgent(config={"skip_sandbox": True}).execute(
            AgentContext(target_path="example.py", patches=[patch])
        ).test_results

        verification = next(result for result in results if result.test_name.startswith("fix_verify:"))
        assert not verification.passed
        assert "unverified" in verification.output.lower()

    def test_patch_without_finding_cannot_be_reported_verified(self):
        from ai_crypto_reviewer.agents.tester import ValidationAgent
        from ai_crypto_reviewer.agents.base import AgentContext

        patch = Patch("example.py", "value = 1\n", "value = 2\n", "Unlinked patch")
        results = ValidationAgent(config={"skip_sandbox": True}).execute(
            AgentContext(target_path="example.py", patches=[patch])
        ).test_results

        verification = next(result for result in results if result.test_name.startswith("fix_verify:"))
        assert not verification.passed
        assert "unverified" in verification.output.lower()

    def test_duplicate_lines_with_ambiguous_identity_are_unverified(self):
        from ai_crypto_reviewer.agents.tester import ValidationAgent
        from ai_crypto_reviewer.agents.base import AgentContext

        original = 'eval(input())\neval(input())\n'
        finding = Finding("SEC101", Severity.CRITICAL, "eval()", "example.py", 2)
        patch = Patch("example.py", original, 'eval(input())\n', "Delete one duplicate", finding=finding)
        results = ValidationAgent(config={"skip_sandbox": True}).execute(
            AgentContext(target_path="example.py", patches=[patch])
        ).test_results

        verification = next(result for result in results if result.test_name.startswith("fix_verify:"))
        assert not verification.passed
        assert "unverified" in verification.output.lower()

    def test_conflicting_patches_are_unverified_when_sandbox_is_skipped(self):
        from ai_crypto_reviewer.agents.tester import ValidationAgent
        from ai_crypto_reviewer.agents.base import AgentContext

        original = 'first = eval("1")\nsecond = eval("2")\n'
        first = Finding("SEC101", Severity.CRITICAL, "eval()", "example.py", 1)
        second = Finding("SEC101", Severity.CRITICAL, "eval()", "example.py", 2)
        patches = [
            Patch("example.py", original, "first = 1\nsecond = 2\n", "First", finding=first),
            Patch("example.py", original, "first = 10\nsecond = 20\n", "Second", finding=second),
        ]
        results = ValidationAgent(config={"skip_sandbox": True}).execute(
            AgentContext(target_path="example.py", patches=patches)
        ).test_results

        verifications = [result for result in results if result.test_name.startswith("fix_verify:")]
        assert len(verifications) == 2
        assert all(not result.passed and "unverified" in result.output.lower() for result in verifications)

    def test_aliased_eval_is_not_reported_as_a_fix(self):
        from ai_crypto_reviewer.agents.tester import ValidationAgent
        from ai_crypto_reviewer.agents.base import AgentContext

        original = 'value = eval(input())\n'
        patched = 'from builtins import eval as run\nvalue = run(input())\n'
        finding = Finding("SEC101", Severity.CRITICAL, "eval()", "example.py", 1)
        patch = Patch("example.py", original, patched, "Alias eval", finding=finding)
        results = ValidationAgent(config={"skip_sandbox": True}).execute(
            AgentContext(target_path="example.py", patches=[patch])
        ).test_results

        verification = next(result for result in results if result.test_name.startswith("fix_verify:"))
        assert not verification.passed
        assert "unverified" in verification.output.lower()


def test_reports_distinguish_skipped_tests_from_success():
    report = ReviewReport(target_path="example.py")

    json_report = report.to_dict()
    sarif = report_to_sarif(report)

    assert json_report["tests_passed"] is None
    assert json_report["test_status"] == "not_run"
    assert sarif["runs"][0]["properties"]["testStatus"] == "not_run"
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_json_and_sarif_expose_warning_and_validation_outcomes():
    finding = Finding("SEC101", Severity.CRITICAL, "eval()", "example.py", 1)
    patch = Patch("example.py", "old", "new", "Warning", finding=finding, kind="warning")
    report = ReviewReport(
        target_path="example.py", patches=[patch],
        test_results=[RunResult(False, "fix_verify:example.py:SEC101", "Unverified")],
    )

    json_report = report.to_dict()
    sarif_properties = report_to_sarif(report)["runs"][0]["properties"]

    assert json_report["test_status"] == "not_run"
    assert json_report["validation_status"] == "failed"
    assert json_report["patches"][0]["kind"] == "warning"
    assert json_report["test_results"][0]["passed"] is False
    assert sarif_properties["testStatus"] == "not_run"
    assert sarif_properties["validationStatus"] == "failed"
    assert sarif_properties["patches"][0]["kind"] == "warning"


def test_sarif_recommendation_is_not_a_machine_applicable_fix():
    finding = Finding(
        "SEC101", Severity.CRITICAL, "eval()", "example.py", 1,
        recommendation="Review and replace eval",
    )

    result = finding_to_sarif_result(finding)

    assert "fixes" not in result
    assert result["properties"]["recommendation"] == "Review and replace eval"


def test_syntax_checks_do_not_imply_sandbox_or_fix_verification_ran():
    report = ReviewReport(
        target_path="example.py", test_results=[RunResult(True, "syntax_check:example.py")],
    )

    json_report = report.to_dict()
    sarif_properties = report_to_sarif(report)["runs"][0]["properties"]

    assert json_report["test_status"] == "not_run"
    assert json_report["tests_passed"] is None
    assert json_report["validation_status"] == "passed"
    assert json_report["sandbox_test_status"] == "not_run"
    assert json_report["fix_verification_status"] == "not_run"
    assert sarif_properties["sandboxTestStatus"] == "not_run"
    assert sarif_properties["fixVerificationStatus"] == "not_run"


def test_partial_sandbox_application_is_distinct_from_passing_suite():
    report = ReviewReport(target_path="example.py", test_results=[
        RunResult(False, "apply_patch:example.py", "conflicting patch"),
        RunResult(True, "sandbox_test_suite", "passed on other applied patches"),
    ])

    json_report = report.to_dict()
    sarif_properties = report_to_sarif(report)["runs"][0]["properties"]

    assert json_report["test_status"] == "passed"
    assert json_report["validation_status"] == "failed"
    assert json_report["patch_application_status"] == "failed"
    assert sarif_properties["patchApplicationStatus"] == "failed"
