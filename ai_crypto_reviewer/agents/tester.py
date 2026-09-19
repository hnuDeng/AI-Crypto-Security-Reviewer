"""Tester Agent - Validates patches by running tests in sandboxed environment.

This agent:
1. Creates a sandboxed copy of the codebase
2. Applies generated patches
3. Runs existing tests to verify no regressions
4. Runs security-specific validation tests
5. Reports test results back to the pipeline
"""

from __future__ import annotations

import time

from ai_crypto_reviewer.agents.base import AgentContext, BaseAgent
from ai_crypto_reviewer.environment.sandbox import Sandbox
from ai_crypto_reviewer.types import Patch, RunResult


class ValidationAgent(BaseAgent):
    """Agent responsible for validating patches through automated testing."""

    def __init__(self, config: dict | None = None):
        super().__init__("Tester", config)
        self._test_command = self.config.get("test_command", "")

    def execute(self, context: AgentContext) -> AgentContext:
        """Apply patches and run tests in sandbox."""
        self.log(f"Testing {len(context.patches)} patches")

        if not context.patches:
            self.log("No patches to test")
            context.test_results = []
            return context

        results: list[RunResult] = []

        # Test 1: Verify patches are valid diffs
        results.extend(self._validate_patch_syntax(context))

        # Test 2: Run in sandbox if target is a directory
        if not self.config.get("skip_sandbox", False):
            sandbox_results = self._test_in_sandbox(context)
            results.extend(sandbox_results)

        # Test 3: Verify fixes resolve the original findings
        if not self.config.get("skip_fix_verification", False):
            fix_results = self._verify_fixes(context)
            results.extend(fix_results)

        context.test_results = results
        passed = sum(1 for r in results if r.passed)
        self.log(f"Testing complete: {passed}/{len(results)} tests passed")
        return context
    def _validate_patch_syntax(self, context: AgentContext) -> list[RunResult]:
        """Validate that patches produce valid syntax."""
        results = []

        for patch in context.patches:
            start_time = time.time()
            try:
                if patch.file_path.endswith((".py", ".pyx")):
                    # Verify Python syntax
                    import ast
                    try:
                        ast.parse(patch.patched_code, filename=patch.file_path)
                        results.append(RunResult(
                            passed=True,
                            test_name=f"syntax_check:{patch.file_path}",
                            output="Python syntax is valid",
                            duration_seconds=time.time() - start_time,
                        ))
                    except SyntaxError as e:
                        results.append(RunResult(
                            passed=False,
                            test_name=f"syntax_check:{patch.file_path}",
                            output=f"Syntax error after patch: {e}",
                            duration_seconds=time.time() - start_time,
                        ))
                else:
                    # For non-Python files, just verify the patch is non-empty
                    results.append(RunResult(
                        passed=not patch.is_empty,
                        test_name=f"patch_validity:{patch.file_path}",
                        output="Patch is non-empty" if not patch.is_empty else "Patch is empty",
                        duration_seconds=time.time() - start_time,
                    ))
            except Exception as e:
                results.append(RunResult(
                    passed=False,
                    test_name=f"patch_validation:{patch.file_path}",
                    output=f"Validation error: {e}",
                    duration_seconds=time.time() - start_time,
                ))

        return results

    def _test_in_sandbox(self, context: AgentContext) -> list[RunResult]:
        """Apply all patches in a sandbox and run tests."""
        results = []
        start_time = time.time()

        try:
            with Sandbox(context.target_path) as sandbox:
                # Apply all patches
                applied_count = 0
                for patch in context.patches:
                    try:
                        sandbox.apply_patch_to_file(patch.file_path, patch.patched_code)
                        applied_count += 1
                    except Exception as e:
                        results.append(RunResult(
                            passed=False,
                            test_name=f"apply_patch:{patch.file_path}",
                            output=f"Failed to apply patch: {e}",
                        ))

                self.log(f"Applied {applied_count}/{len(context.patches)} patches to sandbox")

                # Run existing tests
                test_output, test_rc = sandbox.run_python_tests(
                    test_command=self._test_command,
                    timeout=self.config.get("timeout", 120),
                )

                results.append(RunResult(
                    passed=(test_rc == 0),
                    test_name="sandbox_test_suite",
                    output=test_output[:2000] if test_output else "No output",
                    exit_code=test_rc,
                    duration_seconds=time.time() - start_time,
                ))

                # Run syntax check on all patched Python files
                for patch in context.patches:
                    if patch.file_path.endswith(".py"):
                        check_output, check_rc = sandbox.run_command(
                            ["python", "-c", f"import ast; ast.parse(open('{patch.file_path}').read()); print('OK')"],
                            timeout=30,
                        )
                        results.append(RunResult(
                            passed=(check_rc == 0),
                            test_name=f"sandbox_syntax:{patch.file_path}",
                            output=check_output.strip(),
                            exit_code=check_rc,
                        ))

        except Exception as e:
            results.append(RunResult(
                passed=False,
                test_name="sandbox_setup",
                output=f"Sandbox error: {e}",
                duration_seconds=time.time() - start_time,
            ))

        return results
    def _verify_fixes(self, context: AgentContext) -> list[RunResult]:
        """Re-run analyzer on patched files to verify findings are resolved."""
        from ai_crypto_reviewer.tools.static_analyzer import PythonAnalyzer
        import time
        results = []
        analyzer = PythonAnalyzer()

        for patch in context.patches:
            if not patch.file_path.endswith(".py") or patch.is_empty:
                continue
            if patch.finding is None:
                continue

            start = time.time()
            patched_findings = analyzer.analyze(patch.file_path, patch.patched_code)
            original_rule = patch.finding.rule_id
            still_present = any(
                f.rule_id == original_rule and f.line_number == patch.finding.line_number
                for f in patched_findings
            )

            results.append(RunResult(
                passed=not still_present,
                test_name=f"fix_verify:{patch.file_path}:{original_rule}",
                output=f"Finding {original_rule} resolved" if not still_present else f"Finding {original_rule} still present",
                duration_seconds=time.time() - start,
            ))

        return results
