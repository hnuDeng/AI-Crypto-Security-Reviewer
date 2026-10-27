"""Tester Agent - Validates patches by running tests in sandboxed environment.

This agent:
1. Creates a sandboxed copy of the codebase
2. Applies generated patches
3. Runs existing tests to verify no regressions
4. Runs security-specific validation tests
5. Reports test results back to the pipeline
"""

from __future__ import annotations

import ast
import sys
import time
from collections import Counter
from dataclasses import replace
from difflib import SequenceMatcher
from pathlib import Path

from ai_crypto_reviewer.agents.base import AgentContext, BaseAgent
from ai_crypto_reviewer.environment.sandbox import Sandbox
from ai_crypto_reviewer.types import Patch, RunResult


def _combine_patches(patches: list[Patch]) -> str:
    original = patches[0].original_code
    if any(patch.original_code != original for patch in patches):
        raise ValueError("conflicting patches have different original versions")
    original_lines = original.splitlines(keepends=True)
    changes = []
    for patch in patches:
        patched_lines = patch.patched_code.splitlines(keepends=True)
        matcher = SequenceMatcher(None, original_lines, patched_lines, autojunk=False)
        for tag, original_start, original_end, patched_start, patched_end in matcher.get_opcodes():
            if tag != "equal":
                changes.append((original_start, original_end, patched_lines[patched_start:patched_end]))

    changes.sort(key=lambda change: (change[0], change[1]))
    for previous, current in zip(changes, changes[1:]):
        previous_start, previous_end, _ = previous
        current_start, current_end, _ = current
        overlapping = current_start < previous_end
        same_insertion = previous_start == previous_end == current_start == current_end
        insertion_boundary = (
            previous_start == previous_end and current_start <= previous_start <= current_end
        ) or (
            current_start == current_end and previous_start <= current_start <= previous_end
        )
        if overlapping or same_insertion or insertion_boundary:
            raise ValueError("conflicting patches overlap in the same file")

    combined = []
    position = 0
    for start, end, replacement in changes:
        combined.extend(original_lines[position:start])
        combined.extend(replacement)
        position = end
    combined.extend(original_lines[position:])
    return "".join(combined)


def _combine_for_rescan(context: AgentContext) -> dict[int, str]:
    target = Path(context.target_path).resolve()
    root = target if target.is_dir() else target.parent
    groups = {}
    for patch in context.patches:
        path = Path(patch.file_path)
        target_file = path.resolve() if path.is_absolute() else (root / path).resolve()
        groups.setdefault(target_file, []).append(patch)

    combined_codes = {}
    for patches in groups.values():
        try:
            combined = _combine_patches(patches)
        except ValueError:
            continue
        for patch in patches:
            combined_codes[id(patch)] = combined
    return combined_codes


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
        applied_codes = None
        if not self.config.get("skip_sandbox", False):
            sandbox_results, applied_codes = self._test_in_sandbox(context)
            results.extend(sandbox_results)
        else:
            applied_codes = _combine_for_rescan(context)

        # Test 3: Verify fixes resolve the original findings
        if not self.config.get("skip_fix_verification", False):
            fix_results = self._verify_fixes(context, applied_codes)
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

    def _test_in_sandbox(self, context: AgentContext) -> tuple[list[RunResult], dict[int, str]]:
        """Apply all patches in a sandbox and run tests."""
        results = []
        applied_codes: dict[int, str] = {}
        start_time = time.time()

        try:
            with Sandbox(context.target_path) as sandbox:
                applied_patches: list[Patch] = []
                patch_groups = {}
                for patch in context.patches:
                    try:
                        sandbox_file = sandbox.get_sandbox_copy(patch.file_path)
                        patch_groups.setdefault(sandbox_file, []).append(patch)
                    except Exception as e:
                        results.append(RunResult(
                            passed=False,
                            test_name=f"apply_patch:{patch.file_path}",
                            output=f"Failed to apply patch: {e}",
                        ))

                for sandbox_file, patches in patch_groups.items():
                    try:
                        existing = sandbox_file.read_text(encoding="utf-8") if sandbox_file.exists() else ""
                        if existing != patches[0].original_code:
                            raise ValueError("conflicting patch: original source differs from sandbox copy")
                        combined = _combine_patches(patches)
                        sandbox.apply_patch_to_file(patches[0].file_path, combined)
                        applied_patches.extend(patches)
                        for patch in patches:
                            applied_codes[id(patch)] = combined
                            results.append(RunResult(
                                passed=True,
                                test_name=f"apply_patch:{patch.file_path}",
                                output="Applied to sandbox copy",
                            ))
                    except Exception as e:
                        for patch in patches:
                            results.append(RunResult(
                                passed=False,
                                test_name=f"apply_patch:{patch.file_path}",
                                output=f"Failed to apply patch: {e}",
                            ))

                self.log(f"Applied {len(applied_patches)}/{len(context.patches)} patches to sandbox")

                # Run existing tests
                if applied_patches:
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
                for patch in applied_patches:
                    if patch.file_path.endswith(".py"):
                        sandbox_file = sandbox.get_sandbox_copy(patch.file_path)
                        check_output, check_rc = sandbox.run_command(
                            [
                                sys.executable,
                                "-c",
                                "import ast, pathlib, sys; "
                                "source = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'); "
                                "ast.parse(source, filename=sys.argv[1]); print('OK')",
                                str(sandbox_file),
                            ],
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

        return results, applied_codes
    def _verify_fixes(self, context: AgentContext, applied_codes: dict[int, str] | None = None) -> list[RunResult]:
        """Re-run analyzer on patched files to verify findings are resolved."""
        from ai_crypto_reviewer.tools.static_analyzer import PythonAnalyzer
        results = []
        analyzer = PythonAnalyzer()

        for patch in context.patches:
            start = time.time()
            original_rule = patch.finding.rule_id if patch.finding else "unlinked"
            result_name = f"fix_verify:{patch.file_path}:{original_rule}"
            if applied_codes is not None and id(patch) not in applied_codes:
                output = f"Finding {original_rule} is unverified: patch could not be combined or applied"
                passed = False
            elif patch.finding is None:
                output = "Patch is unverified: no original finding was provided"
                passed = False
            elif patch.kind == "warning":
                output = f"Warning only; finding {original_rule} is unverified"
                passed = False
            elif not patch.file_path.endswith(".py") or patch.is_empty or not patch.original_code:
                output = f"Finding {original_rule} is unverified: no supported changed Python source"
                passed = False
            else:
                if applied_codes is not None:
                    patch = replace(patch, patched_code=applied_codes[id(patch)])
                try:
                    syntax_tree = ast.parse(patch.patched_code, filename=patch.file_path)
                except (SyntaxError, ValueError):
                    results.append(RunResult(
                        passed=False,
                        test_name=result_name,
                        output=f"Finding {original_rule} is unverified: patched Python is invalid",
                        duration_seconds=time.time() - start,
                    ))
                    continue
                original_findings = [
                    finding for finding in analyzer.analyze(patch.file_path, patch.original_code)
                    if finding.rule_id == original_rule
                ]
                target_line = patch.finding.line_number
                if not any(finding.line_number == target_line for finding in original_findings):
                    output = f"Finding {original_rule} is unverified: original finding was not reproduced"
                    passed = False
                else:
                    patched_findings = [
                        finding for finding in (
                            analyzer.analyze(patch.file_path, patch.patched_code)
                            if patch.patched_code else []
                        ) if finding.rule_id == original_rule
                    ]
                    original_lines = patch.original_code.splitlines()
                    patched_lines = patch.patched_code.splitlines()
                    target_source = original_lines[target_line - 1] if 0 < target_line <= len(original_lines) else ""
                    ambiguous_duplicate = bool(target_source) and original_lines.count(target_source) > 1 and (
                        original_lines.count(target_source) != patched_lines.count(target_source)
                    )
                    direct_eval_calls = {
                        id(node.func) for node in ast.walk(syntax_tree)
                        if isinstance(node, ast.Call)
                        and ((isinstance(node.func, ast.Name) and node.func.id == "eval")
                             or (isinstance(node.func, ast.Attribute) and node.func.attr == "eval"))
                    }
                    aliased_eval = original_rule == "SEC101" and any(
                        (isinstance(node, ast.ImportFrom) and node.module == "builtins"
                         and any(alias.name == "eval" for alias in node.names))
                        or (isinstance(node, ast.Name) and node.id == "eval" and id(node) not in direct_eval_calls)
                        or (isinstance(node, ast.Attribute) and node.attr == "eval" and id(node) not in direct_eval_calls)
                        for node in ast.walk(syntax_tree)
                    )
                    line_map = {}
                    matcher = SequenceMatcher(None, original_lines, patched_lines, autojunk=False)
                    for tag, original_start, original_end, patched_start, _ in matcher.get_opcodes():
                        if tag == "equal":
                            for offset in range(original_end - original_start):
                                line_map[original_start + offset + 1] = patched_start + offset + 1

                    mapped_target = line_map.get(target_line)
                    if ambiguous_duplicate or aliased_eval:
                        output = f"Finding {original_rule} is unverified: ambiguous source mapping or unsafe alias"
                        passed = False
                    elif mapped_target is not None and any(
                        finding.line_number == mapped_target for finding in patched_findings
                    ):
                        output = f"Finding {original_rule} still present"
                        passed = False
                    else:
                        other_findings = Counter(
                            line_map[finding.line_number]
                            for finding in original_findings
                            if finding.line_number != target_line and finding.line_number in line_map
                        )
                        patched_counts = Counter(finding.line_number for finding in patched_findings)
                        if any(count > other_findings[line] for line, count in patched_counts.items()):
                            output = f"Finding {original_rule} is unverified: remaining matches cannot be mapped reliably"
                            passed = False
                        else:
                            output = f"Rule {original_rule} no longer detected at mapped target; security correctness is unverified"
                            passed = True

            results.append(RunResult(
                passed=passed,
                test_name=result_name,
                output=output,
                duration_seconds=time.time() - start,
            ))

        return results
