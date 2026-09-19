"""Memory safety analysis for C/C++ code."""

from __future__ import annotations

import re
from pathlib import Path

from ai_crypto_reviewer.types import Finding, Severity
from ai_crypto_reviewer.tools.static_analyzer import PythonAnalyzer


class MemoryChecker:
    """Analyzes C/C++ code for memory management issues."""

    def analyze(self, file_path: str, source: str = "") -> list[Finding]:
        if not source:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")

        findings: list[Finding] = []
        findings.extend(self._check_buffer_overflows(file_path, source))
        findings.extend(self._check_memory_leaks(file_path, source))
        findings.extend(self._check_use_after_free(file_path, source))
        findings.extend(self._check_null_dereference(file_path, source))
        findings.extend(self._check_format_strings(file_path, source))
        return findings

    def _check_buffer_overflows(self, file_path: str, source: str) -> list[Finding]:
        findings = []

        # Check for fixed-size buffers with unsafe operations
        buf_pattern = re.compile(r"(?:char|wchar_t)\s+(\w+)\s*\[\s*(\d+)\s*\]")
        for match in buf_pattern.finditer(source):
            buf_name = match.group(1)
            buf_size = int(match.group(2))
            line_num = source[:match.start()].count("\n") + 1

            if buf_size < 256:
                findings.append(Finding(
                    rule_id="MEM-BUF-SMALL",
                    severity=Severity.LOW,
                    message=f"Small fixed buffer '{buf_name}' ({buf_size} bytes) - verify all writes are bounded",
                    file_path=file_path,
                    line_number=line_num,
                    category="buffer_overflow",
                    tool="memory_checker",
                    recommendation=f"Verify all writes to '{buf_name}' are within {buf_size} byte bounds.",
                ))

        # Check for strcpy/strcat into named buffers
        unsafe_ops = [
            (r"strcpy\s*\(\s*(\w+)\s*,", "strcpy"),
            (r"strcat\s*\(\s*(\w+)\s*,", "strcat"),
            (r"sprintf\s*\(\s*(\w+)\s*,", "sprintf"),
        ]
        for pattern, op_name in unsafe_ops:
            for match in re.finditer(pattern, source):
                buf_name = match.group(1)
                line_num = source[:match.start()].count("\n") + 1
                findings.append(Finding(
                    rule_id=f"MEM-{op_name.upper()}",
                    severity=Severity.HIGH,
                    message=f"{op_name}() into '{buf_name}' without bounds checking",
                    file_path=file_path,
                    line_number=line_num,
                    category="buffer_overflow",
                    tool="memory_checker",
                    recommendation=f"Replace {op_name}() with {op_name.replace('str', 'strn') if 'str' in op_name else 'snprintf'}() with explicit size limit.",
                    cwe_id="CWE-120",
                ))

        return findings

    def _check_memory_leaks(self, file_path: str, source: str) -> list[Finding]:
        findings = []
        lines = source.splitlines()

        # Track malloc/calloc/realloc calls and verify corresponding free
        allocations = {}  # var_name -> line_num
        deallocations = set()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Detect allocations
            alloc_match = re.search(
                r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc|new(?:\s*\[\s*\d*\s*\])?)\s*\(",
                stripped,
            )
            if alloc_match:
                var = alloc_match.group(1)
                allocations[var] = i

            # Detect frees
            free_match = re.search(r"(?:free|delete(?:\s*\[\])?)\s*\(\s*(\w+)", stripped)
            if free_match:
                deallocations.add(free_match.group(1))

        for var, line_num in allocations.items():
            if var not in deallocations:
                findings.append(Finding(
                    rule_id="MEM-LEAK",
                    severity=Severity.MEDIUM,
                    message=f"Possible memory leak: '{var}' allocated but never freed",
                    file_path=file_path,
                    line_number=line_num,
                    category="memory_leak",
                    tool="memory_checker",
                    cwe_id="CWE-401",
                    recommendation=f"Ensure '{var}' is freed when no longer needed. Consider using smart pointers.",
                ))

        return findings

    def _check_use_after_free(self, file_path: str, source: str) -> list[Finding]:
        findings = []
        lines = source.splitlines()

        freed_vars: dict[str, int] = {}
        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Detect free
            free_match = re.search(r"free\s*\(\s*(\w+)\s*\)", stripped)
            if free_match:
                var = free_match.group(1)
                freed_vars[var] = i

                # Check if there's usage after this free in the same block
                remaining = "\n".join(lines[i:])
                usage_match = re.search(rf"\b{re.escape(var)}\s*(?:->|\.|\[|\)|;|\+|\-|\*|/)", remaining)
                if usage_match:
                    findings.append(Finding(
                        rule_id="MEM-UAF",
                        severity=Severity.CRITICAL,
                        message=f"Possible use-after-free: '{var}' used after being freed on line {i}",
                        file_path=file_path,
                        line_number=i + remaining[:usage_match.start()].count("\n") + 1,
                        category="use_after_free",
                        tool="memory_checker",
                        cwe_id="CWE-416",
                        recommendation=f"Set '{var} = NULL' after free() and check before use.",
                    ))

        return findings

    def _check_null_dereference(self, file_path: str, source: str) -> list[Finding]:
        findings = []
        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Detect malloc without NULL check
            if re.search(r"\w+\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(", stripped):
                # Check next line for NULL check
                if i < len(lines):
                    next_line = lines[i].strip() if i < len(lines) else ""
                    if not re.search(r"if\s*\(\s*!\s*\w+|if\s*\(\s*\w+\s*==\s*(?:NULL|nullptr|0)\s*\)", next_line):
                        findings.append(Finding(
                            rule_id="MEM-NULL",
                            severity=Severity.MEDIUM,
                            message="malloc() result not checked for NULL before use",
                            file_path=file_path,
                            line_number=i,
                            category="null_dereference",
                            tool="memory_checker",
                            cwe_id="CWE-476",
                            recommendation="Always check malloc() return value: if (ptr == NULL) { handle error }",
                        ))

        return findings

    def _check_format_strings(self, file_path: str, source: str) -> list[Finding]:
        findings = []
        for match in re.finditer(r"(?:printf|fprintf|sprintf)\s*\(\s*(\w+)\s*\)", source):
            line_num = source[:match.start()].count("\n") + 1
            findings.append(Finding(
                rule_id="MEM-FMTSTR",
                severity=Severity.HIGH,
                message="Format string is a variable - potential format string vulnerability",
                file_path=file_path,
                line_number=line_num,
                category="format_string",
                tool="memory_checker",
                cwe_id="CWE-134",
                recommendation="Use a literal format string or validate input before use as format.",
            ))
        return findings
