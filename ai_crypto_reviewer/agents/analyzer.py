"""Analyzer Agent - Scans code for security vulnerabilities.

This agent coordinates multiple static analysis tools and pattern-based checks
to identify security issues in source code, with special focus on:
- Cryptographic implementation weaknesses
- Memory safety issues (C/C++)
- Common vulnerability patterns (injection, hardcoded secrets, etc.)
- Algorithmic complexity issues in security-critical code
"""

from __future__ import annotations

import os
from pathlib import Path

from ai_crypto_reviewer.agents.base import AgentContext, BaseAgent
from ai_crypto_reviewer.tools.code_parser import detect_language, parse_python_file
from ai_crypto_reviewer.tools.static_analyzer import (
    CppAnalyzer,
    PythonAnalyzer,
    run_bandit,
    run_cppcheck,
    run_flake8,
)
from ai_crypto_reviewer.tools.crypto_checker import CryptoChecker
from ai_crypto_reviewer.tools.memory_checker import MemoryChecker
from ai_crypto_reviewer.types import Finding, Severity


class AnalyzerAgent(BaseAgent):
    """Agent responsible for comprehensive security analysis of source code.

    Performs multi-layered analysis:
    1. Pattern-based static analysis (regex + AST)
    2. External tool integration (cppcheck, flake8, bandit)
    3. Cryptographic implementation verification
    4. Memory safety analysis (C/C++)
    5. Code structure analysis
    """

    PYTHON_EXTENSIONS = {".py", ".pyx", ".pyi"}
    CPP_EXTENSIONS = {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".hxx"}

    def __init__(self, config: dict | None = None):
        super().__init__("Analyzer", config)
        self.python_analyzer = PythonAnalyzer()
        self.cpp_analyzer = CppAnalyzer()
        self.crypto_checker = CryptoChecker()
        self.memory_checker = MemoryChecker()
        self._min_severity = Severity[self.config.get("min_severity", "INFO").upper()]

    def execute(self, context: AgentContext) -> AgentContext:
        """Run all analysis passes on the target codebase."""
        self.log(f"Starting analysis of: {context.target_path}")
        all_findings: list[Finding] = []

        source_files = self._discover_source_files(context.target_path)
        context.source_files = source_files
        self.log(f"Discovered {len(source_files)} source files")

        for file_path in source_files:
            lang = detect_language(file_path)
            source = context.get_source(file_path)
            if not source.strip():
                continue

            file_findings = self._analyze_file(file_path, source, lang)
            all_findings.extend(file_findings)

        # Deduplicate findings
        all_findings = self._deduplicate(all_findings)

        # Filter by severity
        filtered = [f for f in all_findings if f.severity >= self._min_severity]

        # Limit total findings
        max_findings = self.config.get("max_findings", 500)
        if len(filtered) > max_findings:
            filtered = sorted(filtered, key=lambda f: list(Severity).index(f.severity), reverse=True)[:max_findings]

        context.findings = filtered
        self.log(f"Analysis complete: {len(filtered)} findings ({len(all_findings)} total before filtering)")
        return context

    def _discover_source_files(self, target_path: str) -> list[str]:
        """Discover all source files in the target path."""
        target = Path(target_path)
        all_extensions = self.PYTHON_EXTENSIONS | self.CPP_EXTENSIONS

        if target.is_file():
            return [str(target)]

        files = []
        skip_dirs = {
            "__pycache__", ".git", "node_modules", ".venv", "venv",
            ".tox", "dist", "build", ".eggs", "egg-info",
        }

        for root, dirs, filenames in os.walk(target):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in filenames:
                if Path(fname).suffix.lower() in all_extensions:
                    files.append(os.path.join(root, fname))

        return sorted(files)

    def _analyze_file(self, file_path: str, source: str, language: str) -> list[Finding]:
        """Run all relevant analyzers on a single file."""
        findings: list[Finding] = []

        # Layer 1: Language-specific pattern analysis
        if language == "python":
            findings.extend(self.python_analyzer.analyze(file_path, source))
        elif language in ("cpp", "c", "c_header", "cpp_header"):
            findings.extend(self.cpp_analyzer.analyze(file_path, source))

        # Layer 2: Cryptographic analysis (all languages)
        findings.extend(self.crypto_checker.analyze(file_path, source))

        # Layer 3: Memory safety analysis (C/C++ only)
        if language in ("cpp", "c", "c_header", "cpp_header"):
            findings.extend(self.memory_checker.analyze(file_path, source))

        # Layer 4: External tools (if enabled)
        if language == "python" and self.config.get("run_flake8", True):
            findings.extend(run_flake8(file_path))
        if language == "python" and self.config.get("run_bandit", True):
            findings.extend(run_bandit(file_path))
        if language in ("cpp", "c") and self.config.get("run_cppcheck", True):
            findings.extend(run_cppcheck(file_path))

        return findings

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings based on file+line+rule."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.file_path, f.line_number, f.rule_id)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
