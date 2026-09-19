"""Multi-Agent Orchestrator - Coordinates the Analyzer -> Coder -> Tester pipeline.

This is the main entry point for the security review pipeline. It:
1. Validates configuration
2. Creates the shared agent context
3. Runs the Analyzer Agent to find vulnerabilities
4. Runs the Coder Agent to generate patches
5. Runs the Tester Agent to validate patches
6. Assembles the final ReviewReport
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from ai_crypto_reviewer.agents.analyzer import AnalyzerAgent
from ai_crypto_reviewer.agents.base import AgentContext
from ai_crypto_reviewer.agents.coder import CoderAgent
from ai_crypto_reviewer.agents.tester import ValidationAgent
from ai_crypto_reviewer.sarif_report import report_to_sarif, save_sarif_report
from ai_crypto_reviewer.config import PipelineConfig
from ai_crypto_reviewer.exceptions import ConfigurationError
from ai_crypto_reviewer.types import ReviewReport, Severity
from ai_crypto_reviewer.risk import compute_risk_score, risk_level


logger = logging.getLogger("orchestrator")


class SecurityReviewPipeline:
    """Multi-agent pipeline for security code review and auto-remediation.

    Architecture:
        Analyzer Agent -> Coder Agent -> Tester Agent

    The Analyzer scans code for vulnerabilities using static analysis,
    pattern matching, and external tools. The Coder generates patches
    based on findings. The Tester validates patches in a sandbox.
    """

    def __init__(self, config: PipelineConfig):
        self.config = config
        self._setup_logging()

        # Initialize agents with their specific configs
        self.analyzer = AnalyzerAgent(config={
            "min_severity": config.min_severity,
            "max_findings": config.max_findings,
            "run_flake8": config.tools.flake8_enabled,
            "run_bandit": config.tools.bandit_enabled,
            "run_cppcheck": config.tools.cppcheck_enabled,
        })
        self.coder = CoderAgent(config={
            "crypto_strict": config.crypto_strict_mode,
        })
        self.tester = ValidationAgent(config={
            "skip_sandbox": not config.run_tests,
            "timeout": config.tester.timeout_seconds,
        })

    def _setup_logging(self) -> None:
        level = logging.DEBUG if self.config.verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%H:%M:%S",
        )

    def run(self) -> ReviewReport:
        """Execute the full security review pipeline.

        Returns:
            ReviewReport with all findings, patches, and test results.
        """
        start_time = time.time()

        # Validate configuration
        errors = self.config.validate()
        if errors:
            raise ConfigurationError(f"Configuration errors: {'; '.join(errors)}")

        logger.info("=" * 60)
        logger.info("AI Crypto Security Reviewer - Starting Pipeline")
        logger.info(f"Target: {self.config.target_path}")
        logger.info("=" * 60)

        # Create shared context
        context = AgentContext(
            target_path=self.config.target_path,
            language=self.config.language,
        )

        report = ReviewReport(target_path=self.config.target_path)

        # Phase 1: Analysis
        logger.info("Phase 1/3: Security Analysis")
        try:
            context = self.analyzer.execute(context)
            report.findings = context.findings
            logger.info(f"  Found {len(context.findings)} security issues")
        except Exception as e:
            error_msg = f"Analyzer failed: {e}"
            logger.error(error_msg)
            report.errors.append(error_msg)

        # Phase 2: Patch Generation
        if self.config.auto_patch and context.findings:
            logger.info("Phase 2/3: Patch Generation")
            try:
                context = self.coder.execute(context)
                report.patches = context.patches
                logger.info(f"  Generated {len(context.patches)} patches")
            except Exception as e:
                error_msg = f"Coder failed: {e}"
                logger.error(error_msg)
                report.errors.append(error_msg)
        else:
            logger.info("Phase 2/3: Patch Generation (skipped)")

        # Phase 3: Testing
        if self.config.run_tests and context.patches:
            logger.info("Phase 3/3: Patch Validation")
            try:
                context = self.tester.execute(context)
                report.test_results = context.test_results
                passed = sum(1 for r in context.test_results if r.passed)
                logger.info(f"  Tests: {passed}/{len(context.test_results)} passed")
            except Exception as e:
                error_msg = f"Tester failed: {e}"
                logger.error(error_msg)
                report.errors.append(error_msg)
        else:
            logger.info("Phase 3/3: Patch Validation (skipped)")

        # Store agent outputs
        report.agent_outputs = {
            "analyzer": {"findings_count": len(report.findings)},
            "coder": {"patches_count": len(report.patches)},
            "tester": {"tests_count": len(report.test_results)},
        }
        report.errors.extend(context.errors)

        # Generate summary
        report.summary = self._generate_summary(report)

        elapsed = time.time() - start_time
        logger.info("=" * 60)
        logger.info(f"Pipeline complete in {elapsed:.1f}s")
        logger.info(f"  Findings: {len(report.findings)}")
        logger.info(f"  Critical: {len(report.critical_findings)}")
        logger.info(f"  Patches: {len(report.patches)}")
        logger.info(f"  Tests passed: {report.all_tests_passed}")
        logger.info("=" * 60)

        return report

    def _generate_summary(self, report: ReviewReport) -> str:
        """Generate a human-readable summary of the review."""
        lines = [
            "Security Review Summary",
            "=" * 40,
            f"Target: {report.target_path}",
            f"Total findings: {len(report.findings)}",
            "",
            "Severity breakdown:",
        ]

        severity_counts = {}
        for f in report.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(f"  {sev.value.upper():10s}: {count}")

        crypto_count = len(report.crypto_findings)
        if crypto_count > 0:
            lines.extend([
                "",
                f"Cryptographic issues: {crypto_count}",
            ])

        risk_score = compute_risk_score(report.findings)
        lines.extend([
            "",
            f"Risk score: {risk_score}/100 ({risk_level(risk_score)})",
        ])

        if report.patches:
            lines.extend([
                "",
                f"Patches generated: {len(report.patches)}",
            ])

        if report.test_results:
            passed = sum(1 for r in report.test_results if r.passed)
            total = len(report.test_results)
            lines.append(f"Tests: {passed}/{total} passed")

        if report.errors:
            lines.extend(["", "Errors:"] + [f"  - {e}" for e in report.errors])

        return "\n".join(lines)

    def save_report(self, report: ReviewReport, output_path: str = "") -> str:
        """Save the review report to a JSON file."""
        if not output_path:
            output_dir = Path(self.config.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = str(output_dir / "review_report.json")

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)

        logger.info(f"Report saved to: {output_path}")
        return output_path

    def save_sarif_report(self, report: ReviewReport, output_path: str = "") -> str:
        """Save the review report in SARIF format for CI/CD integration."""
        if not output_path:
            output_dir = Path(self.config.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = str(output_dir / "review_report.sarif")

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        save_sarif_report(report, output_path)
        logger.info(f"SARIF report saved to: {output_path}")
        return output_path
