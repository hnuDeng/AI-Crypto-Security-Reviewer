"""CLI entry point for AI Crypto Security Reviewer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ai_crypto_reviewer.config import PipelineConfig
from ai_crypto_reviewer.orchestrator import SecurityReviewPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-crypto-reviewer",
        description="AI-powered multi-agent security code review system optimized for cryptographic implementations.",
    )
    parser.add_argument("target", help="Path to the source file or directory to review")
    parser.add_argument("-o", "--output", default="review_output", help="Output directory for reports")
    parser.add_argument("-l", "--language", default="auto", choices=["auto", "python", "cpp", "c"],
                        help="Source language (auto-detect by default)")
    parser.add_argument("--min-severity", default="info", choices=["info", "low", "medium", "high", "critical"],
                        help="Minimum severity level to report")
    parser.add_argument("--max-findings", type=int, default=500, help="Maximum number of findings to report")
    parser.add_argument("--no-patch", action="store_true", help="Skip patch generation")
    parser.add_argument("--no-test", action="store_true", help="Skip patch testing")
    parser.add_argument("--no-flake8", action="store_true", help="Disable flake8 analysis")
    parser.add_argument("--no-bandit", action="store_true", help="Disable bandit analysis")
    parser.add_argument("--no-cppcheck", action="store_true", help="Disable cppcheck analysis")
    parser.add_argument("--config", help="Path to YAML configuration file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--sarif", action="store_true", help="Also save a SARIF report for CI/CD integration")
    parser.add_argument("--version", action="version", version="AI Crypto Security Reviewer 1.0.0")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Build config from YAML if provided, otherwise from CLI args
    if args.config:
        config = PipelineConfig.from_yaml(args.config)
        config.target_path = args.target
    else:
        config = PipelineConfig(
            target_path=args.target,
            output_dir=args.output,
            language=args.language,
            min_severity=args.min_severity,
            max_findings=args.max_findings,
            auto_patch=not args.no_patch,
            run_tests=not args.no_test,
            verbose=args.verbose,
        )
        config.tools.flake8_enabled = not args.no_flake8
        config.tools.bandit_enabled = not args.no_bandit
        config.tools.cppcheck_enabled = not args.no_cppcheck

    # Validate
    errors = config.validate()
    if errors:
        for err in errors:
            print(f"Error: {err}", file=sys.stderr)
        return 1

    # Run pipeline
    pipeline = SecurityReviewPipeline(config)
    try:
        report = pipeline.run()
    except Exception as e:
        print(f"Pipeline error: {e}", file=sys.stderr)
        return 2

    # Save report
    report_path = pipeline.save_report(report)
    print(f"\nReport saved to: {report_path}")
    if args.sarif:
        sarif_path = pipeline.save_sarif_report(report)
        print(f"SARIF report saved to: {sarif_path}")

    # Print summary
    print("\n" + report.summary)

    # Exit code based on findings
    if report.critical_findings:
        return 3
    if report.high_findings:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
