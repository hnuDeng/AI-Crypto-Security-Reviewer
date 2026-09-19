"""SARIF (Static Analysis Results Interchange Format) report generation.

SARIF is an OASIS standard for representing static analysis results.
It is widely used in CI/CD pipelines (GitHub Code Scanning, Azure DevOps, etc.).
See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ai_crypto_reviewer.types import Finding, ReviewReport, Severity


SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

SARIF_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def finding_to_sarif_result(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to a SARIF result object."""
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": SARIF_LEVEL_MAP.get(finding.severity, "warning"),
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path.replace("\\", "/"),
                    },
                    "region": {
                        "startLine": max(1, finding.line_number),
                    },
                }
            }
        ],
    }

    if finding.end_line and finding.end_line > finding.line_number:
        result["locations"][0]["physicalLocation"]["region"]["endLine"] = finding.end_line

    if finding.code_snippet:
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": finding.code_snippet
        }

    if finding.cwe_id:
        result["properties"] = {"cwe": finding.cwe_id}

    if finding.recommendation:
        result["fixes"] = [
            {
                "description": {"text": finding.recommendation},
            }
        ]

    return result


def finding_to_sarif_rule(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to a SARIF rule descriptor."""
    rule: dict[str, Any] = {
        "id": finding.rule_id,
        "shortDescription": {"text": finding.message},
        "defaultConfiguration": {
            "level": SARIF_LEVEL_MAP.get(finding.severity, "warning"),
        },
    }

    if finding.category:
        rule["properties"] = {"tags": [finding.category]}

    if finding.cwe_id:
        if "properties" not in rule:
            rule["properties"] = {}
        if "tags" not in rule["properties"]:
            rule["properties"]["tags"] = []
        rule["properties"]["tags"].append(finding.cwe_id)

    return rule


def report_to_sarif(report: ReviewReport) -> dict[str, Any]:
    """Convert a ReviewReport to SARIF v2.1.0 format."""
    # Collect unique rules
    rules_seen: dict[str, dict] = {}
    results = []

    for finding in report.findings:
        if finding.rule_id not in rules_seen:
            rules_seen[finding.rule_id] = finding_to_sarif_rule(finding)
        results.append(finding_to_sarif_result(finding))

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI-Crypto-Security-Reviewer",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/hnuDeng/AI-Crypto-Security-Reviewer",
                        "rules": list(rules_seen.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": report.all_tests_passed,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                "results": results,
                "properties": {
                    "totalFindings": len(report.findings),
                    "criticalCount": len(report.critical_findings),
                    "highCount": len(report.high_findings),
                    "cryptoCount": len(report.crypto_findings),
                    "patchesGenerated": len(report.patches),
                    "summary": report.summary,
                },
            }
        ],
    }

    return sarif


def save_sarif_report(report: ReviewReport, output_path: str) -> str:
    """Save the review report in SARIF format."""
    sarif = report_to_sarif(report)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)
    return output_path
