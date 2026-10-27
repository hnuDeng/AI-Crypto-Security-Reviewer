"""Run a small, hand-labeled regression check without external tools."""

import json
from importlib.resources import files

from ai_crypto_reviewer.tools.static_analyzer import CppAnalyzer, PythonAnalyzer


def evaluate_cases(cases):
    analyzers = {"python": PythonAnalyzer(), "c": CppAnalyzer()}
    results = []
    for case in cases:
        suffix = ".py" if case["language"] == "python" else ".c"
        findings = analyzers[case["language"]].analyze(case["id"] + suffix, case["source"])
        detected = any(finding.rule_id == case["rule_id"] for finding in findings)
        results.append({
            "id": case["id"],
            "language": case["language"],
            "rule_id": case["rule_id"],
            "expected": case["expected"],
            "detected": detected,
            "matched": detected == case["expected"],
        })

    summary = {
        "cases": len(results),
        "matched": sum(case["matched"] for case in results),
        "true_positives": sum(case["expected"] and case["detected"] for case in results),
        "true_negatives": sum(not case["expected"] and not case["detected"] for case in results),
        "false_positives": sum(not case["expected"] and case["detected"] for case in results),
        "false_negatives": sum(case["expected"] and not case["detected"] for case in results),
    }
    return {
        "mode": "synthetic_offline",
        "scope": "Handwritten rule-level regression cases; not real-world accuracy or security certification.",
        "summary": summary,
        "cases": results,
    }


def main():
    case_file = files("ai_crypto_reviewer").joinpath("data").joinpath("offline_cases.json")
    cases = json.loads(case_file.read_text(encoding="utf-8"))
    report = evaluate_cases(cases)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["summary"]["matched"] == report["summary"]["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
