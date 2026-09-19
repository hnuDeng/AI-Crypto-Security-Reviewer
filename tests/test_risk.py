"""Tests for risk scoring utilities."""

from ai_crypto_reviewer.types import Finding, Severity, ReviewReport
from ai_crypto_reviewer.risk import compute_risk_score, risk_level


def test_compute_risk_score_caps_at_100():
    findings = [Finding(rule_id="R", severity=Severity.CRITICAL, message="x", file_path="f.py", line_number=i) for i in range(20)]
    assert compute_risk_score(findings) == 100


def test_compute_risk_score_returns_zero_for_empty():
    assert compute_risk_score([]) == 0


def test_risk_level_thresholds():
    assert risk_level(0) == "Informational"
    assert risk_level(19) == "Informational"
    assert risk_level(20) == "Low"
    assert risk_level(40) == "Medium"
    assert risk_level(60) == "High"
    assert risk_level(80) == "Critical"


def test_review_report_to_dict_includes_risk_fields():
    findings = [
        Finding(rule_id="R1", severity=Severity.HIGH, message="x", file_path="f.py", line_number=1),
        Finding(rule_id="R2", severity=Severity.HIGH, message="y", file_path="f.py", line_number=2),
        Finding(rule_id="R3", severity=Severity.MEDIUM, message="z", file_path="f.py", line_number=3),
    ]
    report = ReviewReport(target_path="t", findings=findings)
    data = report.to_dict()
    assert data["risk_score"] == 18
    assert data["risk_level"] == "Informational"
    assert report.summary == ""


def test_summary_contains_risk_score(tmp_path):
    project = tmp_path / "p"
    project.mkdir()
    (project / "a.py").write_text('password = "x"\n', encoding="utf-8")
    from ai_crypto_reviewer.config import PipelineConfig
    from ai_crypto_reviewer.orchestrator import SecurityReviewPipeline

    config = PipelineConfig(target_path=str(project), min_severity="info", auto_patch=False, run_tests=False)
    report = SecurityReviewPipeline(config).run()
    assert "Risk score:" in report.summary
