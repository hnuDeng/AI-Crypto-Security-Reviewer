"""Tests for the orchestrator (full pipeline integration)."""

import json
import pytest
from pathlib import Path
from ai_crypto_reviewer.config import PipelineConfig
from ai_crypto_reviewer.orchestrator import SecurityReviewPipeline
from ai_crypto_reviewer.exceptions import ConfigurationError


@pytest.fixture
def sample_project(tmp_path):
    """Create a small project with known vulnerabilities for integration testing."""
    project = tmp_path / "test_project"
    project.mkdir()

    (project / "vulnerable.py").write_text(
        'import hashlib\n'
        'password = "secret123"\n'
        'def bad():\n'
        '    return eval(input())\n'
        'def weak():\n'
        '    return hashlib.md5(b"x").hexdigest()\n',
        encoding="utf-8",
    )

    (project / "safe.py").write_text(
        'import hashlib\n'
        'def good():\n'
        '    return hashlib.sha256(b"x").hexdigest()\n',
        encoding="utf-8",
    )

    return str(project)


@pytest.fixture
def sample_c_project(tmp_path):
    """Create a small C project with known vulnerabilities."""
    project = tmp_path / "c_project"
    project.mkdir()

    (project / "main.c").write_text(
        '#include <stdio.h>\n'
        '#include <string.h>\n'
        '#include <stdlib.h>\n'
        '\n'
        'void unsafe(char* input) {\n'
        '    char buf[64];\n'
        '    strcpy(buf, input);\n'
        '    printf(buf);\n'
        '}\n'
        '\n'
        'int* leak() {\n'
        '    int* p = (int*)malloc(sizeof(int));\n'
        '    *p = 42;\n'
        '    return p;\n'
        '}\n',
        encoding="utf-8",
    )

    return str(project)


class TestSecurityReviewPipeline:
    def test_invalid_config(self):
        config = PipelineConfig()
        with pytest.raises(ConfigurationError):
            pipeline = SecurityReviewPipeline(config)
            pipeline.run()

    def test_full_pipeline_python(self, sample_project, tmp_path):
        config = PipelineConfig(
            target_path=sample_project,
            output_dir=str(tmp_path / "output"),
            language="python",
            auto_patch=True,
            run_tests=True,
            min_severity="info",
            verbose=False,
        )

        pipeline = SecurityReviewPipeline(config)
        report = pipeline.run()

        # Should find vulnerabilities
        assert len(report.findings) > 0

        # Should generate patches
        assert len(report.patches) > 0

        # Summary should be non-empty
        assert report.summary
        assert "Security Review Summary" in report.summary

        # Should have agent outputs
        assert "analyzer" in report.agent_outputs
        assert "coder" in report.agent_outputs

    def test_full_pipeline_c(self, sample_c_project, tmp_path):
        config = PipelineConfig(
            target_path=sample_c_project,
            output_dir=str(tmp_path / "output"),
            language="c",
            auto_patch=True,
            run_tests=False,  # Skip sandbox tests for C
            min_severity="info",
        )

        pipeline = SecurityReviewPipeline(config)
        report = pipeline.run()

        assert len(report.findings) > 0
        # Should detect C-specific issues
        rule_ids = {f.rule_id for f in report.findings}
        assert any(r.startswith("CSEC") for r in rule_ids)

    def test_save_report(self, sample_project, tmp_path):
        config = PipelineConfig(
            target_path=sample_project,
            output_dir=str(tmp_path / "output"),
            language="python",
            min_severity="medium",
        )

        pipeline = SecurityReviewPipeline(config)
        report = pipeline.run()
        report_path = pipeline.save_report(report)

        assert Path(report_path).exists()
        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)
        assert "findings" in data
        assert "total_findings" in data

    def test_no_patch_mode(self, sample_project, tmp_path):
        config = PipelineConfig(
            target_path=sample_project,
            output_dir=str(tmp_path / "output"),
            language="python",
            auto_patch=False,
            run_tests=False,
        )

        pipeline = SecurityReviewPipeline(config)
        report = pipeline.run()

        assert len(report.findings) > 0
        assert len(report.patches) == 0

    def test_report_to_dict(self, sample_project, tmp_path):
        config = PipelineConfig(
            target_path=sample_project,
            output_dir=str(tmp_path / "output"),
            language="python",
            min_severity="high",
        )

        pipeline = SecurityReviewPipeline(config)
        report = pipeline.run()
        d = report.to_dict()

        assert isinstance(d, dict)
        assert "total_findings" in d
        assert "critical_count" in d
        assert d["target_path"] == sample_project

    def test_findings_have_correct_fields(self, sample_project, tmp_path):
        config = PipelineConfig(
            target_path=sample_project,
            output_dir=str(tmp_path / "output"),
            language="python",
            min_severity="info",
        )

        pipeline = SecurityReviewPipeline(config)
        report = pipeline.run()

        for f in report.findings:
            assert f.rule_id
            assert f.severity
            assert f.message
            assert f.file_path
            assert f.line_number > 0
            assert f.tool
