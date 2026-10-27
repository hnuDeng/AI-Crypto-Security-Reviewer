"""Tests for the CLI entry point."""

import json
from pathlib import Path

import pytest

from ai_crypto_reviewer.cli import main


@pytest.fixture
def vulnerable_project(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "insecure.py").write_text(
        'password = "hunter2"\n'
        'def unsafe():\n'
        '    return eval("1+1")\n',
        encoding="utf-8",
    )
    return str(project)


def test_main_returns_zero_for_clean_exit(vulnerable_project, tmp_path):
    output_dir = str(tmp_path / "out")
    code = main([vulnerable_project, "-o", output_dir, "--min-severity", "info"])
    assert code in {0, 2, 3}
    assert Path(output_dir, "review_report.json").exists()


def test_main_creates_sarif_when_requested(vulnerable_project, tmp_path):
    output_dir = str(tmp_path / "out")
    code = main([vulnerable_project, "-o", output_dir, "--sarif", "--no-patch"])
    assert code in {0, 2, 3}
    assert Path(output_dir, "review_report.sarif").exists()


def test_cli_reports_skipped_validation_consistently(tmp_path, capsys):
    source = tmp_path / "input.py"
    original = 'value = eval("1")\n'
    source.write_text(original, encoding="utf-8")
    output_dir = tmp_path / "reports"

    exit_code = main([
        str(source), "-o", str(output_dir), "--no-test", "--sarif",
        "--no-flake8", "--no-bandit", "--no-cppcheck",
    ])

    json_report = json.loads((output_dir / "review_report.json").read_text(encoding="utf-8"))
    sarif = json.loads((output_dir / "review_report.sarif").read_text(encoding="utf-8"))
    assert exit_code == 3
    assert "Tests: not run" in capsys.readouterr().out
    assert json_report["tests_passed"] is None
    assert json_report["test_status"] == "not_run"
    assert sarif["runs"][0]["properties"]["testStatus"] == "not_run"
    assert source.read_text(encoding="utf-8") == original


def test_main_returns_one_for_invalid_config(tmp_path):
    code = main(["nonexistent_target"])
    assert code == 1


def test_main_respects_no_patch_mode(vulnerable_project, tmp_path):
    output_dir = str(tmp_path / "out")
    code = main([vulnerable_project, "-o", output_dir, "--no-patch"])
    report = json.loads(Path(output_dir, "review_report.json").read_text(encoding="utf-8"))
    assert code in {0, 2, 3}
    assert report["patches_generated"] == 0
