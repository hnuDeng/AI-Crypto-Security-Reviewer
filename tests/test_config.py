"""Tests for configuration module."""

import os
import tempfile
import pytest
from pathlib import Path
from ai_crypto_reviewer.config import PipelineConfig, AgentConfig, ToolConfig


class TestPipelineConfig:
    def test_default_config(self):
        config = PipelineConfig()
        assert config.language == "auto"
        assert config.auto_patch is True
        assert config.run_tests is True
        assert config.verbose is False

    def test_validate_no_target(self):
        config = PipelineConfig()
        errors = config.validate()
        assert any("target_path is required" in e for e in errors)

    def test_validate_nonexistent_target(self):
        config = PipelineConfig(target_path="/nonexistent/path")
        errors = config.validate()
        assert any("does not exist" in e for e in errors)

    def test_validate_valid_target(self, tmp_path):
        target = tmp_path / "test.py"
        target.write_text("x = 1\n")
        config = PipelineConfig(target_path=str(target))
        errors = config.validate()
        assert len(errors) == 0

    def test_validate_invalid_severity(self, tmp_path):
        target = tmp_path / "test.py"
        target.write_text("x = 1\n")
        config = PipelineConfig(target_path=str(target), min_severity="invalid")
        errors = config.validate()
        assert any("min_severity" in e for e in errors)

    def test_from_yaml(self, tmp_path):
        yaml_content = """
target_path: /some/path
language: python
auto_patch: false
min_severity: high
verbose: true
tools:
  flake8_enabled: false
  bandit_enabled: true
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(yaml_content, encoding="utf-8")

        config = PipelineConfig.from_yaml(str(config_path))
        assert config.target_path == "/some/path"
        assert config.language == "python"
        assert config.auto_patch is False
        assert config.min_severity == "high"
        assert config.verbose is True
        assert config.tools.flake8_enabled is False
        assert config.tools.bandit_enabled is True

    def test_to_dict(self):
        config = PipelineConfig(target_path="/tmp/test")
        d = config.to_dict()
        assert d["target_path"] == "/tmp/test"
        assert "tools" in d
        assert "analyzer" in d

    def test_agent_config(self):
        ac = AgentConfig(enabled=True, max_retries=5, timeout_seconds=600)
        assert ac.enabled is True
        assert ac.max_retries == 5

    def test_tool_config_defaults(self):
        tc = ToolConfig()
        assert tc.cppcheck_enabled is True
        assert tc.flake8_enabled is True
        assert tc.bandit_enabled is True
        assert tc.memory_check_enabled is True
