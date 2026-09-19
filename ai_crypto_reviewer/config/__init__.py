"""Pipeline configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AgentConfig:
    """Configuration for a single agent."""
    enabled: bool = True
    max_retries: int = 3
    timeout_seconds: int = 300
    extra_args: dict[str, str] = field(default_factory=dict)


@dataclass
class ToolConfig:
    """Configuration for external security tools."""
    cppcheck_enabled: bool = True
    cppcheck_args: list[str] = field(default_factory=lambda: [
        "--enable=warning,performance,portability,information", "--inconclusive"
    ])
    flake8_enabled: bool = True
    bandit_enabled: bool = True
    memory_check_enabled: bool = True


@dataclass
class PipelineConfig:
    """Configuration for the entire security review pipeline."""
    target_path: str = ""
    output_dir: str = "review_output"
    language: str = "auto"

    # Agent configs
    analyzer: AgentConfig = field(default_factory=AgentConfig)
    coder: AgentConfig = field(default_factory=AgentConfig)
    tester: AgentConfig = field(default_factory=AgentConfig)

    # Tool configs
    tools: ToolConfig = field(default_factory=ToolConfig)

    # Pipeline behavior
    auto_patch: bool = True
    run_tests: bool = True
    max_findings: int = 500
    min_severity: str = "info"
    verbose: bool = False

    # Crypto-specific
    crypto_strict_mode: bool = True
    check_weak_algorithms: bool = True
    check_key_sizes: bool = True
    check_random_sources: bool = True

    def validate(self) -> list[str]:
        """Validate configuration, return list of errors."""
        errors = []
        if not self.target_path:
            errors.append("target_path is required")
        elif not Path(self.target_path).exists():
            errors.append(f"target_path does not exist: {self.target_path}")

        valid_severities = {"info", "low", "medium", "high", "critical"}
        if self.min_severity not in valid_severities:
            errors.append(f"min_severity must be one of {valid_severities}")

        valid_languages = {"auto", "python", "cpp", "c", "c++"}
        if self.language.lower() not in valid_languages:
            errors.append(f"language must be one of {valid_languages}")

        return errors

    @classmethod
    def from_yaml(cls, path: str) -> PipelineConfig:
        """Load config from a YAML file."""
        import yaml
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        config = cls()
        if "target_path" in data:
            config.target_path = data["target_path"]
        if "output_dir" in data:
            config.output_dir = data["output_dir"]
        if "language" in data:
            config.language = data["language"]
        if "auto_patch" in data:
            config.auto_patch = data["auto_patch"]
        if "run_tests" in data:
            config.run_tests = data["run_tests"]
        if "verbose" in data:
            config.verbose = data["verbose"]
        if "min_severity" in data:
            config.min_severity = data["min_severity"]
        if "max_findings" in data:
            config.max_findings = data["max_findings"]
        if "crypto_strict_mode" in data:
            config.crypto_strict_mode = data["crypto_strict_mode"]
        if "check_weak_algorithms" in data:
            config.check_weak_algorithms = data["check_weak_algorithms"]
        if "check_key_sizes" in data:
            config.check_key_sizes = data["check_key_sizes"]
        if "check_random_sources" in data:
            config.check_random_sources = data["check_random_sources"]

        for section, attr in [("analyzer", "analyzer"), ("coder", "coder"), ("tester", "tester")]:
            if section in data and isinstance(data[section], dict):
                cfg = getattr(config, attr)
                for k, v in data[section].items():
                    if hasattr(cfg, k):
                        setattr(cfg, k, v)

        if "tools" in data and isinstance(data["tools"], dict):
            for k, v in data["tools"].items():
                if hasattr(config.tools, k):
                    setattr(config.tools, k, v)

        return config

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)
