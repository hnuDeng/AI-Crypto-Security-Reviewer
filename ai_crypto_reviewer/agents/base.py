"""Base agent interface for the multi-agent pipeline."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentContext:
    """Shared context passed between agents in the pipeline."""
    target_path: str = ""
    language: str = "auto"
    source_files: list[str] = field(default_factory=list)
    source_cache: dict[str, str] = field(default_factory=dict)
    findings: list[Any] = field(default_factory=list)
    patches: list[Any] = field(default_factory=list)
    test_results: list[Any] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_source(self, file_path: str) -> str:
        """Get cached source code for a file."""
        if file_path not in self.source_cache:
            from pathlib import Path
            try:
                self.source_cache[file_path] = Path(file_path).read_text(encoding="utf-8", errors="replace")
            except Exception:
                self.source_cache[file_path] = ""
        return self.source_cache[file_path]


class BaseAgent(ABC):
    """Abstract base class for all pipeline agents."""

    def __init__(self, name: str, config: dict | None = None):
        self.name = name
        self.config = config or {}
        self.logger = logging.getLogger(f"agent.{name}")

    @abstractmethod
    def execute(self, context: AgentContext) -> AgentContext:
        """Execute the agent's work and return updated context."""
        ...

    def log(self, message: str, level: str = "info") -> None:
        getattr(self.logger, level)(f"[{self.name}] {message}")
