"""Sandbox environment for safe code analysis and patch testing."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ai_crypto_reviewer.exceptions import EnvironmentError


class Sandbox:
    """Provides an isolated environment for analyzing and testing code patches.

    Creates a temporary copy of the target directory so that modifications
    during patch testing don't affect the original codebase.
    """

    def __init__(self, target_path: str, cleanup: bool = True):
        self.target_path = Path(target_path).resolve()
        self.cleanup = cleanup
        self._sandbox_dir: Path | None = None
        self._original_cwd = os.getcwd()

    @property
    def sandbox_path(self) -> Path:
        if self._sandbox_dir is None:
            raise EnvironmentError("Sandbox not initialized. Call create() first.")
        return self._sandbox_dir

    def create(self) -> Path:
        """Create sandbox by copying target to a temporary directory."""
        if not self.target_path.exists():
            raise EnvironmentError(f"Target path does not exist: {self.target_path}")

        self._sandbox_dir = Path(tempfile.mkdtemp(prefix="crypto_review_"))

        if self.target_path.is_file():
            dest = self._sandbox_dir / self.target_path.name
            shutil.copy2(self.target_path, dest)
        else:
            # Copy directory, excluding common large/irrelevant dirs
            dest = self._sandbox_dir / self.target_path.name
            shutil.copytree(
                self.target_path,
                dest,
                ignore=shutil.ignore_patterns(
                    "__pycache__", ".git", "node_modules", ".venv", "venv",
                    "*.pyc", ".tox", "*.egg-info", "dist", "build",
                ),
            )

        return self.sandbox_path

    def get_sandbox_copy(self, relative_path: str = "") -> Path:
        """Get the path to a file/directory within the sandbox."""
        if not self._sandbox_dir:
            raise EnvironmentError("Sandbox not initialized.")
        if relative_path:
            return self._sandbox_dir / self.target_path.name / relative_path
        return self._sandbox_dir / self.target_path.name

    def apply_patch_to_file(self, file_path: str, new_content: str) -> None:
        """Write new content to a file within the sandbox."""
        sandbox_file = self.get_sandbox_copy(file_path)
        sandbox_file.parent.mkdir(parents=True, exist_ok=True)
        sandbox_file.write_text(new_content, encoding="utf-8")

    def read_file(self, file_path: str) -> str:
        """Read a file from the sandbox."""
        sandbox_file = self.get_sandbox_copy(file_path)
        return sandbox_file.read_text(encoding="utf-8", errors="replace")

    def run_command(self, cmd: str | list[str], timeout: int = 120, cwd: str = "") -> tuple[str, int]:
        """Run a command within the sandbox directory."""
        work_dir = self.get_sandbox_copy(cwd) if cwd else self.get_sandbox_copy()
        try:
            if isinstance(cmd, str):
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True,
                    timeout=timeout, cwd=str(work_dir),
                    encoding="utf-8", errors="replace",
                )
            else:
                result = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=timeout, cwd=str(work_dir),
                    encoding="utf-8", errors="replace",
                )
            return result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "[command timed out]", -1
        except FileNotFoundError as e:
            return f"[command not found: {e}]", -2

    def run_python_tests(self, test_command: str = "", timeout: int = 120) -> tuple[str, int]:
        """Run Python tests in the sandbox."""
        if test_command:
            return self.run_command(test_command, timeout=timeout)

        # Try pytest first, then unittest
        for cmd in [
            ["python", "-m", "pytest", "--tb=short", "-q"],
            ["python", "-m", "pytest", "--tb=short", "-q", "tests/"],
            ["python", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
            ["python", "-m", "unittest", "discover"],
        ]:
            output, rc = self.run_command(cmd, timeout=timeout)
            if rc >= 0:
                return output, rc

        return "No test runner found (pytest/unittest)", -1

    def cleanup_sandbox(self) -> None:
        """Remove the sandbox directory."""
        if self._sandbox_dir and self._sandbox_dir.exists():
            try:
                shutil.rmtree(self._sandbox_dir, ignore_errors=True)
            except Exception:
                pass
            self._sandbox_dir = None

    def __enter__(self) -> Sandbox:
        self.create()
        return self

    def __exit__(self, *args) -> None:
        if self.cleanup:
            self.cleanup_sandbox()
