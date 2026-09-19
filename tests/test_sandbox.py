"""Tests for the sandbox environment."""

import os
import tempfile
import pytest
from pathlib import Path
from ai_crypto_reviewer.environment.sandbox import Sandbox


@pytest.fixture
def sample_project(tmp_path):
    """Create a sample project directory for testing."""
    project_dir = tmp_path / "sample_project"
    project_dir.mkdir()

    # Create a Python file
    (project_dir / "main.py").write_text(
        "def hello():\n    return 'world'\n",
        encoding="utf-8",
    )

    # Create a subdirectory with another file
    sub = project_dir / "utils"
    sub.mkdir()
    (sub / "helper.py").write_text(
        "def add(a, b):\n    return a + b\n",
        encoding="utf-8",
    )

    return str(project_dir)


class TestSandbox:
    def test_create_and_cleanup(self, sample_project):
        sandbox = Sandbox(sample_project)
        sandbox.create()
        assert sandbox.sandbox_path.exists()
        sandbox.cleanup_sandbox()
        assert sandbox._sandbox_dir is None

    def test_context_manager(self, sample_project):
        with Sandbox(sample_project) as sandbox:
            assert sandbox.sandbox_path.exists()
            copy_path = sandbox.get_sandbox_copy()
            assert copy_path.exists()
        # After context manager, sandbox should be cleaned up

    def test_get_sandbox_copy(self, sample_project):
        with Sandbox(sample_project) as sandbox:
            main_copy = sandbox.get_sandbox_copy("main.py")
            assert main_copy.exists()
            assert "hello" in main_copy.read_text()

    def test_read_file(self, sample_project):
        with Sandbox(sample_project) as sandbox:
            content = sandbox.read_file("main.py")
            assert "hello" in content
            assert "world" in content

    def test_apply_patch_to_file(self, sample_project):
        with Sandbox(sample_project) as sandbox:
            sandbox.apply_patch_to_file("main.py", "def hello():\n    return 'patched'\n")
            content = sandbox.read_file("main.py")
            assert "patched" in content
            # Original should not be affected
            original = Path(sample_project) / "main.py"
            assert "world" in original.read_text()

    def test_run_command(self, sample_project):
        with Sandbox(sample_project) as sandbox:
            output, rc = sandbox.run_command(["python", "-c", "print('sandbox works')"])
            assert "sandbox works" in output
            assert rc == 0

    def test_run_command_timeout(self, sample_project):
        with Sandbox(sample_project) as sandbox:
            output, rc = sandbox.run_command(["python", "-c", "import time; time.sleep(10)"], timeout=2)
            assert rc != 0  # Should timeout

    def test_python_test_no_tests(self, sample_project):
        with Sandbox(sample_project) as sandbox:
            output, rc = sandbox.run_python_tests(timeout=30)
            # No tests dir, should report not found or fail gracefully
            assert isinstance(output, str)

    def test_isolation(self, sample_project):
        """Verify that sandbox changes don't affect the original."""
        original_content = (Path(sample_project) / "main.py").read_text()
        with Sandbox(sample_project) as sandbox:
            sandbox.apply_patch_to_file("main.py", "MODIFIED CONTENT")
            modified_content = sandbox.read_file("main.py")
            assert "MODIFIED" in modified_content
        # Original unchanged
        assert (Path(sample_project) / "main.py").read_text() == original_content
