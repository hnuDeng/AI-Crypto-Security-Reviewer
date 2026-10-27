"""Tests for the sandbox environment."""

import os
import sys
import tempfile
import pytest
from pathlib import Path
from ai_crypto_reviewer.environment.sandbox import Sandbox
from ai_crypto_reviewer.exceptions import EnvironmentError


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

    def test_python_tests_use_current_interpreter(self, sample_project, monkeypatch):
        test_file = Path(sample_project) / "test_copy.py"
        test_file.write_text(
            "from pathlib import Path\n"
            "def test_patched_source():\n"
            "    assert 'patched' in Path('main.py').read_text(encoding='utf-8')\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("PATH", "")

        with Sandbox(sample_project) as sandbox:
            sandbox.apply_patch_to_file("main.py", "value = 'patched'\n")
            run_command = sandbox.run_command

            def run_with_current_interpreter(command, timeout):
                assert command[0] == sys.executable
                return run_command(command, timeout=timeout)

            monkeypatch.setattr(sandbox, "run_command", run_with_current_interpreter)
            output, exit_code = sandbox.run_python_tests(timeout=30)

        assert exit_code == 0, output
        assert "1 passed" in output
        assert "world" in (Path(sample_project) / "main.py").read_text(encoding="utf-8")

    def test_isolation(self, sample_project):
        """Verify that sandbox changes don't affect the original."""
        original_content = (Path(sample_project) / "main.py").read_text()
        with Sandbox(sample_project) as sandbox:
            sandbox.apply_patch_to_file("main.py", "MODIFIED CONTENT")
            modified_content = sandbox.read_file("main.py")
            assert "MODIFIED" in modified_content
        # Original unchanged
        assert (Path(sample_project) / "main.py").read_text() == original_content

    def test_absolute_patch_path_preserves_original(self, sample_project):
        original = Path(sample_project) / "utils" / "helper.py"
        original_content = original.read_text(encoding="utf-8")

        with Sandbox(sample_project) as sandbox:
            sandbox.apply_patch_to_file(str(original), "value = 'patched'\n")

            assert original.read_text(encoding="utf-8") == original_content
            assert sandbox.read_file("utils/helper.py") == "value = 'patched'\n"

    @pytest.mark.parametrize("file_path", ["../escaped.py", "../../escaped.py", "utils/../../escaped.py"])
    def test_rejects_path_traversal(self, sample_project, file_path):
        with Sandbox(sample_project) as sandbox:
            with pytest.raises(EnvironmentError):
                sandbox.get_sandbox_copy(file_path)

            with pytest.raises(EnvironmentError):
                sandbox.read_file(file_path)

    def test_rejects_absolute_path_outside_target(self, sample_project, tmp_path):
        outside = tmp_path / "outside.py"
        outside.write_text("value = 'original'\n", encoding="utf-8")

        with Sandbox(sample_project) as sandbox:
            with pytest.raises(EnvironmentError):
                sandbox.apply_patch_to_file(str(outside), "value = 'escaped'\n")

            with pytest.raises(EnvironmentError):
                sandbox.read_file(str(outside))

        assert outside.read_text(encoding="utf-8") == "value = 'original'\n"

    @pytest.mark.parametrize("absolute_path", [False, True])
    def test_single_file_patch_preserves_original(self, tmp_path, absolute_path):
        original = tmp_path / "module.py"
        original.write_text("value = 'original'\n", encoding="utf-8")
        patch_path = str(original) if absolute_path else original.name

        with Sandbox(str(original)) as sandbox:
            sandbox.apply_patch_to_file(patch_path, "value = 'patched'\n")

            assert original.read_text(encoding="utf-8") == "value = 'original'\n"
            assert sandbox.read_file(patch_path) == "value = 'patched'\n"
            assert sandbox.get_sandbox_copy().read_text(encoding="utf-8") == "value = 'patched'\n"

    def test_single_file_rejects_other_files(self, tmp_path):
        original = tmp_path / "module.py"
        original.write_text("value = 1\n", encoding="utf-8")

        with Sandbox(str(original)) as sandbox:
            with pytest.raises(EnvironmentError):
                sandbox.apply_patch_to_file("other.py", "value = 2\n")

    def test_single_file_command_uses_copy_directory(self, tmp_path):
        original = tmp_path / "module.py"
        original.write_text("value = 'original'\n", encoding="utf-8")

        with Sandbox(str(original)) as sandbox:
            output, exit_code = sandbox.run_command([
                sys.executable,
                "-c",
                "from pathlib import Path; print(Path('module.py').read_text())",
            ])

        assert exit_code == 0, output
        assert "value = 'original'" in output
