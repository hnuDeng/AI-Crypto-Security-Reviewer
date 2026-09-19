"""Tests for custom exceptions."""

import pytest
from ai_crypto_reviewer.exceptions import (
    ReviewerError,
    AnalysisError,
    PatchGenerationError,
    SecurityTestError,
    ConfigurationError,
    ToolNotFoundError,
    EnvironmentError,
    CryptoVerificationError,
)


class TestExceptions:
    def test_base_exception(self):
        with pytest.raises(ReviewerError):
            raise ReviewerError("base error")

    def test_analysis_error(self):
        with pytest.raises(AnalysisError):
            raise AnalysisError("analysis failed")
        with pytest.raises(ReviewerError):  # Inheritance
            raise AnalysisError("analysis failed")

    def test_patch_generation_error(self):
        with pytest.raises(PatchGenerationError):
            raise PatchGenerationError("patch failed")

    def test_test_execution_error(self):
        with pytest.raises(SecurityTestError):
            raise SecurityTestError("test failed")

    def test_configuration_error(self):
        with pytest.raises(ConfigurationError):
            raise ConfigurationError("config invalid")

    def test_tool_not_found_error(self):
        with pytest.raises(ToolNotFoundError):
            raise ToolNotFoundError("cppcheck not found")

    def test_environment_error(self):
        with pytest.raises(EnvironmentError):
            raise EnvironmentError("sandbox failed")

    def test_crypto_verification_error(self):
        with pytest.raises(CryptoVerificationError):
            raise CryptoVerificationError("crypto check failed")

    def test_inheritance_chain(self):
        """All custom exceptions should inherit from ReviewerError."""
        for exc_class in [
            AnalysisError, PatchGenerationError, SecurityTestError,
            ConfigurationError, ToolNotFoundError, EnvironmentError,
            CryptoVerificationError,
        ]:
            assert issubclass(exc_class, ReviewerError)
            assert issubclass(exc_class, Exception)

    def test_exception_message(self):
        try:
            raise AnalysisError("specific error message")
        except AnalysisError as e:
            assert str(e) == "specific error message"
