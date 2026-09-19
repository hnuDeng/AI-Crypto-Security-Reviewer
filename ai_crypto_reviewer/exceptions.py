"""Custom exceptions for the AI Crypto Security Reviewer pipeline."""


class ReviewerError(Exception):
    """Base exception for all reviewer errors."""


class AnalysisError(ReviewerError):
    """Raised when code analysis fails."""


class PatchGenerationError(ReviewerError):
    """Raised when patch generation fails."""


class SecurityTestError(ReviewerError):
    """Raised when test execution fails unexpectedly."""


class ConfigurationError(ReviewerError):
    """Raised when configuration is invalid."""


class ToolNotFoundError(ReviewerError):
    """Raised when a required external tool is not installed."""


class EnvironmentError(ReviewerError):
    """Raised when the sandbox environment cannot be set up."""


class CryptoVerificationError(ReviewerError):
    """Raised when cryptographic verification fails."""
