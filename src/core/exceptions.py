"""Custom exceptions for taint analysis system."""


class TaintAnalysisError(Exception):
    """Base exception for taint analysis errors."""

    pass


class LLMError(TaintAnalysisError):
    """Exception raised when LLM inference fails."""

    pass


class ParsingError(TaintAnalysisError):
    """Exception raised when parsing code or LLM output fails."""

    pass


class VerificationError(TaintAnalysisError):
    """Exception raised when taint chain verification fails."""

    pass
