"""Custom exceptions for taint analysis system."""


class TaintAnalysisError(Exception):
    """Base exception for taint analysis errors."""

    pass


class LLMError(TaintAnalysisError):
    """Exception raised when LLM inference fails."""

    pass


class EmptyLLMResponseError(LLMError):
    """Raised when a provider returns a successful response without content."""

    pass


class TruncatedLLMResponseError(LLMError):
    """Raised when output tokens are exhausted before a usable answer."""

    pass


class ParsingError(TaintAnalysisError):
    """Exception raised when parsing code or LLM output fails."""

    pass


class VerificationError(TaintAnalysisError):
    """Exception raised when taint chain verification fails."""

    pass
