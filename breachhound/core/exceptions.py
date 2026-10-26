"""Business exceptions. Every expected failure maps to one of these."""

from __future__ import annotations


class BreachHoundError(Exception):
    """Base class for all expected errors."""

    exit_code = 1


class ConfigError(BreachHoundError):
    exit_code = 3


class TargetNotFoundError(BreachHoundError):
    exit_code = 4


class FileAccessError(BreachHoundError):
    """A file or directory could not be read."""


class ParseError(BreachHoundError):
    """Input could not be parsed."""


class ReportError(BreachHoundError):
    """A report could not be generated or written."""


class LLMError(BreachHoundError):
    """Base class for LLM provider failures."""

    retryable = False


class LLMTimeoutError(LLMError):
    retryable = True


class LLMConnectionError(LLMError):
    retryable = True


class LLMServerError(LLMError):
    retryable = True


class LLMAuthError(LLMError):
    pass


class LLMModelNotFoundError(LLMError):
    pass


class LLMResponseError(LLMError):
    pass


class LLMProviderError(LLMError):
    pass
