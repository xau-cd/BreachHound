"""Logging setup with secret redaction."""

from __future__ import annotations

import logging
import re

_SECRET_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        r"(?i)\b(api[_-]?key|access[_-]?token|client[_-]?secret|authorization|x-api-key)"
        r"(\s*[:=]\s*)[\x27\x22]?[^\s\x27\x22&,;]{6,}"
    ),
)


def redact_secrets(text: str) -> str:
    """Mask well-known secret formats (API keys, bearer tokens)."""
    for index, pattern in enumerate(_SECRET_PATTERNS):
        if index < 3:
            text = pattern.sub("***REDACTED***", text)
        else:
            text = pattern.sub(r"\1\2***REDACTED***", text)
    return text


class RedactingFilter(logging.Filter):
    """Never let a secret reach a log handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_secrets(str(record.getMessage()))
        record.args = None
        return True


def setup_logging(verbose: bool = False, debug: bool = False) -> logging.Logger:
    """Configure the ``breachhound`` logger (stderr)."""
    logger = logging.getLogger("breachhound")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING)
    logger.propagate = False
    return logger
