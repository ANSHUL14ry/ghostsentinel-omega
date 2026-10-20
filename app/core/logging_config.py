"""
GHOSTSENTINEL Ω — Structured Logging
Redacts sensitive fields before any log output.
"""
import logging
import re
import sys
from typing import Any

# Fields to redact from log messages
SENSITIVE_PATTERNS = [
    re.compile(r'(password["\s:=]+)([^\s"&,}\]]+)', re.IGNORECASE),
    re.compile(r'(secret["\s:=]+)([^\s"&,}\]]+)', re.IGNORECASE),
    re.compile(r'(token["\s:=]+)([^\s"&,}\]]+)', re.IGNORECASE),
    re.compile(r'(key["\s:=]+)([^\s"&,}\]]+)', re.IGNORECASE),
]


try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


class RedactingFormatter(logging.Formatter):
    """Log formatter that strips sensitive values from messages."""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        for pattern in SENSITIVE_PATTERNS:
            msg = pattern.sub(r'\1[REDACTED]', msg)
        return msg


def get_logger(name: str) -> logging.Logger:
    """Return a named logger with sensitive-data redaction."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            RedactingFormatter(
                fmt="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
