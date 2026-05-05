"""
Structured Logging Setup
=========================

Configures the root logger for the converter package based on CLI
verbosity flags.  All modules use ``logging.getLogger(__name__)`` so
they inherit the configuration set here.

Log levels
----------
- ``-v`` / ``--verbose``   → INFO
- ``-vv`` / ``--debug``    → DEBUG
- default                   → WARNING

Error classification
--------------------
We define semantic log levels that the CLI can translate into exit codes:
- ``ERROR_UNSUPPORTED``  — format / conversion not supported
- ``ERROR_MISSING_DEP``  — external tool missing
- ``ERROR_FILE``         — file I/O / validation failure
- ``ERROR_CONVERSION``   — conversion logic failure
"""

from __future__ import annotations

import logging
import sys
from typing import Optional


# Semantic error codes (attached to LogRecords as ``record.error_code``)
ERROR_UNSUPPORTED = "unsupported_format"
ERROR_MISSING_DEP = "missing_dependency"
ERROR_FILE        = "file_error"
ERROR_CONVERSION  = "conversion_error"


class ErrorFilter(logging.Filter):
    """Attach an error code to records that look like specific error classes."""

    PATTERNS = {
        ERROR_UNSUPPORTED: ("not supported", "unsupported", "cannot convert"),
        ERROR_MISSING_DEP: ("not found on $PATH", "required tool", "install"),
        ERROR_FILE: ("does not exist", "not a regular file", "permission",
                      "Cannot read", "Cannot write", "disk space"),
        ERROR_CONVERSION: ("failed", "error while", "conversion"),
    }

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno < logging.ERROR:
            return True
        message = record.getMessage().lower()
        for code, keywords in self.PATTERNS.items():
            if any(kw in message for kw in keywords):
                record.error_code = code  # type: ignore[attr-defined]
                break
        return True


class ConsoleFormatter(logging.Formatter):
    """Colourised console formatter for development ergonomics.

    On non-TTY streams (pipes, CI), falls back to plain text.
    """

    _COLOURS = {
        logging.DEBUG:    "\033[36m",   # cyan
        logging.INFO:     "\033[32m",   # green
        logging.WARNING:  "\033[33m",   # yellow
        logging.ERROR:    "\033[31m",   # red
        logging.CRITICAL: "\033[1;31m", # bold red
    }
    _RESET = "\033[0m"

    def __init__(self, *, colour: bool = True):
        super().__init__()
        self._colour = colour and hasattr(sys.stderr, "isatty") and sys.stderr.isatty()

    def format(self, record: logging.LogRecord) -> str:
        # Build a compact:  [LEVEL] message
        level = record.levelname.ljust(7)
        if self._colour:
            c = self._COLOURS.get(record.levelno, "")
            formatted = f"{c}[{level}]{self._RESET} {record.getMessage()}"
        else:
            formatted = f"[{level}] {record.getMessage()}"

        # Append error code if present
        error_code = getattr(record, "error_code", None)
        if error_code:
            formatted += f"  ({error_code})"
        return formatted


def configure_logging(verbosity: int = 0) -> logging.Logger:
    """Set up the ``converter`` package logger based on verbosity.

    Parameters
    ----------
    verbosity : int
        0 → WARNING (default)
        1 → INFO  (-v)
        2 → DEBUG (-vv / --debug)

    Returns the root package logger.
    """
    root = logging.getLogger("converter")

    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity >= 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    root.setLevel(level)

    # Avoid adding duplicate handlers on repeated calls (e.g. in tests)
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(level)
        handler.setFormatter(ConsoleFormatter())
        handler.addFilter(ErrorFilter())
        root.addHandler(handler)

    return root
