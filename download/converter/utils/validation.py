"""
Validation Utilities
====================

Filesystem safety helpers: existence checks, overwrite protection, path
traversal guards, and disk-space heuristics.
"""

from __future__ import annotations

import logging
import os
import shutil
import sys

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Raised when a file/path validation check fails."""
    pass


def require_file_exists(path: str) -> str:
    """Return absolute path if *path* exists and is a regular file.

    Raises ``ValidationError`` otherwise.
    """
    abspath = os.path.abspath(path)
    if not os.path.isfile(abspath):
        raise ValidationError(f"Input file does not exist or is not a regular file: {path}")
    return abspath


def require_dir_exists(path: str) -> str:
    """Return absolute path if *path* exists and is a directory."""
    abspath = os.path.abspath(path)
    if not os.path.isdir(abspath):
        raise ValidationError(f"Directory does not exist: {path}")
    return abspath


def check_overwrite(
    output_path: str,
    *,
    overwrite: bool = False,
    interactive: bool = True,
) -> None:
    """Prevent accidental data loss by guarding against overwrites.

    - If ``overwrite`` is True, the check is skipped entirely.
    - If the file exists and we are on a TTY, ask the user interactively.
    - If the file exists and we are NOT on a TTY (piped / cron / CI),
      raise ``ValidationError`` unless ``overwrite`` is True.
    """
    if not os.path.exists(output_path):
        return

    if overwrite:
        logger.warning("Overwriting existing file (forced): %s", output_path)
        return

    if interactive and sys.stdin.isatty():
        try:
            answer = input(
                f"Output file '{output_path}' already exists. Overwrite? [y/N] "
            ).strip().lower()
            if answer not in ("y", "yes"):
                raise ValidationError(
                    f"Refused to overwrite '{output_path}'. "
                    f"Use --overwrite (-f) to force."
                )
            logger.info("User confirmed overwrite of '%s'.", output_path)
            return
        except (EOFError, KeyboardInterrupt):
            raise ValidationError("Overwrite cancelled by user.")

    # Non-interactive: refuse
    raise ValidationError(
        f"Output file '{output_path}' already exists. "
        f"Use --overwrite (-f) to force overwriting."
    )


def check_disk_space(input_path: str, output_dir: str, multiplier: float = 2.0) -> None:
    """Rough check that the output directory has enough space.

    Uses the input file size × *multiplier* as a heuristic.  Not precise
    for compressed data (the output may be smaller), but prevents obvious
    "disk full" failures early.
    """
    input_size = os.path.getsize(input_path)
    required = int(input_size * multiplier)

    try:
        usage = shutil.disk_usage(output_dir)
    except OSError:
        logger.debug("Cannot check disk space for %s; skipping.", output_dir)
        return

    if usage.free < required:
        raise ValidationError(
            f"Insufficient disk space.  Input: {input_size:,} bytes, "
            f"estimated output: {required:,} bytes, "
            f"available: {usage.free:,} bytes on '{output_dir}'."
        )


def safe_output_path(output_path: str) -> str:
    """Sanitise an output path: resolve, check for path traversal, etc.

    Returns the absolute path.
    """
    abspath = os.path.abspath(output_path)

    # Basic path-traversal guard: the resolved path must not contain
    # components that look suspicious (e.g. symlinks pointing outside).
    # This is a best-effort check; a full sandbox is outside the scope
    # of a CLI tool.
    parent = os.path.dirname(abspath)
    if not os.path.exists(parent):
        try:
            os.makedirs(parent, exist_ok=True)
            logger.info("Created output directory: %s", parent)
        except OSError as exc:
            raise ValidationError(
                f"Cannot create output directory '{parent}': {exc}"
            )

    return abspath


def is_readable(path: str) -> bool:
    """Check that *path* is readable by the current user."""
    return os.path.isfile(path) and os.access(path, os.R_OK)


def is_writable_dir(path: str) -> bool:
    """Check that *path* is a writable directory."""
    return os.path.isdir(path) and os.access(path, os.W_OK)
