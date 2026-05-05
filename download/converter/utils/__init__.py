"""Converter utilities package."""
from .logging import configure_logging, ERROR_UNSUPPORTED, ERROR_MISSING_DEP, ERROR_FILE, ERROR_CONVERSION
from .validation import (
    require_file_exists, require_dir_exists,
    check_overwrite, check_disk_space,
    safe_output_path, is_readable, is_writable_dir,
    ValidationError,
)

__all__ = [
    "configure_logging", "ERROR_UNSUPPORTED", "ERROR_MISSING_DEP",
    "ERROR_FILE", "ERROR_CONVERSION",
    "require_file_exists", "require_dir_exists",
    "check_overwrite", "check_disk_space",
    "safe_output_path", "is_readable", "is_writable_dir",
    "ValidationError",
]
