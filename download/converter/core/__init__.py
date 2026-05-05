"""Converter core package."""
from .detector import (
    FormatID, FormatCategory, FormatInfo,
    detect_format, format_from_extension,
    get_category, get_extension,
    all_archive_formats, all_disk_formats,
)
from .dispatcher import (
    Dispatcher, ConversionError, UnsupportedConversion,
    MissingDependency, ConversionSupport,
)
from .dependencies import check_all, ensure_tool, DependencyReport, ToolInfo

__all__ = [
    "FormatID", "FormatCategory", "FormatInfo",
    "detect_format", "format_from_extension",
    "get_category", "get_extension",
    "all_archive_formats", "all_disk_formats",
    "Dispatcher", "ConversionError", "UnsupportedConversion",
    "MissingDependency", "ConversionSupport",
    "check_all", "ensure_tool", "DependencyReport", "ToolInfo",
]
