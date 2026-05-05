"""
Universal File Converter
=======================
A professional-grade Python tool for converting between archive/compression
formats and disk image formats.

Architecture:
    - core/: Detection, dispatch, and conversion matrix
    - handlers/: Per-format-family handlers (archive, disk)
    - utils/: Logging, validation, dependency checking

Usage:
    python -m converter -i input.img -o output.qcow2
    python -m converter --extract archive.zip
    python -m converter --create archive.tar.gz folder/
"""

__version__ = "1.0.0"
__author__ = "Universal Converter Team"

import os
import sys

# Ensure the project root is on sys.path so `python -m converter` works
# from any working directory when the converter package lives on the path.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
