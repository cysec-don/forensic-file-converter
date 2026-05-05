"""
Forensic File Converter
=======================
A professional-grade Python tool for converting between archive/compression
formats, disk image formats, and forensic image formats.

Author: Cysec Don | cysecdon@gmail.com

Architecture:
    - core/: Detection, dispatch, and conversion matrix
    - handlers/: Per-format-family handlers (archive, disk)
    - utils/: Logging, validation, dependency checking

Usage:
    python -m converter -i input.img -o output.qcow2
    python -m converter --extract archive.zip
    python -m converter --create archive.tar.gz folder/
    python -m converter -i mem.lime -o mem.raw
"""

__version__ = "1.0.0"
__author__ = "Cysec Don"
__email__ = "cysecdon@gmail.com"

import os
import sys

# Ensure the project root is on sys.path so `python -m converter` works
# from any working directory when the converter package lives on the path.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
