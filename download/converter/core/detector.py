"""
Format Detection Module
=======================
Detects file formats using a layered strategy:

1. **Extension lookup** (fast path) — maps common extensions to format IDs.
2. **Magic bytes** (reliable path) — reads the first N bytes and matches
   against a signature table.

Both layers feed into a single ``FormatInfo`` that the dispatcher uses to
route the file to the correct handler.

Design decisions
----------------
- No third-party dependency on ``python-magic``: we ship our own compact
  signature table so the tool works on any system with a standard CPython
  install.
- Compound extensions (``.tar.gz``, ``.tar.bz2``, ``.tar.xz``) are
  canonicalised before lookup so that ``file.tar.gz`` is detected as
  ``tar_gz``, not ``gz``.
- Detection is *lenient by default*: if magic bytes and extension disagree,
  the magic bytes win (they are harder to spoof), but the discrepancy is
  logged at WARNING level.
"""

from __future__ import annotations

import enum
import logging
import os
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Format taxonomy
# ---------------------------------------------------------------------------

class FormatCategory(enum.Enum):
    """High-level category used by the dispatcher."""
    ARCHIVE = "archive"
    DISK_IMAGE = "disk_image"
    UNKNOWN = "unknown"


class FormatID(enum.Enum):
    """Concrete format identifier.  Each value maps to exactly one handler."""

    # -- archive / compression ------------------------------------------
    ZIP = "zip"
    RAR = "rar"
    SEVEN_ZIP = "7z"
    TAR = "tar"
    GZIP = "gz"
    BZIP2 = "bz2"
    XZ = "xz"
    CAB = "cab"
    TAR_GZ = "tar.gz"
    TAR_BZ2 = "tar.bz2"
    TAR_XZ = "tar.xz"

    # -- disk images -----------------------------------------------------
    ISO = "iso"
    IMG = "img"
    RAW = "raw"
    DD = "dd"
    BIN = "bin"
    VHD = "vhd"
    VHDX = "vhdx"
    VMDK = "vmdk"
    QCOW2 = "qcow2"
    DMG = "dmg"


# ---------------------------------------------------------------------------
# Magic-byte signatures
# ---------------------------------------------------------------------------

# Each entry: (offset, signature_bytes, FormatID)
_MAGIC_SIGNATURES: List[Tuple[int, bytes, FormatID]] = [
    # Archives
    (0, b"PK\x03\x04",          FormatID.ZIP),
    (0, b"PK\x05\x06",          FormatID.ZIP),   # empty zip
    (0, b"Rar!\x1a\x07",        FormatID.RAR),
    (0, b"7z\xbc\xaf\x27\x1c", FormatID.SEVEN_ZIP),
    (0, b"\x1f\x8b",            FormatID.GZIP),
    (0, b"BZh",                 FormatID.BZIP2),
    (0, b"\xfd7zXZ\x00",        FormatID.XZ),
    (0, b"MSCF\x00\x00\x00\x00", FormatID.CAB),
    # Tar (ustar magic at offset 257)
    (257, b"ustar",              FormatID.TAR),
    # Disk images
    (32769, b"CD001",            FormatID.ISO),   # ISO 9660 primary volume
    (34817, b"CD001",            FormatID.ISO),   # ISO 9660 supplementary
    (0,   b"KDMV",               FormatID.VMDK),
    # QCOW2 – version is at bytes 4-7; we check the full header prefix
    (0,   b"QFI\xfb\x00\x00\x00", FormatID.QCOW2),
    # VHD footer signature "conectix" at offset +0x40 in a 512-byte footer
    # We look for the 8-byte cookie at offset -(512-40) from end of file.
    # Handled specially in _detect_vhd() because it is at a *trailing*
    # offset.
    # DMG – starts with a zero-filled 512-byte header; hard to detect
    # unambiguously via magic bytes alone.  We rely on extension for DMG.
]

# How many trailing bytes to read for formats with footer magic
_TRAILING_READ_SIZE = 4096  # enough for a VHD footer (512 bytes)


# ---------------------------------------------------------------------------
# Extension mapping
# ---------------------------------------------------------------------------

_EXTENSION_MAP: Dict[str, FormatID] = {
    ".zip":    FormatID.ZIP,
    ".rar":    FormatID.RAR,
    ".7z":     FormatID.SEVEN_ZIP,
    ".tar":    FormatID.TAR,
    ".gz":     FormatID.GZIP,
    ".gzip":   FormatID.GZIP,
    ".bz2":    FormatID.BZIP2,
    ".xz":     FormatID.XZ,
    ".cab":    FormatID.CAB,
    # compound
    ".tar.gz":  FormatID.TAR_GZ,
    ".tgz":     FormatID.TAR_GZ,
    ".tar.bz2": FormatID.TAR_BZ2,
    ".tbz2":    FormatID.TAR_BZ2,
    ".tar.xz":  FormatID.TAR_XZ,
    ".txz":     FormatID.TAR_XZ,
    # disk images
    ".iso":    FormatID.ISO,
    ".img":    FormatID.IMG,
    ".raw":    FormatID.RAW,
    ".dd":     FormatID.DD,
    ".bin":    FormatID.BIN,
    ".cue":    FormatID.BIN,  # .cue references a .bin; treat as bin family
    ".vhd":    FormatID.VHD,
    ".vhdx":   FormatID.VHDX,
    ".vmdk":   FormatID.VMDK,
    ".qcow2":  FormatID.QCOW2,
    ".dmg":    FormatID.DMG,
}

# Format -> category
_FORMAT_CATEGORY: Dict[FormatID, FormatCategory] = {
    FormatID.ZIP:      FormatCategory.ARCHIVE,
    FormatID.RAR:      FormatCategory.ARCHIVE,
    FormatID.SEVEN_ZIP:FormatCategory.ARCHIVE,
    FormatID.TAR:      FormatCategory.ARCHIVE,
    FormatID.GZIP:     FormatCategory.ARCHIVE,
    FormatID.BZIP2:    FormatCategory.ARCHIVE,
    FormatID.XZ:       FormatCategory.ARCHIVE,
    FormatID.CAB:      FormatCategory.ARCHIVE,
    FormatID.TAR_GZ:   FormatCategory.ARCHIVE,
    FormatID.TAR_BZ2:  FormatCategory.ARCHIVE,
    FormatID.TAR_XZ:   FormatCategory.ARCHIVE,
    FormatID.ISO:      FormatCategory.DISK_IMAGE,
    FormatID.IMG:      FormatCategory.DISK_IMAGE,
    FormatID.RAW:      FormatCategory.DISK_IMAGE,
    FormatID.DD:       FormatCategory.DISK_IMAGE,
    FormatID.BIN:      FormatCategory.DISK_IMAGE,
    FormatID.VHD:      FormatCategory.DISK_IMAGE,
    FormatID.VHDX:     FormatCategory.DISK_IMAGE,
    FormatID.VMDK:     FormatCategory.DISK_IMAGE,
    FormatID.QCOW2:    FormatCategory.DISK_IMAGE,
    FormatID.DMG:      FormatCategory.DISK_IMAGE,
}

# Canonical output extensions (for generating default output names)
_FORMAT_EXT: Dict[FormatID, str] = {
    FormatID.ZIP:      ".zip",
    FormatID.RAR:      ".rar",
    FormatID.SEVEN_ZIP:".7z",
    FormatID.TAR:      ".tar",
    FormatID.GZIP:     ".gz",
    FormatID.BZIP2:    ".bz2",
    FormatID.XZ:       ".xz",
    FormatID.CAB:      ".cab",
    FormatID.TAR_GZ:   ".tar.gz",
    FormatID.TAR_BZ2:  ".tar.bz2",
    FormatID.TAR_XZ:   ".tar.xz",
    FormatID.ISO:      ".iso",
    FormatID.IMG:      ".img",
    FormatID.RAW:      ".raw",
    FormatID.DD:       ".dd",
    FormatID.BIN:      ".bin",
    FormatID.VHD:      ".vhd",
    FormatID.VHDX:     ".vhdx",
    FormatID.VMDK:     ".vmdk",
    FormatID.QCOW2:    ".qcow2",
    FormatID.DMG:      ".dmg",
}


# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------

@dataclass
class FormatInfo:
    """Everything the dispatcher needs to know about a file."""
    format_id: FormatID
    category: FormatCategory
    detected_by: str           # "extension", "magic", "explicit"
    confidence: str            # "high", "medium", "low"
    path: str                  # absolute path to the file
    file_size: int = 0
    extra: dict = field(default_factory=dict)  # handler-specific metadata


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

def _normalise_ext(filename: str) -> str:
    """Return the lower-cased extension, handling compound ones.

    ``foo.tar.gz`` -> ``.tar.gz``
    ``foo.tgz``    -> ``.tgz``
    ``foo.zip``    -> ``.zip``
    """
    lower = filename.lower()
    # Try longest compound extension first
    for compound in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if lower.endswith(compound):
            return compound
    # Standard single extension
    _, ext = os.path.splitext(lower)
    return ext


def _detect_vhd(path: str) -> bool:
    """Check for VHD footer magic ('conectix') at the expected offset.

    A valid VHD file has a 512-byte footer at the end of the file with the
    cookie string ``conectix`` at offset 0x40 within that footer, i.e.
    ``filesize - 512 + 0x40``.
    """
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            file_size = fh.tell()
            if file_size < 512:
                return False
            fh.seek(file_size - 512 + 0x40)
            cookie = fh.read(8)
            return cookie == b"conectix"
    except OSError:
        return False


def detect_format(
    path: str,
    explicit_format: Optional[FormatID] = None,
) -> FormatInfo:
    """Detect the format of a file.

    Parameters
    ----------
    path : str
        Absolute or relative path to the file.
    explicit_format : FormatID, optional
        If the caller already knows the format (e.g. from ``--format``),
        bypass detection and return it directly.

    Returns
    -------
    FormatInfo
    """
    abspath = os.path.abspath(path)
    file_size = os.path.getsize(abspath) if os.path.isfile(abspath) else 0

    # Fast path: explicit format
    if explicit_format is not None:
        cat = _FORMAT_CATEGORY.get(explicit_format, FormatCategory.UNKNOWN)
        return FormatInfo(
            format_id=explicit_format,
            category=cat,
            detected_by="explicit",
            confidence="high",
            path=abspath,
            file_size=file_size,
        )

    # --- Layer 1: extension -------------------------------------------
    ext = _normalise_ext(os.path.basename(abspath))
    ext_fmt = _EXTENSION_MAP.get(ext)

    # --- Layer 2: magic bytes ------------------------------------------
    magic_fmt: Optional[FormatID] = None

    try:
        with open(abspath, "rb") as fh:
            header = fh.read(max(32769 + 5, _TRAILING_READ_SIZE))
    except OSError as exc:
        logger.warning("Cannot read %s for magic-byte detection: %s", abspath, exc)
    else:
        for offset, sig, fmt_id in _MAGIC_SIGNATURES:
            end = offset + len(sig)
            if end <= len(header) and header[offset:end] == sig:
                magic_fmt = fmt_id
                break

        # VHD special case (trailing footer)
        if magic_fmt is None and _detect_vhd(abspath):
            magic_fmt = FormatID.VHD

    # Compound extensions that should always win over ambiguous magic bytes.
    # A .tar.gz file *is* gzip at the byte level, but the compound extension
    # tells us it is a tar archive wrapped in gzip — semantically different
    # from a single-file gzip stream.
    _COMPOUND_EXTS = {FormatID.TAR_GZ, FormatID.TAR_BZ2, FormatID.TAR_XZ}

    # --- Resolve --------------------------------------------------------
    if magic_fmt is not None and ext_fmt is not None:
        if magic_fmt != ext_fmt:
            # If the extension is a compound format, trust it over a
            # single-stream magic match (e.g. .tar.gz → gzip magic).
            if ext_fmt in _COMPOUND_EXTS:
                logger.debug(
                    "Compound extension %s overrides magic %s for %s.",
                    ext_fmt.value, magic_fmt.value, abspath,
                )
                chosen = ext_fmt
                by = "extension"
                conf = "high"
            else:
                logger.warning(
                    "Format conflict for %s: extension says %s, magic bytes say %s. "
                    "Trusting magic bytes.",
                    abspath, ext_fmt.value, magic_fmt.value,
                )
                chosen = magic_fmt
                by = "magic"
                conf = "high"
        else:
            chosen = magic_fmt
            by = "magic"
            conf = "high"
    elif magic_fmt is not None:
        chosen = magic_fmt
        by = "magic"
        conf = "high"
    elif ext_fmt is not None:
        chosen = ext_fmt
        by = "extension"
        conf = "medium"
    else:
        chosen = FormatID.ZIP  # fallback — will be caught by dispatcher
        by = "fallback"
        conf = "low"
        logger.warning("Could not detect format for %s; defaulting to generic.", abspath)

    cat = _FORMAT_CATEGORY.get(chosen, FormatCategory.UNKNOWN)
    return FormatInfo(
        format_id=chosen,
        category=cat,
        detected_by=by,
        confidence=conf,
        path=abspath,
        file_size=file_size,
    )


def format_from_extension(ext_hint: str) -> Optional[FormatID]:
    """Look up a FormatID purely from a user-supplied extension string.

    Accepts leading dot or no dot, case-insensitive.
    """
    key = ext_hint.lower()
    if not key.startswith("."):
        key = "." + key
    return _EXTENSION_MAP.get(key)


def get_category(fmt: FormatID) -> FormatCategory:
    return _FORMAT_CATEGORY.get(fmt, FormatCategory.UNKNOWN)


def get_extension(fmt: FormatID) -> str:
    return _FORMAT_EXT.get(fmt, "")


def all_archive_formats() -> List[FormatID]:
    return [f for f, c in _FORMAT_CATEGORY.items() if c == FormatCategory.ARCHIVE]


def all_disk_formats() -> List[FormatID]:
    return [f for f, c in _FORMAT_CATEGORY.items() if c == FormatCategory.DISK_IMAGE]
