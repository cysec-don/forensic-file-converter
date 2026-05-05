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

    # -- forensic / memory dump ------------------------------------------
    DUMP = "dump"
    LIME = "lime"
    E01 = "e01"
    EX01 = "ex01"
    AFF = "aff"


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
    # Forensic / memory dump formats
    # Windows crash dump (64-bit): "PAGEDU" at offset 0 — check BEFORE PAGE
    (0, b"PAGEDU",            FormatID.DUMP),
    # Windows crash dump (32-bit): "PAGE" at offset 0
    (0, b"PAGE",              FormatID.DUMP),
    # LiME (Linux Memory Extractor): "LiME" at offset 0
    (0, b"LiME",              FormatID.LIME),
    # EWF / EnCase E01: "EVF" signature at offset 0
    # E01 v1 (legacy): EVF\x09\x0D\x0A\xFF\x00
    # EX01 v2 (EnCase 8+): EVF\x09\x0D\x0A\xFF\x01
    (0, b"EVF\x09\x0d\x0a\xff\x00", FormatID.E01),
    (0, b"EVF\x09\x0d\x0a\xff\x01", FormatID.EX01),
    # AFF (Advanced Forensics Format): "AFF\x00" at offset 0
    (0, b"AFF\x00",            FormatID.AFF),
    # AFF v1b variant: "AFF" followed by version byte 0x01
    (0, b"AFF\x01",            FormatID.AFF),
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
    # forensic / memory dump
    ".dump":   FormatID.DUMP,
    ".dmp":    FormatID.DUMP,   # Windows crash dump alias
    ".vdmp":   FormatID.DUMP,   # VMware dump alias
    ".lime":   FormatID.LIME,
    # EnCase Expert Witness Format (EWF) — used by Autopsy & Guymager
    ".e01":    FormatID.E01,
    ".ex01":   FormatID.EX01,
    ".ewf":    FormatID.E01,    # generic EWF extension alias
    ".e02":    FormatID.E01,    # split segments
    ".e03":    FormatID.E01,
    ".e04":    FormatID.E01,
    ".e05":    FormatID.E01,
    ".e06":    FormatID.E01,
    ".e07":    FormatID.E01,
    ".e08":    FormatID.E01,
    ".e09":    FormatID.E01,
    ".e10":    FormatID.E01,
    # Advanced Forensics Format
    ".aff":    FormatID.AFF,
    ".afd":    FormatID.AFF,    # AFF data file alias
    ".afm":    FormatID.AFF,    # AFF metadata alias
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
    FormatID.DUMP:     FormatCategory.DISK_IMAGE,
    FormatID.LIME:     FormatCategory.DISK_IMAGE,
    FormatID.E01:      FormatCategory.DISK_IMAGE,
    FormatID.EX01:     FormatCategory.DISK_IMAGE,
    FormatID.AFF:      FormatCategory.DISK_IMAGE,
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
    FormatID.DUMP:     ".dump",
    FormatID.LIME:     ".lime",
    FormatID.E01:      ".e01",
    FormatID.EX01:     ".ex01",
    FormatID.AFF:      ".aff",
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


# ---------------------------------------------------------------------------
# EWF (EnCase Expert Witness Format) header constants and parsing
# ---------------------------------------------------------------------------
# EWF is the forensic disk image format used by EnCase (and Autopsy/Guymager).
# The format stores disk images in compressed segments (.E01, .E02, ...).
#
# EWF file header layout (first 13+ bytes):
#   Offset  Size  Field
#   0       3     Signature (b"EVF")
#   3       1     Version part 1 (0x09)
#   4       1     Version part 2 (0x0D)
#   5       1     Version part 3 (0x0A)
#   6       1     Flags (0xFF)
#   7       1     Version code: 0x00 = E01 (legacy), 0x01 = EX01 (v8+)
#   8       16    Segment name / case number (null-padded)
#   24      4     Section count (uint32 LE)
#   28      4     Section number (uint32 LE)
#   32      ...   Padding to 624 bytes
#   624     ...   First data section follows
#
# The first segment (.E01) contains the EWF file header followed by
# data sections.  Subsequent segments (.E02, .E03, ...) are data-only
# sections that continue the compressed image data.
#
# Reference: libewf (https://github.com/libyal/libewf)

EWF_SIGNATURE = b"EVF"
EWF_HEADER_SIZE = 13
EWF_FULL_HEADER_SIZE = 624  # total header + padding
EWF_VERSION_OFFSET = 7
EWF_CASE_NUMBER_OFFSET = 8
EWF_CASE_NUMBER_SIZE = 16
EWF_SECTION_COUNT_OFFSET = 24


def parse_ewf_header(path: str) -> Optional[dict]:
    """Parse an EWF/E01/EX01 file header and return metadata.

    Returns ``None`` if the file is not a valid EWF image.

    Parameters
    ----------
    path : str
        Path to the EWF file (.e01 / .ex01).

    Returns
    -------
    dict | None
        ``{"version_code": int, "is_ex01": bool, "case_number": str,
        "section_count": int, "header_size": int}``
    """
    try:
        with open(path, "rb") as fh:
            header = fh.read(32)
    except OSError:
        return None

    if len(header) < EWF_HEADER_SIZE:
        return None
    if header[:3] != EWF_SIGNATURE:
        return None

    version_code = header[EWF_VERSION_OFFSET]
    is_ex01 = version_code == 0x01

    case_bytes = header[EWF_CASE_NUMBER_OFFSET:
                     EWF_CASE_NUMBER_OFFSET + EWF_CASE_NUMBER_SIZE]
    case_number = case_bytes.split(b"\x00")[0].decode("ascii", errors="replace")

    section_count = struct.unpack_from("<I", header, EWF_SECTION_COUNT_OFFSET)[0] \
        if len(header) >= EWF_SECTION_COUNT_OFFSET + 4 else 0

    return {
        "version_code": version_code,
        "is_ex01": is_ex01,
        "case_number": case_number,
        "section_count": section_count,
        "header_size": EWF_FULL_HEADER_SIZE,
    }


def build_ewf_header(
    case_number: str = "",
    is_ex01: bool = False,
) -> bytes:
    """Build a minimal EWF file header (624 bytes).

    Parameters
    ----------
    case_number : str
        Case identifier string (max 16 ASCII chars).
    is_ex01 : bool
        If True, produce EX01 (EnCase v8+) header; otherwise E01.

    Returns
    -------
    bytes  — exactly ``EWF_FULL_HEADER_SIZE`` bytes.
    """
    header = bytearray(EWF_FULL_HEADER_SIZE)
    # EWF signature
    header[0:3] = EWF_SIGNATURE
    # Version fields
    header[3] = 0x09
    header[4] = 0x0D
    header[5] = 0x0A
    header[6] = 0xFF
    header[EWF_VERSION_OFFSET] = 0x01 if is_ex01 else 0x00
    # Case number (truncated to 16 chars)
    case_bytes = case_number.encode("ascii", errors="replace")[:EWF_CASE_NUMBER_SIZE]
    header[EWF_CASE_NUMBER_OFFSET:
          EWF_CASE_NUMBER_OFFSET + len(case_bytes)] = case_bytes
    # Section count = 1 (single segment)
    struct.pack_into("<I", header, EWF_SECTION_COUNT_OFFSET, 1)
    return bytes(header)


# ---------------------------------------------------------------------------
# AFF (Advanced Forensics Format) header constants and parsing
# ---------------------------------------------------------------------------
# AFF is an open-source forensic image format supporting compression,
# encryption, and metadata.  AFFv1 has a simple page-based layout:
#
#   Offset  Size  Field
#   0       4     Magic (b"AFF\x00" for AFFv1)
#   4       4     Major version (uint32 BE)
#   8       4     Minor version (uint32 BE)
#   12      8     Total size (uint64 BE)
#   20      8     Compressed size (uint64 BE)
#   28      8     Page size (uint64 BE, typically 4096)
#   36      ...   Pages follow (compressed)
#
# Reference: AFF Library (https://github.com/sshock/AFFLIB)

AFF_MAGIC = b"AFF\x00"
AFF_HEADER_SIZE = 36
AFF_MAJOR_OFFSET = 4
AFF_MINOR_OFFSET = 8
AFF_TOTAL_SIZE_OFFSET = 12
AFF_COMPRESSED_SIZE_OFFSET = 20
AFF_PAGE_SIZE_OFFSET = 28


def parse_aff_header(path: str) -> Optional[dict]:
    """Parse an AFF file header and return metadata.

    Returns ``None`` if the file is not a valid AFF image.

    Parameters
    ----------
    path : str
        Path to the AFF file (.aff).

    Returns
    -------
    dict | None
        ``{"major": int, "minor": int, "total_size": int,
        "compressed_size": int, "page_size": int, "header_size": int}``
    """
    try:
        with open(path, "rb") as fh:
            header = fh.read(AFF_HEADER_SIZE)
    except OSError:
        return None

    if len(header) < AFF_HEADER_SIZE:
        return None
    if header[:4] != AFF_MAGIC:
        return None

    major = struct.unpack_from(">I", header, AFF_MAJOR_OFFSET)[0]
    minor = struct.unpack_from(">I", header, AFF_MINOR_OFFSET)[0]
    total_size = struct.unpack_from(">Q", header, AFF_TOTAL_SIZE_OFFSET)[0]
    compressed_size = struct.unpack_from(">Q", header, AFF_COMPRESSED_SIZE_OFFSET)[0]
    page_size = struct.unpack_from(">Q", header, AFF_PAGE_SIZE_OFFSET)[0]

    return {
        "major": major,
        "minor": minor,
        "total_size": total_size,
        "compressed_size": compressed_size,
        "page_size": page_size,
        "header_size": AFF_HEADER_SIZE,
    }


def build_aff_header(
    page_size: int = 4096,
    major: int = 1,
    minor: int = 0,
) -> bytes:
    """Build a minimal AFF file header (36 bytes).

    Parameters
    ----------
    page_size : int
        AFF page size (typically 4096).
    major : int
        AFF major version.
    minor : int
        AFF minor version.

    Returns
    -------
    bytes  — exactly ``AFF_HEADER_SIZE`` bytes.
    """
    header = bytearray(AFF_HEADER_SIZE)
    header[0:4] = AFF_MAGIC
    struct.pack_into(">I", header, AFF_MAJOR_OFFSET, major)
    struct.pack_into(">I", header, AFF_MINOR_OFFSET, minor)
    # total_size and compressed_size set to 0 — will be updated by the caller
    # when the actual data is written.
    struct.pack_into(">Q", header, AFF_TOTAL_SIZE_OFFSET, 0)
    struct.pack_into(">Q", header, AFF_COMPRESSED_SIZE_OFFSET, 0)
    struct.pack_into(">Q", header, AFF_PAGE_SIZE_OFFSET, page_size)
    return bytes(header)


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


# ---------------------------------------------------------------------------
# LiME header constants and parsing
# ---------------------------------------------------------------------------
# LiME (Linux Memory Extractor) is a forensic tool that captures physical
# memory from a running Linux system.  The output file has a small header
# followed by the raw memory pages.
#
# LiME v1 header layout (24 bytes total):
#   Offset  Size  Field
#   0       4     Magic (b"LiME")
#   4       1     Version (typically 1)
#   5       3     Reserved (zero padding)
#   8       8     Base address (uint64 LE) — start of physical memory
#   16      8     Reserved (zero padding)
#
# The actual memory data begins at byte 24.
# Reference: https://github.com/504ensicsLab/LiME

LIME_MAGIC = b"LiME"
LIME_HEADER_SIZE_V1 = 24
LIME_VERSION_OFFSET = 4


def parse_lime_header(path: str) -> Optional[dict]:
    """Parse a LiME file header and return metadata.

    Returns ``None`` if the file is not a valid LiME image.

    Parameters
    ----------
    path : str
        Path to the LiME file.

    Returns
    -------
    dict | None
        ``{"version": int, "base_address": int, "header_size": int,
        "data_offset": int}``
    """
    try:
        with open(path, "rb") as fh:
            header = fh.read(LIME_HEADER_SIZE_V1 + 1)
    except OSError:
        return None

    if len(header) < LIME_HEADER_SIZE_V1:
        return None
    if header[:4] != LIME_MAGIC:
        return None

    version = header[LIME_VERSION_OFFSET]
    base_address = struct.unpack_from("<Q", header, 8)[0]

    return {
        "version": version,
        "base_address": base_address,
        "header_size": LIME_HEADER_SIZE_V1,
        "data_offset": LIME_HEADER_SIZE_V1,
    }


def build_lime_header(version: int = 1, base_address: int = 0) -> bytes:
    """Build a 24-byte LiME v1 header.

    Parameters
    ----------
    version : int
        LiME format version (typically 1).
    base_address : int
        Physical memory base address (little-endian uint64).

    Returns
    -------
    bytes  — exactly ``LIME_HEADER_SIZE_V1`` bytes.
    """
    header = bytearray(LIME_HEADER_SIZE_V1)
    header[0:4] = LIME_MAGIC
    header[LIME_VERSION_OFFSET] = version & 0xFF
    struct.pack_into("<Q", header, 8, base_address)
    return bytes(header)


# ---------------------------------------------------------------------------
# Windows crash dump header constants and parsing
# ---------------------------------------------------------------------------
# Windows crash dumps have several sub-types.  All share a signature at
# offset 0:
#   b"PAGE"   — 32-bit complete / kernel dump
#   b"PAGEDU" — 64-bit complete / kernel dump
#
# The DUMP_HEADER structure at offset 0 contains a ``ValidDump`` field
# (uint32 at offset 8) that identifies the dump type:
#   1 = MiniDump (user-mode)
#   2 = FullDump (complete physical memory)
#   3 = KernelDump
#
# The DUMP_HEADER is followed by a PHYSICAL_MEMORY_RUN array that
# describes the memory pages.  For our DUMP → RAW conversion we use a
# conservative approach: skip the fixed-size header region (4096 bytes)
# and stream the rest as raw memory data.
#
# Reference: Microsoft Debug Help Library / crash dump specification.

WIN_DUMP_SIGNATURE_32 = b"PAGE"
WIN_DUMP_SIGNATURE_64 = b"PAGEDU"
WIN_DUMP_HEADER_SIZE = 4096


def parse_dump_header(path: str) -> Optional[dict]:
    """Parse a Windows crash dump header.

    Returns ``None`` if the file is not a recognized Windows dump.

    Parameters
    ----------
    path : str
        Path to the dump file.

    Returns
    -------
    dict | None
        ``{"signature": str, "dump_type": str, "valid_dump": int,
        "header_size": int}``
    """
    try:
        with open(path, "rb") as fh:
            header = fh.read(64)
    except OSError:
        return None

    if len(header) < 8:
        return None

    if header[:6] == WIN_DUMP_SIGNATURE_64:
        sig = "PAGEDU"
    elif header[:4] == WIN_DUMP_SIGNATURE_32:
        sig = "PAGE"
    else:
        return None

    valid_dump = struct.unpack_from("<I", header, 8)[0] if len(header) >= 12 else 0
    dump_types = {1: "MiniDump", 2: "FullDump", 3: "KernelDump"}
    dump_type = dump_types.get(valid_dump, f"Unknown (ValidDump={valid_dump})")

    return {
        "signature": sig,
        "dump_type": dump_type,
        "valid_dump": valid_dump,
        "header_size": WIN_DUMP_HEADER_SIZE,
    }
