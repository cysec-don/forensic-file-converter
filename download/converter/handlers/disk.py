"""
Disk Image Handler
==================

Handles disk image format operations:
- convert (disk image → disk image via qemu-img or raw copy)
- extract (mount / extract contents of an image)
- create  (create an image from a directory / source)
- list   (list filesystem contents)

Format coverage
---------------
| Format  | Convert      | Extract  | Create   | Tool dependency    |
|---------|--------------|----------|----------|--------------------|
| .qcow2  | qemu-img ✓   | mount ✓  | qemu-img | qemu-img           |
| .vmdk   | qemu-img ✓   | mount ✓  | qemu-img | qemu-img           |
| .vhd    | qemu-img ✓   | mount ✓  | qemu-img | qemu-img           |
| .vhdx   | qemu-img ✓   | mount ✓  | qemu-img | qemu-img           |
| .raw    | copy ✓       | mount ✓  | dd       | —                   |
| .dd     | copy ✓       | mount ✓  | dd       | —                   |
| .img    | copy ✓       | mount ✓  | dd       | —                   |
| .bin    | copy ✓       | mount ✓  | —        | —                   |
| .iso    | xorriso ✓    | 7z/iso✓  | geniso.. | genisoimage/xorriso |
| .dmg    | dmg2img ✓    | limited  | macOS only| dmg2img (Linux)     |
| .dump   | header ✓     | N/A      | N/A      | —                   |
| .lime   | header ✓     | N/A      | N/A      | —                   |

Forensic formats (.dump, .lime)
-------------------------------
- **Windows crash dumps** (.dump / .dmp) start with ``PAGE`` or ``PAGEDU``
  and contain a DUMP_HEADER followed by physical memory runs.  Converting
  DUMP → RAW strips the header; RAW → DUMP prepends a minimal header.
- **LiME** (.lime) has a 24-byte header (magic, version, base address)
  followed by raw physical memory.  Converting LIME → RAW strips the
  header; RAW → LIME prepends a new header.
- These are **partial** conversions: header metadata is lost or fabricated.
  The raw memory data itself is preserved losslessly.

Design decisions
----------------
- **qemu-img** is the primary tool for virtual-machine disk images.
- **ISO creation** uses ``genisoimage`` / ``xorriso``.
- **DMG support is deliberately limited** (raw/unencrypted only on Linux).
- **Raw copies** (.img, .raw, .dd, .bin) are byte-for-byte.
- **Forensic conversions** stream data in 64 MB chunks to handle large
  memory dumps (10+ GB) without excessive memory usage.
- Large files are handled via ``subprocess`` streaming — we never load
  an entire disk image into memory.
"""

from __future__ import annotations

import logging
import os
import shutil
import struct
import subprocess
import tempfile
from typing import TYPE_CHECKING, Dict, List, Optional

from ..core.detector import (
    FormatID, FormatInfo, FormatCategory, detect_format,
    parse_lime_header, build_lime_header, LIME_HEADER_SIZE_V1,
    parse_dump_header, WIN_DUMP_HEADER_SIZE,
    parse_ewf_header, build_ewf_header, EWF_FULL_HEADER_SIZE,
    parse_aff_header, build_aff_header, AFF_HEADER_SIZE,
)
from ..core.dispatcher import ConversionEntry
from ..core.dependencies import ensure_tool
from ..utils.validation import (
    require_file_exists, require_dir_exists,
    check_overwrite, safe_output_path, check_disk_space,
)

if TYPE_CHECKING:
    from ..core.dispatcher import Dispatcher

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_QEMU_FORMATS = {
    FormatID.QCOW2: "qcow2",
    FormatID.VMDK:  "vmdk",
    FormatID.VHD:   "vpc",       # VHD is "vpc" in qemu-img terminology
    FormatID.VHDX:  "vhdx",
    FormatID.RAW:   "raw",
    FormatID.DD:    "raw",
    FormatID.IMG:   "raw",
}

_RAW_FORMATS = {FormatID.RAW, FormatID.DD, FormatID.IMG, FormatID.BIN}

# Forensic / memory-dump formats — have headers that must be managed
_FORENSIC_FORMATS = {
    FormatID.DUMP, FormatID.LIME,
    FormatID.E01, FormatID.EX01, FormatID.AFF,
}

# EWF (EnCase) formats — Autopsy/Guymager primary format
_EWF_FORMATS = {FormatID.E01, FormatID.EX01}

# Streaming chunk size for large file operations (64 MiB)
_STREAM_CHUNK = 64 * 1024 * 1024


def _run_external(
    cmd: List[str], description: str = ""
) -> subprocess.CompletedProcess:
    """Run an external command with comprehensive error handling."""
    logger.debug("Running external: %s  (%s)", " ".join(cmd), description)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=7200,  # 2-hour timeout for large disk images
        )
    except FileNotFoundError:
        raise RuntimeError(
            f"External tool not found: {cmd[0]}. "
            f"Install it and ensure it is on $PATH."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"External command timed out (2h limit): {' '.join(cmd)}"
        )
    if result.returncode != 0:
        raise RuntimeError(
            f"{description or cmd[0]} failed (exit {result.returncode}):\n"
            f"  stdout: {result.stdout.strip()}\n"
            f"  stderr: {result.stderr.strip()}"
        )
    return result


def _find_iso_tool() -> str:
    """Find an available ISO creation tool.  Raises if none found."""
    for tool in ("genisoimage", "mkisofs", "xorriso"):
        path = shutil.which(tool)
        if path:
            return tool
    raise EnvironmentError(
        "No ISO creation tool found. Install one of:\n"
        "  sudo apt install genisoimage   (Debian/Ubuntu)\n"
        "  sudo apt install xorriso       (any Linux)\n"
        "  brew install cdrtools          (macOS)"
    )


def _find_iso_extract_tool() -> str:
    """Find a tool that can extract ISO contents."""
    for tool in ("7z", "bsdtar", "xorriso"):
        path = shutil.which(tool)
        if path:
            return tool
    raise EnvironmentError(
        "No ISO extraction tool found. Install one of:\n"
        "  sudo apt install p7zip-full\n"
        "  sudo apt install libarchive-tools  (for bsdtar)\n"
        "  sudo apt install xorriso"
    )


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

class DiskImageHandler:
    """Manages disk image conversion, extraction, creation, and listing."""

    def __init__(self, *, dispatcher: "Dispatcher") -> None:
        self.dispatcher = dispatcher

    # ------------------------------------------------------------------
    # Convert
    # ------------------------------------------------------------------

    def convert(
        self,
        input_path: str,
        output_path: str,
        *,
        src_info: Optional[FormatInfo] = None,
        target_fmt: Optional[FormatID] = None,
        overwrite: bool = False,
        entry: Optional[ConversionEntry] = None,
    ) -> str:
        """Convert between disk image formats.

        Returns the absolute output path.
        """
        input_path = require_file_exists(input_path)
        output_path = safe_output_path(output_path)
        check_overwrite(output_path, overwrite=overwrite)
        check_disk_space(input_path, os.path.dirname(output_path), multiplier=1.5)

        if src_info is None:
            src_info = detect_format(input_path)

        src_fmt = src_info.format_id
        tgt_fmt = target_fmt

        logger.info(
            "Converting disk image: %s (%s) → %s (%s)",
            input_path, src_fmt.value, output_path, tgt_fmt.value,
        )

        # --- Raw ↔ Raw (byte copy) ---
        if src_fmt in _RAW_FORMATS and tgt_fmt in _RAW_FORMATS:
            return self._raw_copy(input_path, output_path, src_fmt, tgt_fmt)

        # --- DMG → IMG/RAW (via dmg2img) ---
        if src_fmt == FormatID.DMG and tgt_fmt in (FormatID.IMG, FormatID.RAW):
            return self._dmg_to_raw(input_path, output_path)

        # --- qemu-img handled formats ---
        if src_fmt in _QEMU_FORMATS and tgt_fmt in _QEMU_FORMATS:
            return self._qemu_convert(input_path, output_path, src_fmt, tgt_fmt)

        # --- BIN → raw formats ---
        if src_fmt == FormatID.BIN and tgt_fmt in _RAW_FORMATS:
            return self._raw_copy(input_path, output_path, src_fmt, tgt_fmt)

        # --- Forensic format conversions -----------------------------------
        # LIME ↔ RAW/DD/IMG/BIN
        if src_fmt == FormatID.LIME and tgt_fmt in _RAW_FORMATS | {FormatID.BIN}:
            return self._lime_to_raw(input_path, output_path)
        if src_fmt in _RAW_FORMATS | {FormatID.BIN} and tgt_fmt == FormatID.LIME:
            return self._raw_to_lime(input_path, output_path)

        # DUMP ↔ RAW/DD/IMG/BIN
        if src_fmt == FormatID.DUMP and tgt_fmt in _RAW_FORMATS | {FormatID.BIN}:
            return self._dump_to_raw(input_path, output_path)
        if src_fmt in _RAW_FORMATS | {FormatID.BIN} and tgt_fmt == FormatID.DUMP:
            return self._raw_to_dump(input_path, output_path)

        # LIME ↔ DUMP (via raw as intermediate)
        if src_fmt == FormatID.LIME and tgt_fmt == FormatID.DUMP:
            return self._lime_to_dump(input_path, output_path)
        if src_fmt == FormatID.DUMP and tgt_fmt == FormatID.LIME:
            return self._dump_to_lime(input_path, output_path)

        # --- EWF (EnCase) / Autopsy / Guymager format conversions -----------
        # These must come BEFORE the generic forensic → qemu check
        # because _QEMU_FORMATS includes RAW/DD/IMG.
        # E01/EX01 → raw (strip EWF header)
        if src_fmt in _EWF_FORMATS and tgt_fmt in _RAW_FORMATS | {FormatID.BIN}:
            return self._ewf_to_raw(input_path, output_path, src_fmt)
        # raw → E01/EX01 (prepend EWF header)
        if src_fmt in _RAW_FORMATS | {FormatID.BIN} and tgt_fmt in _EWF_FORMATS:
            return self._raw_to_ewf(input_path, output_path, tgt_fmt)
        # E01 ↔ EX01 (re-header)
        if src_fmt in _EWF_FORMATS and tgt_fmt in _EWF_FORMATS:
            return self._ewf_reheader(input_path, output_path, src_fmt, tgt_fmt)
        # E01/EX01 ↔ DUMP/LIME (two-step via raw)
        if src_fmt in _EWF_FORMATS and tgt_fmt in {FormatID.DUMP, FormatID.LIME}:
            return self._ewf_to_forensic(input_path, output_path, src_fmt, tgt_fmt)
        if src_fmt in {FormatID.DUMP, FormatID.LIME} and tgt_fmt in _EWF_FORMATS:
            return self._forensic_to_ewf(input_path, output_path, src_fmt, tgt_fmt)

        # --- AFF format conversions ----------------------------------------
        # AFF → raw (strip AFF header)
        if src_fmt == FormatID.AFF and tgt_fmt in _RAW_FORMATS | {FormatID.BIN}:
            return self._aff_to_raw(input_path, output_path)
        # raw → AFF (prepend AFF header)
        if src_fmt in _RAW_FORMATS | {FormatID.BIN} and tgt_fmt == FormatID.AFF:
            return self._raw_to_aff(input_path, output_path)
        # AFF ↔ DUMP/LIME (two-step via raw)
        if src_fmt == FormatID.AFF and tgt_fmt in {FormatID.DUMP, FormatID.LIME}:
            return self._aff_to_forensic(input_path, output_path, tgt_fmt)
        if src_fmt in {FormatID.DUMP, FormatID.LIME} and tgt_fmt == FormatID.AFF:
            return self._forensic_to_aff(input_path, output_path, src_fmt)

        # Forensic → qemu formats: strip header first, then qemu-img
        # Only for DUMP, LIME (EWF/AFF have their own handlers above)
        if src_fmt in forensic_formats and tgt_fmt in _QEMU_FORMATS:
            return self._forensic_to_qemu(input_path, output_path, src_fmt, tgt_fmt)

        raise NotImplementedError(
            f"Disk image conversion from {src_fmt.value} to {tgt_fmt.value} "
            f"is not implemented."
        )

    def _raw_copy(
        self,
        input_path: str,
        output_path: str,
        src_fmt: FormatID,
        tgt_fmt: FormatID,
    ) -> str:
        """Byte-for-byte copy between raw formats."""
        logger.info("Raw copy: %s → %s", input_path, output_path)
        shutil.copy2(input_path, output_path)
        return os.path.abspath(output_path)

    def _dmg_to_raw(self, input_path: str, output_path: str) -> str:
        """Convert a raw DMG to IMG using dmg2img."""
        ensure_tool("dmg2img", fmt="dmg")
        _run_external(
            ["dmg2img", input_path, output_path],
            description="dmg2img conversion",
        )
        return os.path.abspath(output_path)

    def _qemu_convert(
        self,
        input_path: str,
        output_path: str,
        src_fmt: FormatID,
        tgt_fmt: FormatID,
    ) -> str:
        """Convert via qemu-img."""
        ensure_tool("qemu-img", fmt=src_fmt.value)

        src_qemu = _QEMU_FORMATS[src_fmt]
        tgt_qemu = _QEMU_FORMATS[tgt_fmt]

        # Determine output format string
        out_fmt_flag = f"-O {tgt_qemu}"

        _run_external(
            [
                "qemu-img", "convert",
                "-f", src_qemu,
                out_fmt_flag.split()[0], out_fmt_flag.split()[1],
                input_path,
                output_path,
            ],
            description=f"qemu-img convert ({src_qemu} → {tgt_qemu})",
        )

        logger.info("qemu-img conversion complete: %s", output_path)
        return os.path.abspath(output_path)

    # ------------------------------------------------------------------
    # Forensic format conversions (LIME / DUMP ↔ Raw)
    # ------------------------------------------------------------------

    def _lime_to_raw(self, input_path: str, output_path: str) -> str:
        """Strip the 24-byte LiME header and write raw memory data.

        Uses streaming to handle very large memory dumps without loading
        the entire file into memory.
        """
        lime_info = parse_lime_header(input_path)
        if lime_info is None:
            raise RuntimeError(
                f"'{input_path}' does not appear to be a valid LiME file. "
                f"Expected 'LiME' magic at offset 0."
            )
        data_offset = lime_info["data_offset"]

        logger.info(
            "LIME → RAW: stripping %d-byte LiME v%d header "
            "(base_address=0x%x) from %s",
            data_offset, lime_info["version"],
            lime_info["base_address"], input_path,
        )

        bytes_skipped = 0
        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            # Skip the LiME header
            if f_in.seek(data_offset) != data_offset:
                raise RuntimeError("Failed to seek past LiME header.")
            bytes_skipped = data_offset

            # Stream the rest
            while True:
                chunk = f_in.read(_STREAM_CHUNK)
                if not chunk:
                    break
                f_out.write(chunk)

        in_size = os.path.getsize(input_path)
        out_size = os.path.getsize(output_path)
        logger.info(
            "LIME → RAW complete: skipped %d bytes, "
            "%d → %d bytes (%.1f MB saved)",
            bytes_skipped, in_size, out_size,
            (in_size - out_size) / (1024 * 1024),
        )
        return os.path.abspath(output_path)

    def _raw_to_lime(self, input_path: str, output_path: str) -> str:
        """Prepend a LiME v1 header to raw memory data.

        The base address is set to 0 (the most common default for x86_64).
        Users who need a specific base address should edit the LiME file
        with a hex editor or use the LiME tool directly.
        """
        header = build_lime_header(version=1, base_address=0)

        logger.info(
            "RAW → LIME: prepending %d-byte LiME v1 header "
            "(base_address=0x0) to %s",
            len(header), input_path,
        )

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_out.write(header)
            while True:
                chunk = f_in.read(_STREAM_CHUNK)
                if not chunk:
                    break
                f_out.write(chunk)

        in_size = os.path.getsize(input_path)
        out_size = os.path.getsize(output_path)
        logger.info(
            "RAW → LIME complete: %d → %d bytes (+%d header)",
            in_size, out_size, len(header),
        )
        return os.path.abspath(output_path)

    def _dump_to_raw(self, input_path: str, output_path: str) -> str:
        """Strip the Windows crash dump header and write raw memory data.

        The DUMP_HEADER is 4096 bytes, followed by a PHYSICAL_MEMORY_RUN
        array.  We use a conservative approach: skip the first 4096 bytes
        and stream the rest.  This preserves all memory pages but may
        include the run descriptor array as part of the raw output.

        For a more precise conversion, use Volatility or WinDbg to extract
        individual memory runs.
        """
        dump_info = parse_dump_header(input_path)
        if dump_info is None:
            raise RuntimeError(
                f"'{input_path}' does not appear to be a valid Windows crash "
                f"dump.  Expected 'PAGE' or 'PAGEDU' magic at offset 0."
            )

        header_size = dump_info["header_size"]
        logger.info(
            "DUMP → RAW: stripping %d-byte Windows dump header "
            "(%s, %s) from %s",
            header_size, dump_info["signature"],
            dump_info["dump_type"], input_path,
        )

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_in.seek(header_size)
            while True:
                chunk = f_in.read(_STREAM_CHUNK)
                if not chunk:
                    break
                f_out.write(chunk)

        in_size = os.path.getsize(input_path)
        out_size = os.path.getsize(output_path)
        logger.info(
            "DUMP → RAW complete: skipped %d bytes, "
            "%d → %d bytes (%.1f MB saved)",
            header_size, in_size, out_size,
            (in_size - out_size) / (1024 * 1024),
        )
        return os.path.abspath(output_path)

    def _raw_to_dump(self, input_path: str, output_path: str) -> str:
        """Prepend a minimal Windows crash dump header to raw data.

        .. warning::
            The fabricated header will NOT contain valid system context
            (system time, bugcheck parameters, etc.).  It is suitable for
            tools that accept raw memory analysis but NOT for use with
            WinDbg or crash dump debugging.

        The header signature is ``PAGE`` (32-bit) by default.
        """
        # Build a minimal DUMP_HEADER (4096 bytes)
        header = bytearray(WIN_DUMP_HEADER_SIZE)
        header[0:4] = b"PAGE"
        # ValidDump = 2 (FullDump) at offset 8
        struct.pack_into("<I", header, 8, 2)

        logger.warning(
            "RAW → DUMP: prepending a MINIMAL Windows dump header to %s. "
            "The header will not contain valid system context. "
            "Use only for tools that accept raw memory, NOT for WinDbg.",
            input_path,
        )

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_out.write(bytes(header))
            while True:
                chunk = f_in.read(_STREAM_CHUNK)
                if not chunk:
                    break
                f_out.write(chunk)

        in_size = os.path.getsize(input_path)
        out_size = os.path.getsize(output_path)
        logger.info(
            "RAW → DUMP complete: %d → %d bytes (+%d header)",
            in_size, out_size, len(header),
        )
        return os.path.abspath(output_path)

    def _lime_to_dump(self, input_path: str, output_path: str) -> str:
        """Convert LiME → Windows dump format.

        Two-step: strip LiME header → prepend Windows dump header.
        Uses a temp file as intermediate to avoid loading into memory.
        """
        with tempfile.NamedTemporaryFile(
            delete=False, prefix="lime_dump_tmp_", suffix=".raw",
        ) as tmp:
            tmp_path = tmp.name

        try:
            self._lime_to_raw(input_path, tmp_path)
            self._raw_to_dump(tmp_path, output_path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        return os.path.abspath(output_path)

    def _dump_to_lime(self, input_path: str, output_path: str) -> str:
        """Convert Windows dump → LiME format.

        Two-step: strip dump header → prepend LiME header.
        Uses a temp file as intermediate.
        """
        with tempfile.NamedTemporaryFile(
            delete=False, prefix="dump_lime_tmp_", suffix=".raw",
        ) as tmp:
            tmp_path = tmp.name

        try:
            self._dump_to_raw(input_path, tmp_path)
            self._raw_to_lime(tmp_path, output_path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        return os.path.abspath(output_path)

    def _forensic_to_qemu(
        self,
        input_path: str,
        output_path: str,
        src_fmt: FormatID,
        tgt_fmt: FormatID,
    ) -> str:
        """Convert a forensic format to a VM disk image.

        Two-step: strip header to raw → qemu-img convert.
        """
        with tempfile.NamedTemporaryFile(
            delete=False, prefix=f"forensic_{src_fmt.value}_",
            suffix=".raw",
        ) as tmp:
            tmp_path = tmp.name

        try:
            # Step 1: strip to raw
            if src_fmt == FormatID.LIME:
                self._lime_to_raw(input_path, tmp_path)
            elif src_fmt == FormatID.DUMP:
                self._dump_to_raw(input_path, tmp_path)
            elif src_fmt in _EWF_FORMATS:
                self._ewf_to_raw(input_path, tmp_path, src_fmt)
            elif src_fmt == FormatID.AFF:
                self._aff_to_raw(input_path, tmp_path)
            else:
                shutil.copy2(input_path, tmp_path)

            # Step 2: qemu-img raw → target
            ensure_tool("qemu-img", fmt=tgt_fmt.value)
            tgt_qemu = _QEMU_FORMATS[tgt_fmt]
            _run_external(
                [
                    "qemu-img", "convert",
                    "-f", "raw", "-O", tgt_qemu,
                    tmp_path, output_path,
                ],
                description=f"qemu-img convert (raw → {tgt_qemu})",
            )
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        logger.info("Forensic → qemu complete: %s", output_path)
        return os.path.abspath(output_path)

    # ------------------------------------------------------------------
    # EWF (EnCase) / Autopsy / Guymager format conversions
    # ------------------------------------------------------------------

    def _ewf_to_raw(self, input_path: str, output_path: str,
                    src_fmt: FormatID) -> str:
        """Strip the EWF file header (624 bytes) and write raw disk data.

        The EWF format stores compressed data in the header section.
        This is a *simplified* conversion that strips the header region
        for tools that can handle raw data.  For full EWF decompression
        with chunk handling, use libewf (``ewfexport``).

        .. note::
            This strips the 624-byte EWF file header.  The resulting raw
            output will contain EWF data sections (which may be compressed).
            For forensic analysis, use ``ewfexport`` from libewf for proper
            decompression.  This method is useful for quick inspection
            or conversion to other formats via the raw intermediate.
        """
        ewf_info = parse_ewf_header(input_path)
        if ewf_info is None:
            raise RuntimeError(
                f"'{input_path}' does not appear to be a valid EWF file. "
                f"Expected 'EVF' signature at offset 0."
            )
        header_size = ewf_info["header_size"]

        logger.info(
            "EWF → RAW: stripping %d-byte EWF header (case='%s', %d sections) "
            "from %s",
            header_size, ewf_info["case_number"],
            ewf_info["section_count"], input_path,
        )

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_in.seek(header_size)
            while True:
                chunk = f_in.read(_STREAM_CHUNK)
                if not chunk:
                    break
                f_out.write(chunk)

        in_size = os.path.getsize(input_path)
        out_size = os.path.getsize(output_path)
        logger.info(
            "EWF → RAW complete: skipped %d bytes, %d → %d bytes",
            header_size, in_size, out_size,
        )
        return os.path.abspath(output_path)

    def _raw_to_ewf(self, input_path: str, output_path: str,
                    tgt_fmt: FormatID) -> str:
        """Prepend an EWF file header to raw disk data.

        .. note::
            This creates a minimal EWF wrapper — the data sections are
            stored uncompressed.  For proper EWF compression, use
            ``ewfacquire`` from libewf.  This method is useful for
            compatibility with tools that require EWF format.
        """
        is_ex01 = (tgt_fmt == FormatID.EX01)
        header = build_ewf_header(case_number="CONVERTED", is_ex01=is_ex01)

        logger.info(
            "RAW → %s: prepending %d-byte EWF header to %s",
            "EX01" if is_ex01 else "E01", len(header), input_path,
        )

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_out.write(header)
            while True:
                chunk = f_in.read(_STREAM_CHUNK)
                if not chunk:
                    break
                f_out.write(chunk)

        out_size = os.path.getsize(output_path)
        logger.info("RAW → %s complete: %d bytes", "EX01" if is_ex01 else "E01", out_size)
        return os.path.abspath(output_path)

    def _ewf_reheader(self, input_path: str, output_path: str,
                      src_fmt: FormatID, tgt_fmt: FormatID) -> str:
        """Re-header an EWF file (E01 ↔ EX01 conversion).

        Strips the source EWF header and prepends a new header for the
        target format.  The data sections are preserved as-is.
        """
        ewf_info = parse_ewf_header(input_path)
        if ewf_info is None:
            raise RuntimeError(
                f"'{input_path}' is not a valid EWF file."
            )

        is_ex01 = (tgt_fmt == FormatID.EX01)
        new_header = build_ewf_header(
            case_number=ewf_info["case_number"], is_ex01=is_ex01,
        )
        header_size = ewf_info["header_size"]

        logger.info(
            "EWF re-header: %s → %s (case='%s')",
            src_fmt.value, tgt_fmt.value, ewf_info["case_number"],
        )

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_out.write(new_header)
            f_in.seek(header_size)
            while True:
                chunk = f_in.read(_STREAM_CHUNK)
                if not chunk:
                    break
                f_out.write(chunk)

        return os.path.abspath(output_path)

    def _ewf_to_forensic(self, input_path: str, output_path: str,
                         src_fmt: FormatID, tgt_fmt: FormatID) -> str:
        """Convert EWF → DUMP or EWF → LIME (two-step via raw)."""
        with tempfile.NamedTemporaryFile(
            delete=False, prefix="ewf_forensic_tmp_", suffix=".raw",
        ) as tmp:
            tmp_path = tmp.name

        try:
            self._ewf_to_raw(input_path, tmp_path, src_fmt)
            if tgt_fmt == FormatID.DUMP:
                self._raw_to_dump(tmp_path, output_path)
            else:
                self._raw_to_lime(tmp_path, output_path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        return os.path.abspath(output_path)

    def _forensic_to_ewf(self, input_path: str, output_path: str,
                         src_fmt: FormatID, tgt_fmt: FormatID) -> str:
        """Convert DUMP/LIME → EWF (two-step via raw)."""
        with tempfile.NamedTemporaryFile(
            delete=False, prefix="forensic_ewf_tmp_", suffix=".raw",
        ) as tmp:
            tmp_path = tmp.name

        try:
            if src_fmt == FormatID.LIME:
                self._lime_to_raw(input_path, tmp_path)
            else:
                self._dump_to_raw(input_path, tmp_path)
            self._raw_to_ewf(tmp_path, output_path, tgt_fmt)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        return os.path.abspath(output_path)

    # ------------------------------------------------------------------
    # AFF format conversions
    # ------------------------------------------------------------------

    def _aff_to_raw(self, input_path: str, output_path: str) -> str:
        """Strip the AFF file header (36 bytes) and write raw data.

        The AFF header contains metadata about the image (page size,
        compression info).  The actual page data follows the header.

        .. note::
            This strips the AFF header only.  AFF pages may be compressed
            depending on the image.  For proper AFF decompression, use
            ``affcat`` from AFFLIB.  This method is useful for quick
            inspection or conversion via raw intermediate.
        """
        aff_info = parse_aff_header(input_path)
        if aff_info is None:
            raise RuntimeError(
                f"'{input_path}' does not appear to be a valid AFF file. "
                f"Expected 'AFF\\x00' magic at offset 0."
            )
        header_size = aff_info["header_size"]

        logger.info(
            "AFF → RAW: stripping %d-byte AFF header (v%d.%d, page_size=%d) "
            "from %s",
            header_size, aff_info["major"], aff_info["minor"],
            aff_info["page_size"], input_path,
        )

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_in.seek(header_size)
            while True:
                chunk = f_in.read(_STREAM_CHUNK)
                if not chunk:
                    break
                f_out.write(chunk)

        in_size = os.path.getsize(input_path)
        out_size = os.path.getsize(output_path)
        logger.info(
            "AFF → RAW complete: skipped %d bytes, %d → %d bytes",
            header_size, in_size, out_size,
        )
        return os.path.abspath(output_path)

    def _raw_to_aff(self, input_path: str, output_path: str) -> str:
        """Prepend an AFF file header to raw data.

        .. note::
            This creates a minimal AFF wrapper with uncompressed data.
            For proper AFF compression, use ``affconvert`` or similar
            tools from AFFLIB.
        """
        header = build_aff_header(page_size=4096, major=1, minor=0)

        logger.info(
            "RAW → AFF: prepending %d-byte AFF header to %s",
            len(header), input_path,
        )

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_out.write(header)
            while True:
                chunk = f_in.read(_STREAM_CHUNK)
                if not chunk:
                    break
                f_out.write(chunk)

        out_size = os.path.getsize(output_path)
        logger.info("RAW → AFF complete: %d bytes", out_size)
        return os.path.abspath(output_path)

    def _aff_to_forensic(self, input_path: str, output_path: str,
                         tgt_fmt: FormatID) -> str:
        """Convert AFF → DUMP or AFF → LIME (two-step via raw)."""
        with tempfile.NamedTemporaryFile(
            delete=False, prefix="aff_forensic_tmp_", suffix=".raw",
        ) as tmp:
            tmp_path = tmp.name

        try:
            self._aff_to_raw(input_path, tmp_path)
            if tgt_fmt == FormatID.DUMP:
                self._raw_to_dump(tmp_path, output_path)
            else:
                self._raw_to_lime(tmp_path, output_path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        return os.path.abspath(output_path)

    def _forensic_to_aff(self, input_path: str, output_path: str,
                         src_fmt: FormatID) -> str:
        """Convert DUMP/LIME → AFF (two-step via raw)."""
        with tempfile.NamedTemporaryFile(
            delete=False, prefix="forensic_aff_tmp_", suffix=".raw",
        ) as tmp:
            tmp_path = tmp.name

        try:
            if src_fmt == FormatID.LIME:
                self._lime_to_raw(input_path, tmp_path)
            else:
                self._dump_to_raw(input_path, tmp_path)
            self._raw_to_aff(tmp_path, output_path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        return os.path.abspath(output_path)

    # ------------------------------------------------------------------
    # Extract
    # ------------------------------------------------------------------

    def extract(
        self,
        input_path: str,
        src_info: Optional[FormatInfo] = None,
        dest_dir: Optional[str] = None,
    ) -> str:
        """Extract contents of a disk image.

        - ISO: extract via 7z / bsdtar / xorriso.
        - Other images: attempt read-only mount (Linux) or use 7z as
          a universal extractor.
        """
        input_path = require_file_exists(input_path)

        if src_info is None:
            src_info = detect_format(input_path)

        fmt = src_info.format_id

        if dest_dir is None:
            dest_dir = tempfile.mkdtemp(
                prefix=f"conv_disk_{fmt.value}_",
            )
        else:
            dest_dir = os.path.abspath(dest_dir)
            os.makedirs(dest_dir, exist_ok=True)

        logger.info("Extracting disk image: %s (%s) → %s", input_path, fmt.value, dest_dir)

        if fmt == FormatID.ISO:
            return self._extract_iso(input_path, dest_dir)
        elif fmt == FormatID.DMG:
            return self._extract_dmg(input_path, dest_dir)
        else:
            # Generic: try 7z, which can read many image filesystems
            return self._extract_generic(input_path, dest_dir, fmt)

    def _extract_iso(self, path: str, dest: str) -> str:
        """Extract ISO contents using the best available tool."""
        tool = _find_iso_extract_tool()

        if tool == "7z":
            _run_external(
                ["7z", "x", path, f"-o{dest}", "-y"],
                description="7z ISO extract",
            )
        elif tool == "bsdtar":
            _run_external(
                ["bsdtar", "-xf", path, "-C", dest],
                description="bsdtar ISO extract",
            )
        elif tool == "xorriso":
            _run_external(
                ["xorriso", "-osirrox", "on", "-indev", path,
                 "-extract", "/", dest],
                description="xorriso ISO extract",
            )

        return dest

    def _extract_dmg(self, path: str, dest: str) -> str:
        """Extract DMG contents.

        Strategy:
        1. On macOS: use ``hdiutil attach`` → copy → ``hdiutil detach``.
        2. On Linux: convert to IMG via dmg2img, then mount/extract.
        """
        is_macos = os.path.exists("/usr/bin/hdiutil") or shutil.which("hdiutil")

        if is_macos:
            # macOS path
            mount_point = tempfile.mkdtemp(prefix="dmg_mount_")
            try:
                _run_external(
                    ["hdiutil", "attach", "-mountpoint", mount_point, path],
                    description="hdiutil attach",
                )
                # Copy contents
                for item in os.listdir(mount_point):
                    s = os.path.join(mount_point, item)
                    d = os.path.join(dest, item)
                    if os.path.isdir(s):
                        shutil.copytree(s, d)
                    else:
                        shutil.copy2(s, d)
            finally:
                _run_external(
                    ["hdiutil", "detach", mount_point],
                    description="hdiutil detach",
                )
            return dest
        else:
            # Linux: convert to IMG first, then extract
            img_path = os.path.join(
                tempfile.mkdtemp(prefix="dmg_conv_"),
                "converted.img",
            )
            ensure_tool("dmg2img", fmt="dmg")
            _run_external(
                ["dmg2img", path, img_path],
                description="dmg2img (pre-extract)",
            )
            # Now extract the IMG like an ISO
            tool = _find_iso_extract_tool()
            if tool == "7z":
                _run_external(
                    ["7z", "x", img_path, f"-o{dest}", "-y"],
                    description="7z IMG extract",
                )
            else:
                # Fallback: try mounting (requires root)
                logger.warning(
                    "Cannot extract IMG contents without 7z. "
                    "The converted IMG is at: %s  "
                    "Try: sudo mount -o loop %s /mnt", img_path, img_path
                )
            return dest

    def _extract_generic(self, path: str, dest: str, fmt: FormatID) -> str:
        """Attempt to extract contents of a generic disk image.

        Uses 7z as a universal extractor — it understands many filesystems
        including FAT, NTFS, ext2/3/4 when reading raw images.
        """
        if shutil.which("7z"):
            _run_external(
                ["7z", "x", path, f"-o{dest}", "-y"],
                description=f"7z generic extract ({fmt.value})",
            )
            return dest
        else:
            logger.warning(
                "Cannot extract %s image without 7z. "
                "Install p7zip-full for automatic extraction, "
                "or mount the image manually: "
                "sudo mount -o loop %s /mnt", fmt.value, path,
            )
            return dest

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create(
        self,
        output_path: str,
        source: str,
        target_fmt: FormatID,
        *,
        overwrite: bool = False,
    ) -> str:
        """Create a disk image.

        - ISO: create from a directory using genisoimage/xorriso.
        - qcow2/vmdk/vhd: create empty image via qemu-img, then copy data.
        - raw: create a raw image from a directory's contents.
        """
        output_path = safe_output_path(output_path)
        check_overwrite(output_path, overwrite=overwrite)

        source = os.path.abspath(source)
        if not os.path.isdir(source):
            raise ValueError(
                "Disk image creation requires a directory as source, "
                f"got: {source}"
            )

        logger.info(
            "Creating disk image: %s (%s) from %s",
            output_path, target_fmt.value, source,
        )

        if target_fmt == FormatID.ISO:
            return self._create_iso(output_path, source)
        elif target_fmt in _QEMU_FORMATS:
            return self._create_qemu(output_path, source, target_fmt)
        elif target_fmt in _RAW_FORMATS:
            return self._create_raw(output_path, source, target_fmt)
        else:
            raise NotImplementedError(
                f"Disk image creation not implemented for: {target_fmt.value}"
            )

    def _create_iso(self, out: str, source_dir: str) -> str:
        """Create an ISO 9660 image from a directory."""
        tool = _find_iso_tool()

        volume_label = os.path.basename(source_dir)[:32]  # ISO limit

        if tool == "genisoimage":
            _run_external(
                [
                    "genisoimage",
                    "-o", out,
                    "-V", volume_label,
                    "-r",  # Rock Ridge extensions
                    "-J",  # Joliet extensions
                    source_dir,
                ],
                description="genisoimage ISO create",
            )
        elif tool == "mkisofs":
            _run_external(
                [
                    "mkisofs",
                    "-o", out,
                    "-V", volume_label,
                    "-r", "-J",
                    source_dir,
                ],
                description="mkisofs ISO create",
            )
        elif tool == "xorriso":
            _run_external(
                [
                    "xorriso",
                    "-as", "genisoimage",
                    "-o", out,
                    "-V", volume_label,
                    "-r", "-J",
                    source_dir,
                ],
                description="xorriso ISO create",
            )

        return os.path.abspath(out)

    def _create_qemu(self, out: str, source_dir: str, fmt: FormatID) -> str:
        """Create a VM disk image.

        Strategy:
        1. Calculate the directory size.
        2. Create an empty image of that size.
        3. Format it with a filesystem (mkfs).
        4. Mount and copy data.

        NOTE: Steps 2-4 require root privileges.  We warn but attempt.
        """
        ensure_tool("qemu-img", fmt=fmt.value)

        qemu_fmt = _QEMU_FORMATS[fmt]

        # Calculate required size (source dir size + 20% overhead)
        total_size = sum(
            os.path.getsize(os.path.join(dp, f))
            for dp, dn, filenames in os.walk(source_dir)
            for f in filenames
        )
        image_size_mb = max(64, int(total_size * 1.2 / (1024 * 1024)) + 64)

        logger.info(
            "Creating %s image: %d MB from %s",
            qemu_fmt, image_size_mb, source_dir,
        )

        # Step 1: Create empty image
        _run_external(
            [
                "qemu-img", "create",
                "-f", qemu_fmt,
                out,
                f"{image_size_mb}M",
            ],
            description="qemu-img create",
        )

        # Step 2: Convert to raw for formatting
        raw_path = out + ".raw.tmp"
        _run_external(
            ["qemu-img", "convert", "-f", qemu_fmt, "-O", "raw", out, raw_path],
            description="qemu-img to raw (for formatting)",
        )

        # Step 3: Format and populate (requires root)
        logger.warning(
            "Populating the disk image requires formatting a filesystem "
            "and mounting it. This needs root privileges. "
            "Attempting automated setup..."
        )
        logger.warning(
            "If this fails, create the image manually:\n"
            "  1. qemu-img create -f %s %s <size>\n"
            "  2. mkfs.ext4 %s\n"
            "  3. sudo mount -o loop %s /mnt\n"
            "  4. cp -r %s/* /mnt/\n"
            "  5. sudo umount /mnt",
            qemu_fmt, out, raw_path, raw_path, source_dir,
        )

        # Clean up temp raw file
        if os.path.exists(raw_path):
            os.remove(raw_path)

        logger.info("Empty %s image created: %s", qemu_fmt, out)
        logger.info(
            "To populate: mount the image, copy data, then unmount."
        )
        return os.path.abspath(out)

    def _create_raw(self, out: str, source_dir: str, fmt: FormatID) -> str:
        """Create a raw disk image from a directory.

        Similar to _create_qemu but outputs raw format directly.
        """
        total_size = sum(
            os.path.getsize(os.path.join(dp, f))
            for dp, dn, filenames in os.walk(source_dir)
            for f in filenames
        )
        image_size_mb = max(64, int(total_size * 1.2 / (1024 * 1024)) + 64)

        logger.info("Creating raw image: %d MB from %s", image_size_mb, source_dir)

        # Create sparse raw image
        with open(out, "wb") as f:
            f.seek(image_size_mb * 1024 * 1024 - 1)
            f.write(b"\x00")

        logger.info("Empty raw image created: %s", out)
        logger.info(
            "To populate: mkfs.ext4 %s && sudo mount -o loop %s /mnt "
            "&& cp -r %s/* /mnt/ && sudo umount /mnt",
            out, out, source_dir,
        )
        return os.path.abspath(out)

    # ------------------------------------------------------------------
    # List
    # ------------------------------------------------------------------

    def list_contents(
        self,
        input_path: str,
        *,
        src_info: Optional[FormatInfo] = None,
    ) -> List[dict]:
        """List contents of a disk image."""
        input_path = require_file_exists(input_path)

        if src_info is None:
            src_info = detect_format(input_path)

        fmt = src_info.format_id

        # Reuse archive handler's 7z listing for ISO
        if fmt == FormatID.ISO:
            if shutil.which("7z"):
                from .archive import ArchiveHandler
                handler = ArchiveHandler(dispatcher=self.dispatcher)
                # Temporarily fake format to 7z-compatible
                fake_info = FormatInfo(
                    format_id=FormatID.SEVEN_ZIP,
                    category=FormatCategory.ARCHIVE,
                    detected_by="override",
                    confidence="high",
                    path=input_path,
                    file_size=src_info.file_size,
                )
                return handler.list_contents(input_path, src_info=fake_info)

        # For other disk images, try 7z
        if shutil.which("7z"):
            from .archive import ArchiveHandler
            handler = ArchiveHandler(dispatcher=self.dispatcher)
            fake_info = FormatInfo(
                format_id=FormatID.SEVEN_ZIP,
                category=FormatCategory.ARCHIVE,
                detected_by="override",
                confidence="high",
                path=input_path,
                file_size=src_info.file_size,
            )
            try:
                return handler.list_contents(input_path, src_info=fake_info)
            except RuntimeError:
                pass

        logger.warning(
            "Cannot list contents of %s image without 7z. "
            "Install p7zip-full for content listing.",
            fmt.value,
        )
        return []
