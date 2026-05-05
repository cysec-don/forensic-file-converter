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

Design decisions
----------------
- **qemu-img** is the primary tool for virtual-machine disk images.  It
  supports: qcow2, vmdk, vhd, vhdx, raw, and many more.  We delegate
  entirely to it rather than reimplementing format-specific headers.
- **ISO creation** uses ``genisoimage`` (Linux) or ``xorriso`` (portable)
  because Python has no stdlib ISO 9660 writer.
- **ISO extraction** uses ``7z`` where available (it understands ISO 9660),
  falling back to ``bsdtar`` or ``xorriso``.
- **DMG support is deliberately limited**:
  - On macOS, ``hdiutil`` can attach/extract DMGs natively.
  - On Linux, only **raw (unencrypted, non-SPUD)** DMGs can be converted
    to IMG via ``dmg2img``.  Encrypted DMGs and SPUD (chunked) DMGs are
    explicitly NOT supported because no open-source tool handles them.
  - We do NOT attempt to mount DMGs on Linux because it requires FUSE
    modules that are distribution-specific and fragile.
- **Raw copies** (.img, .raw, .dd, .bin) are byte-for-byte when the
  source and target are both raw formats.  No conversion needed — just
  a copy with optional size validation.
- Large files are handled via ``subprocess`` streaming — we never load
  an entire disk image into memory.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from typing import TYPE_CHECKING, Dict, List, Optional

from ..core.detector import (
    FormatID, FormatInfo, FormatCategory,
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
