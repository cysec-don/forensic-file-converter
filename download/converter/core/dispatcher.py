"""
Conversion Dispatcher
=====================

The dispatcher is the central brain of the converter.  Its responsibilities:

1. **Validate conversions** — consult a *conversion matrix* that encodes
   which source → target conversions are supported, lossless, or
   lossy/loss-of-metadata.
2. **Route to the correct handler** — archive handler or disk-image
   handler.
3. **Handle cross-category conversions** — e.g. extracting an archive
   to a directory, then creating an ISO from it (two-step pipeline).

Design decisions
----------------
- The conversion matrix is a *deny-by-default* allowlist.  Adding a new
  conversion is a one-line addition; forgetting to add one results in a
  clear ``UnsupportedConversion`` error rather than silent data loss.
- Cross-category conversions (archive → disk or disk → archive) are
  **explicitly rejected** at the dispatcher level.  These require
  human intent that cannot be guessed.  The user must first extract /
  mount, then convert.
"""

from __future__ import annotations

import enum
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from .detector import FormatID, FormatCategory, FormatInfo, detect_format, get_category
from .dependencies import check_all, DependencyReport, ensure_tool

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Conversion quality / feasibility
# ---------------------------------------------------------------------------

class ConversionSupport(enum.Enum):
    """How well a conversion is supported."""
    FULL       = "full"        # native, lossless, supported
    TWO_STEP   = "two_step"    # supported but requires intermediate step
    EXTERNAL   = "external"    # requires an external tool
    PARTIAL    = "partial"     # some metadata / properties may be lost
    UNSUPPORTED = "unsupported"


@dataclass
class ConversionEntry:
    source: FormatID
    target: FormatID
    support: ConversionSupport
    notes: str = ""
    requires_tool: str = ""     # external tool name, if any


# ---------------------------------------------------------------------------
# Conversion matrix (allowlist)
# ---------------------------------------------------------------------------

def _build_conversion_matrix() -> Dict[Tuple[FormatID, FormatID], ConversionEntry]:
    """Populate the full conversion matrix.

    Every entry represents a conversion the tool *claims* to handle.
    If a pair is missing, it is ``UNSUPPORTED``.

    Strategy
    --------
    - Archive ↔ Archive: decompress → recompress  (lossless for data,
      may lose format-specific metadata like NTFS ACLs in ZIP).
    - Disk ↔ Disk: qemu-img or raw copy where applicable.
    - Cross-category: NOT supported (must be explicit two-step).
    """
    matrix: Dict[Tuple[FormatID, FormatID], ConversionEntry] = {}

    def _add(
        src: FormatID,
        tgt: FormatID,
        support: ConversionSupport,
        notes: str = "",
        requires_tool: str = "",
    ) -> None:
        matrix[(src, tgt)] = ConversionEntry(
            source=src, target=tgt,
            support=support, notes=notes, requires_tool=requires_tool,
        )

    # -- Archive ↔ Archive ------------------------------------------------

    archive_formats = [
        FormatID.ZIP, FormatID.RAR, FormatID.SEVEN_ZIP, FormatID.TAR,
        FormatID.GZIP, FormatID.BZIP2, FormatID.XZ, FormatID.CAB,
        FormatID.TAR_GZ, FormatID.TAR_BZ2, FormatID.TAR_XZ,
    ]

    for src in archive_formats:
        for tgt in archive_formats:
            if src == tgt:
                continue
            _add(src, tgt, ConversionSupport.FULL,
                 "Decompress → recompress pipeline. Data is preserved; "
                 "format-specific metadata (permissions, ACLs, comments) "
                 "may not transfer.")

    # -- Disk ↔ Disk (virtual-machine formats via qemu-img) ---------------

    qemu_formats = [FormatID.QCOW2, FormatID.VMDK, FormatID.VHD, FormatID.VHDX]
    raw_formats  = [FormatID.RAW, FormatID.DD, FormatID.IMG]

    for src in qemu_formats:
        for tgt in qemu_formats:
            if src != tgt:
                _add(src, tgt, ConversionSupport.EXTERNAL,
                     "Converted via qemu-img. All data preserved.",
                     requires_tool="qemu-img")
        for tgt in raw_formats:
            _add(src, tgt, ConversionSupport.EXTERNAL,
                 "Converted to raw image via qemu-img.",
                 requires_tool="qemu-img")

    for src in raw_formats:
        for tgt in qemu_formats:
            _add(src, tgt, ConversionSupport.EXTERNAL,
                 "Converted from raw image via qemu-img.",
                 requires_tool="qemu-img")
        for tgt in raw_formats:
            if src != tgt:
                _add(src, tgt, ConversionSupport.FULL,
                     "Raw-to-raw copy; essentially a rename/re-header.")

    # ISO creation (folder → ISO) is handled via --create, not --input/--output
    # ISO extraction (ISO → folder) handled via --extract

    # BIN ↔ RAW/IMG
    _add(FormatID.BIN, FormatID.IMG, ConversionSupport.FULL,
         "BIN (raw sector data) → IMG (raw image). Lossless rename.")
    _add(FormatID.IMG, FormatID.BIN, ConversionSupport.FULL,
         "IMG → BIN. Lossless rename; companion .cue may need manual update.")
    _add(FormatID.BIN, FormatID.RAW, ConversionSupport.FULL,
         "BIN → RAW. Lossless; assumes BIN contains raw sector data.")
    _add(FormatID.RAW, FormatID.BIN, ConversionSupport.FULL,
         "RAW → BIN. Lossless.")

    # DMG (limited — extract on macOS, convert on Linux via dmg2img)
    _add(FormatID.DMG, FormatID.IMG, ConversionSupport.EXTERNAL,
         "DMG → IMG via dmg2img. Converts raw DMG only; encrypted/SPUD "
         "DMGs are NOT supported.",
         requires_tool="dmg2img")
    _add(FormatID.DMG, FormatID.RAW, ConversionSupport.EXTERNAL,
         "DMG → RAW via dmg2img. Same caveats as DMG → IMG.",
         requires_tool="dmg2img")

    return matrix


_MATRIX = _build_conversion_matrix()


def get_conversion_entry(
    src: FormatID, tgt: FormatID
) -> ConversionEntry:
    """Look up the matrix.  Returns UNSUPPORTED entry for unknown pairs."""
    return _MATRIX.get(
        (src, tgt),
        ConversionEntry(source=src, target=tgt, support=ConversionSupport.UNSUPPORTED),
    )


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class ConversionError(Exception):
    """Base exception for conversion failures."""
    pass


class UnsupportedConversion(ConversionError):
    """Raised when the source→target pair has no conversion path."""
    def __init__(self, src: FormatID, tgt: FormatID, reason: str = ""):
        self.src = src
        self.tgt = tgt
        self.reason = reason
        super().__init__(
            f"Conversion from '{src.value}' to '{tgt.value}' is not supported. "
            f"{reason}".strip()
        )


class MissingDependency(ConversionError):
    """Raised when a required external tool is missing."""
    def __init__(self, tool: str, install_hint: str, fmt: str):
        self.tool = tool
        self.install_hint = install_hint
        self.fmt = fmt
        super().__init__(
            f"External tool '{tool}' is required for format '{fmt}' but was not "
            f"found on $PATH.\n  Install: {install_hint}"
        )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

class Dispatcher:
    """Routes conversion requests to the appropriate handler."""

    def __init__(self) -> None:
        self._dep_report: Optional[DependencyReport] = None

    @property
    def dep_report(self) -> DependencyReport:
        if self._dep_report is None:
            self._dep_report = check_all()
        return self._dep_report

    def validate_conversion(
        self,
        src_info: FormatInfo,
        target_fmt: FormatID,
    ) -> ConversionEntry:
        """Check whether a conversion is feasible and dependencies are met.

        Raises ``UnsupportedConversion`` or ``MissingDependency``.
        Returns the ``ConversionEntry`` on success.
        """
        # Cross-category guard
        src_cat = get_category(src_info.format_id)
        tgt_cat = get_category(target_fmt)
        if (src_cat != FormatCategory.UNKNOWN and tgt_cat != FormatCategory.UNKNOWN
                and src_cat != tgt_cat):
            raise UnsupportedConversion(
                src_info.format_id, target_fmt,
                f"Cannot convert between categories "
                f"({src_cat.value} → {tgt_cat.value}). "
                f"Perform the operation in two steps: first extract/mount, "
                f"then convert."
            )

        entry = get_conversion_entry(src_info.format_id, target_fmt)

        if entry.support == ConversionSupport.UNSUPPORTED:
            raise UnsupportedConversion(src_info.format_id, target_fmt)

        if entry.requires_tool:
            missing = self.dep_report.missing_for_format(entry.requires_tool)
            for tool_info in missing:
                if tool_info.name == entry.requires_tool:
                    raise MissingDependency(
                        tool_info.name, tool_info.install_hint,
                        src_info.format_id.value,
                    )

        return entry

    def dispatch(
        self,
        input_path: str,
        output_path: str,
        src_info: Optional[FormatInfo] = None,
        target_fmt: Optional[FormatID] = None,
        *,
        overwrite: bool = False,
    ) -> str:
        """Execute a conversion and return the output path.

        Parameters
        ----------
        input_path : str
            Path to the source file.
        output_path : str
            Desired output path.
        src_info : FormatInfo, optional
            Pre-detected source format info.
        target_fmt : FormatID, optional
            Explicit target format.
        overwrite : bool
            If True, allow overwriting existing output files.

        Returns
        -------
        str  — absolute path to the output file.
        """
        # --- Detect source format ----------------------------------------
        if src_info is None:
            src_info = detect_format(input_path)

        # --- Determine target format from output extension ---------------
        if target_fmt is None:
            from .detector import format_from_extension
            ext = os.path.splitext(output_path)[1].lower()
            target_fmt = format_from_extension(ext)
            if target_fmt is None:
                raise ConversionError(
                    f"Cannot determine target format from output path "
                    f"'{output_path}'.  Use --format to specify explicitly."
                )

        # --- Validate ----------------------------------------------------
        entry = self.validate_conversion(src_info, target_fmt)
        logger.info(
            "Dispatching: %s → %s  (method: %s)",
            src_info.format_id.value, target_fmt.value, entry.support.value,
        )

        # --- Import and call handler -------------------------------------
        if src_info.category == FormatCategory.ARCHIVE:
            from ..handlers.archive import ArchiveHandler
            handler = ArchiveHandler(dispatcher=self)
            return handler.convert(
                input_path, output_path,
                src_info=src_info, target_fmt=target_fmt,
                overwrite=overwrite, entry=entry,
            )
        elif src_info.category == FormatCategory.DISK_IMAGE:
            from ..handlers.disk import DiskImageHandler
            handler = DiskImageHandler(dispatcher=self)
            return handler.convert(
                input_path, output_path,
                src_info=src_info, target_fmt=target_fmt,
                overwrite=overwrite, entry=entry,
            )
        else:
            raise UnsupportedConversion(
                src_info.format_id, target_fmt,
                "Source file has unknown format category.",
            )

    def extract(self, input_path: str, dest_dir: Optional[str] = None) -> str:
        """Extract an archive or disk image to *dest_dir*.

        Returns the path to the extraction directory.
        """
        src_info = detect_format(input_path)

        if src_info.category == FormatCategory.ARCHIVE:
            from ..handlers.archive import ArchiveHandler
            handler = ArchiveHandler(dispatcher=self)
            return handler.extract(input_path, dest_dir=dest_dir)
        elif src_info.category == FormatCategory.DISK_IMAGE:
            from ..handlers.disk import DiskImageHandler
            handler = DiskImageHandler(dispatcher=self)
            return handler.extract(input_path, dest_dir=dest_dir)
        else:
            raise ConversionError(
                f"Cannot extract '{input_path}': unknown format category."
            )

    def create(
        self,
        output_path: str,
        source: str,
        fmt: Optional[FormatID] = None,
    ) -> str:
        """Create an archive or disk image from a file/directory.

        Parameters
        ----------
        output_path : str
            Desired output archive / image path.
        source : str
            File or directory to archive / image.
        fmt : FormatID, optional
            Explicit target format.
        """
        from .detector import format_from_extension
        if fmt is None:
            ext = os.path.splitext(output_path)[1].lower()
            fmt = format_from_extension(ext)
            if fmt is None:
                # Try compound extension
                lower = output_path.lower()
                for compound in (".tar.gz", ".tar.bz2", ".tar.xz"):
                    if lower.endswith(compound):
                        fmt = format_from_extension(compound)
                        break
                if fmt is None:
                    raise ConversionError(
                        f"Cannot determine output format from '{output_path}'. "
                        f"Use --format to specify."
                    )

        cat = get_category(fmt)
        if cat == FormatCategory.ARCHIVE:
            from ..handlers.archive import ArchiveHandler
            handler = ArchiveHandler(dispatcher=self)
            return handler.create(output_path, source, target_fmt=fmt)
        elif cat == FormatCategory.DISK_IMAGE:
            from ..handlers.disk import DiskImageHandler
            handler = DiskImageHandler(dispatcher=self)
            return handler.create(output_path, source, target_fmt=fmt)
        else:
            raise ConversionError(f"Cannot create format '{fmt.value}'.")

    def list_contents(self, input_path: str) -> List[dict]:
        """List the contents of an archive without extracting."""
        src_info = detect_format(input_path)

        if src_info.category == FormatCategory.ARCHIVE:
            from ..handlers.archive import ArchiveHandler
            handler = ArchiveHandler(dispatcher=self)
            return handler.list_contents(input_path, src_info=src_info)
        elif src_info.category == FormatCategory.DISK_IMAGE:
            from ..handlers.disk import DiskImageHandler
            handler = DiskImageHandler(dispatcher=self)
            return handler.list_contents(input_path, src_info=src_info)
        else:
            raise ConversionError(
                f"Cannot list contents of '{input_path}': unknown format."
            )
