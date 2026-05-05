"""
Archive Handler
===============

Handles all archive / compression format operations:
- extract (decompress)
- create  (compress a file/directory into an archive)
- convert (archive → archive: decompress → recompress)
- list   (list contents without extracting)

Format coverage
---------------
| Format   | Extract       | Create        | Convert | Notes                   |
|----------|---------------|---------------|---------|-------------------------|
| .zip     | zipfile ✓     | zipfile ✓     | ✓       | Pure Python             |
| .tar     | tarfile ✓     | tarfile ✓     | ✓       | Pure Python             |
| .tar.gz  | tarfile ✓     | tarfile ✓     | ✓       | Pure Python             |
| .tar.bz2 | tarfile ✓     | tarfile ✓     | ✓       | Pure Python             |
| .tar.xz  | tarfile ✓     | tarfile ✓     | ✓       | Pure Python             |
| .gz      | gzip ✓        | gzip ✓        | ✓       | Single-file compression |
| .bz2     | bz2 ✓         | bz2 ✓         | ✓       | Single-file compression |
| .xz      | lzma ✓        | lzma ✓        | ✓       | Single-file compression |
| .7z      | 7z (external) | 7z (external) | ✓       | Requires p7zip-full     |
| .rar     | unrar (ext.)  | rar (external)| ✓       | Requires unrar          |
| .cab     | cabextract    | cabenc (ext.) | partial | Read-heavy; write needs lcab/cabarc |

Design decisions
----------------
- We **always** use Python stdlib when possible; external tools are only
  invoked as a fallback or when no stdlib support exists (RAR, 7z, CAB).
- For cross-format conversion we use a **temporary working directory**:
  extract source → recompress to target.  This is the safest approach
  because it avoids in-memory buffering of large archives.
- Compound extensions (``.tar.gz``, ``.tar.bz2``, ``.tar.xz``) are
  handled specially by ``tarfile``'s native mode support.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from typing import TYPE_CHECKING, Dict, List, Optional

from ..core.detector import (
    FormatID, FormatInfo, FormatCategory,
    get_extension, detect_format,
)
from ..core.dispatcher import ConversionEntry
from ..core.dependencies import ensure_tool
from ..utils.validation import (
    require_file_exists, require_dir_exists,
    check_overwrite, safe_output_path, is_readable,
)

if TYPE_CHECKING:
    from ..core.dispatcher import Dispatcher

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Formats that tarfile can open natively
_TARFILE_MODES: Dict[FormatID, str] = {
    FormatID.TAR:    "r:",
    FormatID.TAR_GZ: "r:gz",
    FormatID.TAR_BZ2:"r:bz2",
    FormatID.TAR_XZ: "r:xz",
}

_TARFILE_WRITE_MODES: Dict[FormatID, str] = {
    FormatID.TAR:    "w:",
    FormatID.TAR_GZ: "w:gz",
    FormatID.TAR_BZ2:"w:bz2",
    FormatID.TAR_XZ: "w:xz",
}

# Formats that are single-stream compressors (not containers)
_STREAM_FORMATS = {FormatID.GZIP, FormatID.BZIP2, FormatID.XZ}

_STREAM_MODULES = {
    FormatID.GZIP: gzip,
    FormatID.BZIP2: bz2,
    FormatID.XZ:   lzma,
}


def _run_external(
    cmd: List[str], description: str = ""
) -> subprocess.CompletedProcess:
    """Run an external command with error handling."""
    logger.debug("Running external: %s  (%s)", " ".join(cmd), description)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,  # 1-hour timeout for large files
        )
    except FileNotFoundError:
        raise RuntimeError(
            f"External tool not found: {cmd[0]}. "
            f"Check that it is installed and on $PATH."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"External command timed out: {' '.join(cmd)}"
        )
    if result.returncode != 0:
        raise RuntimeError(
            f"{description or cmd[0]} failed (exit {result.returncode}):\n"
            f"  stdout: {result.stdout.strip()}\n"
            f"  stderr: {result.stderr.strip()}"
        )
    return result


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

class ArchiveHandler:
    """Manages archive extraction, creation, conversion, and listing."""

    def __init__(self, *, dispatcher: "Dispatcher") -> None:
        self.dispatcher = dispatcher

    # ------------------------------------------------------------------
    # Extract
    # ------------------------------------------------------------------

    def extract(
        self,
        input_path: str,
        src_info: Optional[FormatInfo] = None,
        dest_dir: Optional[str] = None,
    ) -> str:
        """Extract *input_path* to *dest_dir*.

        Returns the absolute path to the extraction directory.
        """
        input_path = require_file_exists(input_path)

        if src_info is None:
            src_info = detect_format(input_path)

        if src_info.category != FormatCategory.ARCHIVE:
            raise ValueError(
                f"'{input_path}' is not an archive format "
                f"(detected: {src_info.format_id.value})."
            )

        if dest_dir is None:
            dest_dir = tempfile.mkdtemp(
                prefix=f"conv_{src_info.format_id.value}_",
            )
        else:
            dest_dir = os.path.abspath(dest_dir)
            os.makedirs(dest_dir, exist_ok=True)

        fmt = src_info.format_id
        logger.info("Extracting %s (%s) → %s", input_path, fmt.value, dest_dir)

        if fmt in _TARFILE_MODES:
            self._extract_tar(input_path, dest_dir, fmt)
        elif fmt == FormatID.ZIP:
            self._extract_zip(input_path, dest_dir)
        elif fmt in _STREAM_FORMATS:
            self._extract_stream(input_path, dest_dir, fmt)
        elif fmt == FormatID.SEVEN_ZIP:
            self._extract_7z(input_path, dest_dir)
        elif fmt == FormatID.RAR:
            self._extract_rar(input_path, dest_dir)
        elif fmt == FormatID.CAB:
            self._extract_cab(input_path, dest_dir)
        else:
            raise NotImplementedError(
                f"Extraction not implemented for format: {fmt.value}"
            )

        logger.info("Extraction complete: %s", dest_dir)
        return dest_dir

    def _extract_tar(self, path: str, dest: str, fmt: FormatID) -> None:
        mode = _TARFILE_MODES[fmt]
        with tarfile.open(path, mode) as tf:
            # Security: guard against path traversal (CVE-2007-4559)
            members = tf.getmembers()
            for m in members:
                member_path = os.path.realpath(os.path.join(dest, m.name))
                if not member_path.startswith(os.path.realpath(dest) + os.sep):
                    raise ValueError(
                        f"Path traversal detected in tar archive: {m.name}"
                    )
            tf.extractall(dest, members=members, filter="data")

    def _extract_zip(self, path: str, dest: str) -> None:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                # Security: guard against zip-slip
                member_path = os.path.realpath(os.path.join(dest, info.filename))
                if not member_path.startswith(os.path.realpath(dest) + os.sep):
                    raise ValueError(
                        f"Path traversal detected in zip archive: {info.filename}"
                    )
            zf.extractall(dest)

    def _extract_stream(self, path: str, dest: str, fmt: FormatID) -> None:
        """Extract a single-stream compressed file (gz/bz2/xz).

        The output filename is the input filename minus the compression
        extension.
        """
        mod = _STREAM_MODULES[fmt]
        base = os.path.basename(path)
        # Strip the compression extension
        for ext in (".gz", ".gzip", ".bz2", ".xz"):
            if base.lower().endswith(ext):
                base = base[: -len(ext)]
                break
        out = os.path.join(dest, base)

        try:
            with mod.open(path, "rb") as f_in:
                with open(out, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to decompress {fmt.value} file: {exc}"
            ) from exc

    def _extract_7z(self, path: str, dest: str) -> None:
        ensure_tool("7z", fmt="7z")
        _run_external(
            ["7z", "x", path, f"-o{dest}", "-y"],
            description="7z extract",
        )

    def _extract_rar(self, path: str, dest: str) -> None:
        # Prefer unrar (free) over rar (shareware)
        unrar = shutil.which("unrar")
        if unrar:
            _run_external(
                [unrar, "x", "-o+", path, dest + "/"],
                description="unrar extract",
            )
        else:
            # Try 7z as fallback (many .rar files are RAR4 which 7z handles)
            if shutil.which("7z"):
                _run_external(
                    ["7z", "x", path, f"-o{dest}", "-y"],
                    description="7z extract (RAR fallback)",
                )
            else:
                ensure_tool("unrar", fmt="rar")

    def _extract_cab(self, path: str, dest: str) -> None:
        # Try cabextract first
        cabextract = shutil.which("cabextract")
        if cabextract:
            _run_external(
                [cabextract, "-d", dest, path],
                description="cabextract",
            )
        else:
            # Fallback: 7z can extract many .cab files
            if shutil.which("7z"):
                _run_external(
                    ["7z", "x", path, f"-o{dest}", "-y"],
                    description="7z extract (CAB fallback)",
                )
            else:
                ensure_tool("cabextract", fmt="cab")

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
        """Create an archive from *source* (file or directory).

        Returns the absolute output path.
        """
        output_path = safe_output_path(output_path)
        check_overwrite(output_path, overwrite=overwrite)

        source = os.path.abspath(source)
        if not os.path.exists(source):
            raise FileNotFoundError(f"Source does not exist: {source}")

        logger.info("Creating %s (%s) from %s", output_path, target_fmt.value, source)

        is_dir = os.path.isdir(source)

        if target_fmt in _TARFILE_WRITE_MODES:
            self._create_tar(output_path, source, target_fmt, is_dir=is_dir)
        elif target_fmt == FormatID.ZIP:
            self._create_zip(output_path, source, is_dir=is_dir)
        elif target_fmt in _STREAM_FORMATS:
            self._create_stream(output_path, source, target_fmt)
        elif target_fmt == FormatID.SEVEN_ZIP:
            self._create_7z(output_path, source, is_dir=is_dir)
        elif target_fmt == FormatID.RAR:
            self._create_rar(output_path, source, is_dir=is_dir)
        else:
            raise NotImplementedError(
                f"Creation not implemented for format: {target_fmt.value}"
            )

        logger.info("Archive created: %s", output_path)
        return output_path

    def _create_tar(self, out: str, source: str, fmt: FormatID, *, is_dir: bool) -> None:
        mode = _TARFILE_WRITE_MODES[fmt]
        with tarfile.open(out, mode) as tf:
            if is_dir:
                tf.add(source, arcname=os.path.basename(source))
            else:
                tf.add(source, arcname=os.path.basename(source))

    def _create_zip(self, out: str, source: str, *, is_dir: bool) -> None:
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            if is_dir:
                for root, dirs, files in os.walk(source):
                    for file in files:
                        full = os.path.join(root, file)
                        arcname = os.path.relpath(full, os.path.dirname(source))
                        zf.write(full, arcname)
            else:
                zf.write(source, arcname=os.path.basename(source))

    def _create_stream(self, out: str, source: str, fmt: FormatID) -> None:
        """Compress a single file into a gz/bz2/xz stream."""
        if os.path.isdir(source):
            raise ValueError(
                f"Stream formats ({fmt.value}) can only compress single files, "
                f"not directories.  Use .tar.{fmt.value} instead."
            )
        mod = _STREAM_MODULES[fmt]
        with open(source, "rb") as f_in:
            with mod.open(out, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

    def _create_7z(self, out: str, source: str, *, is_dir: bool) -> None:
        ensure_tool("7z", fmt="7z")
        _run_external(
            ["7z", "a", "-y", out, source],
            description="7z create",
        )

    def _create_rar(self, out: str, source: str, *, is_dir: bool) -> None:
        ensure_tool("rar", fmt="rar")
        _run_external(
            ["rar", "a", "-r", out, source],
            description="rar create",
        )

    # ------------------------------------------------------------------
    # Convert  (archive → archive)
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
        """Convert between archive formats.

        Strategy: extract → recompress.  Uses a temporary directory as
        the intermediate staging area.
        """
        input_path = require_file_exists(input_path)
        output_path = safe_output_path(output_path)
        check_overwrite(output_path, overwrite=overwrite)

        if src_info is None:
            src_info = detect_format(input_path)

        # Stream-to-stream: can do in-memory for single files
        if src_info.format_id in _STREAM_FORMATS and target_fmt in _STREAM_FORMATS:
            return self._convert_stream_to_stream(
                input_path, output_path, src_info.format_id, target_fmt,
            )

        # General case: extract to temp dir → recompress
        with tempfile.TemporaryDirectory(
            prefix=f"conv_{src_info.format_id.value}_",
        ) as tmpdir:
            self.extract(input_path, src_info=src_info, dest_dir=tmpdir)

            # Determine what to compress: if extraction produced a single
            # file, compress that file; if a directory, compress the dir.
            items = os.listdir(tmpdir)
            if len(items) == 1:
                stage_source = os.path.join(tmpdir, items[0])
            else:
                # Multiple items — wrap in a directory
                stage_source = tmpdir

            return self.create(
                output_path, stage_source, target_fmt,
                overwrite=overwrite,
            )

    def _convert_stream_to_stream(
        self,
        input_path: str,
        output_path: str,
        src_fmt: FormatID,
        tgt_fmt: FormatID,
    ) -> str:
        """Efficient single-file stream → stream conversion."""
        src_mod = _STREAM_MODULES[src_fmt]
        tgt_mod = _STREAM_MODULES[tgt_fmt]

        try:
            with src_mod.open(input_path, "rb") as f_in:
                with tgt_mod.open(output_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
        except Exception as exc:
            # Clean up partial output
            if os.path.exists(output_path):
                os.remove(output_path)
            raise RuntimeError(
                f"Stream conversion ({src_fmt.value} → {tgt_fmt.value}) failed: {exc}"
            ) from exc

        return os.path.abspath(output_path)

    # ------------------------------------------------------------------
    # List
    # ------------------------------------------------------------------

    def list_contents(
        self,
        input_path: str,
        *,
        src_info: Optional[FormatInfo] = None,
    ) -> List[dict]:
        """List archive contents without extracting.

        Returns a list of dicts with keys:
          ``name``, ``size``, ``is_dir``, ``date_time``
        """
        input_path = require_file_exists(input_path)
        if src_info is None:
            src_info = detect_format(input_path)

        fmt = src_info.format_id

        if fmt in _TARFILE_MODES:
            return self._list_tar(input_path, fmt)
        elif fmt == FormatID.ZIP:
            return self._list_zip(input_path)
        elif fmt == FormatID.SEVEN_ZIP:
            return self._list_7z(input_path)
        elif fmt == FormatID.RAR:
            return self._list_rar(input_path)
        elif fmt in _STREAM_FORMATS:
            # Single-file: just report the one decompressed file
            base = os.path.basename(input_path)
            for ext in (".gz", ".gzip", ".bz2", ".xz"):
                if base.lower().endswith(ext):
                    base = base[: -len(ext)]
                    break
            return [{"name": base, "size": "—", "is_dir": False, "date_time": "—"}]
        elif fmt == FormatID.CAB:
            return self._list_cab(input_path)
        else:
            raise NotImplementedError(
                f"Listing not implemented for format: {fmt.value}"
            )

    def _list_tar(self, path: str, fmt: FormatID) -> List[dict]:
        mode = _TARFILE_MODES[fmt]
        entries = []
        with tarfile.open(path, mode) as tf:
            for m in tf.getmembers():
                entries.append({
                    "name": m.name,
                    "size": m.size,
                    "is_dir": m.isdir(),
                    "date_time": m.mtime,
                })
        return entries

    def _list_zip(self, path: str) -> List[dict]:
        entries = []
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                entries.append({
                    "name": info.filename,
                    "size": info.file_size,
                    "is_dir": info.is_dir(),
                    "date_time": info.date_time,
                })
        return entries

    def _list_7z(self, path: str) -> List[dict]:
        ensure_tool("7z", fmt="7z")
        result = _run_external(["7z", "l", "-slt", path], description="7z list")
        # Parse 7z's semi-structured output
        entries = []
        current: dict = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("---"):
                if current:
                    entries.append(current)
                    current = {}
            elif "=" in line:
                key, val = line.split("=", 1)
                current[key.strip()] = val.strip()
        if current:
            entries.append(current)
        return [
            {
                "name": e.get("Path", "?"),
                "size": e.get("Size", "?"),
                "is_dir": e.get("Folder", "") == "yes",
                "date_time": e.get("Modified", "?"),
            }
            for e in entries
        ]

    def _list_rar(self, path: str) -> List[dict]:
        # Use unrar or 7z for listing
        if shutil.which("unrar"):
            result = _run_external(
                ["unrar", "lt", path], description="unrar list"
            )
            # Parse unrar output (simplified)
            entries = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[-1] not in ("", "-----------"):
                    try:
                        size = int(parts[2])
                        name = parts[-1]
                        entries.append({
                            "name": name,
                            "size": size,
                            "is_dir": name.endswith("/"),
                            "date_time": f"{parts[0]} {parts[1]}",
                        })
                    except (ValueError, IndexError):
                        continue
            return entries
        elif shutil.which("7z"):
            # Re-use 7z listing (which runs its own 7z command)
            return self._list_7z(path)
        else:
            ensure_tool("unrar", fmt="rar")
            return []  # unreachable

    def _list_cab(self, path: str) -> List[dict]:
        # Try 7z listing for CAB
        if shutil.which("7z"):
            result = _run_external(
                ["7z", "l", "-slt", path], description="7z list (cab)"
            )
            entries = []
            current: dict = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("---"):
                    if current:
                        entries.append(current)
                        current = {}
                elif "=" in line:
                    key, val = line.split("=", 1)
                    current[key.strip()] = val.strip()
            if current:
                entries.append(current)
            return [
                {
                    "name": e.get("Path", "?"),
                    "size": e.get("Size", "?"),
                    "is_dir": e.get("Folder", "") == "yes",
                    "date_time": e.get("Modified", "?"),
                }
                for e in entries
            ]
        ensure_tool("cabextract", fmt="cab")
        return []  # unreachable
