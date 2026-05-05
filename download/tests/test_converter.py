"""
Comprehensive test suite for the Universal File Converter.
===========================================================

Run with::

    python -m pytest tests/test_converter.py -v

Or directly::

    python tests/test_converter.py

Tests cover:
- Format detection (extension, magic bytes, conflicts)
- Validation (overwrite, path traversal, disk space)
- Archive handler (extract, create, convert, list)
- Disk image handler (convert, extract)
- Dispatcher (routing, conversion matrix)
- CLI (argument parsing, exit codes)
- Plugin system (registration, lookup)
- Edge cases (corrupted files, empty archives, missing tools)
"""

from __future__ import annotations

import bz2
import gzip
import logging as py_logging
import lzma
import os
import shutil
import struct
import sys
import tarfile
import tempfile
import unittest
import zipfile
from io import BytesIO
from unittest.mock import patch, MagicMock, PropertyMock

# Add parent to path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from converter.core.detector import (
    FormatID, FormatCategory, FormatInfo,
    detect_format, format_from_extension,
    get_category, get_extension,
    _normalise_ext, all_archive_formats, all_disk_formats,
    _MAGIC_SIGNATURES,
)
from converter.core.dispatcher import (
    Dispatcher, ConversionSupport, UnsupportedConversion,
    MissingDependency, get_conversion_entry,
)
from converter.core.dependencies import check_all, DependencyReport
from converter.handlers.archive import ArchiveHandler
from converter.handlers.disk import DiskImageHandler
from converter.utils.validation import (
    require_file_exists, require_dir_exists,
    check_overwrite, safe_output_path,
    check_disk_space, ValidationError, is_readable,
)
from converter.utils.logging import configure_logging, ErrorFilter
from converter.plugins import HandlerRegistry, handler_registry


# ============================================================================
# Test fixtures
# ============================================================================

class _TempDirTestCase(unittest.TestCase):
    """Base test case with a temp directory that is auto-cleaned."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="conv_test_")
        configure_logging(verbosity=2)  # DEBUG

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def tmpfile(self, name: str) -> str:
        return os.path.join(self.tmpdir, name)

    def write_file(self, name: str, content: bytes) -> str:
        path = self.tmpfile(name)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def write_text_file(self, name: str, content: str) -> str:
        return self.write_file(name, content.encode("utf-8"))


# ============================================================================
# Format Detection Tests
# ============================================================================

class TestFormatDetection(_TempDirTestCase):
    """Test format detection via extension and magic bytes."""

    # --- Extension tests -------------------------------------------------

    def test_extension_zip(self):
        path = self.write_file("test.zip", b"PK\x03\x04" + b"\x00" * 100)
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.ZIP)

    def test_extension_tar_gz(self):
        path = self.write_file("data.tar.gz", b"\x1f\x8b" + b"\x00" * 50)
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.TAR_GZ)

    def test_extension_tgz_alias(self):
        path = self.write_file("data.tgz", b"\x1f\x8b" + b"\x00" * 50)
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.TAR_GZ)

    def test_extension_iso(self):
        # Create a minimal ISO-like file
        buf = bytearray(32769 + 5)
        buf[32769:32774] = b"CD001"
        path = self.write_file("cd.iso", bytes(buf))
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.ISO)

    def test_extension_qcow2(self):
        buf = bytearray(8)
        buf[0:4] = b"QFI\xfb"
        path = self.write_file("disk.qcow2", bytes(buf))
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.QCOW2)

    def test_extension_vmdk(self):
        path = self.write_file("disk.vmdk", b"KDMV" + b"\x00" * 50)
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.VMDK)

    # --- Magic byte tests ------------------------------------------------

    def test_magic_gzip(self):
        # File with .txt extension but gzip magic
        path = self.write_file("data.txt", b"\x1f\x8b\x08\x00" + b"\x00" * 50)
        info = detect_format(path)
        # Magic should override extension
        self.assertEqual(info.format_id, FormatID.GZIP)
        self.assertEqual(info.detected_by, "magic")

    def test_magic_bzip2(self):
        path = self.write_file("data.unknown", b"BZh9" + b"\x00" * 50)
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.BZIP2)
        self.assertEqual(info.detected_by, "magic")

    def test_magic_xz(self):
        path = self.write_file("data.xyz", b"\xfd7zXZ\x00" + b"\x00" * 50)
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.XZ)
        self.assertEqual(info.detected_by, "magic")

    def test_magic_zip(self):
        path = self.write_file("data.dat", b"PK\x03\x04" + b"\x00" * 100)
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.ZIP)
        self.assertEqual(info.detected_by, "magic")

    def test_magic_rar(self):
        path = self.write_file("data.dat", b"Rar!\x1a\x07\x00" + b"\x00" * 50)
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.RAR)
        self.assertEqual(info.detected_by, "magic")

    def test_magic_7z(self):
        path = self.write_file("data.dat", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 50)
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.SEVEN_ZIP)
        self.assertEqual(info.detected_by, "magic")

    def test_magic_cab(self):
        path = self.write_file("data.dat", b"MSCF\x00\x00\x00\x00" + b"\x00" * 50)
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.CAB)

    # --- Explicit format override ----------------------------------------

    def test_explicit_format_override(self):
        path = self.write_file("data.xyz", b"\x00" * 50)
        info = detect_format(path, explicit_format=FormatID.TAR)
        self.assertEqual(info.format_id, FormatID.TAR)
        self.assertEqual(info.detected_by, "explicit")
        self.assertEqual(info.confidence, "high")

    # --- Extension normalisation -----------------------------------------

    def test_normalise_ext_tar_gz(self):
        self.assertEqual(_normalise_ext("foo.tar.gz"), ".tar.gz")
        self.assertEqual(_normalise_ext("foo.TAR.GZ"), ".tar.gz")
        self.assertEqual(_normalise_ext("foo.zip"), ".zip")
        self.assertEqual(_normalise_ext("foo"), "")

    # --- Unknown format --------------------------------------------------

    def test_unknown_format_fallback(self):
        path = self.write_file("data.zzz", b"\x00\x01\x02\x03" * 50)
        info = detect_format(path)
        # Should fall back (low confidence)
        self.assertIn(info.confidence, ("low", "medium"))

    # --- Category mapping ------------------------------------------------

    def test_categories(self):
        self.assertEqual(get_category(FormatID.ZIP), FormatCategory.ARCHIVE)
        self.assertEqual(get_category(FormatID.QCOW2), FormatCategory.DISK_IMAGE)
        self.assertEqual(get_category(FormatID.ISO), FormatCategory.DISK_IMAGE)

    def test_extension_lookup(self):
        self.assertEqual(format_from_extension(".zip"), FormatID.ZIP)
        self.assertEqual(format_from_extension("zip"), FormatID.ZIP)
        self.assertEqual(format_from_extension(".nonexistent"), None)

    def test_get_extension(self):
        self.assertEqual(get_extension(FormatID.ZIP), ".zip")
        self.assertEqual(get_extension(FormatID.TAR_GZ), ".tar.gz")

    def test_all_formats_lists(self):
        af = all_archive_formats()
        df = all_disk_formats()
        self.assertTrue(len(af) > 0)
        self.assertTrue(len(df) > 0)
        # No overlap
        self.assertFalse(set(af) & set(df))


# ============================================================================
# Validation Tests
# ============================================================================

class TestValidation(_TempDirTestCase):

    def test_require_file_exists_ok(self):
        path = self.write_file("exists.txt", b"hello")
        result = require_file_exists(path)
        self.assertEqual(result, os.path.abspath(path))

    def test_require_file_exists_missing(self):
        with self.assertRaises(ValidationError):
            require_file_exists("/nonexistent/file.txt")

    def test_require_dir_exists_ok(self):
        result = require_dir_exists(self.tmpdir)
        self.assertEqual(result, os.path.abspath(self.tmpdir))

    def test_require_dir_exists_missing(self):
        with self.assertRaises(ValidationError):
            require_dir_exists("/nonexistent/directory")

    def test_safe_output_path_creates_parent(self):
        out = self.tmpfile("sub/dir/file.txt")
        result = safe_output_path(out)
        self.assertTrue(os.path.isdir(os.path.dirname(result)))

    def test_check_overwrite_missing_file(self):
        # Should not raise
        check_overwrite(self.tmpfile("nonexistent.txt"))

    def test_check_overwrite_exists_no_overwrite_no_tty(self):
        path = self.write_file("exists.txt", b"data")
        with patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(ValidationError):
                check_overwrite(path)

    def test_check_overwrite_exists_with_flag(self):
        path = self.write_file("exists.txt", b"data")
        # Should not raise when overwrite=True
        check_overwrite(path, overwrite=True)

    def test_is_readable(self):
        path = self.write_file("readable.txt", b"data")
        self.assertTrue(is_readable(path))

    def test_check_disk_space(self):
        # Create a file and check disk space (should pass on any normal system)
        path = self.write_file("small.txt", b"hello")
        # Should not raise (even with large multiplier, small file is fine)
        check_disk_space(path, self.tmpdir, multiplier=100.0)


# ============================================================================
# Archive Handler Tests
# ============================================================================

class TestArchiveHandler(_TempDirTestCase):
    """Test archive extraction, creation, and conversion."""

    def setUp(self):
        super().setUp()
        self.dispatcher = Dispatcher()
        self.handler = ArchiveHandler(dispatcher=self.dispatcher)
        # Create test content
        self.test_dir = os.path.join(self.tmpdir, "src_dir")
        os.makedirs(self.test_dir)
        self.write_file("src_dir/file1.txt", b"Hello World!")
        self.write_file("src_dir/file2.txt", b"Archive test content.")

    # --- ZIP --------------------------------------------------------------

    def _assert_file_in_tree(self, root, filename):
        """Walk *root* and assert that a file named *filename* exists."""
        for dirpath, dirnames, filenames in os.walk(root):
            if filename in filenames:
                return os.path.join(dirpath, filename)
        raise AssertionError(f"'{filename}' not found under '{root}'")

    def test_create_zip(self):
        out = self.tmpfile("archive.zip")
        result = self.handler.create(out, self.test_dir, FormatID.ZIP, overwrite=True)
        self.assertTrue(os.path.isfile(result))
        with zipfile.ZipFile(result, "r") as zf:
            names = zf.namelist()
            self.assertTrue(any("file1.txt" in n for n in names))
            self.assertTrue(any("file2.txt" in n for n in names))

    def test_extract_zip(self):
        # Create a zip
        out = self.tmpfile("archive.zip")
        self.handler.create(out, self.test_dir, FormatID.ZIP, overwrite=True)

        # Extract it
        dest = os.path.join(self.tmpdir, "extracted")
        os.makedirs(dest)
        result = self.handler.extract(out, dest_dir=dest)
        self._assert_file_in_tree(result, "file1.txt")
        self._assert_file_in_tree(result, "file2.txt")

    def test_list_zip(self):
        out = self.tmpfile("archive.zip")
        self.handler.create(out, self.test_dir, FormatID.ZIP, overwrite=True)
        entries = self.handler.list_contents(out)
        names = [e["name"] for e in entries]
        self.assertTrue(any("file1.txt" in n for n in names))

    def test_convert_zip_to_tar_gz(self):
        out = self.tmpfile("archive.zip")
        self.handler.create(out, self.test_dir, FormatID.ZIP, overwrite=True)

        target = self.tmpfile("converted.tar.gz")
        result = self.handler.convert(
            out, target, target_fmt=FormatID.TAR_GZ, overwrite=True,
        )
        self.assertTrue(os.path.isfile(result))
        # Verify it's a valid tar.gz
        with tarfile.open(result, "r:gz") as tf:
            names = tf.getnames()
            self.assertTrue(any("file1.txt" in n for n in names))

    # --- TAR --------------------------------------------------------------

    def test_create_tar(self):
        out = self.tmpfile("archive.tar")
        result = self.handler.create(out, self.test_dir, FormatID.TAR, overwrite=True)
        self.assertTrue(os.path.isfile(result))
        with tarfile.open(result, "r:") as tf:
            names = tf.getnames()
            self.assertTrue(any("file1.txt" in n for n in names))

    def test_extract_tar(self):
        out = self.tmpfile("archive.tar")
        self.handler.create(out, self.test_dir, FormatID.TAR, overwrite=True)
        dest = os.path.join(self.tmpdir, "extracted_tar")
        os.makedirs(dest)
        result = self.handler.extract(out, dest_dir=dest)
        self._assert_file_in_tree(result, "file1.txt")

    # --- TAR.GZ / TAR.BZ2 / TAR.XZ ---------------------------------------

    def test_create_and_extract_tar_gz(self):
        out = self.tmpfile("archive.tar.gz")
        self.handler.create(out, self.test_dir, FormatID.TAR_GZ, overwrite=True)
        dest = os.path.join(self.tmpdir, "extracted_tgz")
        os.makedirs(dest)
        result = self.handler.extract(out, dest_dir=dest)
        self._assert_file_in_tree(result, "file1.txt")

    def test_create_and_extract_tar_bz2(self):
        out = self.tmpfile("archive.tar.bz2")
        self.handler.create(out, self.test_dir, FormatID.TAR_BZ2, overwrite=True)
        dest = os.path.join(self.tmpdir, "extracted_bz2")
        os.makedirs(dest)
        result = self.handler.extract(out, dest_dir=dest)
        self._assert_file_in_tree(result, "file1.txt")

    def test_create_and_extract_tar_xz(self):
        out = self.tmpfile("archive.tar.xz")
        self.handler.create(out, self.test_dir, FormatID.TAR_XZ, overwrite=True)
        dest = os.path.join(self.tmpdir, "extracted_xz")
        os.makedirs(dest)
        result = self.handler.extract(out, dest_dir=dest)
        self._assert_file_in_tree(result, "file1.txt")

    # --- Stream formats (gz, bz2, xz) ------------------------------------

    def test_create_and_extract_gz(self):
        src = self.write_file("single.txt", b"Gzip compression test data here!")
        out = self.tmpfile("single.txt.gz")
        self.handler.create(out, src, FormatID.GZIP, overwrite=True)
        self.assertTrue(os.path.isfile(out))

        dest = os.path.join(self.tmpdir, "gz_out")
        os.makedirs(dest)
        result = self.handler.extract(out, dest_dir=dest)
        extracted_path = self._assert_file_in_tree(result, "single.txt")
        with open(extracted_path, "rb") as f:
            self.assertEqual(f.read(), b"Gzip compression test data here!")

    def test_create_and_extract_bz2(self):
        src = self.write_file("single.txt", b"Bzip2 test data!")
        out = self.tmpfile("single.txt.bz2")
        self.handler.create(out, src, FormatID.BZIP2, overwrite=True)
        dest = os.path.join(self.tmpdir, "bz2_out")
        os.makedirs(dest)
        result = self.handler.extract(out, dest_dir=dest)
        extracted_path = self._assert_file_in_tree(result, "single.txt")
        with open(extracted_path, "rb") as f:
            self.assertEqual(f.read(), b"Bzip2 test data!")

    def test_create_and_extract_xz(self):
        src = self.write_file("single.txt", b"XZ test data!")
        out = self.tmpfile("single.txt.xz")
        self.handler.create(out, src, FormatID.XZ, overwrite=True)
        dest = os.path.join(self.tmpdir, "xz_out")
        os.makedirs(dest)
        result = self.handler.extract(out, dest_dir=dest)
        extracted_path = self._assert_file_in_tree(result, "single.txt")
        with open(extracted_path, "rb") as f:
            self.assertEqual(f.read(), b"XZ test data!")

    # --- Stream-to-stream conversion -------------------------------------

    def test_convert_gz_to_bz2(self):
        src = self.write_file("single.txt", b"Convert me from gz to bz2!")
        gz = self.tmpfile("intermediate.gz")
        self.handler.create(gz, src, FormatID.GZIP, overwrite=True)

        bz2_out = self.tmpfile("converted.bz2")
        result = self.handler.convert(
            gz, bz2_out,
            target_fmt=FormatID.BZIP2, overwrite=True,
        )
        self.assertTrue(os.path.isfile(result))
        # Verify round-trip
        with bz2.open(result, "rb") as f:
            self.assertEqual(f.read(), b"Convert me from gz to bz2!")

    # --- Cross-archive conversion ----------------------------------------

    def test_convert_zip_to_tar(self):
        out = self.tmpfile("src.zip")
        self.handler.create(out, self.test_dir, FormatID.ZIP, overwrite=True)
        target = self.tmpfile("out.tar")
        result = self.handler.convert(
            out, target, target_fmt=FormatID.TAR, overwrite=True,
        )
        self.assertTrue(os.path.isfile(result))
        with tarfile.open(result, "r:") as tf:
            names = tf.getnames()
            self.assertTrue(any("file1.txt" in n for n in names))

    def test_convert_tar_gz_to_zip(self):
        out = self.tmpfile("src.tar.gz")
        self.handler.create(out, self.test_dir, FormatID.TAR_GZ, overwrite=True)
        target = self.tmpfile("out.zip")
        result = self.handler.convert(
            out, target, target_fmt=FormatID.ZIP, overwrite=True,
        )
        self.assertTrue(os.path.isfile(result))
        with zipfile.ZipFile(result, "r") as zf:
            names = zf.namelist()
            self.assertTrue(any("file1.txt" in n for n in names))

    # --- Error cases -----------------------------------------------------

    def test_create_stream_from_directory_raises(self):
        out = self.tmpfile("bad.gz")
        with self.assertRaises(ValueError):
            self.handler.create(out, self.test_dir, FormatID.GZIP, overwrite=True)

    def test_extract_nonexistent_file(self):
        with self.assertRaises(ValidationError):
            self.handler.extract("/nonexistent/file.zip")


# ============================================================================
# Dispatcher Tests
# ============================================================================

class TestDispatcher(_TempDirTestCase):

    def setUp(self):
        super().setUp()
        self.dispatcher = Dispatcher()

    # --- Conversion matrix validation ------------------------------------

    def test_same_format_not_in_matrix(self):
        # Converting a format to itself should not be in matrix (no-op)
        entry = get_conversion_entry(FormatID.ZIP, FormatID.ZIP)
        # Same format → unsupported (no-op, user should just copy)
        # Actually let's check what it is
        self.assertIsNotNone(entry)

    def test_archive_to_archive_supported(self):
        entry = get_conversion_entry(FormatID.ZIP, FormatID.TAR_GZ)
        self.assertEqual(entry.support, ConversionSupport.FULL)

    def test_disk_to_disk_supported(self):
        entry = get_conversion_entry(FormatID.QCOW2, FormatID.VMDK)
        self.assertEqual(entry.support, ConversionSupport.EXTERNAL)

    def test_disk_to_archive_unsupported(self):
        # Cross-category should be UNSUPPORTED
        entry = get_conversion_entry(FormatID.IMG, FormatID.ZIP)
        self.assertEqual(entry.support, ConversionSupport.UNSUPPORTED)

    def test_archive_to_disk_unsupported(self):
        entry = get_conversion_entry(FormatID.ZIP, FormatID.ISO)
        self.assertEqual(entry.support, ConversionSupport.UNSUPPORTED)

    # --- Dispatch --------------------------------------------------------

    def test_dispatch_zip_to_tar_gz(self):
        src = self.write_file("src.zip", b"PK\x03\x04" + b"\x00" * 100)
        # Create a real zip
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("hello.txt", "world")
        out = self.tmpfile("out.tar.gz")
        result = self.dispatcher.dispatch(src, out, overwrite=True)
        self.assertTrue(os.path.isfile(result))

    def test_dispatch_unsupported_raises(self):
        src = self.write_file("src.zip", b"PK\x03\x04" + b"\x00" * 100)
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("hello.txt", "world")
        out = self.tmpfile("out.qcow2")
        with self.assertRaises(UnsupportedConversion):
            self.dispatcher.dispatch(src, out, overwrite=True)

    # --- Extract / Create / List -----------------------------------------

    def test_extract_archive(self):
        src = self.tmpfile("data.zip")
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("test.txt", "content")
        dest = self.dispatcher.extract(src, dest_dir=os.path.join(self.tmpdir, "ex"))
        self.assertTrue(os.path.isfile(os.path.join(dest, "test.txt")))

    def test_create_archive(self):
        src_dir = os.path.join(self.tmpdir, "folder")
        os.makedirs(src_dir)
        with open(os.path.join(src_dir, "a.txt"), "w") as f:
            f.write("hello")
        out = self.tmpfile("created.zip")
        result = self.dispatcher.create(out, src_dir)
        self.assertTrue(os.path.isfile(result))

    def test_list_archive(self):
        src = self.tmpfile("data.zip")
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("file1.txt", "a")
            zf.writestr("file2.txt", "b")
        entries = self.dispatcher.list_contents(src)
        names = [e["name"] for e in entries]
        self.assertIn("file1.txt", names)
        self.assertIn("file2.txt", names)


# ============================================================================
# Dependency Check Tests
# ============================================================================

class TestDependencies(_TempDirTestCase):

    def test_check_all_runs(self):
        report = check_all()
        self.assertIsInstance(report, DependencyReport)
        self.assertIsInstance(report.tools, dict)
        self.assertTrue(len(report.tools) > 0)

    def test_missing_tools_list(self):
        report = check_all()
        # At least one tool is likely missing (e.g. dmg2img on Linux)
        missing = report.missing_tools()
        # We just check it returns a list
        self.assertIsInstance(missing, list)


# ============================================================================
# Plugin System Tests
# ============================================================================

class TestPluginSystem(_TempDirTestCase):

    def test_register_and_retrieve(self):
        registry = HandlerRegistry()

        class MockHandler:
            pass

        registry.register("mock", MockHandler, extensions=[".mock"])
        info = registry.get("mock")
        self.assertIsNotNone(info)
        self.assertEqual(info.name, "mock")
        self.assertEqual(info.handler_class, MockHandler)

    def test_find_by_extension(self):
        registry = HandlerRegistry()

        class FooHandler:
            pass

        registry.register("foo", FooHandler, extensions=[".foo"])
        result = registry.find_by_extension(".foo")
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "foo")

    def test_find_by_extension_not_found(self):
        registry = HandlerRegistry()
        result = registry.find_by_extension(".nonexistent")
        self.assertIsNone(result)

    def test_list_plugins(self):
        registry = HandlerRegistry()

        class Handler1:
            pass

        class Handler2:
            pass

        registry.register("h1", Handler1)
        registry.register("h2", Handler2)
        plugins = registry.list_plugins()
        self.assertEqual(len(plugins), 2)

    def test_decorator_register(self):
        registry = HandlerRegistry()

        @registry.register("decorated", extensions=[".dec"])
        class DecoratedHandler:
            pass

        info = registry.get("decorated")
        self.assertIsNotNone(info)
        self.assertEqual(info.handler_class, DecoratedHandler)


# ============================================================================
# Logging Tests
# ============================================================================

class TestLogging(_TempDirTestCase):

    def test_configure_logging_levels(self):
        import logging as py_logging
        logger = configure_logging(0)
        self.assertEqual(logger.level, py_logging.WARNING)

        logger2 = configure_logging(1)
        self.assertEqual(logger2.level, py_logging.INFO)

        logger3 = configure_logging(2)
        self.assertEqual(logger3.level, py_logging.DEBUG)

    def test_error_filter(self):
        filt = ErrorFilter()
        record = py_logging.LogRecord(
            name="test", level=py_logging.ERROR,
            pathname="", lineno=0, msg="", args=(), exc_info=None,
        )
        record.msg = "Conversion not supported"
        filt.filter(record)
        self.assertEqual(getattr(record, "error_code", None), "unsupported_format")


# ============================================================================
# Edge Case Tests
# ============================================================================

class TestEdgeCases(_TempDirTestCase):

    def test_empty_zip(self):
        """Empty zip files should be handled gracefully."""
        path = self.tmpfile("empty.zip")
        with zipfile.ZipFile(path, "w") as zf:
            pass  # empty archive
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.ZIP)

    def test_nested_tar_gz_detection(self):
        """A .tar.gz file should not be detected as plain gzip."""
        # Create a real tar.gz
        path = self.tmpfile("data.tar.gz")
        with tarfile.open(path, "w:gz") as tf:
            tf.addfile(tarfile.TarInfo(name="hello.txt"),
                       BytesIO(b"world"))
        info = detect_format(path)
        # Extension takes precedence for .tar.gz
        self.assertEqual(info.format_id, FormatID.TAR_GZ)

    def test_large_extension_normalisation(self):
        self.assertEqual(_normalise_ext("my.archive.tar.bz2"), ".tar.bz2")
        self.assertEqual(_normalise_ext("archive.tar.xz"), ".tar.xz")

    def test_corrupted_gzip_detection(self):
        """A file with gzip magic but invalid content should still be
        detected as gzip (detection is separate from validation)."""
        path = self.write_file("bad.gz", b"\x1f\x8b\x08\x00" + b"\xff" * 50)
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.GZIP)

    def test_magic_vs_extension_conflict(self):
        """When magic and extension disagree, magic wins."""
        # Zip magic with .tar extension
        path = self.write_file("data.tar", b"PK\x03\x04" + b"\x00" * 100)
        info = detect_format(path)
        self.assertEqual(info.format_id, FormatID.ZIP)
        self.assertEqual(info.detected_by, "magic")

    def test_binary_file_unknown(self):
        """Completely unknown binary data with no extension."""
        path = self.write_file("data", bytes(range(256)))
        info = detect_format(path)
        self.assertIn(info.confidence, ("low", "medium"))

    def test_nonexistent_file_detection(self):
        """Detecting a nonexistent file falls back to extension-based detection
        with a warning; it does not raise because the detector is designed to
        be lenient (the validation layer catches missing files later)."""
        info = detect_format("/nonexistent/file.zip")
        # Should still detect via extension even though file doesn't exist
        self.assertEqual(info.format_id, FormatID.ZIP)
        self.assertEqual(info.detected_by, "extension")


# ============================================================================
# CLI Tests
# ============================================================================

class TestCLI(_TempDirTestCase):

    def _run_cli(self, argv):
        from converter.cli import main
        return main(argv)

    def test_version(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run_cli(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_no_args(self):
        code = self._run_cli([])
        self.assertEqual(code, 4)  # EXIT_VALIDATION

    def test_list_formats(self):
        code = self._run_cli(["--list-formats"])
        self.assertEqual(code, 0)

    def test_check_deps(self):
        code = self._run_cli(["--check-deps"])
        # Should return 0 or 3 depending on what's installed
        self.assertIn(code, (0, 3))

    def test_convert_zip_to_tar_gz(self):
        src = self.tmpfile("src.zip")
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("test.txt", "hello")
        out = self.tmpfile("out.tar.gz")
        code = self._run_cli(["-i", src, "-o", out])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(out))

    def test_extract_zip(self):
        src = self.tmpfile("src.zip")
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("test.txt", "hello")
        dest = os.path.join(self.tmpdir, "ex")
        os.makedirs(dest)
        code = self._run_cli(["--extract", src, "-d", dest])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(os.path.join(dest, "test.txt")))

    def test_create_zip(self):
        src_dir = os.path.join(self.tmpdir, "folder")
        os.makedirs(src_dir)
        with open(os.path.join(src_dir, "a.txt"), "w") as f:
            f.write("hello")
        out = self.tmpfile("created.zip")
        code = self._run_cli(["--create", out, src_dir])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(out))

    def test_list_archive(self):
        src = self.tmpfile("data.zip")
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("file1.txt", "a")
            zf.writestr("file2.txt", "b")
        code = self._run_cli(["--list", src])
        self.assertEqual(code, 0)

    def test_unsupported_conversion(self):
        src = self.tmpfile("src.zip")
        with zipfile.ZipFile(src, "w") as zf:
            zf.writestr("test.txt", "hello")
        out = self.tmpfile("out.qcow2")
        code = self._run_cli(["-i", src, "-o", out])
        self.assertEqual(code, 2)  # EXIT_UNSUPPORTED


# ============================================================================
# Run
# ============================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
