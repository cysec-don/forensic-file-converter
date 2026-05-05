"""
Command-Line Interface
======================

Entry point for the universal converter tool.

Modes of operation
------------------
1. **Convert**:   ``-i INPUT -o OUTPUT``       (format conversion)
2. **Extract**:   ``--extract ARCHIVE``         (decompress to directory)
3. **Create**:    ``--create OUTPUT SOURCE``    (compress directory/file)
4. **List**:      ``--list ARCHIVE``            (show contents)

Examples
--------
::

    # Convert between disk image formats
    python -m converter -i disk.img -o disk.qcow2

    # Convert between archive formats
    python -m converter -i data.zip -o data.tar.gz

    # Extract an archive
    python -m converter --extract archive.tar.bz2
    python -m converter --extract archive.tar.bz2 -d /tmp/extracted

    # Create an archive from a directory
    python -m converter --create backup.tar.gz /path/to/folder/

    # Create an ISO from a directory
    python -m converter --create cdrom.iso /path/to/cd-contents/

    # List archive contents
    python -m converter --list archive.zip

    # Force overwrite
    python -m converter -i in.img -o out.qcow2 -f

    # Verbose / debug mode
    python -m converter -i in.img -o out.qcow2 -vv
"""

from __future__ import annotations

import argparse
import sys
import textwrap
import logging

from . import __version__
from .core.detector import FormatID, all_archive_formats, all_disk_formats
from .core.dispatcher import Dispatcher, UnsupportedConversion, MissingDependency, ConversionError
from .core.dependencies import check_all
from .utils.logging import configure_logging, ERROR_UNSUPPORTED, ERROR_MISSING_DEP
from .utils.validation import ValidationError


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="converter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Universal File Converter
            ========================
            Convert between archive/compression formats and disk image formats.

            Supported archive formats:
              .zip  .rar  .7z  .tar  .tar.gz  .tar.bz2  .tar.xz
              .gz  .bz2  .xz  .cab

            Supported disk image formats:
              .qcow2  .vmdk  .vhd  .vhdx  .iso  .img  .raw  .dd  .bin  .dmg
        """),
        epilog=textwrap.dedent("""\
            Examples:
              converter -i disk.img -o disk.qcow2           Convert disk image
              converter -i data.zip -o data.tar.gz           Convert archive
              converter --extract archive.tar.bz2            Extract archive
              converter --create backup.tar.gz ./src/        Create archive
              converter --create cdrom.iso ./cd/             Create ISO
              converter --list archive.zip                   List contents
        """),
    )

    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {__version__}",
    )

    # --- Mode selection ---------------------------------------------------
    mode = parser.add_argument_group("Mode of operation")
    mode.add_argument(
        "-i", "--input", metavar="FILE",
        help="Input file (source for conversion or extraction)",
    )
    mode.add_argument(
        "-o", "--output", metavar="FILE",
        help="Output file (target for conversion or creation)",
    )
    mode.add_argument(
        "--extract", metavar="ARCHIVE",
        help="Extract an archive/disk image to a directory",
    )
    mode.add_argument(
        "--create", nargs=2, metavar=("OUTPUT", "SOURCE"),
        help="Create an archive/image: --create output.zip folder/",
    )
    mode.add_argument(
        "--list", metavar="FILE",
        help="List contents of an archive/disk image",
    )

    # --- Options ----------------------------------------------------------
    opts = parser.add_argument_group("Options")
    opts.add_argument(
        "--format", metavar="FMT",
        help="Explicitly specify output format (e.g., qcow2, zip, tar.gz)",
    )
    opts.add_argument(
        "-d", "--dest", metavar="DIR",
        help="Destination directory for extraction (default: temp dir)",
    )
    opts.add_argument(
        "--overwrite", "-f", action="store_true", dest="overwrite",
        help="Overwrite existing output files without asking",
    )
    opts.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase verbosity: -v = INFO, -vv = DEBUG",
    )
    opts.add_argument(
        "--debug", action="store_true",
        help="Alias for -vv (DEBUG log level)",
    )
    opts.add_argument(
        "--check-deps", action="store_true",
        help="Check for required external tools and exit",
    )
    opts.add_argument(
        "--list-formats", action="store_true",
        help="List all supported formats and exit",
    )
    opts.add_argument(
        "--no-color", action="store_true",
        help="Disable coloured output",
    )

    return parser


# ---------------------------------------------------------------------------
# Exit code mapping
# ---------------------------------------------------------------------------

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_UNSUPPORTED = 2
EXIT_MISSING_DEP = 3
EXIT_VALIDATION = 4


def _exit_for_error(exc: Exception) -> int:
    """Map an exception to a CLI exit code."""
    msg = str(exc)
    if isinstance(exc, UnsupportedConversion):
        print(f"Error: {msg}", file=sys.stderr)
        return EXIT_UNSUPPORTED
    elif isinstance(exc, MissingDependency):
        print(f"Error: {msg}", file=sys.stderr)
        return EXIT_MISSING_DEP
    elif isinstance(exc, ValidationError):
        print(f"Error: {msg}", file=sys.stderr)
        return EXIT_VALIDATION
    elif isinstance(exc, ConversionError):
        print(f"Error: {msg}", file=sys.stderr)
        return EXIT_ERROR
    else:
        print(f"Unexpected error: {msg}", file=sys.stderr)
        return EXIT_ERROR


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def _cmd_convert(args: argparse.Namespace, dispatcher: Dispatcher) -> int:
    """Handle ``-i INPUT -o OUTPUT``."""
    if not args.input or not args.output:
        print("Error: --input and --output are required for conversion.",
              file=sys.stderr)
        return EXIT_VALIDATION

    target_fmt = None
    if args.format:
        target_fmt = _resolve_format(args.format)

    try:
        result = dispatcher.dispatch(
            args.input, args.output,
            target_fmt=target_fmt,
            overwrite=args.overwrite,
        )
        print(f"Conversion complete: {result}")
        return EXIT_OK
    except Exception as exc:
        return _exit_for_error(exc)


def _cmd_extract(args: argparse.Namespace, dispatcher: Dispatcher) -> int:
    """Handle ``--extract ARCHIVE``."""
    archive = args.extract
    if not archive:
        print("Error: --extract requires a file path.", file=sys.stderr)
        return EXIT_VALIDATION

    try:
        dest = dispatcher.extract(archive, dest_dir=args.dest)
        print(f"Extracted to: {dest}")
        return EXIT_OK
    except Exception as exc:
        return _exit_for_error(exc)


def _cmd_create(args: argparse.Namespace, dispatcher: Dispatcher) -> int:
    """Handle ``--create OUTPUT SOURCE``."""
    if not args.create:
        print("Error: --create requires OUTPUT and SOURCE.", file=sys.stderr)
        return EXIT_VALIDATION

    output_path, source = args.create
    fmt = None
    if args.format:
        fmt = _resolve_format(args.format)

    try:
        result = dispatcher.create(output_path, source, fmt=fmt)
        print(f"Created: {result}")
        return EXIT_OK
    except Exception as exc:
        return _exit_for_error(exc)


def _cmd_list(args: argparse.Namespace, dispatcher: Dispatcher) -> int:
    """Handle ``--list FILE``."""
    target = getattr(args, "list", None)
    if not target:
        print("Error: --list requires a file path.", file=sys.stderr)
        return EXIT_VALIDATION

    try:
        entries = dispatcher.list_contents(target)
        if not entries:
            print("(empty or cannot list contents)")
            return EXIT_OK

        # Tabular output
        name_w = max(len(str(e.get("name", ""))) for e in entries)
        size_w = max(len(str(e.get("size", ""))) for e in entries)
        size_w = max(size_w, 4)
        name_w = max(name_w, 4)

        header = f"{'NAME':<{name_w}}  {'SIZE':>{size_w}}  {'TYPE':<5}  {'DATE'}"
        print(header)
        print("-" * len(header))
        for e in entries:
            name = str(e.get("name", "?"))
            size = str(e.get("size", "?"))
            typ = "DIR" if e.get("is_dir") else "FILE"
            dt = str(e.get("date_time", "—"))
            print(f"{name:<{name_w}}  {size:>{size_w}}  {typ:<5}  {dt}")
        return EXIT_OK
    except Exception as exc:
        return _exit_for_error(exc)


def _cmd_check_deps(args: argparse.Namespace) -> int:
    """Check for required external tools."""
    report = check_all()
    print("External Tool Dependency Check")
    print("=" * 50)

    all_ok = True
    for name, info in sorted(report.tools.items()):
        status = "\u2713 FOUND" if info.available else "\u2717 MISSING"
        path_str = f"  ({info.path})" if info.path else ""
        print(f"  {status:12s}  {name:<14s}{path_str}")
        if not info.available:
            all_ok = False
            formats = ", ".join(info.required_for)
            print(f"               Required for: {formats}")
            print(f"               Install: {info.install_hint}")

    print()
    if all_ok:
        print("All dependencies satisfied.")
        return EXIT_OK
    else:
        print("Some dependencies are missing. Install them for full functionality.")
        return EXIT_MISSING_DEP


def _cmd_list_formats(args: argparse.Namespace) -> int:
    """List all supported formats."""
    print("Supported Formats")
    print("=" * 60)
    print()
    print("Archive / Compression Formats:")
    for f in all_archive_formats():
        print(f"  .{f.value:<10s}")
    print()
    print("Disk Image Formats:")
    for f in all_disk_formats():
        print(f"  .{f.value:<10s}")
    print()
    print("Compound extensions supported: .tar.gz .tar.bz2 .tar.xz")
    print("Aliases: .tgz → .tar.gz, .tbz2 → .tar.bz2, .txz → .tar.xz")
    return EXIT_OK


def _resolve_format(fmt_str: str) -> FormatID:
    """Resolve a user-supplied format string to a FormatID."""
    from .core.detector import format_from_extension
    fmt = format_from_extension(fmt_str)
    if fmt is not None:
        return fmt

    # Try as a bare name (no dot)
    try:
        return FormatID(fmt_str)
    except ValueError:
        pass

    print(f"Error: Unknown format '{fmt_str}'. "
          f"Use --list-formats to see supported formats.",
          file=sys.stderr)
    sys.exit(EXIT_UNSUPPORTED)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """CLI entry point.  Returns an exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Configure logging
    verbosity = args.verbose + (2 if getattr(args, "debug", False) else 0)
    logger = configure_logging(verbosity)

    # Info-only modes
    if args.check_deps:
        return _cmd_check_deps(args)
    if args.list_formats:
        return _cmd_list_formats(args)

    # Ensure at least one action is specified
    has_convert = args.input and args.output
    has_extract = args.extract is not None
    has_create  = args.create is not None
    has_list    = getattr(args, "list", None) is not None

    if not any([has_convert, has_extract, has_create, has_list]):
        parser.print_help(sys.stderr)
        return EXIT_VALIDATION

    dispatcher = Dispatcher()

    # Route to sub-command
    if has_convert:
        return _cmd_convert(args, dispatcher)
    elif has_extract:
        return _cmd_extract(args, dispatcher)
    elif has_create:
        return _cmd_create(args, dispatcher)
    elif has_list:
        return _cmd_list(args, dispatcher)

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
