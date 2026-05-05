<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Tests-199%20passed-brightgreen.svg" alt="199 tests passing">
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="Apache 2.0 License">
  <img src="https://img.shields.io/badge/Formats-27+-orange.svg" alt="27+ formats">
</p>

<h1 align="center">Forensic File Converter</h1>

<p align="center"><strong>A professional-grade Python tool for converting between archive, disk image, and forensic file formats.</strong></p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#supported-formats">Formats</a> •
  <a href="#installation">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#python-api">API</a> •
  <a href="#forensic-format-details">Forensic Details</a> •
  <a href="#security">Security</a> •
  <a href="#testing">Tests</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## Overview

Forensic File Converter is a modular, extensible command-line tool designed for digital forensics practitioners, incident responders, and security analysts. It provides seamless conversion between **27+ file formats** across three major categories:

- **Archive / Compression formats** (11 formats) — ZIP, TAR, TAR.GZ, TAR.BZ2, TAR.XZ, GZIP, BZIP2, XZ, 7-Zip, RAR, CAB
- **Disk image formats** (10 formats) — QCOW2, VMDK, VHD, VHDX, ISO, IMG, RAW, DD, BIN, DMG
- **Forensic image formats** (6 formats) — Windows Crash Dump (`.dump`/`.dmp`), LiME (`.lime`), EnCase E01/EX01 (`.e01`/`.ex01`), AFF (`.aff`)

The tool features intelligent format detection via magic byte signatures and extension analysis, a deny-by-default conversion matrix for safety, streaming large-file support for multi-gigabyte memory dumps, and comprehensive security protections against path traversal attacks. It is built with a zero-third-party-dependency philosophy for core operations — all primary functionality uses only the Python standard library. External tools like `qemu-img`, `7z`, and `dmg2img` are optional fallbacks for formats that the stdlib cannot handle natively.

**Author:** Cysec Don | [cysecdon@gmail.com](mailto:cysecdon@gmail.com)

---

## Features

### Core Capabilities

- **Format Detection** — Dual-layer detection using magic byte signatures and extension mapping, with conflict resolution logic that prefers magic bytes (harder to spoof) while allowing compound extensions like `.tar.gz` to override ambiguous magic matches
- **Conversion Matrix** — Deny-by-default allowlist encoding which conversions are supported, lossless, partial, or require external tools. Every missing entry results in a clear `UnsupportedConversion` error rather than silent data loss
- **Streaming Engine** — 64 MiB chunk-based streaming for large forensic images (10+ GB memory dumps) without excessive memory usage. Files are never loaded entirely into memory
- **Plugin System** — Decorator-based handler registry for extending format support without modifying core code. New formats can be added with a simple `@handler_registry.register` decorator
- **Security Hardened** — Path traversal guards (CVE-2007-4559 for ZIP, TAR slip for tar archives), overwrite protection requiring explicit `--overwrite` flag in non-interactive contexts, pre-conversion disk space checks, and no network access
- **Zero Third-Party Dependencies** — Pure Python stdlib for core operations; external tools are optional fallbacks for formats like 7z, RAR, QCOW2, VMDK, etc.

### Forensic Format Support

- **Windows Crash Dumps** (`.dump` / `.dmp`) — Parses `PAGE` and `PAGEDU` headers, supports MiniDump, FullDump, and KernelDump types. Converts to/from RAW by stripping or prepending the 4096-byte DUMP_HEADER
- **LiME Memory Dumps** (`.lime`) — Parses 24-byte LiME v1 headers with base address extraction. Converts to/from RAW by stripping or prepending the header
- **EnCase EWF** (`.e01` / `.ex01`) — Parses EWF file headers with case number and section count. Supports E01↔EX01 re-headering, EWF↔RAW conversion, and cross-forensic conversions (EWF↔DUMP, EWF↔LIME). Compatible with Autopsy and Guymager workflows
- **AFF** (`.aff`) — Parses AFF v1 headers with page size and compression metadata. Supports AFF↔RAW, AFF↔DUMP, AFF↔LIME, and AFF↔EWF conversions

---

## Supported Formats

### Archive / Compression Formats

| Format | Extensions | Extract | Create | Convert | Notes |
|--------|-----------|---------|--------|---------|-------|
| ZIP | `.zip` | stdlib | stdlib | Full | Pure Python, path traversal protected (CVE-2007-4559) |
| TAR | `.tar` | stdlib | stdlib | Full | Pure Python, path traversal protected |
| TAR.GZ | `.tar.gz`, `.tgz` | stdlib | stdlib | Full | Compound extension aware |
| TAR.BZ2 | `.tar.bz2`, `.tbz2` | stdlib | stdlib | Full | Compound extension aware |
| TAR.XZ | `.tar.xz`, `.txz` | stdlib | stdlib | Full | Compound extension aware |
| GZIP | `.gz`, `.gzip` | stdlib | stdlib | Full | Single-file compression only |
| BZIP2 | `.bz2` | stdlib | stdlib | Full | Single-file compression only |
| XZ | `.xz` | stdlib | stdlib | Full | Single-file compression only |
| 7-Zip | `.7z` | 7z (ext) | 7z (ext) | Full | Requires `p7zip-full` |
| RAR | `.rar` | unrar/7z | rar (ext) | Full | Requires `unrar` or `rar` |
| CAB | `.cab` | cabextract/7z | limited | Partial | Requires `cabextract` |

### Disk Image Formats

| Format | Extensions | Convert | Tool |
|--------|-----------|---------|------|
| QCOW2 | `.qcow2` | External | `qemu-img` |
| VMDK | `.vmdk` | External | `qemu-img` |
| VHD | `.vhd` | External | `qemu-img` |
| VHDX | `.vhdx` | External | `qemu-img` |
| ISO | `.iso` | External | `genisoimage` / `xorriso` |
| IMG | `.img` | Full | Pure Python |
| RAW | `.raw` | Full | Pure Python |
| DD | `.dd` | Full | Pure Python |
| BIN | `.bin`, `.cue` | Full | Pure Python |
| DMG | `.dmg` | External | `dmg2img` (Linux) / `hdiutil` (macOS) |

### Forensic Formats

| Format | Extensions | Magic Signature | Description |
|--------|-----------|----------------|-------------|
| Windows Dump | `.dump`, `.dmp`, `.vdmp` | `PAGE` / `PAGEDU` | Windows crash dump (32/64-bit) |
| LiME | `.lime` | `LiME` | Linux Memory Extractor |
| E01 (EWF) | `.e01` - `.e10`, `.ewf` | `EVF\x09\x0d\x0a\xff\x00` | EnCase Expert Witness Format |
| EX01 (EWF) | `.ex01` | `EVF\x09\x0d\x0a\xff\x01` | EnCase v8+ EWF Format |
| AFF | `.aff`, `.afd`, `.afm` | `AFF\x00` / `AFF\x01` | Advanced Forensics Format |

---

## Installation

### From Source

```bash
git clone https://github.com/cysec-don/forensic-file-converter.git
cd forensic-file-converter
pip install -e .
```

This installs the `converter` command-line tool and makes the Python package available for import.

### Optional External Tools

For full format support, install these optional tools. The tool gracefully handles missing dependencies — it will simply report which conversions are unavailable and suggest installation commands.

```bash
# Archive tools
sudo apt install p7zip-full unrar cabextract

# Disk image tools
sudo apt install qemu-utils genisoimage xorriso

# DMG support (Linux)
sudo apt install dmg2img

# Forensic tools (for full EWF/AFF decompression)
sudo apt install libewf-tools afflib-tools
```

### On macOS

```bash
brew install p7zip qemu cdrtools
```

### Verifying Installation

After installation, verify everything is working:

```bash
# Show version
python -m converter --version

# Check for available external tools
python -m converter --check-deps

# List all supported formats
python -m converter --list-formats
```

---

## Usage

### Command-Line Interface

```
python -m converter [OPTIONS]
```

### Convert Between Formats

The primary mode of operation is format conversion. Specify an input file with `-i` and an output file with `-o`. The tool automatically detects the source format from magic bytes and/or extension, and determines the target format from the output file extension.

```bash
# Convert disk image formats
python -m converter -i disk.img -o disk.qcow2
python -m converter -i disk.vmdk -o disk.vhdx

# Convert archive formats
python -m converter -i data.zip -o data.tar.gz
python -m converter -i archive.7z -o archive.tar.bz2

# Convert forensic formats
python -m converter -i mem.lime -o mem.raw
python -m converter -i crash.dump -o crash.raw
python -m converter -i evidence.e01 -o evidence.raw
python -m converter -i image.aff -o image.raw

# Cross-format forensic conversions
python -m converter -i mem.lime -o mem.dump
python -m converter -i evidence.e01 -o evidence.ex01
python -m converter -i evidence.e01 -o evidence.aff

# Forensic to VM format (strip header + qemu-img convert)
python -m converter -i mem.dump -o mem.qcow2

# Explicitly specify output format (overrides extension detection)
python -m converter -i input.dat -o output.img --format raw
```

### Extract Archives and Images

```bash
# Extract archives to a directory
python -m converter --extract archive.tar.gz
python -m converter --extract archive.tar.gz -d /tmp/extracted

# Extract disk images (ISO, etc.)
python -m converter --extract cdrom.iso -d /mnt/iso
```

### Create Archives and Images

```bash
# Create archives from directories
python -m converter --create backup.tar.gz /path/to/folder/
python -m converter --create archive.zip /path/to/folder/

# Create ISO images from directories
python -m converter --create cdrom.iso /path/to/cd-contents/

# Create single-file compressed archives
python -m converter --create document.gz /path/to/single-file.txt
```

### List Contents

```bash
# List archive contents in tabular format
python -m converter --list archive.zip
python -m converter --list disk.iso
```

### Utility Commands

```bash
# Check for required external tools
python -m converter --check-deps

# List all supported formats
python -m converter --list-formats

# Show version
python -m converter --version

# Verbose / debug mode (-v = INFO, -vv or --debug = DEBUG)
python -m converter -i in.img -o out.qcow2 -vv

# Force overwrite existing output files
python -m converter -i in.img -o out.qcow2 --overwrite
```

### Exit Codes

The tool uses semantic exit codes to distinguish between different failure modes, making it suitable for use in scripts and CI/CD pipelines:

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error / conversion failure |
| 2 | Unsupported conversion (source → target pair not in conversion matrix) |
| 3 | Missing external dependency (required tool not found on `$PATH`) |
| 4 | Validation error (file not found, overwrite refused, disk space insufficient) |

---

## Architecture

```
converter/
    __init__.py          # Package metadata, version, author
    __main__.py          # Entry point for `python -m converter`
    cli.py               # Argument parser, sub-commands, exit codes
    plugins.py           # Extensible handler registry with decorator API
    core/
        __init__.py      # Re-exports from core modules
        detector.py      # Format detection (magic bytes + extension)
        dispatcher.py    # Conversion matrix, routing, error types
        dependencies.py  # External tool discovery and reporting
    handlers/
        __init__.py      # Handler re-exports
        archive.py       # Archive/compression handler (11 formats)
        disk.py          # Disk image + forensic handler (16 formats)
    utils/
        __init__.py      # Utility re-exports
        validation.py    # File safety, overwrite protection, path guards
        logging.py       # Structured logging with error classification
tests/
    test_converter.py    # 199 unit tests covering all modules
```

### Design Decisions

1. **Deny-by-default conversion matrix** — Every conversion must be explicitly listed in the matrix. Missing entries result in `UnsupportedConversion` rather than silent data loss. This prevents the tool from attempting conversions that could corrupt data or lose metadata.

2. **Magic bytes over extension** — When magic bytes and extension disagree, magic bytes win (they are harder to spoof). Compound extensions (`.tar.gz`) are an exception — they always override ambiguous magic matches because a `.tar.gz` file is semantically different from a single-file gzip stream, even though both share the same gzip magic bytes.

3. **Cross-category rejection** — Archive-to-disk and disk-to-archive conversions are explicitly blocked at the dispatcher level. Users must perform a two-step extract-then-convert workflow. This prevents the tool from making incorrect assumptions about how to transform data across fundamentally different format categories.

4. **Streaming for large files** — Forensic conversions use 64 MiB chunk-based streaming to handle multi-gigabyte memory dumps without loading entire files into memory. This is critical for real-world forensic workflows where memory images can exceed 10 GB.

5. **Security protections** — ZIP extraction guards against CVE-2007-4559 (zip-slip). TAR extraction validates all member paths against the destination directory using `os.path.realpath()`. Overwrite protection requires explicit `--overwrite` flag in non-interactive contexts. Pre-conversion disk space checks prevent "disk full" failures mid-conversion.

6. **Zero stdlib violations** — All core operations use only Python standard library modules (`zipfile`, `tarfile`, `gzip`, `bz2`, `lzma`, `struct`, `shutil`). External tools like `qemu-img`, `7z`, and `dmg2img` are invoked only for formats the stdlib cannot handle, and their absence is reported gracefully rather than causing crashes.

---

## Forensic Format Details

### Windows Crash Dumps (`.dump` / `.dmp`)

Windows crash dumps begin with a `PAGE` (32-bit) or `PAGEDU` (64-bit) signature at offset 0, followed by a 4096-byte `DUMP_HEADER` structure. The `ValidDump` field at offset 8 identifies the dump type:

| ValidDump | Type | Description |
|-----------|------|-------------|
| 1 | MiniDump | User-mode process dump |
| 2 | FullDump | Complete physical memory dump |
| 3 | KernelDump | Kernel-mode memory dump |

Converting DUMP to RAW strips the 4096-byte header. Converting RAW to DUMP prepends a minimal header (without valid system context). These are **partial** conversions — header metadata is lost or fabricated. The raw memory data itself is preserved losslessly.

### LiME (`.lime`)

LiME (Linux Memory Extractor) files have a 24-byte header:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic (`LiME`) |
| 4 | 1 | Version (typically 1) |
| 5 | 3 | Reserved |
| 8 | 8 | Base address (uint64 LE) |
| 16 | 8 | Reserved |

Converting LIME to RAW strips the 24-byte header. Converting RAW to LIME prepends a header with `base_address=0`. The base address should ideally match the source system for accurate forensic analysis, so manual adjustment may be required.

### EWF / EnCase (`.e01` / `.ex01`)

The EnCase Expert Witness Format is the primary forensic imaging format used by EnCase, Autopsy, and Guymager. The EWF file header (624 bytes) contains:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 3 | Signature (`EVF`) |
| 7 | 1 | Version code (0x00=E01, 0x01=EX01) |
| 8 | 16 | Case number (null-padded) |
| 24 | 4 | Section count (uint32 LE) |

E01 to EX01 conversion preserves data sections and only re-headers the file. For full EWF decompression with chunk handling, use `ewfexport` from libewf. The tool's simplified conversion strips the 624-byte header for raw intermediate processing.

### AFF (`.aff`)

The Advanced Forensics Format supports compression and encryption. The AFF v1 header (36 bytes) contains:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic (`AFF\x00`) |
| 4 | 4 | Major version (uint32 BE) |
| 8 | 4 | Minor version (uint32 BE) |
| 12 | 8 | Total size (uint64 BE) |
| 20 | 8 | Compressed size (uint64 BE) |
| 28 | 8 | Page size (uint64 BE, typically 4096) |

The tool strips the 36-byte AFF header for conversion. AFF pages may still be compressed after header removal; for full AFF decompression, use `affcat` from AFFLIB.

---

## Python API

The tool can also be used as a Python library for programmatic access:

### Format Detection

```python
from converter.core.detector import detect_format, FormatID, FormatCategory

# Detect a file's format
info = detect_format("memory.lime")
print(info.format_id)    # FormatID.LIME
print(info.detected_by)  # "magic"
print(info.category)     # FormatCategory.DISK_IMAGE
print(info.confidence)   # "high"
```

### Conversions

```python
from converter.core.dispatcher import Dispatcher

dispatcher = Dispatcher()

# Convert files
dispatcher.dispatch("input.lime", "output.raw", overwrite=True)
dispatcher.dispatch("input.zip", "output.tar.gz", overwrite=True)

# Extract archives
dest = dispatcher.extract("archive.tar.gz", dest_dir="/tmp/out")

# Create archives
dispatcher.create("backup.zip", "/path/to/folder/")

# List contents
entries = dispatcher.list_contents("archive.zip")
for entry in entries:
    print(f"{entry['name']}  {entry['size']}  {entry['is_dir']}")
```

### Forensic Header Parsing

```python
from converter.core.detector import (
    parse_lime_header, build_lime_header,
    parse_dump_header,
    parse_ewf_header, build_ewf_header,
    parse_aff_header, build_aff_header,
)

# Parse forensic file headers
lime_info = parse_lime_header("mem.lime")
print(f"Version: {lime_info['version']}, Base: 0x{lime_info['base_address']:x}")

dump_info = parse_dump_header("crash.dump")
print(f"Type: {dump_info['dump_type']}, Signature: {dump_info['signature']}")

ewf_info = parse_ewf_header("evidence.e01")
print(f"Case: {ewf_info['case_number']}, Sections: {ewf_info['section_count']}")

aff_info = parse_aff_header("image.aff")
print(f"Version: {aff_info['major']}.{aff_info['minor']}, Page: {aff_info['page_size']}")

# Build headers from scratch
header = build_lime_header(version=1, base_address=0x100000)
header = build_ewf_header(case_number="CASE-001", is_ex01=False)
header = build_aff_header(page_size=4096, major=1, minor=0)
```

### Plugin System

```python
from converter.plugins import handler_registry

@handler_registry.register("custom", extensions=[".custom"])
class CustomFormatHandler:
    def extract(self, input_path, dest_dir=None):
        ...

    def create(self, output_path, source, target_fmt=None):
        ...

    def convert(self, input_path, output_path, **kwargs):
        ...

    def list_contents(self, input_path):
        ...
```

---

## Security

### Path Traversal Protection

- **ZIP extraction** guards against CVE-2007-4559 (zip-slip). Every member path in the archive is validated using `os.path.realpath()` to ensure it resolves within the destination directory.
- **TAR extraction** validates all member paths similarly. Any path that would escape the destination directory is rejected with a clear error message.
- **Output paths** are sanitized via `safe_output_path()`, which resolves absolute paths and creates parent directories safely.

### Overwrite Protection

- Non-interactive contexts (pipelines, CI, cron jobs) refuse to overwrite existing files unless `--overwrite` is explicitly set.
- Interactive (TTY) contexts prompt the user for confirmation before overwriting.

### No Network Access

The tool performs no network operations. All conversions are entirely local. No data is transmitted externally.

### Disk Space Checks

Pre-conversion disk space validation prevents "disk full" failures mid-conversion. The check uses a configurable multiplier (default 2x) of the input file size as a heuristic estimate.

### External Tool Sandboxing

External commands (`qemu-img`, `7z`, `dmg2img`, etc.) are run with `capture_output=True` and explicit timeouts (1-2 hours) to prevent hanging or unexpected interaction with the terminal.

---

## Testing

The test suite contains **199 unit tests** covering all modules:

```bash
# Run all tests
python -m pytest tests/test_converter.py -v

# Run specific test class
python -m pytest tests/test_converter.py::TestForensicConversions -v
python -m pytest tests/test_converter.py::TestEwfConversions -v
python -m pytest tests/test_converter.py::TestAffConversions -v

# Run with coverage
python -m pytest tests/test_converter.py -v --cov=converter

# Run a single test
python -m pytest tests/test_converter.py::TestLimeHeader::test_lime_roundtrip_build_parse -v
```

### Test Coverage

| Module | Test Class | Tests |
|--------|-----------|-------|
| Format Detection | `TestFormatDetection` | Extension, magic bytes, conflicts, normalisation |
| Validation | `TestValidation` | File/dir existence, overwrite, disk space |
| Archive Handler | `TestArchiveHandler` | ZIP, TAR, TAR.GZ/BZ2/XZ, stream formats, conversions |
| Dispatcher | `TestDispatcher` | Conversion matrix, routing, forensic support |
| LiME Header | `TestLimeHeader` | Build, parse, roundtrip, edge cases |
| Dump Header | `TestDumpHeader` | PAGE/PAGEDU, types, edge cases |
| EWF Header | `TestEwfHeader` | E01/EX01 build, parse, roundtrip |
| AFF Header | `TestAffHeader` | Build, parse, roundtrip, edge cases |
| Forensic Conversions | `TestForensicConversions` | LIME↔RAW, DUMP↔RAW, LIME↔DUMP, BIN, streaming |
| EWF Conversions | `TestEwfConversions` | E01↔RAW, E01↔EX01, E01↔DUMP/LIME |
| AFF Conversions | `TestAffConversions` | AFF↔RAW, AFF↔DUMP/LIME, AFF↔BIN |
| Dispatcher (EWF/AFF) | `TestEwfAffDispatcher` | Matrix entries for all forensic conversions |
| CLI | `TestCLI` | Argument parsing, exit codes, all modes |
| Plugin System | `TestPluginSystem` | Registration, lookup, decorator, extension search |
| Logging | `TestLogging` | Level configuration, error classification |
| Edge Cases | `TestEdgeCases` | Corrupted files, empty archives, format conflicts |

---

## Contributing

Contributions are welcome! Here's how to get started:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and add tests
4. Run the test suite: `python -m pytest tests/test_converter.py -v`
5. Commit with a descriptive message
6. Push and create a Pull Request

### Adding a New Format

1. Add a `FormatID` enum value in `converter/core/detector.py`
2. Add the extension mapping in `_EXTENSION_MAP`
3. Add the magic byte signature in `_MAGIC_SIGNATURES` (if applicable)
4. Add the category mapping in `_FORMAT_CATEGORY`
5. Add conversion entries in `_build_conversion_matrix()` in `dispatcher.py`
6. Implement the handler methods in the appropriate handler class
7. Add comprehensive tests

---

## Requirements

- **Python**: 3.10 or later
- **No required third-party packages** — core functionality uses only Python stdlib
- **Optional external tools** for extended format support (see Installation)

---

## License

Copyright 2024 Cysec Don (cysecdon@gmail.com)

Licensed under the **Apache License, Version 2.0** (the "License"); you may not use this software except in compliance with the License. You may obtain a copy of the License at:

- [LICENSE](LICENSE) — Full Apache 2.0 license text
- [NOTICE](NOTICE) — Attribution and third-party acknowledgement requirements
- http://www.apache.org/licenses/LICENSE-2.0

### Strong Attribution Requirement

This project uses a **NOTICE file** that imposes mandatory attribution requirements in addition to the standard Apache 2.0 terms. In summary:

- **Visible credit** — Any derivative work, fork, or redistribution must display the following attribution prominently (e.g., in an About dialog, README, startup banner, or documentation landing page):

  > *"Based on Forensic File Converter by Cysec Don — https://github.com/cysec-don/forensic-file-converter"*

- **Documentation credit** — All documentation and marketing materials for derivative works must include:

  > *"Powered by Forensic File Converter (Cysec Don)"*

- **Source code attribution** — Modified source files must retain the original copyright notice and include a comment near the top of the file indicating the original source:

  ```python
  # Original source: Forensic File Converter by Cysec Don
  # https://github.com/cysec-don/forensic-file-converter
  ```

- **Fork naming** — Public forks must not use the name "Forensic File Converter" as their primary project name without written permission. Use a distinguishing name such as *"Forensic File Converter (Fork by [Name])"* or a completely different name with attribution.

- **Commercial use** — Commercial use is permitted provided all attribution requirements are met. Removing attribution notices to claim sole authorship of the original Work is strictly prohibited.

- **License preservation** — Both the LICENSE and NOTICE files must be included in all copies or substantial portions of the Software.

See the [NOTICE](NOTICE) file for the complete and authoritative attribution requirements.

### Third-Party Tools

This software may optionally invoke external tools (qemu-img, 7z, unrar, cabextract, dmg2img, genisoimage, xorriso, libewf, AFFLIB) when available on the system. These tools are **not included** with this software and are each subject to their own respective licenses. See the [NOTICE](NOTICE) file for the full list of third-party acknowledgements.

---

## Contact

**Cysec Don** — [cysecdon@gmail.com](mailto:cysecdon@gmail.com)

GitHub: [github.com/cysec-don](https://github.com/cysec-don)
