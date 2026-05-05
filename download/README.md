# Forensic File Converter

<p align="center">
  <strong>A professional-grade Python tool for converting between archive, disk image, and forensic file formats.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Tests-199%20passed-brightgreen.svg" alt="199 tests passing">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/Formats-27+-orange.svg" alt="27+ formats">
</p>

**Author:** Cysec Don | [cysecdon@gmail.com](mailto:cysecdon@gmail.com)

---

## Overview

Forensic File Converter is a modular, extensible command-line tool designed for digital forensics practitioners, incident responders, and security analysts. It provides seamless conversion between **27+ file formats** across three major categories:

- **Archive / Compression formats** (11 formats)
- **Disk image formats** (10 formats)
- **Forensic image formats** (6 formats: `.dump`, `.lime`, `.e01`, `.ex01`, `.aff`)

The tool features intelligent format detection via magic byte signatures and extension analysis, a deny-by-default conversion matrix for safety, streaming large-file support for multi-gigabyte memory dumps, and comprehensive security protections against path traversal attacks.

---

## Features

### Core Capabilities
- **Format Detection** — Dual-layer detection using magic byte signatures and extension mapping, with conflict resolution logic
- **Conversion Matrix** — Deny-by-default allowlist encoding which conversions are supported, lossless, partial, or require external tools
- **Streaming Engine** — 64 MiB chunk-based streaming for large forensic images (10+ GB memory dumps) without excessive memory usage
- **Plugin System** — Decorator-based handler registry for extending format support without modifying core code
- **Security Hardened** — Path traversal guards (CVE-2007-4559 for ZIP, TAR slip), overwrite protection, disk space checks
- **Zero Third-Party Dependencies** — Pure Python stdlib for core operations; external tools are optional fallbacks

### Forensic Format Support
- **Windows Crash Dumps** (`.dump` / `.dmp`) — Parses `PAGE` and `PAGEDU` headers, supports MiniDump, FullDump, and KernelDump types
- **LiME Memory Dumps** (`.lime`) — Parses 24-byte LiME v1 headers with base address extraction
- **EnCase EWF** (`.e01` / `.ex01`) — Parses EWF file headers, supports E01↔EX01 re-headering, compatible with Autopsy and Guymager workflows
- **AFF** (`.aff`) — Parses AFF v1 headers with page size and compression metadata
- Cross-format forensic conversions (e.g., LiME↔DUMP, E01↔RAW, AFF↔E01) via raw intermediate

---

## Supported Formats

### Archive / Compression Formats

| Format | Extensions | Extract | Create | Convert | Notes |
|--------|-----------|---------|--------|---------|-------|
| ZIP | `.zip` | stdlib | stdlib | Full | Pure Python, path traversal protected |
| TAR | `.tar` | stdlib | stdlib | Full | Pure Python |
| TAR.GZ | `.tar.gz`, `.tgz` | stdlib | stdlib | Full | Compound extension aware |
| TAR.BZ2 | `.tar.bz2`, `.tbz2` | stdlib | stdlib | Full | Compound extension aware |
| TAR.XZ | `.tar.xz`, `.txz` | stdlib | stdlib | Full | Compound extension aware |
| GZIP | `.gz`, `.gzip` | stdlib | stdlib | Full | Single-file compression |
| BZIP2 | `.bz2` | stdlib | stdlib | Full | Single-file compression |
| XZ | `.xz` | stdlib | stdlib | Full | Single-file compression |
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

### Optional External Tools

For full format support, install these optional tools:

```bash
# Archive tools
sudo apt install p7zip-full unrar cabextract

# Disk image tools
sudo apt install qemu-utils genisoimage xorriso

# DMG support (Linux)
sudo apt install dmg2img

# Forensic tools
sudo apt install libewf-tools afflib-tools
```

### On macOS

```bash
brew install p7zip qemu cdrtools
```

---

## Usage

### Command-Line Interface

```
python -m converter [OPTIONS]
```

### Convert Between Formats

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

# Forensic to VM format (strip header + qemu-img)
python -m converter -i mem.dump -o mem.qcow2
```

### Extract Archives and Images

```bash
# Extract archives
python -m converter --extract archive.tar.gz
python -m converter --extract archive.tar.gz -d /tmp/extracted

# Extract disk images (ISO, etc.)
python -m converter --extract cdrom.iso -d /mnt/iso
```

### Create Archives and Images

```bash
# Create archives
python -m converter --create backup.tar.gz /path/to/folder/
python -m converter --create archive.zip /path/to/folder/

# Create ISO images
python -m converter --create cdrom.iso /path/to/cd-contents/
```

### List Contents

```bash
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

# Verbose / debug mode
python -m converter -i in.img -o out.qcow2 -vv

# Force overwrite
python -m converter -i in.img -o out.qcow2 --overwrite
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error / conversion failure |
| 2 | Unsupported conversion |
| 3 | Missing external dependency |
| 4 | Validation error (file not found, overwrite refused) |

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

1. **Deny-by-default conversion matrix** — Every conversion must be explicitly listed. Missing entries result in `UnsupportedConversion` rather than silent data loss.

2. **Magic bytes over extension** — When magic bytes and extension disagree, magic bytes win (harder to spoof). Compound extensions (`.tar.gz`) are an exception — they always override ambiguous magic matches.

3. **Cross-category rejection** — Archive-to-disk and disk-to-archive conversions are explicitly blocked at the dispatcher level. Users must perform a two-step extract-then-convert workflow.

4. **Streaming for large files** — Forensic conversions use 64 MiB chunk-based streaming to handle multi-gigabyte memory dumps without loading entire files into memory.

5. **Security protections** — ZIP extraction guards against CVE-2007-4559 (zip-slip). TAR extraction validates all member paths against the destination directory. Overwrite protection requires explicit `--overwrite` flag in non-interactive contexts.

---

## Forensic Format Details

### Windows Crash Dumps (`.dump` / `.dmp`)

Windows crash dumps begin with a `PAGE` (32-bit) or `PAGEDU` (64-bit) signature at offset 0, followed by a 4096-byte `DUMP_HEADER` structure. The `ValidDump` field at offset 8 identifies the dump type:

| ValidDump | Type | Description |
|-----------|------|-------------|
| 1 | MiniDump | User-mode process dump |
| 2 | FullDump | Complete physical memory dump |
| 3 | KernelDump | Kernel-mode memory dump |

Converting DUMP to RAW strips the 4096-byte header. Converting RAW to DUMP prepends a minimal header (without valid system context). These are **partial** conversions — header metadata is lost or fabricated.

### LiME (`.lime`)

LiME (Linux Memory Extractor) files have a 24-byte header:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic (`LiME`) |
| 4 | 1 | Version (typically 1) |
| 5 | 3 | Reserved |
| 8 | 8 | Base address (uint64 LE) |
| 16 | 8 | Reserved |

Converting LIME to RAW strips the 24-byte header. Converting RAW to LIME prepends a header with `base_address=0`.

### EWF / EnCase (`.e01` / `.ex01`)

The EnCase Expert Witness Format is the primary forensic imaging format used by EnCase, Autopsy, and Guymager. The EWF file header (624 bytes) contains:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 3 | Signature (`EVF`) |
| 7 | 1 | Version code (0x00=E01, 0x01=EX01) |
| 8 | 16 | Case number (null-padded) |
| 24 | 4 | Section count (uint32 LE) |

E01 to EX01 conversion preserves data sections and only re-headers the file.

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

---

## Python API

```python
from converter.core.detector import detect_format, FormatID
from converter.core.dispatcher import Dispatcher

# Detect a file's format
info = detect_format("memory.lime")
print(info.format_id)    # FormatID.LIME
print(info.detected_by)  # "magic"
print(info.category)     # FormatCategory.DISK_IMAGE

# Convert files
dispatcher = Dispatcher()
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

# Parse forensic headers
from converter.core.detector import parse_lime_header, parse_dump_header
from converter.core.detector import parse_ewf_header, parse_aff_header

lime_info = parse_lime_header("mem.lime")
dump_info = parse_dump_header("crash.dump")
ewf_info = parse_ewf_header("evidence.e01")
aff_info = parse_aff_header("image.aff")
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

## Running Tests

```bash
# Run all tests
python -m pytest tests/test_converter.py -v

# Run specific test class
python -m pytest tests/test_converter.py::TestForensicConversions -v

# Run with coverage
python -m pytest tests/test_converter.py -v --cov=converter
```

All **199 tests** pass, covering format detection, validation, archive operations, disk image operations, forensic conversions, dispatcher routing, CLI parsing, plugin registration, logging, and edge cases.

---

## Security Considerations

- **Path Traversal Protection**: ZIP extraction guards against CVE-2007-4559 (zip-slip). TAR extraction validates all member paths. Output paths are sanitized.
- **Overwrite Protection**: Non-interactive contexts (pipelines, CI) refuse to overwrite existing files unless `--overwrite` is explicitly set.
- **No Network Access**: The tool performs no network operations. All conversions are local.
- **Disk Space Checks**: Pre-conversion disk space validation prevents "disk full" failures mid-conversion.
- **External Tool Sandboxing**: External commands are run with `capture_output=True` and explicit timeouts (1-2 hours).

---

## Requirements

- **Python**: 3.10 or later
- **No required third-party packages** — core functionality uses only Python stdlib
- **Optional external tools** for extended format support (see Installation)

---

## License

MIT License

Copyright (c) 2024 Cysec Don

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Contact

**Cysec Don** — [cysecdon@gmail.com](mailto:cysecdon@gmail.com)

GitHub: [github.com/cysec-don](https://github.com/cysec-don)
