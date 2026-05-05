---
Task ID: 1
Agent: Super Z (Main)
Task: Design and implement a professional-grade Python file converter supporting archive/compression formats and disk image formats.

Work Log:
- Analyzed format conversion feasibility matrix — determined supported vs unsupported conversions
- Created modular project structure: converter/{core,handlers,utils}, tests/
- Implemented core/detector.py — format detection via magic bytes + extension with compound extension awareness
- Implemented core/dependencies.py — external tool discovery (qemu-img, 7z, unrar, genisoimage, dmg2img, etc.)
- Implemented core/dispatcher.py — conversion matrix (deny-by-default allowlist), cross-category rejection, routing
- Implemented handlers/archive.py — extract/create/convert/list for ZIP, TAR, TAR.GZ/BZ2/XZ, GZ, BZ2, XZ, 7Z, RAR, CAB
- Implemented handlers/disk.py — convert/extract/create/list for QCOW2, VMDK, VHD, VHDX, ISO, IMG, RAW, DD, BIN, DMG
- Implemented utils/validation.py — overwrite protection, disk space checks, path traversal guards
- Implemented utils/logging.py — structured logging with error classification and colourised output
- Implemented cli.py — full argparse CLI with convert/extract/create/list/check-deps/list-formats modes
- Implemented plugins.py — extensible handler registry with decorator support
- Created comprehensive test suite (82 tests, all passing) covering detection, validation, archive ops, disk ops, dispatcher, CLI, plugins, edge cases
- Fixed compound extension detection (tar.gz vs gzip magic bytes conflict)
- Fixed CLI argparse -f flag conflict between --format and --overwrite
- Fixed archive extraction path structure in tests

Stage Summary:
- Total: ~4,068 lines of Python across 15 source files
- 82 unit tests — ALL PASSING
- 11 archive formats + 10 disk image formats supported
- External tool integration: qemu-img, 7z, unrar, genisoimage, xorriso, dmg2img, cabextract
- Security: path traversal guards (CVE-2007-4559), overwrite protection, interactive confirmation
- Cross-platform: Linux-first with macOS/Windows notes

---
Task ID: 2
Agent: Super Z (Main)
Task: Add .raw (extended), .dump (Windows crash dump), and .lime (LiME) format support.

Work Log:
- Added FormatID.DUMP and FormatID.LIME to FormatID enum in detector.py
- Added magic byte signatures: PAGE (32-bit Windows dump), PAGEDU (64-bit Windows dump), LiME
  - PAGEDU checked before PAGE in both magic-byte list and parse_dump_header() to avoid prefix collision
- Added extension mappings: .dump, .dmp, .vdmp → DUMP; .lime → LIME
- Implemented parse_lime_header() — parses 24-byte LiME v1 header (magic, version, base_address)
- Implemented build_lime_header() — constructs 24-byte LiME v1 header with configurable version/base_address
- Implemented parse_dump_header() — parses Windows crash dump header (PAGE/PAGEDU, ValidDump type)
- Defined WIN_DUMP_HEADER_SIZE (4096 bytes) and LIME_HEADER_SIZE_V1 (24 bytes) constants
- Updated dispatcher conversion matrix with all forensic conversion entries:
  - DUMP ↔ RAW/DD/IMG/BIN (PARTIAL — header metadata lost)
  - LIME ↔ RAW/DD/IMG/BIN (PARTIAL — header metadata lost)
  - DUMP ↔ LIME (PARTIAL — cross-format via RAW intermediate)
  - DUMP/LIME ↔ BIN (PARTIAL)
  - DUMP/LIME → qemu formats (EXTERNAL — strip header, qemu-img convert)
- Added lime tool to dependencies.py
- Implemented 6 forensic conversion methods in handlers/disk.py:
  - _lime_to_raw(): streaming strip of 24-byte LiME header (64 MiB chunks)
  - _raw_to_lime(): streaming prepend of LiME v1 header
  - _dump_to_raw(): streaming strip of 4096-byte Windows dump header
  - _raw_to_dump(): streaming prepend of minimal PAGE header (with WARNING about invalid system context)
  - _lime_to_dump() / _dump_to_lime(): two-step conversion via temp file
  - _forensic_to_qemu(): strip header → qemu-img convert to VM format
- All forensic conversions use 64 MiB streaming chunks for large memory dumps (10+ GB)
- Fixed PAGEDU vs PAGE magic byte ordering (PAGEDU is 6 bytes, not 5; must check longer sig first)
- Added 45 new tests (127 total, all passing):
  - Format detection: 8 tests for DUMP/LIME extensions and magic bytes
  - Dispatcher: 7 tests for forensic conversion matrix entries
  - LiME header: 7 tests (build, parse, roundtrip, edge cases)
  - Dump header: 7 tests (PAGE, PAGEDU, MiniDump, edge cases)
  - Forensic conversions: 16 tests (LIME↔RAW, LIME↔DUMP, LIME↔BIN, error cases, large file streaming)

Stage Summary:
- .raw already supported; .dump and .lime are new (pure Python, no external tools required for core conversions)
- 13 disk image formats + 11 archive formats = 24 total formats
- 127 unit tests — ALL PASSING
- All forensic conversions are marked PARTIAL because header metadata is lost or fabricated
- Design justification documented in docstrings: why LiME base_address=0, why RAW→DUMP header is unsafe for WinDbg
