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
