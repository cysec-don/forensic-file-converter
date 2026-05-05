"""
Dependency Detection Module
===========================

Checks for the presence of external tools required by various handlers.
Each check is a fast ``shutil.which()`` probe; results are cached for the
lifetime of the process so repeated calls are free.

The public API returns structured ``DependencyInfo`` objects that the CLI
can render into human-readable messages or the dispatcher can use to
short-circuit impossible conversions.
"""

from __future__ import annotations

import shutil
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ToolInfo:
    """Metadata about a single external tool."""
    name: str
    available: bool
    path: Optional[str] = None
    install_hint: str = ""
    required_for: List[str] = field(default_factory=list)  # format IDs


@dataclass
class DependencyReport:
    """Aggregate result of a dependency scan."""
    all_ok: bool
    tools: Dict[str, ToolInfo]

    def missing_tools(self) -> List[ToolInfo]:
        return [t for t in self.tools.values() if not t.available]

    def missing_for_format(self, fmt: str) -> List[ToolInfo]:
        return [
            t for t in self.tools.values()
            if not t.available and fmt in t.required_for
        ]


# Cache singleton — populated once per process
_cache: Dict[str, ToolInfo] = {}


def _probe(name: str, install_hint: str, required_for: List[str]) -> ToolInfo:
    """Probe for *name* on ``$PATH``; cache and return a ``ToolInfo``."""
    if name in _cache:
        return _cache[name]

    path = shutil.which(name)
    info = ToolInfo(
        name=name,
        available=path is not None,
        path=path,
        install_hint=install_hint,
        required_for=required_for,
    )
    _cache[name] = info
    if info.available:
        logger.debug("Found external tool: %s -> %s", name, path)
    else:
        logger.debug("External tool NOT found: %s", name)
    return info


def check_all() -> DependencyReport:
    """Probe for every known external tool and return a full report."""
    tools: Dict[str, ToolInfo] = {}
    definitions: List[tuple] = [
        (
            "7z",
            "Install p7zip-full:  sudo apt install p7zip-full  |  brew install p7zip",
            ["7z", "rar", "cab"],
        ),
        (
            "7za",
            "Install p7zip:  sudo apt install p7zip",
            ["7z", "rar", "cab"],
        ),
        (
            "rar",
            "Install rar:  sudo apt install rar  |  brew install rar",
            ["rar"],
        ),
        (
            "unrar",
            "Install unrar:  sudo apt install unrar  |  brew install unrar",
            ["rar"],
        ),
        (
            "cabextract",
            "Install cabextract:  sudo apt install cabextract",
            ["cab"],
        ),
        (
            "qemu-img",
            "Install QEMU utils:  sudo apt install qemu-utils  |  brew install qemu",
            ["qcow2", "vmdk", "vhd", "vhdx", "img", "raw", "dd"],
        ),
        (
            "genisoimage",
            "Install genisoimage:  sudo apt install genisoimage  |  brew install cdrtools",
            ["iso"],
        ),
        (
            "mkisofs",
            "Install cdrtools:  sudo apt install cdrtools  |  brew install cdrtools",
            ["iso"],
        ),
        (
            "xorriso",
            "Install xorriso:  sudo apt install xorriso  |  brew install libxorriso",
            ["iso"],
        ),
        (
            "hdiutil",
            "macOS only — not available on Linux/Windows",
            ["dmg"],
        ),
        (
            "dmg2img",
            "Install dmg2img:  sudo apt install dmg2img",
            ["dmg"],
        ),
    ]

    for name, hint, formats in definitions:
        info = _probe(name, hint, formats)
        tools[name] = info

    all_ok = all(t.available for t in tools.values())
    return DependencyReport(all_ok=all_ok, tools=tools)


def ensure_tool(name: str, fmt: str = "") -> ToolInfo:
    """Return the ToolInfo for *name*, raising if missing and *fmt* given."""
    report = check_all()
    info = report.tools.get(name)
    if info is None:
        info = ToolInfo(name=name, available=False, required_for=[fmt])
    if not info.available and fmt:
        raise EnvironmentError(
            f"Required tool '{name}' not found on $PATH. "
            f"Needed for format: {fmt}\n"
            f"  Install hint: {info.install_hint}"
        )
    return info
