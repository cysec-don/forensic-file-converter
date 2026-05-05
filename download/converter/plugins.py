"""
Plugin System
=============

Provides an extensible registry for adding new format handlers without
modifying the core converter code.

To register a new handler:

::

    from converter.plugins import handler_registry

    @handler_registry.register("custom")
    class CustomHandler:
        def extract(self, input_path, dest_dir=None): ...
        def create(self, output_path, source, target_fmt=None): ...
        def convert(self, input_path, output_path, ...): ...
        def list_contents(self, input_path): ...

The dispatcher can then route to ``CustomHandler`` when it encounters
files with a matching extension or magic bytes.

This is a lightweight alternative to ``entry_points`` / ``pluggy``:
it works without a build system and is suitable for a standalone tool.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Type

logger = logging.getLogger(__name__)


@dataclass
class PluginInfo:
    """Metadata about a registered handler plugin."""
    name: str
    handler_class: Type
    extensions: List[str] = field(default_factory=list)
    magic_bytes: Optional[bytes] = None
    magic_offset: int = 0
    description: str = ""


class HandlerRegistry:
    """Registry for format handler plugins.

    Usage::

        registry = HandlerRegistry()
        registry.register("myfmt", MyHandler, extensions=[".myf"])
    """

    def __init__(self) -> None:
        self._handlers: Dict[str, PluginInfo] = {}

    def register(
        self,
        name_or_class: object,
        handler_class: Optional[Type] = None,
        *,
        extensions: Optional[List[str]] = None,
        magic_bytes: Optional[bytes] = None,
        magic_offset: int = 0,
        description: str = "",
    ) -> Callable:
        """Register a handler class.

        Supports three call styles:

        1. **Direct call**::

            registry.register("name", HandlerClass, extensions=[".ext"])

        2. **Decorator with kwargs**::

            @registry.register("name", extensions=[".ext"])
            class MyHandler: ...

        3. **Decorator with class as first arg** (no kwargs shorthand)::

            @registry.register("name")
            class MyHandler: ...
        """

        def _do_register(cls: Type) -> Type:
            info = PluginInfo(
                name=_name,
                handler_class=cls,
                extensions=_extensions or [],
                magic_bytes=magic_bytes,
                magic_offset=magic_offset,
                description=description,
            )
            self._handlers[_name] = info
            logger.info("Registered handler plugin: %s (%s)", _name, cls.__name__)
            return cls

        # Determine if this is a direct call or a decorator invocation.
        if isinstance(name_or_class, str):
            # Direct call: register("name", HandlerClass, ...)
            # or decorator: @register("name") / @register("name", ext=[...])
            _name = name_or_class
            _extensions = extensions

            if handler_class is not None:
                # Direct call with class provided
                return _do_register(handler_class)
            else:
                # Decorator without parentheses or with kwargs:
                # @register("name")  →  class arrives later
                # @register("name", extensions=[...])  →  class arrives later
                return _do_register
        else:
            # @register(HandlerClass) — name is the class itself (unusual)
            # Treat the class as both name and handler
            cls = name_or_class
            _name = getattr(cls, "__name__", str(cls))
            _extensions = extensions
            return _do_register(cls)

    def get(self, name: str) -> Optional[PluginInfo]:
        return self._handlers.get(name)

    def list_plugins(self) -> List[PluginInfo]:
        return list(self._handlers.values())

    def find_by_extension(self, ext: str) -> Optional[PluginInfo]:
        """Find a plugin that handles the given file extension."""
        lower_ext = ext.lower()
        if not lower_ext.startswith("."):
            lower_ext = "." + lower_ext
        for info in self._handlers.values():
            for plugin_ext in info.extensions:
                if plugin_ext.lower() == lower_ext:
                    return info
        return None


# Global registry instance
handler_registry = HandlerRegistry()
