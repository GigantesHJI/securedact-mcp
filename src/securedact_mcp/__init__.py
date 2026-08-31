"""MCP surface for the Securedact privacy engine."""

from __future__ import annotations

from typing import Any

__all__ = ["create_server"]
__version__ = "0.5.0"


def __getattr__(name: str) -> Any:
    """Lazily expose ``create_server`` without importing the MCP server stack.

    Importing the package must not eagerly pull in ``mcp`` (and its transitive
    base-interpreter re-exec on CPython 3.12). Clients that only use the managed
    agent surface, the CLI, or the model tooling never need the MCP server import.
    """

    if name == "create_server":
        from .server import create_server

        return create_server
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
