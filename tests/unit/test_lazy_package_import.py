# SPDX-License-Identifier: Apache-2.0
"""Regression tests for lazy package import of the MCP server surface.

Importing ``securedact_mcp`` (and the managed-agent CLI) must NOT eagerly pull
in ``mcp``. On CPython 3.12 that transitive import re-execs the agent process
into the base interpreter instead of the machine-owned runtime. ``create_server``
remains available as a lazy attribute, but only when actually requested.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

import securedact_mcp
from securedact_core import build_production_engine
from securedact_mcp import server
from securedact_mcp.agent import service_taskscheduler as ts
from securedact_mcp.agent.service_taskscheduler import _LAUNCHER_SOURCE


def _import_pulls_in_mcp(module: str) -> bool:
    """Return True if importing ``module`` also imports ``mcp``.

    Runs in a fresh interpreter so the result is independent of any imports
    already performed by the surrounding test session.
    """

    code = f"import sys\nimport {module}\nprint('MCP_IN_MODULES', 'mcp' in sys.modules)\n"
    result = subprocess.run(  # noqa: S603 - sys.executable + local f-string, no untrusted input
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return "MCP_IN_MODULES True" in result.stdout


def test_importing_package_does_not_import_mcp() -> None:
    assert not _import_pulls_in_mcp("securedact_mcp")


def test_importing_agent_cli_does_not_import_mcp() -> None:
    assert not _import_pulls_in_mcp("securedact_mcp.agent.cli")


def test_create_server_remains_accessible_as_lazy_attribute() -> None:
    # The attribute is provided lazily and resolves to the real factory.
    assert securedact_mcp.create_server is server.create_server
    assert callable(securedact_mcp.create_server)


def test_create_server_builds_server_without_eager_mcp_import() -> None:
    engine = build_production_engine(require_contextual=False)
    app = securedact_mcp.create_server(engine)
    assert isinstance(app, FastMCP)


def test_launcher_script_source_uses_agent_cli_not_mcp() -> None:
    assert "from securedact_mcp.agent.cli import main" in _LAUNCHER_SOURCE
    # The launcher must never pull in the MCP server stack at import time.
    assert "from securedact_mcp.server" not in _LAUNCHER_SOURCE
    assert "import mcp" not in _LAUNCHER_SOURCE


def test_launcher_script_written_is_canonical(tmp_path: Path) -> None:
    interpreter = tmp_path / "python.exe"
    launcher = ts.write_launcher_script(interpreter)
    assert launcher.read_text(encoding="utf-8") == _LAUNCHER_SOURCE
    assert launcher.parent == interpreter.parent


def test_task_definition_uses_provided_runtime_interpreter(tmp_path: Path) -> None:
    runtime_python = tmp_path / "Scripts" / "python.exe"
    definition = ts.build_task_definition(data_dir=tmp_path / "data", runtime_python=runtime_python)
    assert definition.executable == runtime_python
    assert "securedact_agent_loop.py" in definition.arguments
    # The launched script lives next to the runtime interpreter.
    launched = Path(definition.arguments.strip('"').split(" ")[0])
    assert launched.parent == runtime_python.parent


def test_resolve_runtime_interpreter_returns_explicit_path() -> None:
    explicit = Path("C:/explicit/runtime/Scripts/python.exe")
    assert ts._resolve_runtime_interpreter(explicit) == explicit
