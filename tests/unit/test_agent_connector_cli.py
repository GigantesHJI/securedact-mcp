# SPDX-License-Identifier: Apache-2.0
"""Connector-binding CLI contract tests (AGENT-010 / M365-102).

Locks down the parser so the supported platform choices are derived from the
authoritative :data:`SUPPORTED_BINDING_PLATFORMS` constant. Drift in either
direction is caught here before it reaches production.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from securedact_mcp.agent.cli import build_agent_parser
from securedact_mcp.agent.config import AgentFiles
from securedact_mcp.agent.connectors import (
    SUPPORTED_BINDING_PLATFORMS,
    ConnectorBinding,
    ConnectorBindingStore,
)
from securedact_mcp.agent.errors import ConnectorBindingError


def test_supported_binding_platforms_constant_lists_both() -> None:
    """The canonical platform set must include Google and Microsoft."""

    assert "google_workspace" in SUPPORTED_BINDING_PLATFORMS
    assert "microsoft365" in SUPPORTED_BINDING_PLATFORMS


def test_cli_bind_choices_derived_from_supported_constant() -> None:
    """The argparse choices list must mirror SUPPORTED_BINDING_PLATFORMS exactly.

    Regression guard: the previous implementation hard-coded
    ``choices=["google_workspace"]`` even though the constant listed Microsoft.
    """

    root = argparse.ArgumentParser(prog="securedact-mcp")
    sub = root.add_subparsers(dest="command", required=True)
    build_agent_parser(sub)
    bind_choices = _find_bind_platform_choices(root)
    assert bind_choices is not None, "bind subparser not found"
    assert set(bind_choices) == set(SUPPORTED_BINDING_PLATFORMS), (
        "agent connector CLI choices drifted from SUPPORTED_BINDING_PLATFORMS; "
        "derive from the constant instead of hard-coding."
    )


def test_google_workspace_still_binds(tmp_path: Path) -> None:
    """Binding google_workspace must continue to work unchanged."""

    store = _make_store(tmp_path)
    binding = ConnectorBinding(integration_id="int-google", platform="google_workspace")
    store.bind(binding)
    persisted = store.get("int-google")
    assert persisted is not None
    assert persisted.platform == "google_workspace"


def test_microsoft365_binds_via_store(tmp_path: Path) -> None:
    """microsoft365 must be accepted by the binding store (CLI parity)."""

    store = _make_store(tmp_path)
    binding = ConnectorBinding(integration_id="int-ms", platform="microsoft365")
    store.bind(binding)
    persisted = store.get("int-ms")
    assert persisted is not None
    assert persisted.platform == "microsoft365"
    assert persisted.integration_id == "int-ms"


def test_unsupported_platform_rejected(tmp_path: Path) -> None:
    """An unknown platform must fail closed."""

    store = _make_store(tmp_path)
    bad = ConnectorBinding(integration_id="int-x", platform="dropbox")
    with pytest.raises(ConnectorBindingError):
        store.bind(bad)


def test_binding_persists_only_non_secret_metadata(tmp_path: Path) -> None:
    """Binding JSON must contain only integration_id / platform / local_profile.

    The serialized payload must never contain OAuth tokens, client secrets, or
    drive/folder/item identifiers.
    """

    store = _make_store(tmp_path)
    binding = ConnectorBinding(
        integration_id="int-ms", platform="microsoft365", local_profile="default"
    )
    store.bind(binding)

    raw = store._path.read_text(encoding="utf-8")
    parsed = json.loads(raw)
    assert set(parsed["int-ms"].keys()) <= {
        "integration_id",
        "platform",
        "local_profile",
        "display_name",
    }
    for forbidden in (
        "client_secret",
        "access_token",
        "refresh_token",
        "driveId",
        "drive_id",
        "folderId",
        "folder_id",
        "itemId",
        "item_id",
        "siteId",
        "site_id",
        "graph.microsoft.com",
    ):
        assert forbidden not in raw, f"binding file leaks {forbidden!r}"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _make_store(tmp_path: Path) -> ConnectorBindingStore:
    """Build a ConnectorBindingStore rooted in ``tmp_path``."""

    files = AgentFiles.resolve(root=tmp_path)
    return ConnectorBindingStore(files=files)


def _find_bind_platform_choices(parser: argparse.ArgumentParser) -> list[str] | None:
    """Walk the parser tree to find the ``agent connectors bind --platform`` choices."""

    found: list[str] | None = None

    def _walk(p: argparse.ArgumentParser) -> None:
        nonlocal found
        for action in p._actions:
            if isinstance(action, argparse._SubParsersAction):
                for sub_name, sub_parser in action.choices.items():
                    if sub_name == "bind":
                        for bind_action in sub_parser._actions:
                            if getattr(bind_action, "dest", None) == "platform":
                                found = list(bind_action.choices or [])
                        return
                    _walk(sub_parser)

    _walk(parser)
    return found
