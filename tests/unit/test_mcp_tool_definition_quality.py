"""Regression tests for MCP tool-definition quality.

These assert that every registered tool exposes a meaningful, agent-facing
description and that every MCP-visible parameter carries a non-empty
description. They also guard against silent drift of tool names, parameter
names, required/optional status, and defaults (which would break backward
compatibility).

The checks are semantic, not exact-string snapshots, so they survive wording
tweaks while still failing if descriptions or parameters are stripped.
"""

from __future__ import annotations

import asyncio

import pytest

from securedact_mcp.server import create_server

EXPECTED_TOOLS = {
    "prepare_for_external_ai",
    "analyze_text",
    "redact_text",
    "restore_text",
    "create_safe_copy",
    "securedact_read_file",
}

EXPECTED_PARAMS: dict[str, set[str]] = {
    "prepare_for_external_ai": {"text", "policy", "language", "response_mode"},
    "analyze_text": {"text", "policy", "response_mode"},
    "redact_text": {"text", "policy", "response_mode"},
    "restore_text": {"text", "restoration_session", "mapping", "trusted_local_review"},
    "create_safe_copy": {"content", "filename", "policy"},
    "securedact_read_file": {"path", "policy", "max_bytes"},
}

EXPECTED_REQUIRED: dict[str, set[str]] = {
    "prepare_for_external_ai": {"text"},
    "analyze_text": {"text"},
    "redact_text": {"text"},
    "restore_text": {"text"},
    "create_safe_copy": {"content", "filename"},
    "securedact_read_file": {"path"},
}

EXPECTED_DEFAULTS: dict[str, dict[str, object]] = {
    "prepare_for_external_ai": {
        "policy": "strict_external_ai",
        "language": "auto",
        "response_mode": "minimal",
    },
    "analyze_text": {"policy": "default", "response_mode": "minimal"},
    "redact_text": {"policy": "default", "response_mode": "minimal"},
    "restore_text": {
        "restoration_session": None,
        "mapping": None,
        "trusted_local_review": False,
    },
    "create_safe_copy": {"policy": "strict_external_ai"},
    "securedact_read_file": {"policy": "strict_external_ai", "max_bytes": None},
}

MIN_TOOL_DESCRIPTION = 80
MIN_PARAM_DESCRIPTION = 20


@pytest.fixture(autouse=True)
def _require_flair_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECUREDACT_REQUIRE_FLAIR", "0")


def _tools() -> dict[str, object]:
    server = create_server()
    return {tool.name: tool for tool in asyncio.run(server.list_tools())}


def test_all_expected_tools_present() -> None:
    assert set(_tools()) == EXPECTED_TOOLS


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_tool_names_and_parameters_unchanged(name: str) -> None:
    tools = _tools()
    schema = tools[name].inputSchema  # type: ignore[attr-defined]
    assert set(schema["properties"]) == EXPECTED_PARAMS[name]
    assert set(schema["required"]) == EXPECTED_REQUIRED[name]


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_required_and_optional_status_unchanged(name: str) -> None:
    tools = _tools()
    schema = tools[name].inputSchema  # type: ignore[attr-defined]
    assert set(schema["required"]) == EXPECTED_REQUIRED[name]
    optional = set(schema["properties"]) - set(schema["required"])
    assert optional == (EXPECTED_PARAMS[name] - EXPECTED_REQUIRED[name])


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_defaults_unchanged(name: str) -> None:
    tools = _tools()
    schema = tools[name].inputSchema  # type: ignore[attr-defined]
    for param, expected in EXPECTED_DEFAULTS[name].items():
        assert schema["properties"][param].get("default", None) == expected


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_tool_description_is_meaningful(name: str) -> None:
    tools = _tools()
    description = (tools[name].description or "").strip()  # type: ignore[attr-defined]
    assert description, f"{name} has an empty description"
    assert len(description) >= MIN_TOOL_DESCRIPTION
    assert "TODO" not in description and "FIXME" not in description
    assert description == (tools[name].description or "")  # type: ignore[attr-defined]


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_every_parameter_has_a_description(name: str) -> None:
    tools = _tools()
    schema = tools[name].inputSchema  # type: ignore[attr-defined]
    for param, definition in schema["properties"].items():
        desc = (definition.get("description") or "").strip()
        assert desc, f"{name}.{param} is missing a parameter description"
        assert len(desc) >= MIN_PARAM_DESCRIPTION


def test_prepare_for_external_ai_disambiguates_peers() -> None:
    tools = _tools()
    description = tools["prepare_for_external_ai"].description  # type: ignore[attr-defined]
    for peer in ("analyze_text", "create_safe_copy", "restore_text"):
        assert peer in description


def test_restore_text_clarifies_security_boundary() -> None:
    tools = _tools()
    description = tools["restore_text"].description  # type: ignore[attr-defined]
    lowered = description.lower()
    assert "trusted" in lowered
    assert "local" in lowered
    assert "reveal" in lowered or "original" in lowered
    assert "never" in lowered or "must never" in lowered


def test_parameter_description_coverage_is_complete() -> None:
    tools = _tools()
    total = 0
    documented = 0
    for name in EXPECTED_TOOLS:
        schema = tools[name].inputSchema  # type: ignore[attr-defined]
        for _param, definition in schema["properties"].items():
            total += 1
            if (definition.get("description") or "").strip():
                documented += 1
    assert total > 0
    assert documented == total
