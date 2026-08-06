from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INTEGRATIONS = ROOT / "integrations"
EXPECTED_TOOLS = {
    "prepare_for_external_ai",
    "analyze_text",
    "redact_text",
    "restore_text",
    "create_safe_copy",
}


def test_host_templates_parse_and_use_bounded_local_stdio_command() -> None:
    codex = tomllib.loads((INTEGRATIONS / "codex" / "config.toml").read_text(encoding="utf-8"))
    cursor = json.loads((INTEGRATIONS / "cursor" / "mcp.json").read_text(encoding="utf-8"))
    windsurf = json.loads(
        (INTEGRATIONS / "windsurf" / "mcp_config.json").read_text(encoding="utf-8")
    )

    configurations = [
        codex["mcp_servers"]["securedact"],
        cursor["mcpServers"]["securedact"],
        windsurf["mcpServers"]["securedact"],
    ]
    for configuration in configurations:
        assert configuration["command"] == "<ABSOLUTE_PATH_TO_PYTHON>"
        assert configuration["args"] == ["-m", "securedact_mcp"]
        assert configuration["env"]["SECUREDACT_REQUIRE_FLAIR"] == "1"
        assert "http" not in json.dumps(configuration).casefold()


def test_every_host_package_documents_safe_workflow_and_enforcement_limit() -> None:
    for host in ("codex", "cursor", "windsurf"):
        text = (INTEGRATIONS / host / "README.md").read_text(encoding="utf-8")
        assert all(f"`{tool}`" in text for tool in EXPECTED_TOOLS)
        assert 'status == "ok"' in text
        assert "sanitized_text" in text
        assert "review_required" in text
        assert "blocked" in text
        assert "debug or legacy mapping" in text
        assert "cannot guarantee" in text
        assert "2026-08-06" in text
