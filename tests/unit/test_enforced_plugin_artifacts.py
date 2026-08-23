from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

GEMINI_EXTENSION_NAME = "securedact-enforced"
GEMINI_EXTENSION_VERSION = "0.4.0"
GEMINI_HOOK_EVENTS = {
    "SessionStart",
    "SessionEnd",
    "BeforeAgent",
    "BeforeModel",
    "BeforeTool",
    "AfterTool",
}
GEMINI_INTERCEPTION_TIMEOUT_MS = 20000


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_claude_plugin_has_portable_hook_configuration() -> None:
    plugin_root = ROOT / "integrations" / "claude-code-enforced" / "securedact-enforced"
    manifest = _read_json(plugin_root / ".claude-plugin" / "plugin.json")
    hooks = _read_json(plugin_root / "hooks" / "hooks.json")

    assert manifest["name"] == "securedact-enforced"
    assert manifest["displayName"] == "SecuRedact Enforced"
    assert manifest["homepage"] == "https://github.com/GigantesHJI/securedact-mcp"
    assert manifest["repository"] == "https://github.com/GigantesHJI/securedact-mcp"
    assert (plugin_root / "README.md").is_file()
    assert (plugin_root / "skills" / "securedact-enforced" / "SKILL.md").is_file()
    configured = hooks["hooks"]
    assert set(configured) == {
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "SessionEnd",
    }
    session_start = configured["SessionStart"][0]["hooks"][0]
    prompt = configured["UserPromptSubmit"][0]["hooks"][0]
    session_end = configured["SessionEnd"][0]["hooks"][0]
    tool = configured["PreToolUse"][0]["hooks"][0]
    post_tool = configured["PostToolUse"][0]["hooks"][0]
    for command in (session_start, prompt, session_end, tool, post_tool):
        assert "C:\\Users\\" not in json.dumps(command)
        assert ".." not in json.dumps(command)
    assert session_start["command"] == "python"
    assert session_start["args"] == [
        "-m",
        "securedact_enforced.claude_hook",
        "--event",
        "session-start",
    ]
    assert session_start["timeout"] == 120
    assert prompt["command"] == "python"
    assert prompt["args"] == [
        "-m",
        "securedact_enforced.claude_hook",
        "--event",
        "user-prompt-submit",
    ]
    assert prompt["timeout"] == 5
    assert session_end["command"] == "python"
    assert session_end["args"] == [
        "-m",
        "securedact_enforced.claude_hook",
        "--event",
        "session-end",
    ]
    assert tool["command"] == "python"
    assert tool["args"] == ["-m", "securedact_enforced.provider_hook"]
    assert post_tool["command"] == "python"
    assert post_tool["args"] == ["-m", "securedact_enforced.provider_hook"]
    scripts_directory = plugin_root / "scripts"
    assert not scripts_directory.exists() or not any(scripts_directory.iterdir())


def test_claude_marketplace_references_the_self_contained_plugin() -> None:
    marketplace = _read_json(ROOT / ".claude-plugin" / "marketplace.json")

    assert marketplace["name"] == "securedact"
    assert marketplace["owner"] == {
        "name": "SecuRedact",
        "url": "https://www.securedact.com",
    }
    assert marketplace["plugins"] == [
        {
            "name": "securedact-enforced",
            "source": "./integrations/claude-code-enforced/securedact-enforced",
            "displayName": "SecuRedact Enforced",
            "description": "Local privacy enforcement for Claude Code. Checks prompts before "
            "model processing and blocks or requires review when SecuRedact detects "
            "protected information.",
            "version": "0.4.0",
            "author": {"name": "SecuRedact", "url": "https://www.securedact.com"},
            "homepage": "https://github.com/GigantesHJI/securedact-mcp",
            "repository": "https://github.com/GigantesHJI/securedact-mcp",
            "license": "Apache-2.0",
            "keywords": ["privacy", "security", "pii", "gdpr", "redaction", "local-processing"],
            "category": "security",
            "tags": ["privacy", "security", "pii", "gdpr", "redaction", "local-processing"],
        }
    ]


def test_packaged_setup_resources_match_provider_integration_behavior() -> None:
    packaged = resources.files("securedact_mcp.setup_assets")
    assert json.loads(
        packaged.joinpath("claude/.claude-plugin/marketplace.json").read_text(encoding="utf-8")
    ) == _read_json(ROOT / ".claude-plugin" / "marketplace.json")
    claude_packaged = packaged.joinpath(
        "claude/integrations/claude-code-enforced/securedact-enforced"
    )
    claude_source = ROOT / "integrations" / "claude-code-enforced" / "securedact-enforced"
    gemini_packaged = packaged.joinpath("gemini")
    gemini_source = ROOT / "integrations" / "gemini-enforced" / "securedact-enforced"

    for relative in (".claude-plugin/plugin.json", "hooks/hooks.json"):
        assert json.loads(
            claude_packaged.joinpath(relative).read_text(encoding="utf-8")
        ) == _read_json(claude_source / relative)
    assert claude_packaged.joinpath("skills/securedact-enforced/SKILL.md").read_text(
        encoding="utf-8"
    ) == (claude_source / "skills" / "securedact-enforced" / "SKILL.md").read_text(encoding="utf-8")
    for relative in ("gemini-extension.json", "hooks/hooks.json"):
        assert json.loads(
            gemini_packaged.joinpath(relative).read_text(encoding="utf-8")
        ) == _read_json(gemini_source / relative)


def test_root_gemini_extension_is_gallery_installable() -> None:
    root_manifest = _read_json(ROOT / "gemini-extension.json")
    root_hooks = _read_json(ROOT / "hooks" / "hooks.json")["hooks"]
    integration_manifest = _read_json(
        ROOT / "integrations" / "gemini-enforced" / "securedact-enforced" / "gemini-extension.json"
    )
    integration_hooks = _read_json(
        ROOT / "integrations" / "gemini-enforced" / "securedact-enforced" / "hooks" / "hooks.json"
    )["hooks"]
    packaged = resources.files("securedact_mcp.setup_assets").joinpath("gemini")
    packaged_manifest = json.loads(
        packaged.joinpath("gemini-extension.json").read_text(encoding="utf-8")
    )
    packaged_hooks = json.loads(packaged.joinpath("hooks/hooks.json").read_text(encoding="utf-8"))[
        "hooks"
    ]

    assert set(root_manifest) == {"name", "version", "description"}
    assert root_manifest["name"] == GEMINI_EXTENSION_NAME
    assert re.fullmatch(r"^[a-zA-Z0-9-]+$", str(root_manifest["name"])) is not None
    assert root_manifest["version"] == GEMINI_EXTENSION_VERSION
    assert str(root_manifest["description"]).strip() != ""

    assert root_manifest == integration_manifest == packaged_manifest
    assert root_hooks == integration_hooks == packaged_hooks

    assert set(root_hooks) == GEMINI_HOOK_EVENTS
    for hooks in root_hooks.values():
        command = hooks[0]["hooks"][0]["command"]
        assert command.startswith("python -m securedact_enforced.gemini_hook")
    for event in ("BeforeAgent", "BeforeModel", "BeforeTool"):
        assert root_hooks[event][0]["hooks"][0]["timeout"] == GEMINI_INTERCEPTION_TIMEOUT_MS


def test_claude_plugin_and_marketplace_metadata_is_complete() -> None:
    plugin = _read_json(
        ROOT
        / "integrations"
        / "claude-code-enforced"
        / "securedact-enforced"
        / ".claude-plugin"
        / "plugin.json"
    )
    marketplace = _read_json(ROOT / ".claude-plugin" / "marketplace.json")
    plugin_entry = marketplace["plugins"][0]
    plugin_root = ROOT / "integrations" / "claude-code-enforced" / "securedact-enforced"

    assert plugin["name"] == "securedact-enforced"
    assert plugin["version"] == "0.4.0"
    assert plugin["homepage"] == "https://github.com/GigantesHJI/securedact-mcp"
    assert plugin["repository"] == "https://github.com/GigantesHJI/securedact-mcp"
    assert plugin["author"]["url"] == "https://www.securedact.com"
    assert (plugin_root / ".claude-plugin" / "plugin.json").is_file()
    assert (plugin_root / "hooks" / "hooks.json").is_file()
    assert (plugin_root / "skills" / "securedact-enforced" / "SKILL.md").is_file()

    assert marketplace["name"] == "securedact"
    assert marketplace["owner"]["name"] == "SecuRedact"
    assert marketplace["owner"]["url"] == "https://www.securedact.com"
    assert plugin_entry["source"] == "./integrations/claude-code-enforced/securedact-enforced"
    assert (ROOT / plugin_entry["source"]).is_dir()
    assert plugin_entry["version"] == plugin["version"]
    assert plugin_entry["author"]["url"] == "https://www.securedact.com"

    hook_text = (plugin_root / "hooks" / "hooks.json").read_text(encoding="utf-8")
    assert "src/" not in hook_text
    assert "C:\\Users\\" not in hook_text
    assert ".." not in hook_text
