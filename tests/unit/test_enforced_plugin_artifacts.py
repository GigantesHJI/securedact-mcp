from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_codex_plugin_has_discoverable_manifest_and_portable_hooks() -> None:
    plugin_root = ROOT / "integrations" / "codex-enforced" / "securedact-enforced"
    manifest = _read_json(plugin_root / ".codex-plugin" / "plugin.json")
    hooks = _read_json(plugin_root / "hooks" / "hooks.json")

    assert manifest["name"] == "securedact-enforced"
    assert manifest["version"].startswith("0.1.0+codex.")
    assert manifest["hooks"] == "./hooks/hooks.json"
    assert (plugin_root / "skills" / "securedact-enforced" / "SKILL.md").is_file()
    assert (plugin_root / "scripts" / "user_prompt_submit.py").is_file()
    configured = hooks["hooks"]
    assert set(configured) == {"UserPromptSubmit", "PreToolUse"}
    prompt_command = configured["UserPromptSubmit"][0]["hooks"][0]
    assert prompt_command["command"] == 'python "$PLUGIN_ROOT/scripts/user_prompt_submit.py"'
    assert (
        prompt_command["commandWindows"] == 'python "%PLUGIN_ROOT%\\scripts\\user_prompt_submit.py"'
    )
    tool_command = configured["PreToolUse"][0]["hooks"][0]
    assert tool_command["command"] == "python -m securedact_enforced.provider_hook --provider codex"
    assert (
        tool_command["commandWindows"]
        == "python -m securedact_enforced.provider_hook --provider codex"
    )
    for command in (prompt_command, tool_command):
        assert "C:\\Users\\" not in command["command"]
        assert "C:\\Users\\" not in command["commandWindows"]
        assert "command_windows" not in command


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
    assert set(configured) == {"SessionStart", "UserPromptSubmit", "PreToolUse", "SessionEnd"}
    session_start = configured["SessionStart"][0]["hooks"][0]
    prompt = configured["UserPromptSubmit"][0]["hooks"][0]
    session_end = configured["SessionEnd"][0]["hooks"][0]
    tool = configured["PreToolUse"][0]["hooks"][0]
    for command in (session_start, prompt, session_end, tool):
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
    assert tool["args"] == ["-m", "securedact_enforced.provider_hook", "--provider", "claude"]
    scripts_directory = plugin_root / "scripts"
    assert not scripts_directory.exists() or not any(scripts_directory.iterdir())


def test_claude_marketplace_references_the_self_contained_plugin() -> None:
    marketplace = _read_json(ROOT / ".claude-plugin" / "marketplace.json")

    assert marketplace["name"] == "securedact"
    assert marketplace["owner"] == {
        "name": "SecuRedact",
        "url": "https://github.com/GigantesHJI/securedact-mcp",
    }
    assert marketplace["plugins"] == [
        {
            "name": "securedact-enforced",
            "source": "./integrations/claude-code-enforced/securedact-enforced",
            "displayName": "SecuRedact Enforced",
            "description": "Local privacy enforcement for Claude Code. Checks prompts before "
            "model processing and blocks or requires review when SecuRedact detects "
            "protected information.",
            "version": "0.1.6",
            "author": {"name": "SecuRedact"},
            "homepage": "https://github.com/GigantesHJI/securedact-mcp",
            "repository": "https://github.com/GigantesHJI/securedact-mcp",
            "license": "Apache-2.0",
            "keywords": ["privacy", "security", "pii", "gdpr", "redaction", "local-processing"],
            "category": "security",
            "tags": ["privacy", "security", "pii", "gdpr", "redaction", "local-processing"],
        }
    ]
