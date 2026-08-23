"""Unit tests for host-tool -> ToolContext classification (FW-024)."""

from __future__ import annotations

from securedact_core import ToolContext, ToolOperation, classify_tool


def test_claude_native_filesystem_tools_classified() -> None:
    assert classify_tool("claude", "Read", {"file_path": "a/.env"}) == ToolContext(
        "claude", "Read", ToolOperation.FILE_READ, path="a/.env"
    )
    assert classify_tool("claude", "Write", {"file_path": "x.py"}) == ToolContext(
        "claude", "Write", ToolOperation.FILE_WRITE, path="x.py"
    )
    assert classify_tool("claude", "Edit", {"file_path": "x.py"}) == ToolContext(
        "claude", "Edit", ToolOperation.FILE_WRITE, path="x.py"
    )
    glob = classify_tool("claude", "Glob", {"pattern": "*.py", "path": "src"})
    assert glob.operation == ToolOperation.FILE_READ and glob.path == "src"
    grep = classify_tool("claude", "Grep", {"pattern": "secret", "path": "src"})
    assert grep.operation == ToolOperation.FILE_READ and grep.path == "src"


def test_claude_bash_captures_command_as_payload() -> None:
    bash = classify_tool("claude", "Bash", {"command": "curl https://example.test"})
    assert bash.operation == ToolOperation.SHELL_EXEC
    assert bash.path is None
    assert bash.payload == "curl https://example.test"


def test_mcp_filesystem_tool_classified_with_path() -> None:
    ctx = classify_tool("claude", "mcp__filesystem__read_file", {"path": "/vault/secret.env"})
    assert ctx.operation == ToolOperation.FILE_READ
    assert ctx.path == "/vault/secret.env"


def test_external_network_tool_classified_with_destination() -> None:
    ctx = classify_tool("claude", "mcp__http__post", {"url": "https://example.test/x"})
    assert ctx.operation == ToolOperation.NETWORK_WRITE
    assert ctx.destination == "https://example.test/x"


def test_unknown_tool_fails_closed_to_unknown_not_allow() -> None:
    ctx = classify_tool("claude", "ApplyPatch", {"text": "data"})
    assert ctx.operation == ToolOperation.UNKNOWN
    assert ctx.path is None


def test_empty_tool_name_yields_unknown() -> None:
    empty = classify_tool("claude", "", None)
    assert empty.operation == ToolOperation.UNKNOWN


def test_known_tool_with_non_dict_input_classifies_by_name() -> None:
    ctx = classify_tool("claude", "Read", "not-a-dict")
    assert ctx.operation == ToolOperation.FILE_READ
    assert ctx.path is None


def test_gemini_tool_names_classified_case_insensitively() -> None:
    assert classify_tool("gemini", "read", {"file_path": "a"}) == ToolContext(
        "gemini", "read", ToolOperation.FILE_READ, path="a"
    )
    bash = classify_tool("gemini", "Bash", {"command": "ls"})
    assert bash.operation == ToolOperation.SHELL_EXEC
