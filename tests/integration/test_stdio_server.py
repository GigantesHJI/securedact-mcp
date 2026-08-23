from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@pytest.mark.asyncio
async def test_stdio_startup_tool_registration_and_synthetic_redaction(
    tmp_path: Path,
) -> None:
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONUTF8": "1",
            "SECUREDACT_APP_DATA_DIR": str(tmp_path / "app-data"),
            "SECUREDACT_REQUIRE_FLAIR": "0",
        }
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "securedact_mcp"],
        env=environment,
    )

    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert {tool.name for tool in tools.tools} == {
                "prepare_for_external_ai",
                "analyze_text",
                "redact_text",
                "restore_text",
                "create_safe_copy",
                "securedact_read_file",
            }

            result = await session.call_tool(
                "prepare_for_external_ai",
                {
                    "text": "Contact alex.example@example.test",
                    "policy": "strict_external_ai",
                },
            )

    assert result.isError is False
    assert result.structuredContent is not None
    assert result.structuredContent["status"] == "ok"
    assert result.structuredContent["sanitized_text"] == "Contact [EMAIL_1]"
    assert "alex.example@example.test" not in result.structuredContent["sanitized_text"]


@pytest.mark.asyncio
async def test_stdio_securedact_read_file_sanitizes_and_blocks(tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONUTF8": "1",
            "SECUREDACT_APP_DATA_DIR": str(tmp_path / "app-data"),
            "SECUREDACT_REQUIRE_FLAIR": "0",
        }
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "securedact_mcp"],
        env=environment,
    )

    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            doc = tmp_path / "doc.txt"
            doc.write_text("Contact alex.example@example.test", encoding="utf-8")
            read = await session.call_tool(
                "securedact_read_file", {"path": str(doc), "policy": "strict_external_ai"}
            )
            assert read.isError is False
            assert read.structuredContent is not None
            assert read.structuredContent["status"] == "ok"
            assert "[EMAIL" in read.structuredContent["sanitized_text"]

            secret = tmp_path / ".env"
            secret.write_text("TOKEN=abc", encoding="utf-8")
            blocked = await session.call_tool(
                "securedact_read_file", {"path": str(secret), "policy": "strict_external_ai"}
            )
            assert blocked.isError is False
            assert blocked.structuredContent is not None
            assert blocked.structuredContent["status"] == "blocked"
