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
