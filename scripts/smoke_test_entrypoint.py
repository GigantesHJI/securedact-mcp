"""Start the installed console entry point over stdio and verify its tool contract."""

from __future__ import annotations

import asyncio
import os
import shutil
import sysconfig
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

EXPECTED_TOOLS = {
    "prepare_for_external_ai",
    "analyze_text",
    "redact_text",
    "restore_text",
    "create_safe_copy",
}


async def smoke_test() -> None:
    command = os.getenv("SECUREDACT_ENTRYPOINT") or shutil.which("securedact-mcp")
    command_arguments = os.getenv("SECUREDACT_ENTRYPOINT_ARGS", "").split()
    if command is None:
        scripts_directory = Path(sysconfig.get_path("scripts"))
        candidates = (
            scripts_directory / "securedact-mcp.exe",
            scripts_directory / "securedact-mcp",
        )
        command = next((str(candidate) for candidate in candidates if candidate.is_file()), None)
    if command is None:
        raise RuntimeError("securedact-mcp console entry point is not installed")

    with tempfile.TemporaryDirectory(prefix="securedact-mcp-smoke-") as app_data:
        environment = dict(os.environ)
        environment.update(
            {
                "PYTHONUTF8": "1",
                "SECUREDACT_APP_DATA_DIR": str(Path(app_data) / "data"),
                "SECUREDACT_REQUIRE_FLAIR": "0",
            }
        )
        parameters = StdioServerParameters(
            command=command,
            args=command_arguments,
            env=environment,
        )
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                names = {tool.name for tool in tools.tools}
                if names != EXPECTED_TOOLS:
                    raise RuntimeError(f"unexpected MCP tools: {sorted(names)}")
                result = await session.call_tool(
                    "prepare_for_external_ai",
                    {
                        "text": "Contact alex.example@example.test",
                    },
                )
                content = result.structuredContent
                if result.isError or content is None:
                    raise RuntimeError("high-level preparation smoke call failed")
                if content.get("status") != "ok":
                    raise RuntimeError("high-level preparation did not approve output")
                if content.get("sanitized_text") != "Contact [EMAIL_1]":
                    raise RuntimeError("high-level preparation returned unexpected output")
                if "mapping" in content or "alex.example@example.test" in str(content):
                    raise RuntimeError("minimal response exposed sensitive content")


def main() -> int:
    asyncio.run(smoke_test())
    print("Installed console entry-point smoke test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
