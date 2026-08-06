# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def _run(command: Path, module: str | None = None) -> None:
    environment = dict(os.environ)
    environment["SECUREDACT_REQUIRE_FLAIR"] = "0"
    parameters = StdioServerParameters(
        command=str(command),
        args=["-m", module] if module is not None else [],
        env=environment,
    )
    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = {tool.name for tool in tools.tools}
            if "prepare_for_external_ai" not in names:
                raise RuntimeError("high_level_tool_missing")
            response = await session.call_tool(
                "prepare_for_external_ai",
                {"text": "Contact alex.release@example.test"},
            )
            payload = response.structuredContent or {}
            if (
                payload.get("status") != "ok"
                or payload.get("sanitized_text") != "Contact [EMAIL_1]"
            ):
                raise RuntimeError("high_level_tool_smoke_failed")
            if "alex.release@example.test" in str(payload) or "mapping" in payload:
                raise RuntimeError("minimal_response_leak")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", type=Path)
    parser.add_argument("--module")
    arguments = parser.parse_args(argv)
    try:
        asyncio.run(_run(arguments.command.resolve(), arguments.module))
    except (OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
