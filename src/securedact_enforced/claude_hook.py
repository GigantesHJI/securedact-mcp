"""Lightweight Claude Code hook client for the warmed local SecuRedact runtime."""

from __future__ import annotations

import argparse
import json
import sys
import time

from .claude_runtime import inspect_prompt, shutdown_runtime, start_runtime, write_hook_receipt
from .provider_messages import FAIL_CLOSED, prompt_block


def _read_event() -> object:
    try:
        return json.load(sys.stdin)
    except Exception:
        return None


def _emit(payload: dict[str, object] | None) -> None:
    if payload is not None:
        sys.stdout.write(json.dumps(payload, separators=(",", ":")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecuRedact Claude hook client")
    parser.add_argument(
        "--event", choices=("session-start", "user-prompt-submit", "session-end"), required=True
    )
    args = parser.parse_args(argv)
    event = _read_event()
    if not isinstance(event, dict):
        if args.event == "user-prompt-submit":
            _emit(prompt_block(FAIL_CLOSED))
        return 0
    session_id = event.get("session_id")
    started = time.monotonic()
    if args.event == "session-start":
        result = start_runtime(session_id)
        write_hook_receipt(
            "SessionStart",
            session_id,
            decision="ready" if result.ready else "warming" if result.started else "unavailable",
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
        return 0
    if args.event == "session-end":
        stopped = shutdown_runtime(session_id)
        write_hook_receipt(
            "SessionEnd",
            session_id,
            decision="stopped" if stopped else "unavailable",
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
        return 0
    decision = inspect_prompt(session_id, event.get("prompt"))
    write_hook_receipt(
        "UserPromptSubmit",
        session_id,
        decision="allow" if decision is None else "block",
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )
    _emit(decision)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
