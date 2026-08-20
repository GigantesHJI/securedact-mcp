"""stdin/stdout Claude Code command hook for outbound tool calls.

The ``PreToolUse`` hook asks the warmed per-session SecuRedact runtime over the
authenticated loopback protocol instead of building a model runtime per call.
No raw hook input is logged, printed to stderr, or placed in provider-visible
reasons. This module is intentionally small: privacy policy remains in
``securedact_core``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Mapping

from . import claude_runtime
from .adapter import EnforcementOutcome, EnforcementResult, PrivacyEnforcer
from .provider_messages import FAIL_CLOSED, PROMPT_BLOCK, REVIEW_BLOCK, TOOL_BLOCK, prompt_block


def is_protected_outbound_tool(tool_name: str) -> bool:
    """Only intercept Claude tool paths that are plausibly external."""

    if tool_name.startswith("mcp__"):
        return True
    return tool_name in {"WebFetch", "WebSearch"}


class _DaemonBackedEnforcer:
    """Warmed-runtime adapter so ``PreToolUse`` never rebuilds SecuRedact."""

    def __init__(self, session_id: object) -> None:
        self._session_id = session_id

    def inspect_payload(self, payload: object) -> tuple[EnforcementResult, object | None]:
        try:
            outcome, sanitized_payload = claude_runtime.inspect_payload(self._session_id, payload)
            parsed_outcome = EnforcementOutcome(outcome)
        except (TypeError, ValueError):
            return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE), None
        return EnforcementResult(outcome=parsed_outcome), sanitized_payload


def _prompt_block(reason: str) -> dict[str, object]:
    return prompt_block(reason)


def _tool_deny(reason: str) -> dict[str, object]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _tool_allow_with_input(payload: object) -> dict[str, object]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": payload,
        }
    }


def _report_outcome(
    observer: Callable[[EnforcementOutcome], None] | None, outcome: EnforcementOutcome
) -> None:
    """Best-effort metadata callback that cannot change the privacy decision."""

    if observer is None:
        return
    try:
        observer(outcome)
    except Exception:
        return


def _inspect_tool_input(
    event: Mapping[str, object],
) -> tuple[EnforcementResult, object | None] | None:
    """Ask the warmed runtime, or ``None`` to signal a fail-closed deny.

    A ``PreToolUse`` event without a valid ``session_id`` cannot be sent to the
    per-session daemon. Any other path would rebuild SecuRedact per call, so it
    is deliberately not supported: the caller must fail closed.
    """

    session_id = event.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        return None
    return _DaemonBackedEnforcer(session_id).inspect_payload(event["tool_input"])


def handle_event(
    event: object,
    *,
    enforcer_factory: Callable[[], PrivacyEnforcer] = PrivacyEnforcer.from_environment,
    diagnostic_observer: Callable[[EnforcementOutcome], None] | None = None,
) -> dict[str, object] | None:
    """Return the exact Claude hook JSON, or ``None`` to leave an action alone."""

    if not isinstance(event, Mapping):
        _report_outcome(diagnostic_observer, EnforcementOutcome.INTERNAL_FAILURE)
        return _prompt_block(FAIL_CLOSED)
    event_name = event.get("hook_event_name")
    if event_name == "UserPromptSubmit":
        prompt = event.get("prompt")
        if not isinstance(prompt, str):
            _report_outcome(diagnostic_observer, EnforcementOutcome.INTERNAL_FAILURE)
            return _prompt_block(FAIL_CLOSED)
        outcome = enforcer_factory().inspect_text(prompt).outcome
        _report_outcome(diagnostic_observer, outcome)
        if outcome == EnforcementOutcome.ALLOW:
            return None
        if outcome == EnforcementOutcome.REVIEW_REQUIRED:
            return _prompt_block(REVIEW_BLOCK)
        if outcome == EnforcementOutcome.INTERNAL_FAILURE:
            return _prompt_block(FAIL_CLOSED)
        # Claude does not currently offer UserPromptSubmit rewriting. Block
        # instead of pretending that the sanitized text replaced the prompt.
        return _prompt_block(PROMPT_BLOCK)

    if event_name != "PreToolUse":
        # This executable is registered only for policy-gating events. An
        # unknown event is malformed configuration/input, not a reason to
        # silently fail open.
        return _prompt_block(FAIL_CLOSED)
    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str):
        return _tool_deny(FAIL_CLOSED)
    if not is_protected_outbound_tool(tool_name):
        return None
    if "tool_input" not in event:
        return _tool_deny(FAIL_CLOSED)
    try:
        inspected = _inspect_tool_input(event)
    except Exception:
        inspected = None
    if inspected is None:
        return _tool_deny(FAIL_CLOSED)
    result, sanitized_payload = inspected
    if result.outcome == EnforcementOutcome.ALLOW:
        return None
    if result.outcome == EnforcementOutcome.SANITIZED and sanitized_payload is not None:
        return _tool_allow_with_input(sanitized_payload)
    if result.outcome == EnforcementOutcome.REVIEW_REQUIRED:
        return _tool_deny(REVIEW_BLOCK)
    if result.outcome == EnforcementOutcome.INTERNAL_FAILURE:
        return _tool_deny(FAIL_CLOSED)
    return _tool_deny(TOOL_BLOCK)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecuRedact Claude Code pre-tool-use hook")
    parser.parse_args(argv)
    output: dict[str, object] | None
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, Mapping):
            output = _prompt_block(FAIL_CLOSED)
        else:
            output = handle_event(event)
    except Exception:
        output = _prompt_block(FAIL_CLOSED)
    if output is not None:
        sys.stdout.write(json.dumps(output, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
