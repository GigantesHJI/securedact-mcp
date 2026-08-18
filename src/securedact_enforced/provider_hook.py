"""stdin/stdout command hooks for Codex and Claude Code.

No raw hook input is logged, printed to stderr, or placed in provider-visible
reasons. This module is intentionally small: privacy policy remains in
``securedact_core``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Mapping
from typing import Literal

from .adapter import EnforcementOutcome, PrivacyEnforcer
from .provider_messages import FAIL_CLOSED, PROMPT_BLOCK, REVIEW_BLOCK, TOOL_BLOCK, prompt_block

Provider = Literal["codex", "claude"]


def is_protected_outbound_tool(provider: Provider, tool_name: str) -> bool:
    """Only intercept provider tool paths that are plausibly external."""

    if tool_name.startswith("mcp__"):
        return True
    return provider == "claude" and tool_name in {"WebFetch", "WebSearch"}


def _prompt_block(provider: Provider, reason: str) -> dict[str, object]:
    return prompt_block(provider, reason)


def _tool_deny(provider: Provider, reason: str) -> dict[str, object]:
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


def handle_event(
    provider: Provider,
    event: object,
    *,
    enforcer_factory: Callable[[], PrivacyEnforcer] = PrivacyEnforcer.from_environment,
    diagnostic_observer: Callable[[EnforcementOutcome], None] | None = None,
) -> dict[str, object] | None:
    """Return the exact provider hook JSON, or ``None`` to leave an action alone."""

    if not isinstance(event, Mapping):
        _report_outcome(diagnostic_observer, EnforcementOutcome.INTERNAL_FAILURE)
        return _prompt_block(provider, FAIL_CLOSED)
    event_name = event.get("hook_event_name")
    if event_name == "UserPromptSubmit":
        prompt = event.get("prompt")
        if not isinstance(prompt, str):
            _report_outcome(diagnostic_observer, EnforcementOutcome.INTERNAL_FAILURE)
            return _prompt_block(provider, FAIL_CLOSED)
        outcome = enforcer_factory().inspect_text(prompt).outcome
        _report_outcome(diagnostic_observer, outcome)
        if outcome == EnforcementOutcome.ALLOW:
            return None
        if outcome == EnforcementOutcome.REVIEW_REQUIRED:
            return _prompt_block(provider, REVIEW_BLOCK)
        if outcome == EnforcementOutcome.INTERNAL_FAILURE:
            return _prompt_block(provider, FAIL_CLOSED)
        # Neither provider currently offers UserPromptSubmit rewriting. Block
        # instead of pretending that the sanitized text replaced the prompt.
        return _prompt_block(provider, PROMPT_BLOCK)

    if event_name != "PreToolUse":
        # This executable is registered only for policy-gating events. An
        # unknown event is malformed configuration/input, not a reason to
        # silently fail open.
        return _prompt_block(provider, FAIL_CLOSED)
    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str):
        return _tool_deny(provider, FAIL_CLOSED)
    if not is_protected_outbound_tool(provider, tool_name):
        return None
    if "tool_input" not in event:
        return _tool_deny(provider, FAIL_CLOSED)
    result, sanitized_payload = enforcer_factory().inspect_payload(event["tool_input"])
    if result.outcome == EnforcementOutcome.ALLOW:
        return None
    if result.outcome == EnforcementOutcome.SANITIZED and sanitized_payload is not None:
        return _tool_allow_with_input(sanitized_payload)
    if result.outcome == EnforcementOutcome.REVIEW_REQUIRED:
        return _tool_deny(provider, REVIEW_BLOCK)
    if result.outcome == EnforcementOutcome.INTERNAL_FAILURE:
        return _tool_deny(provider, FAIL_CLOSED)
    return _tool_deny(provider, TOOL_BLOCK)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecuRedact deterministic provider hook")
    parser.add_argument("--provider", choices=("codex", "claude"), required=True)
    args = parser.parse_args(argv)
    try:
        event = json.load(sys.stdin)
        output = handle_event(args.provider, event)
    except Exception:
        output = _prompt_block(args.provider, FAIL_CLOSED)
    if output is not None:
        sys.stdout.write(json.dumps(output, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
