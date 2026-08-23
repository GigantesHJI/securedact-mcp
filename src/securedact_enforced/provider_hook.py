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

from securedact_core.audit import (
    AuditEventType,
    build_audit_event,
    emit_audit_event,
    is_secret_entity_type,
)
from securedact_core.firewall import (
    MAX_TOOL_RESULT_CHARS,
    DestinationScope,
    FirewallPolicy,
    ToolContext,
    ToolOperation,
    classify_destination_scope,
    classify_tool,
    egress_scan_payload,
    evaluate_firewall,
    load_firewall_policy_from_environment,
    recursive_text_length,
)

from . import claude_runtime
from .adapter import (
    EnforcementOutcome,
    EnforcementResult,
    PrivacyEnforcer,
    ToolResultInspection,
    firewall_decision_outcome,
    inspect_tool_result,
)
from .provider_messages import (
    EGRESS_APPROVAL,
    EGRESS_BLOCKED,
    EGRESS_OVERSIZE,
    FAIL_CLOSED,
    PROMPT_BLOCK,
    RESULT_BLOCKED,
    RESULT_OVERSIZE,
    REVIEW_BLOCK,
    TOOL_BLOCK,
    prompt_block,
)

_NATIVE_FILESYSTEM_TOOLS = {
    "Read",
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
    "Bash",
    "Grep",
    "Glob",
}


def is_protected_outbound_tool(tool_name: str, *, firewall_enabled: bool = False) -> bool:
    """Intercept Claude tools that leave the local trust boundary.

    Native filesystem/shell tools are only intercepted when the firewall is
    enabled, so a host without firewall configuration keeps legacy behavior.
    """

    if tool_name.startswith("mcp__"):
        return True
    if tool_name in {"WebFetch", "WebSearch"}:
        return True
    return firewall_enabled and tool_name in _NATIVE_FILESYSTEM_TOOLS


def _requires_content_inspection(context: ToolOperation, tool_name: str) -> bool:
    """Decide whether the tool input still needs content-based inspection."""

    if context == ToolOperation.UNKNOWN:
        # Classification failed: never skip inspection. An unrecognized tool is
        # at least content-inspected so PII/secrets in its input are not silently
        # allowed through; if the runtime is unavailable it fails closed.
        return True
    if context in {ToolOperation.FILE_READ, ToolOperation.FILE_WRITE}:
        # Path policy is the relevant check; the path string is not content.
        return False
    if context in {
        ToolOperation.SHELL_EXEC,
        ToolOperation.NETWORK_READ,
        ToolOperation.NETWORK_WRITE,
        ToolOperation.DATABASE_READ,
        ToolOperation.DATABASE_WRITE,
        ToolOperation.MCP_CALL,
    }:
        return True
    lowered = tool_name.lower()
    if lowered.startswith("mcp_"):
        return True
    if lowered in {"webfetch", "websearch"}:
        return True
    return any(
        marker in lowered
        for marker in ("http", "web", "search", "fetch", "request", "api", "connect")
    )


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


def _emit_tool_audit(
    outcome: EnforcementOutcome,
    *,
    provider: str,
    tool_name: str | None,
    operation: ToolOperation | None,
    decision: object = None,
) -> None:
    """Best-effort, privacy-preserving firewall audit (FW-033).

    Never raises; a failure here must not change or weaken the host decision.
    """

    try:
        if outcome == EnforcementOutcome.BLOCKED:
            event_type = AuditEventType.TOOL_BLOCKED
            action = "block"
        elif outcome == EnforcementOutcome.REVIEW_REQUIRED:
            event_type = AuditEventType.APPROVAL_REQUIRED
            action = "review"
        else:
            return
        reason = getattr(decision, "reason", None)
        emit_audit_event(
            build_audit_event(
                event_type,
                action=action,
                reason_code=reason or "tool_blocked",
                provider=provider,
                tool_name=tool_name,
                operation=str(operation) if operation is not None else None,
            )
        )
    except Exception:
        return


def _emit_egress_audit(
    *,
    provider: str,
    tool_name: str | None,
    operation: ToolOperation | None,
    destination: str | None,
) -> None:
    """Best-effort, metadata-only EGRESS_BLOCKED audit for a blocked network write.

    Never raises; audit failure must not change or weaken the host decision. The
    destination is the normalized host only (no raw body/headers/credentials).
    """

    try:
        emit_audit_event(
            build_audit_event(
                AuditEventType.EGRESS_BLOCKED,
                action="block",
                reason_code="egress_blocked",
                provider=provider,
                tool_name=tool_name,
                operation=str(operation) if operation is not None else None,
                destination=destination,
            )
        )
    except Exception:
        return


def _inspect_egress(
    event: Mapping[str, object],
    context: ToolContext,
    *,
    provider: str = "claude",
    policy: FirewallPolicy | None = None,
) -> dict[str, object] | None:
    """Inspect an outbound NETWORK_WRITE tool call (FW-030).

    Reuses the warmed-runtime content scanner. A secret in the outbound payload
    is blocked; an external/unknown destination with merely-redacted PII may be
    upgraded to REQUIRE_APPROVAL when the policy opts in. Oversize or unscannable
    payloads fail closed. No raw request body/header/credential reaches the host.
    """

    destination = context.destination
    if recursive_text_length(event.get("tool_input")) > MAX_TOOL_RESULT_CHARS:
        _emit_egress_audit(
            provider=provider,
            tool_name=context.tool_name,
            operation=context.operation,
            destination=destination,
        )
        return _tool_deny(EGRESS_OVERSIZE)

    scan_event = {**event, "tool_input": egress_scan_payload(event.get("tool_input"))}
    try:
        inspected = _inspect_tool_input(scan_event)
    except Exception:
        # Scanner/client failure must fail closed, never allow unverified egress.
        inspected = None
    if inspected is None:
        # No session to reach the warmed runtime: fail closed.
        _emit_egress_audit(
            provider=provider,
            tool_name=context.tool_name,
            operation=context.operation,
            destination=destination,
        )
        return _tool_deny(FAIL_CLOSED)

    result, sanitized = inspected

    if (
        policy is not None
        and policy.egress_external_require_approval
        and result.outcome == EnforcementOutcome.SANITIZED
    ):
        # Always recompute scope with the policy allowlist; the precomputed
        # context scope intentionally ignores the allowlist for general use.
        scope = classify_destination_scope(
            destination, allowlist_domains=policy.egress_allowlist_domains
        )
        if scope in {DestinationScope.EXTERNAL, DestinationScope.UNKNOWN}:
            _emit_tool_audit(
                EnforcementOutcome.REVIEW_REQUIRED,
                provider=provider,
                tool_name=context.tool_name,
                operation=context.operation,
            )
            return _tool_deny(EGRESS_APPROVAL)

    if result.outcome == EnforcementOutcome.BLOCKED:
        _emit_egress_audit(
            provider=provider,
            tool_name=context.tool_name,
            operation=context.operation,
            destination=destination,
        )
        return _tool_deny(EGRESS_BLOCKED)
    if result.outcome == EnforcementOutcome.REVIEW_REQUIRED:
        _emit_tool_audit(
            EnforcementOutcome.REVIEW_REQUIRED,
            provider=provider,
            tool_name=context.tool_name,
            operation=context.operation,
        )
        return _tool_deny(EGRESS_APPROVAL)
    if result.outcome == EnforcementOutcome.INTERNAL_FAILURE:
        _emit_egress_audit(
            provider=provider,
            tool_name=context.tool_name,
            operation=context.operation,
            destination=destination,
        )
        return _tool_deny(FAIL_CLOSED)
    return _apply_inspection_result(
        result,
        sanitized,
        provider=provider,
        tool_name=context.tool_name,
        operation=context.operation,
    )


def _apply_inspection_result(
    result: EnforcementResult,
    sanitized_payload: object | None,
    *,
    provider: str = "claude",
    tool_name: str | None = None,
    operation: ToolOperation | None = None,
) -> dict[str, object] | None:
    """Translate a warmed-runtime inspection into the Claude hook response."""

    if result.outcome == EnforcementOutcome.ALLOW:
        return None
    if result.outcome == EnforcementOutcome.SANITIZED and sanitized_payload is not None:
        return _tool_allow_with_input(sanitized_payload)
    if result.outcome == EnforcementOutcome.REVIEW_REQUIRED:
        _emit_tool_audit(
            EnforcementOutcome.REVIEW_REQUIRED,
            provider=provider,
            tool_name=tool_name,
            operation=operation,
        )
        return _tool_deny(REVIEW_BLOCK)
    if result.outcome == EnforcementOutcome.INTERNAL_FAILURE:
        return _tool_deny(FAIL_CLOSED)
    _emit_tool_audit(
        EnforcementOutcome.BLOCKED,
        provider=provider,
        tool_name=tool_name,
        operation=operation,
    )
    return _tool_deny(TOOL_BLOCK)


# IPC budget for result inspection (FW-020). Bounded below the Claude PostToolUse
# hook timeout so a slow scan fails closed rather than hanging the agent loop.
_RESULT_IPC_TIMEOUT_SECONDS = claude_runtime._RESULT_IPC_TIMEOUT_SECONDS


def _extract_tool_result(event: Mapping[str, object]) -> object:
    """Pick the model-bound tool result payload from a PostToolUse event.

    Claude exposes both a structured ``tool_response`` (preferred, so shape is
    preserved) and a flat ``tool_output`` string. Either may be absent.
    """

    response = event.get("tool_response")
    if isinstance(response, (str, Mapping, list)):
        return response
    return event.get("tool_output")


def _build_result_inspector(
    session_id: object,
) -> Callable[
    [object], tuple[EnforcementOutcome, object | None, tuple[str, ...] | None, str | None]
]:
    """Return a daemon-backed inspector callable for ``inspect_tool_result``."""

    def inspect(
        result: object,
    ) -> tuple[EnforcementOutcome, object | None, tuple[str, ...] | None, str | None]:
        outcome, sanitized, entities, reason_code, _stage = claude_runtime.inspect_tool_result(
            session_id, result, timeout_seconds=_RESULT_IPC_TIMEOUT_SECONDS
        )
        return outcome, sanitized, entities, reason_code

    return inspect


def _emit_result_audit(
    inspection: ToolResultInspection,
    *,
    provider: str,
    tool_name: str | None,
    operation: ToolOperation | None,
) -> None:
    """Best-effort, metadata-only audit for a sanitized/hidden tool result (FW-033)."""

    try:
        entities = inspection.entities or ()
        secret_entities = tuple(e for e in entities if is_secret_entity_type(e))
        action = (
            "block"
            if inspection.action
            in {EnforcementOutcome.BLOCKED, EnforcementOutcome.INTERNAL_FAILURE}
            else "redact"
        )
        if secret_entities:
            event_type = AuditEventType.SECRET_DETECTED
        elif entities:
            event_type = AuditEventType.PII_REDACTED
        else:
            event_type = AuditEventType.TOOL_BLOCKED
        emit_audit_event(
            build_audit_event(
                event_type,
                action=action,
                reason_code=inspection.reason_code or "tool_result_sanitized",
                provider=provider,
                tool_name=tool_name,
                operation=str(operation) if operation is not None else None,
                entity_types=entities,
            )
        )
    except Exception:
        return


def _apply_result_inspection(
    inspection: ToolResultInspection,
    *,
    provider: str,
    tool_name: str | None,
    operation: ToolOperation | None,
) -> dict[str, object] | None:
    """Translate a tool-result inspection into a Claude PostToolUse response."""

    if inspection.action == EnforcementOutcome.ALLOW:
        return None
    if inspection.action == EnforcementOutcome.SANITIZED:
        _emit_result_audit(inspection, provider=provider, tool_name=tool_name, operation=operation)
        return {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": inspection.sanitized_result,
            }
        }
    # BLOCKED / REVIEW_REQUIRED / INTERNAL_FAILURE: the raw result must not reach
    # the model. Replace it with a safe non-sensitive explanation rather than
    # leaving it in place or merely blocking (which could still surface it).
    reason = RESULT_OVERSIZE if inspection.reason_code == "result_oversize" else RESULT_BLOCKED
    _emit_result_audit(inspection, provider=provider, tool_name=tool_name, operation=operation)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": reason,
        }
    }


def _inspect_or_deny(
    event: Mapping[str, object], *, context: ToolOperation | None = None
) -> dict[str, object] | None:
    try:
        inspected = _inspect_tool_input(event)
    except Exception:
        inspected = None
    if inspected is None:
        return _tool_deny(FAIL_CLOSED)
    tool_name = event.get("tool_name") if isinstance(event, Mapping) else None
    tool_name = tool_name if isinstance(tool_name, str) else None
    return _apply_inspection_result(
        *inspected, provider="claude", tool_name=tool_name, operation=context
    )


def handle_event(
    event: object,
    *,
    enforcer_factory: Callable[[], PrivacyEnforcer] = PrivacyEnforcer.from_environment,
    diagnostic_observer: Callable[[EnforcementOutcome], None] | None = None,
    firewall_policy: FirewallPolicy | None = None,
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

    if event_name == "PostToolUse":
        # FW-020: sanitize tool results before the model sees them. Claude
        # supports result replacement via ``updatedToolOutput`` for all tools.
        firewall = (
            firewall_policy
            if firewall_policy is not None
            else load_firewall_policy_from_environment()
        )
        if firewall is None or not firewall.enabled:
            return None
        session_id = event.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            # Without a session the warmed runtime is unreachable; fail closed
            # by hiding the raw result behind a safe replacement.
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedToolOutput": RESULT_BLOCKED,
                }
            }
        tool_name = event.get("tool_name")
        tool_name = tool_name if isinstance(tool_name, str) else None
        result = _extract_tool_result(event)
        if result is None:
            return None
        operation = (
            classify_tool("claude", tool_name or "", event.get("tool_input") or {}).operation
            if tool_name
            else None
        )
        inspection = inspect_tool_result(
            _build_result_inspector(session_id),
            provider="claude",
            tool_name=tool_name,
            operation=operation,
            result=result,
        )
        return _apply_result_inspection(
            inspection, provider="claude", tool_name=tool_name, operation=operation
        )

    if event_name != "PreToolUse":
        # This executable is registered only for policy-gating events. An
        # unknown event is malformed configuration/input, not a reason to
        # silently fail open.
        return _prompt_block(FAIL_CLOSED)
    tool_name = event.get("tool_name")
    if not isinstance(tool_name, str):
        return _tool_deny(FAIL_CLOSED)
    if "tool_input" not in event:
        return _tool_deny(FAIL_CLOSED)
    tool_input = event["tool_input"]
    if not isinstance(tool_input, dict):
        return _tool_deny(FAIL_CLOSED)

    context = classify_tool("claude", tool_name, tool_input)
    firewall = (
        firewall_policy if firewall_policy is not None else load_firewall_policy_from_environment()
    )
    if firewall is not None and firewall.enabled:
        if context.operation != ToolOperation.UNKNOWN:
            decision = evaluate_firewall(firewall, context)
            outcome = firewall_decision_outcome(decision)
            if outcome == EnforcementOutcome.BLOCKED:
                if context.operation == ToolOperation.NETWORK_WRITE:
                    _emit_egress_audit(
                        provider="claude",
                        tool_name=tool_name,
                        operation=context.operation,
                        destination=context.destination,
                    )
                else:
                    _emit_tool_audit(
                        EnforcementOutcome.BLOCKED,
                        provider="claude",
                        tool_name=tool_name,
                        operation=context.operation,
                        decision=decision,
                    )
                return _tool_deny(decision.reason or FAIL_CLOSED)
            if outcome == EnforcementOutcome.REVIEW_REQUIRED:
                _emit_tool_audit(
                    EnforcementOutcome.REVIEW_REQUIRED,
                    provider="claude",
                    tool_name=tool_name,
                    operation=context.operation,
                    decision=decision,
                )
                return _tool_deny(decision.reason or REVIEW_BLOCK)
        if not _requires_content_inspection(context.operation, tool_name):
            return None
        if context.operation == ToolOperation.NETWORK_WRITE:
            return _inspect_egress(event, context, provider="claude", policy=firewall)
        return _inspect_or_deny(event, context=context.operation)

    if not is_protected_outbound_tool(tool_name):
        return None
    if context.operation == ToolOperation.NETWORK_WRITE:
        return _inspect_egress(event, context, provider="claude", policy=firewall)
    return _inspect_or_deny(event, context=context.operation)


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
