"""Gemini CLI hook adapter over the shared warmed SecuRedact runtime.

All policy outcomes use Gemini's structured JSON response with exit status 0;
Gemini treats other nonzero statuses as warnings, so they are never an
enforcement mechanism here.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path

from securedact_core import PolicyRegistry, PrepareOutcome
from securedact_core.audit import (
    AuditEventType,
    build_audit_event,
    emit_audit_event,
    is_secret_entity_type,
)
from securedact_core.firewall import (
    MAX_TOOL_RESULT_CHARS,
    DestinationScope,
    ToolContext,
    ToolOperation,
    classify_destination_scope,
    classify_tool,
    egress_scan_payload,
    evaluate_firewall,
    load_firewall_policy_from_environment,
    recursive_text_length,
)
from securedact_core.models import PrivacyAction
from securedact_core.safe_read import SafeReadError, resolve_safe_path

from . import claude_runtime
from .adapter import (
    EnforcementOutcome,
    firewall_decision_outcome,
)
from .claude_runtime import (
    ensure_runtime,
    inspect_payload_with_prepare_outcome_stage,
    inspect_text_outcome_with_stage,
    runtime_diagnostics,
    runtime_is_warming,
    shutdown_runtime,
    start_runtime,
    write_hook_receipt,
)
from .provider_messages import (
    EGRESS_OVERSIZE,
    FAIL_CLOSED,
    PROMPT_BLOCK,
    PROMPT_RUNTIME_BLOCKED,
    RESULT_BLOCKED,
    RESULT_OVERSIZE,
    REVIEW_BLOCK,
    TOOL_BLOCK,
)

_SCOPE = "gemini"
# A warmed BeforeAgent request contains just the user text, while BeforeModel
# and BeforeTool can contain a larger structured payload.  Both remain below
# Gemini's configured 20-second hook budget and fail closed on expiry.
_PROMPT_IPC_TIMEOUT_SECONDS = 2.0
_PAYLOAD_IPC_TIMEOUT_SECONDS = 18.0
# Budget the hook may spend bringing the local runtime online for a prompt/model
# stage when SessionStart did not leave a live daemon. The Gemini BeforeAgent/
# BeforeModel hook command itself has a 20s budget, so this stays comfortably
# inside it while giving the daemon time to load the contextual model.
_PROMPT_RUNTIME_START_TIMEOUT_SECONDS = 5.0
_INITIALIZING = "SecuRedact is still initializing; this content was not sent."
_INSPECTION_STAGE: ContextVar[str] = ContextVar("gemini_inspection_stage", default="not_invoked")
_PREPARE_OUTCOME: ContextVar[str | None] = ContextVar("gemini_prepare_outcome", default=None)
_GUIDANCE_INJECTED: ContextVar[bool] = ContextVar("gemini_guidance_injected", default=False)
_TOKEN_CATEGORIES: ContextVar[tuple[str, ...]] = ContextVar("gemini_token_categories", default=())
_GUIDANCE_MARKER = "<securedact-pseudonym-token-guidance>"
_GUIDANCE_END_MARKER = "</securedact-pseudonym-token-guidance>"
_TOKEN_PATTERN = re.compile(r"\[([A-Z][A-Z0-9_]*?)_([1-9][0-9]*)\]")
_BARE_TOKEN_PATTERN = re.compile(r"(?<![A-Z0-9_])([A-Z][A-Z0-9_]*?)_([1-9][0-9]*)(?![A-Z0-9_])")
_REDACTED_MARKER = "[REDACTED]"
# Windows drive-rooted path (``C:/...``) after separator normalization; such a
# path is only meaningful on a Windows host.
_WINDOWS_DRIVE_ROOT_PATTERN = re.compile(r"^[A-Za-z]:/")


def _allow() -> dict[str, object]:
    return {"decision": "allow"}


def _deny(reason: str) -> dict[str, object]:
    return {"decision": "deny", "reason": reason}


def _ensure_runtime_ready(session_id: object) -> None:
    """Bring the local enforcement runtime online before a prompt/model stage.

    ``SessionStart`` normally spawns the daemon, but a pathless natural-language
    prompt must not fail closed merely because that one-shot spawn left no live
    daemon (the child died, or a fresh session never fired ``SessionStart``).
    Start it lazily here so the prompt proceeds once the engine is ready instead
    of being misreported as a "protected path" validation failure. A healthy
    runtime is detected immediately and costs nothing; only a cold start pays
    the spawn-and-warm cost.
    """

    try:
        ensure_runtime(
            session_id,
            runtime_scope=_SCOPE,
            startup_timeout_seconds=_PROMPT_RUNTIME_START_TIMEOUT_SECONDS,
        )
    except Exception:
        # Startup failure must not turn into an unhandled error; inspection
        # below fails closed on its own.
        return


def _deny_prompt_outcome(session_id: object, outcome: EnforcementOutcome) -> dict[str, object]:
    """Fail closed for a prompt/model stage, but never as a "protected path".

    A prompt carries no file target, so an inspection/runtime failure here is not
    a filesystem authorization failure. Report it with the path-neutral message
    (or the accurate "still initializing" message while the daemon warms) rather
    than ``FAIL_CLOSED``'s "could not validate this protected path".
    """

    if outcome == EnforcementOutcome.INTERNAL_FAILURE and not runtime_is_warming(
        session_id, runtime_scope=_SCOPE
    ):
        return _deny(PROMPT_RUNTIME_BLOCKED)
    return _deny_for_outcome(session_id, outcome)


@lru_cache(maxsize=1)
def _pseudonymizable_token_categories() -> tuple[str, ...]:
    """Return token labels from the same default policy used by the enforcer."""

    policy = PolicyRegistry().get("default")
    return tuple(
        sorted(
            entity_type.value.upper()
            for entity_type in policy.automatic_pseudonymization_rules
            if policy.action_for(entity_type) not in {PrivacyAction.ALLOW, PrivacyAction.BLOCK}
        )
    )


def _token_categories_in_text(text: str) -> tuple[tuple[str, ...], bool]:
    inspected_text = text.split(_GUIDANCE_MARKER, maxsplit=1)[0]
    allowed = frozenset(_pseudonymizable_token_categories())
    categories = tuple(
        sorted(
            {
                category
                for pattern in (_TOKEN_PATTERN, _BARE_TOKEN_PATTERN)
                for match in pattern.finditer(inspected_text)
                if (category := match.group(1)) in allowed
            }
        )
    )
    return categories, _REDACTED_MARKER in inspected_text


def _pseudonym_guidance(categories: tuple[str, ...], *, has_redaction: bool) -> str:
    category_text = ", ".join(categories)
    marker_text = (
        f" Recognized pseudonym classes in this request: {category_text}." if category_text else ""
    )
    if has_redaction:
        marker_text += " [REDACTED] marks intentionally removed private content."
    return (
        f"{_GUIDANCE_MARKER}\n"
        "SecuRedact privacy-token handling instruction: tokens such as [PERSON_1] or "
        "[EMAIL_1] are intentional opaque privacy-preserving stand-ins."
        f"{marker_text} Treat their labels as high-level semantic categories, not variables, "
        "filesystem identifiers, or unresolved references. Preserve tokens exactly and continue "
        "the user's task normally using them. Repeated identical tokens refer to the same "
        "pseudonymized value within the current transformation scope; different token numbers "
        "refer to different values. Never identify, resolve, reverse, deanonymize, search for, "
        "reconstruct, infer, or recover an original value. Do not search the workspace, local "
        "files, conversation history, tools, MCP servers, or web/network resources for an "
        "original, and do not ask a tool to resolve a token. If asked to recover an original, "
        "explain that the token is an intentional privacy-preserving pseudonym and do not perform "
        f"the lookup.\n{_GUIDANCE_END_MARKER}"
    )


def _inject_pseudonym_guidance(
    request: dict[str, object], selected_indices: list[int]
) -> tuple[dict[str, object], bool, tuple[str, ...]]:
    messages = request.get("messages")
    if not isinstance(messages, list) or not selected_indices:
        return request, False, ()
    selected_index = selected_indices[-1]
    if selected_index < 0 or selected_index >= len(messages):
        return request, False, ()
    message = messages[selected_index]
    if not isinstance(message, Mapping):
        return request, False, ()
    content = message.get("content")
    if not isinstance(content, str):
        return request, False, ()
    categories, has_redaction = _token_categories_in_text(content)
    _TOKEN_CATEGORIES.set(categories)
    if not categories and not has_redaction:
        return request, False, categories
    if _GUIDANCE_MARKER in content:
        return request, False, categories
    guidance = _pseudonym_guidance(categories, has_redaction=has_redaction)
    guided_messages = list(messages)
    guided_messages[selected_index] = {**message, "content": f"{content}\n\n{guidance}"}
    _GUIDANCE_INJECTED.set(True)
    return {**request, "messages": guided_messages}, True, categories


def _block_reason(outcome: EnforcementOutcome, *, tool: bool = False) -> str:
    if outcome == EnforcementOutcome.REVIEW_REQUIRED:
        return REVIEW_BLOCK
    if outcome == EnforcementOutcome.INTERNAL_FAILURE:
        return FAIL_CLOSED
    return TOOL_BLOCK if tool else PROMPT_BLOCK


def _is_external_tool(tool_name: object) -> bool:
    if not isinstance(tool_name, str):
        return False
    lowered = tool_name.casefold()
    return lowered.startswith("mcp_") or any(
        marker in lowered
        for marker in ("http", "web", "search", "fetch", "request", "api", "connect")
    )


def _resolve_workspace_root(cwd: object) -> Path:
    """Return the active Gemini workspace/cwd used to anchor relative paths.

    Gemini supplies a concrete ``cwd`` at ``BeforeTool`` when available; otherwise
    the hook process inherits Gemini's working directory. Either is a safe anchor
    because filesystem authorization only ever *narrows* what a tool may touch.
    """

    if isinstance(cwd, str) and cwd.strip():
        try:
            return Path(cwd).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            pass
    return Path(os.getcwd()).resolve(strict=False)


def _normalize_path_separators(text: str) -> str:
    """Return ``text`` with Windows-style ``\\`` separators expressed as ``/``.

    ``pathlib`` only treats ``\\`` as a separator on the platform it runs on, so
    on POSIX a Windows-style path such as ``..\\outside\\secret.txt`` is a single
    literal filename and its ``..`` traversal is invisible to ``Path.resolve``.
    ``/`` is a valid separator for Windows paths too, so rewriting ``\\`` to ``/``
    yields the same platform-neutral segment structure on every host and keeps
    ``..``/``.`` segments visible to the canonicalizer (FW-012). Drive-letter
    paths such as ``C:\\Users\\...`` stay absolute because ``C:/Users/...`` is
    still drive-rooted on Windows.
    """

    return text.replace("\\", "/")


def _canonicalize_tool_file_path(raw: object, cwd: object) -> str | None:
    """Canonicalize a structured FILE_READ/FILE_WRITE path for policy evaluation.

    Provider-specific key extraction lives in ``classify_tool``; this step only
    turns that raw string into the *real* absolute target the firewall must
    judge. It resolves relative paths against the workspace, keeps absolute paths
    absolute, normalizes separators, follows symlinks, and rejects URLs/UNC/null
    bytes or any resolved target that escapes the workspace (FW-012). A path that
    cannot be safely canonicalized returns ``None`` so the caller fails closed.

    The defense primitives are reused from ``securedact_core.safe_read``; this
    adapter never invents its own canonicalization or allowed-root policy.
    """

    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    lowered = text.lower().replace("\\", "/")
    # Reject URL/UNC/null-byte inputs before any anchoring or separator
    # normalization: anchoring a relative URL into the workspace would strip its
    # scheme marker and let it slip past the canonicalizer, and a UNC prefix must
    # never be reinterpreted as a local path (FW-012). ``resolve_safe_path``
    # still enforces these too.
    if "\x00" in text or "://" in lowered or lowered.startswith("//") or lowered.startswith("\\\\"):
        return None
    root = _resolve_workspace_root(cwd)
    # Separator normalization happens *before* ``Path(...)`` so a Windows-style
    # tool argument is split into segments on POSIX as well; otherwise
    # ``..\\outside\\secret.txt`` would anchor into the workspace as a literal
    # filename and its traversal would escape review (FW-012).
    normalized = _normalize_path_separators(text)
    if os.name != "nt" and _WINDOWS_DRIVE_ROOT_PATTERN.match(normalized):
        # A drive-letter absolute path is not addressable on a POSIX host, and
        # anchoring it into the workspace would invent a bogus in-workspace
        # target, so it fails closed instead.
        return None
    candidate = Path(normalized)
    # Relative paths resolve against the active workspace, never the hook
    # process cwd, so a harmless ``safe_notes.txt`` anchors to the workspace and
    # an absolute path keeps its location (FW-012).
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = resolve_safe_path(str(candidate), allowed_roots=[str(root)])
    except (SafeReadError, OSError, RuntimeError, ValueError):
        return None
    return str(resolved)


def _requires_content_inspection(operation: ToolOperation, tool_name: object) -> bool:
    """Decide whether the tool input still needs content-based inspection."""

    if operation == ToolOperation.UNKNOWN:
        # Classification failed: never skip inspection. An unrecognized tool is
        # at least content-inspected so PII/secrets in its input are not silently
        # allowed through; if the runtime is unavailable it fails closed.
        return True
    if operation in {ToolOperation.FILE_READ, ToolOperation.FILE_WRITE}:
        # Path policy is the relevant check; the path string is not content.
        return False
    if operation in {
        ToolOperation.SHELL_EXEC,
        ToolOperation.NETWORK_READ,
        ToolOperation.NETWORK_WRITE,
        ToolOperation.DATABASE_READ,
        ToolOperation.DATABASE_WRITE,
        ToolOperation.MCP_CALL,
    }:
        return True
    lowered = tool_name.casefold() if isinstance(tool_name, str) else ""
    if lowered.startswith("mcp_"):
        return True
    if lowered in {"webfetch", "websearch"}:
        return True
    return any(
        marker in lowered
        for marker in ("http", "web", "search", "fetch", "request", "api", "connect")
    )


def _model_text_payload(
    request: Mapping[str, object],
) -> tuple[dict[str, object], list[int]] | None:
    """Select the latest untrusted model-bound text field for inspection.

    Earlier user content was deterministically checked by ``BeforeAgent`` in
    its original turn. Gemini uses the ``user`` role for user turns and tool
    results; model/router messages are provider-generated and must not replace
    the selected untrusted input.
    """

    messages = request.get("messages")
    if not isinstance(messages, list):
        return None
    latest: tuple[int, str] | None = None
    for index, message in enumerate(messages):
        if not isinstance(message, Mapping):
            return None
        role = message.get("role")
        content = message.get("content")
        if not isinstance(role, str) or not isinstance(content, str):
            return None
        if role != "user":
            continue
        latest = (index, content)
    if latest is None:
        return {"messages": []}, []
    index, content = latest
    return {"messages": [{"content": content}]}, [index]


def _merge_model_text_payload(
    request: dict[str, object], inspected: object, selected_indices: list[int]
) -> dict[str, object] | None:
    """Merge sanitized message content without modifying request metadata."""

    if not isinstance(inspected, Mapping):
        return None
    original_messages = request.get("messages")
    inspected_messages = inspected.get("messages")
    if not isinstance(original_messages, list) or not isinstance(inspected_messages, list):
        return None
    if len(selected_indices) != len(inspected_messages):
        return None
    merged_messages = list(original_messages)
    for index, replacement in zip(selected_indices, inspected_messages, strict=True):
        original = original_messages[index]
        if not isinstance(original, Mapping) or not isinstance(replacement, Mapping):
            return None
        content = replacement.get("content")
        if not isinstance(content, str):
            return None
        merged_messages[index] = {**original, "content": content}
    return {**request, "messages": merged_messages}


def _inspect(
    session_id: object, payload: object
) -> tuple[EnforcementOutcome, PrepareOutcome | None, object | None]:
    outcome, prepare_outcome, sanitized, stage = inspect_payload_with_prepare_outcome_stage(
        session_id, payload, timeout_seconds=_PAYLOAD_IPC_TIMEOUT_SECONDS, runtime_scope=_SCOPE
    )
    _INSPECTION_STAGE.set(stage)
    _PREPARE_OUTCOME.set(str(prepare_outcome) if prepare_outcome is not None else None)
    return outcome, prepare_outcome, sanitized


def _inspect_model(
    session_id: object, payload: object
) -> tuple[EnforcementOutcome, PrepareOutcome | None, object | None]:
    outcome, prepare_outcome, sanitized, stage = inspect_payload_with_prepare_outcome_stage(
        session_id,
        payload,
        timeout_seconds=_PAYLOAD_IPC_TIMEOUT_SECONDS,
        runtime_scope=_SCOPE,
        operation="inspect_model_payload",
    )
    _INSPECTION_STAGE.set(stage)
    _PREPARE_OUTCOME.set(str(prepare_outcome) if prepare_outcome is not None else None)
    return outcome, prepare_outcome, sanitized


def _inspect_prompt(session_id: object, prompt: object) -> EnforcementOutcome:
    outcome, stage = inspect_text_outcome_with_stage(
        session_id,
        prompt,
        timeout_seconds=_PROMPT_IPC_TIMEOUT_SECONDS,
        runtime_scope=_SCOPE,
        operation="inspect_before_agent_text",
    )
    _INSPECTION_STAGE.set(stage)
    return outcome


def _inspect_result(
    session_id: object, result: object
) -> tuple[EnforcementOutcome, tuple[str, ...] | None, str | None, str]:
    """Inspect a model-bound tool result through the warmed daemon (FW-020)."""

    outcome, _sanitized, entities, reason_code, stage = claude_runtime.inspect_tool_result(
        session_id,
        result,
        timeout_seconds=_PAYLOAD_IPC_TIMEOUT_SECONDS,
        runtime_scope=_SCOPE,
    )
    return outcome, entities, reason_code, stage


def _emit_result_audit(
    outcome: EnforcementOutcome,
    entities: tuple[str, ...] | None,
    *,
    provider: str,
    tool_name: str | None,
    reason_code: str | None,
) -> None:
    """Best-effort, metadata-only audit for a hidden tool result (FW-033)."""

    try:
        entity_types = entities or ()
        secret_entities = tuple(e for e in entity_types if is_secret_entity_type(e))
        action = (
            "block"
            if outcome in {EnforcementOutcome.BLOCKED, EnforcementOutcome.INTERNAL_FAILURE}
            else "redact"
        )
        if secret_entities:
            event_type = AuditEventType.SECRET_DETECTED
        elif entity_types:
            event_type = AuditEventType.PII_REDACTED
        else:
            event_type = AuditEventType.TOOL_BLOCKED
        emit_audit_event(
            build_audit_event(
                event_type,
                action=action,
                reason_code=reason_code or "tool_result_hidden",
                provider=provider,
                tool_name=tool_name,
                entity_types=entity_types,
            )
        )
    except Exception:
        return


def _deny_for_outcome(
    session_id: object, outcome: EnforcementOutcome, *, tool: bool = False
) -> dict[str, object]:
    if outcome == EnforcementOutcome.INTERNAL_FAILURE and runtime_is_warming(
        session_id, runtime_scope=_SCOPE
    ):
        return _deny(_INITIALIZING)
    return _deny(_block_reason(outcome, tool=tool))


def _emit_tool_audit(
    outcome: EnforcementOutcome,
    *,
    provider: str,
    tool_name: str | None,
    operation: ToolOperation | None,
    decision: object = None,
) -> None:
    """Best-effort, privacy-preserving firewall audit (FW-033).

    Never raises; audit failure must not change or weaken the host decision.
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


def _apply_tool_inspection(
    session_id: object,
    outcome: EnforcementOutcome,
    prepare_outcome: PrepareOutcome | None,
    sanitized: object | None,
    *,
    tool_name: str | None = None,
    operation: ToolOperation | None = None,
) -> dict[str, object]:
    if outcome == EnforcementOutcome.ALLOW and prepare_outcome == PrepareOutcome.ALLOW:
        return _allow()
    if (
        outcome == EnforcementOutcome.SANITIZED
        and prepare_outcome in {PrepareOutcome.PSEUDONYMIZED, PrepareOutcome.REDACTED}
        and isinstance(sanitized, dict)
    ):
        return {
            "decision": "allow",
            "hookSpecificOutput": {"hookEventName": "BeforeTool", "tool_input": sanitized},
        }
    if (
        outcome == EnforcementOutcome.REVIEW_REQUIRED
        and prepare_outcome == PrepareOutcome.REVIEW_REQUIRED
    ):
        _emit_tool_audit(
            EnforcementOutcome.REVIEW_REQUIRED,
            provider="gemini",
            tool_name=tool_name,
            operation=operation,
        )
        return _deny_for_outcome(session_id, outcome, tool=True)
    if outcome == EnforcementOutcome.BLOCKED and prepare_outcome == PrepareOutcome.BLOCKED:
        _emit_tool_audit(
            EnforcementOutcome.BLOCKED,
            provider="gemini",
            tool_name=tool_name,
            operation=operation,
        )
        return _deny_for_outcome(session_id, outcome, tool=True)
    return _deny_for_outcome(session_id, EnforcementOutcome.INTERNAL_FAILURE, tool=True)


def _apply_egress_inspection(
    session_id: object,
    tool_name: str | None,
    tool_input: object,
    context: ToolContext,
    firewall: object,
) -> dict[str, object]:
    """Inspect an outbound NETWORK_WRITE tool call for Gemini (FW-030).

    Reuses the warmed-runtime content scanner. A secret in the outbound payload
    is blocked; an external/unknown destination with merely-redacted PII may be
    upgraded to REQUIRE_APPROVAL when the policy opts in. Oversize or unscannable
    payloads fail closed. No raw request body/header/credential reaches the host.
    """

    destination = context.destination
    if recursive_text_length(tool_input) > MAX_TOOL_RESULT_CHARS:
        _emit_egress_audit(
            provider="gemini",
            tool_name=tool_name,
            operation=context.operation,
            destination=destination,
        )
        return _deny(EGRESS_OVERSIZE)

    scan_payload = egress_scan_payload(tool_input)
    try:
        outcome, prepare_outcome, sanitized = _inspect(session_id, scan_payload)
    except Exception:
        # Scanner/client failure must fail closed, never allow unverified egress.
        _emit_egress_audit(
            provider="gemini",
            tool_name=tool_name,
            operation=context.operation,
            destination=destination,
        )
        return _deny_for_outcome(session_id, EnforcementOutcome.INTERNAL_FAILURE, tool=True)

    if (
        firewall is not None
        and getattr(firewall, "egress_external_require_approval", False)
        and outcome == EnforcementOutcome.SANITIZED
    ):
        scope = classify_destination_scope(
            destination, allowlist_domains=getattr(firewall, "egress_allowlist_domains", ())
        )
        if scope in {DestinationScope.EXTERNAL, DestinationScope.UNKNOWN}:
            _emit_tool_audit(
                EnforcementOutcome.REVIEW_REQUIRED,
                provider="gemini",
                tool_name=tool_name,
                operation=context.operation,
            )
            return _deny_for_outcome(session_id, EnforcementOutcome.REVIEW_REQUIRED, tool=True)

    if outcome == EnforcementOutcome.BLOCKED:
        _emit_egress_audit(
            provider="gemini",
            tool_name=tool_name,
            operation=context.operation,
            destination=destination,
        )
        return _deny_for_outcome(session_id, outcome, tool=True)
    if outcome == EnforcementOutcome.REVIEW_REQUIRED:
        _emit_tool_audit(
            EnforcementOutcome.REVIEW_REQUIRED,
            provider="gemini",
            tool_name=tool_name,
            operation=context.operation,
        )
        return _deny_for_outcome(session_id, outcome, tool=True)
    if outcome == EnforcementOutcome.INTERNAL_FAILURE:
        _emit_egress_audit(
            provider="gemini",
            tool_name=tool_name,
            operation=context.operation,
            destination=destination,
        )
        return _deny_for_outcome(session_id, outcome, tool=True)
    return _apply_tool_inspection(
        session_id,
        outcome,
        prepare_outcome,
        sanitized,
        tool_name=tool_name,
        operation=context.operation,
    )


def handle_event(
    event_name: str,
    event: object,
    *,
    diagnostic_observer: Callable[[str | None, EnforcementOutcome], None] | None = None,
) -> dict[str, object]:
    """Return only Gemini protocol JSON; malformed input fails closed."""

    if not isinstance(event, Mapping):
        if event_name in {"BeforeAgent", "BeforeModel"}:
            return _deny(PROMPT_RUNTIME_BLOCKED)
        if event_name == "BeforeTool":
            return _deny(FAIL_CLOSED)
        return _allow()
    session_id = event.get("session_id")
    if event_name == "SessionStart":
        start_runtime(session_id, runtime_scope=_SCOPE, health_timeout_seconds=0.1)
        return _allow()
    if event_name == "SessionEnd":
        shutdown_runtime(session_id, runtime_scope=_SCOPE)
        return _allow()
    if event_name == "BeforeAgent":
        # Prompt sanitization only. A natural-language user prompt may *mention*
        # a filename or path; that is never filesystem authorization. Path
        # validation happens later at BeforeTool against the structured
        # FILE_READ/FILE_WRITE operation, never here, so a harmless prompt is
        # never rejected merely because it names a file.
        _ensure_runtime_ready(session_id)
        prompt = event.get("prompt")
        if not isinstance(prompt, str):
            if diagnostic_observer is not None:
                diagnostic_observer(None, EnforcementOutcome.INTERNAL_FAILURE)
            return _deny(PROMPT_RUNTIME_BLOCKED)
        outcome = _inspect_prompt(session_id, prompt)
        if diagnostic_observer is not None:
            diagnostic_observer("prompt", outcome)
        # Transformable text is allowed to proceed only as far as BeforeModel,
        # where the signed core-provided sanitized text replaces it.
        if outcome in {EnforcementOutcome.ALLOW, EnforcementOutcome.SANITIZED}:
            return _allow()
        return _deny_prompt_outcome(session_id, outcome)
    if event_name == "BeforeModel":
        _GUIDANCE_INJECTED.set(False)
        _TOKEN_CATEGORIES.set(())
        _ensure_runtime_ready(session_id)
        request = event.get("llm_request")
        if not isinstance(request, dict):
            return _deny(PROMPT_RUNTIME_BLOCKED)
        selected_model_text = _model_text_payload(request)
        if selected_model_text is None:
            return _deny(PROMPT_RUNTIME_BLOCKED)
        model_text, selected_indices = selected_model_text
        outcome, prepare_outcome, sanitized = _inspect_model(session_id, model_text)
        if outcome == EnforcementOutcome.ALLOW and prepare_outcome == PrepareOutcome.ALLOW:
            guided_request, injected, _categories = _inject_pseudonym_guidance(
                request, selected_indices
            )
            if not injected:
                return _allow()
            return {
                "decision": "allow",
                "hookSpecificOutput": {
                    "hookEventName": "BeforeModel",
                    "llm_request": guided_request,
                },
            }
        if (
            outcome == EnforcementOutcome.SANITIZED
            and prepare_outcome in {PrepareOutcome.PSEUDONYMIZED, PrepareOutcome.REDACTED}
            and isinstance(sanitized, dict)
        ):
            updated_request = _merge_model_text_payload(request, sanitized, selected_indices)
            if updated_request is None:
                return _deny(PROMPT_RUNTIME_BLOCKED)
            guided_request, _injected, _categories = _inject_pseudonym_guidance(
                updated_request, selected_indices
            )
            return {
                "decision": "allow",
                "hookSpecificOutput": {
                    "hookEventName": "BeforeModel",
                    "llm_request": guided_request,
                },
            }
        if (
            outcome == EnforcementOutcome.REVIEW_REQUIRED
            and prepare_outcome == PrepareOutcome.REVIEW_REQUIRED
        ):
            return _deny_for_outcome(session_id, outcome)
        if outcome == EnforcementOutcome.BLOCKED and prepare_outcome == PrepareOutcome.BLOCKED:
            return _deny_for_outcome(session_id, outcome)
        return _deny_prompt_outcome(session_id, EnforcementOutcome.INTERNAL_FAILURE)
    if event_name == "BeforeTool":
        tool_name = event.get("tool_name")
        tool_input = event.get("tool_input")
        if not isinstance(tool_input, dict):
            return _deny(FAIL_CLOSED)
        context = classify_tool("gemini", tool_name, tool_input)
        firewall = load_firewall_policy_from_environment()
        if firewall is not None and firewall.enabled:
            # Filesystem authorization must operate on the *canonical* target,
            # not the raw user/tool-supplied string, so symlink/``..``/UNC tricks
            # cannot hide a prohibited file from the firewall (FW-012). This is
            # the correct lifecycle stage: BeforeAgent only sanitizes prompt
            # text; the structured FILE_READ/FILE_WRITE path is resolved here.
            if context.operation in {ToolOperation.FILE_READ, ToolOperation.FILE_WRITE}:
                if context.path is not None:
                    # Filesystem authorization must operate on the *canonical*
                    # target, not the raw user/tool-supplied string, so
                    # symlink/``..``/UNC tricks cannot hide a prohibited file from
                    # the firewall (FW-012). This is the correct lifecycle stage:
                    # BeforeAgent only sanitizes prompt text; the structured
                    # FILE_READ/FILE_WRITE path is resolved here.
                    canonical = _canonicalize_tool_file_path(context.path, event.get("cwd"))
                    if canonical is None:
                        _emit_tool_audit(
                            EnforcementOutcome.BLOCKED,
                            provider="gemini",
                            tool_name=tool_name if isinstance(tool_name, str) else None,
                            operation=context.operation,
                            decision=None,
                        )
                        return _deny_for_outcome(session_id, EnforcementOutcome.BLOCKED, tool=True)
                    if context.path != canonical:
                        context = ToolContext(
                            provider=context.provider,
                            tool_name=context.tool_name,
                            operation=context.operation,
                            path=canonical,
                            destination=context.destination,
                            destination_scope=context.destination_scope,
                            payload=context.payload,
                        )
                # A FILE_READ/FILE_WRITE with no concrete file target (for
                # example a directory/pattern search such as Glob/Grep used to
                # *discover* a file) names no specific protected path, so it must
                # not be fail-closed as a protected-path failure. The firewall
                # still judges any present path below; real file targets that
                # fail canonicalization remain blocked above.
            if context.operation != ToolOperation.UNKNOWN:
                decision = evaluate_firewall(firewall, context)
                outcome = firewall_decision_outcome(decision)
                if outcome == EnforcementOutcome.BLOCKED:
                    if context.operation == ToolOperation.NETWORK_WRITE:
                        _emit_egress_audit(
                            provider="gemini",
                            tool_name=tool_name,
                            operation=context.operation,
                            destination=context.destination,
                        )
                    else:
                        _emit_tool_audit(
                            EnforcementOutcome.BLOCKED,
                            provider="gemini",
                            tool_name=tool_name,
                            operation=context.operation,
                            decision=decision,
                        )
                    return _deny_for_outcome(session_id, EnforcementOutcome.BLOCKED, tool=True)
                if outcome == EnforcementOutcome.REVIEW_REQUIRED:
                    _emit_tool_audit(
                        EnforcementOutcome.REVIEW_REQUIRED,
                        provider="gemini",
                        tool_name=tool_name,
                        operation=context.operation,
                        decision=decision,
                    )
                    return _deny_for_outcome(
                        session_id, EnforcementOutcome.REVIEW_REQUIRED, tool=True
                    )
            if not _requires_content_inspection(context.operation, tool_name):
                return _allow()
            if context.operation == ToolOperation.NETWORK_WRITE:
                return _apply_egress_inspection(
                    session_id, tool_name, tool_input, context, firewall
                )
            scan_payload = egress_scan_payload(tool_input)
            outcome, prepare_outcome, sanitized = _inspect(session_id, scan_payload)
            return _apply_tool_inspection(
                session_id,
                outcome,
                prepare_outcome,
                sanitized,
                tool_name=tool_name,
                operation=context.operation,
            )
        if not _is_external_tool(tool_name):
            return _allow()
        if context.operation == ToolOperation.NETWORK_WRITE:
            return _apply_egress_inspection(session_id, tool_name, tool_input, context, firewall)
        scan_payload = egress_scan_payload(tool_input)
        outcome, prepare_outcome, sanitized = _inspect(session_id, scan_payload)
        return _apply_tool_inspection(
            session_id,
            outcome,
            prepare_outcome,
            sanitized,
            tool_name=tool_name,
            operation=context.operation,
        )
    if event_name == "AfterTool":
        # FW-020: hide sensitive tool results. Gemini's AfterTool hook can deny
        # (which replaces the result the model sees with a safe reason) but offers
        # no field to replace the result with a sanitized value, so a sensitive
        # result is hidden rather than redacted.
        tool_name = event.get("tool_name")
        tool_response = event.get("tool_response")
        firewall = load_firewall_policy_from_environment()
        if firewall is None or not firewall.enabled:
            return _allow()
        if not isinstance(tool_response, (str, Mapping, list)):
            return _allow()
        outcome, entities, reason_code, stage = _inspect_result(session_id, tool_response)
        _INSPECTION_STAGE.set(stage)
        if outcome == EnforcementOutcome.ALLOW:
            return _allow()
        safe_reason = RESULT_OVERSIZE if reason_code == "result_oversize" else RESULT_BLOCKED
        _emit_result_audit(
            outcome,
            entities,
            provider="gemini",
            tool_name=tool_name if isinstance(tool_name, str) else None,
            reason_code=reason_code,
        )
        return _deny(safe_reason)
    return _allow()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecuRedact Gemini CLI hook")
    parser.add_argument(
        "--event",
        required=True,
        choices=(
            "SessionStart",
            "SessionEnd",
            "BeforeAgent",
            "BeforeModel",
            "BeforeTool",
            "AfterTool",
        ),
    )
    args = parser.parse_args(argv)
    started = time.monotonic()
    metadata: dict[str, object] = {
        "field_names": [],
        "selected_field": None,
        "enforcement_outcome": None,
        "prepare_outcome": None,
        "pseudonym_guidance_injected": False,
        "token_categories": [],
        "token_category_count": 0,
        "inspection_transport_stage": "not_invoked",
        "inspection_timeout_seconds": None,
    }

    def observe(selected_field: str | None, outcome: EnforcementOutcome) -> None:
        metadata["selected_field"] = selected_field
        metadata["enforcement_outcome"] = str(outcome)

    try:
        _INSPECTION_STAGE.set("not_invoked")
        _PREPARE_OUTCOME.set(None)
        _GUIDANCE_INJECTED.set(False)
        _TOKEN_CATEGORIES.set(())
        event = json.load(sys.stdin)
        if isinstance(event, Mapping):
            metadata["field_names"] = sorted(key for key in event if isinstance(key, str))
            if args.event == "BeforeModel":
                metadata["selected_field"] = "llm_request.messages[].content"
        output = handle_event(args.event, event, diagnostic_observer=observe)
        metadata["inspection_transport_stage"] = _INSPECTION_STAGE.get()
        metadata["prepare_outcome"] = _PREPARE_OUTCOME.get()
        token_categories = list(_TOKEN_CATEGORIES.get())
        metadata["pseudonym_guidance_injected"] = _GUIDANCE_INJECTED.get()
        metadata["token_categories"] = token_categories
        metadata["token_category_count"] = len(token_categories)
        metadata["inspection_timeout_seconds"] = (
            _PROMPT_IPC_TIMEOUT_SECONDS
            if args.event == "BeforeAgent"
            else _PAYLOAD_IPC_TIMEOUT_SECONDS
            if args.event in {"BeforeModel", "BeforeTool"}
            else None
        )
    except Exception:
        output = _deny(FAIL_CLOSED) if args.event.startswith("Before") else _allow()
        event = {}
    session_id = event.get("session_id") if isinstance(event, Mapping) else None
    if isinstance(session_id, str):
        metadata["runtime_diagnostics"] = runtime_diagnostics(
            session_id, runtime_scope=_SCOPE, timeout_seconds=0.2
        )
    write_hook_receipt(
        args.event,
        session_id,
        decision="block" if output.get("decision") == "deny" else "allow",
        elapsed_ms=int((time.monotonic() - started) * 1000),
        runtime_scope=_SCOPE,
        safe_metadata=metadata,
    )
    sys.stdout.write(json.dumps(output, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
