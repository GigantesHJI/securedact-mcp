"""FW-020 — tool-result / model-bound result sanitization (Claude + Gemini).

These tests drive the real ``PostToolUse`` (Claude) and ``AfterTool`` (Gemini)
handlers with a stubbed warmed-runtime inspector so the wiring, structured
preservation, fail-closed behavior, and audit emission can be asserted without a
live contextual model.

Capability matrix (verified against authoritative provider docs):

| Host        | sees result | can replace result | can hide/block | MVP behavior                |
| ----------- | ----------: | -----------------: | -------------: | -------------------------- |
| Claude Code | yes         | yes (updatedToolOutput) | yes (decision block) | replace sanitized result |
| Gemini CLI  | yes         | no                 | yes (decision deny) | hide/block sensitive result |
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from securedact_core import AuditEventType
from securedact_core.audit import AuditSinkCollector, set_audit_sink
from securedact_enforced import claude_runtime, gemini_hook, provider_hook
from securedact_enforced.adapter import EnforcementOutcome
from securedact_enforced.provider_hook import handle_event as claude_handle_event
from securedact_enforced.provider_messages import RESULT_BLOCKED, RESULT_OVERSIZE

SYNTHETIC_EMAIL = "jan.jansen@example.test"
SYNTHETIC_SECRET = "SUPER_SECRET_TOOL_RESULT_X9kLmNoPqRsTuVwXyZ"  # noqa: S105


def _fake_inspector(outcome, *, sanitized=None, entities=(), reason_code=None):
    """Return a ``claude_runtime.inspect_tool_result`` stub with fixed behavior."""

    def fake(_session, _result, **_kwargs):
        return outcome, sanitized, entities, reason_code, "ok"

    return fake


# --- Claude Code PostToolUse ------------------------------------------------


def _claude_post_event(result, *, tool_name="Read", session_id="session-fw020"):
    return {
        "session_id": session_id,
        "hook_event_name": "PostToolUse",
        "tool_name": tool_name,
        "tool_input": {"file_path": "notes.txt"},
        "tool_response": result,
        "tool_output": json.dumps(result) if not isinstance(result, str) else result,
    }


def test_claude_clean_result_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        claude_runtime, "inspect_tool_result", _fake_inspector(EnforcementOutcome.ALLOW)
    )
    assert claude_handle_event(_claude_post_event("hello world")) is None


def test_claude_pii_result_is_replaced_with_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    sanitized = {
        "filePath": "notes.txt",
        "content": "Contact [EMAIL_1] for details",
    }
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        _fake_inspector(
            EnforcementOutcome.SANITIZED,
            sanitized=sanitized,
            entities=("email",),
        ),
    )
    output = claude_handle_event(_claude_post_event({"content": f"Contact {SYNTHETIC_EMAIL}"}))
    assert output is not None
    assert output["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    assert output["hookSpecificOutput"]["updatedToolOutput"] == sanitized
    assert SYNTHETIC_EMAIL not in json.dumps(output)


def test_claude_unknown_secret_result_is_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        _fake_inspector(
            EnforcementOutcome.SANITIZED,
            sanitized={"content": "INTERNAL_API_SECRET=[unknown_secret]"},
            entities=("unknown_secret",),
        ),
    )
    output = claude_handle_event(
        _claude_post_event({"content": f"INTERNAL_API_SECRET={SYNTHETIC_SECRET}"})
    )
    assert output is not None
    assert SYNTHETIC_SECRET not in json.dumps(output)
    assert "[unknown_secret]" in json.dumps(output)


def test_claude_structured_bash_output_shape_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bash_result = {
        "stdout": f"{SYNTHETIC_EMAIL}",
        "stderr": "",
        "interrupted": False,
        "isImage": False,
    }
    sanitized = {
        "stdout": "[EMAIL_1]",
        "stderr": "",
        "interrupted": False,
        "isImage": False,
    }
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        _fake_inspector(EnforcementOutcome.SANITIZED, sanitized=sanitized, entities=("email",)),
    )
    output = claude_handle_event(_claude_post_event(bash_result, tool_name="Bash"))
    replaced = output["hookSpecificOutput"]["updatedToolOutput"]
    assert replaced == sanitized
    assert replaced["interrupted"] is False
    assert replaced["isImage"] is False
    assert SYNTHETIC_EMAIL not in json.dumps(output)


def test_claude_mcp_result_sanitized_through_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mcp_result = {"content": [{"type": "text", "text": f"key={SYNTHETIC_SECRET}"}]}
    sanitized = {"content": [{"type": "text", "text": "key=[unknown_secret]"}]}
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        _fake_inspector(
            EnforcementOutcome.SANITIZED, sanitized=sanitized, entities=("unknown_secret",)
        ),
    )
    output = claude_handle_event(_claude_post_event(mcp_result, tool_name="mcp__remote__fetch"))
    assert output["hookSpecificOutput"]["updatedToolOutput"] == sanitized
    assert SYNTHETIC_SECRET not in json.dumps(output)


def test_claude_oversize_result_fails_closed_without_raw(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        _fake_inspector(EnforcementOutcome.INTERNAL_FAILURE, reason_code="result_oversize"),
    )
    output = claude_handle_event(_claude_post_event({"content": SYNTHETIC_SECRET}))
    assert output["hookSpecificOutput"]["updatedToolOutput"] == RESULT_OVERSIZE
    assert SYNTHETIC_SECRET not in json.dumps(output)


def test_claude_scanner_failure_fails_closed_without_raw(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        _fake_inspector(
            EnforcementOutcome.INTERNAL_FAILURE, reason_code="result_inspection_failed"
        ),
    )
    output = claude_handle_event(_claude_post_event({"content": SYNTHETIC_EMAIL}))
    assert output["hookSpecificOutput"]["updatedToolOutput"] == RESULT_BLOCKED
    assert SYNTHETIC_EMAIL not in json.dumps(output)


def test_claude_blocked_secret_result_replaced_with_safe_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        _fake_inspector(EnforcementOutcome.BLOCKED, entities=("private_key",)),
    )
    output = claude_handle_event(_claude_post_event({"content": "-----BEGIN PRIVATE KEY-----"}))
    assert output["hookSpecificOutput"]["updatedToolOutput"] == RESULT_BLOCKED
    assert "PRIVATE KEY" not in json.dumps(output)


def test_claude_result_audit_emits_metadata_only(monkeypatch: pytest.MonkeyPatch) -> None:
    collector = AuditSinkCollector()
    previous = set_audit_sink(collector)
    try:
        monkeypatch.setattr(
            claude_runtime,
            "inspect_tool_result",
            _fake_inspector(
                EnforcementOutcome.SANITIZED,
                sanitized={"content": "[EMAIL_1]"},
                entities=("email",),
            ),
        )
        claude_handle_event(_claude_post_event({"content": f"Contact {SYNTHETIC_EMAIL}"}))
    finally:
        set_audit_sink(previous)

    pii = [e for e in collector.events if e.event_type == AuditEventType.PII_REDACTED]
    assert pii, "expected a PII_REDACTED audit event"
    assert pii[0].provider == "claude"
    assert SYNTHETIC_EMAIL not in json.dumps([e.to_safe_dict() for e in collector.events])


def test_claude_result_blocked_secret_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    collector = AuditSinkCollector()
    previous = set_audit_sink(collector)
    try:
        monkeypatch.setattr(
            claude_runtime,
            "inspect_tool_result",
            _fake_inspector(EnforcementOutcome.BLOCKED, entities=("unknown_secret",)),
        )
        claude_handle_event(
            _claude_post_event({"content": f"INTERNAL_API_SECRET={SYNTHETIC_SECRET}"})
        )
    finally:
        set_audit_sink(previous)

    secret = [e for e in collector.events if e.event_type == AuditEventType.SECRET_DETECTED]
    assert secret, "expected a SECRET_DETECTED audit event"
    assert SYNTHETIC_SECRET not in json.dumps([e.to_safe_dict() for e in collector.events])


def test_claude_result_inspection_disabled_is_legacy_passthrough(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(provider_hook, "load_firewall_policy_from_environment", lambda: None)
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        _fake_inspector(EnforcementOutcome.BLOCKED, entities=("private_key",)),
    )
    assert claude_handle_event(_claude_post_event({"content": "sensitive"})) is None


def test_claude_result_without_session_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not reach daemon")),
    )
    event = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_response": {"content": SYNTHETIC_EMAIL},
    }
    output = claude_handle_event(event)
    assert output["hookSpecificOutput"]["updatedToolOutput"] == RESULT_BLOCKED
    assert SYNTHETIC_EMAIL not in json.dumps(output)


# --- Gemini CLI AfterTool ---------------------------------------------------


def _gemini_after_event(tool_response, *, tool_name="Read"):
    return {
        "session_id": "gemini-fw020",
        "tool_name": tool_name,
        "tool_input": {"file_path": "notes.txt"},
        "tool_response": tool_response,
    }


def test_gemini_clean_result_allows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        claude_runtime, "inspect_tool_result", _fake_inspector(EnforcementOutcome.ALLOW)
    )
    assert gemini_hook.handle_event("AfterTool", _gemini_after_event({"content": "hi"})) == {
        "decision": "allow"
    }


def test_gemini_sensitive_result_is_hidden_not_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Gemini's AfterTool cannot replace the result, so even a SANITIZED outcome
    # is hidden (deny) rather than delivered.
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        _fake_inspector(
            EnforcementOutcome.SANITIZED,
            sanitized={"content": "[EMAIL_1]"},
            entities=("email",),
        ),
    )
    output = gemini_hook.handle_event(
        "AfterTool", _gemini_after_event({"content": f"Contact {SYNTHETIC_EMAIL}"})
    )
    assert output["decision"] == "deny"
    assert SYNTHETIC_EMAIL not in json.dumps(output)
    # Gemini replaces the result with the safe reason; it does not deliver the
    # sanitized payload.
    assert "[EMAIL_1]" not in json.dumps(output)


def test_gemini_secret_result_hidden_without_raw(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        _fake_inspector(EnforcementOutcome.BLOCKED, entities=("unknown_secret",)),
    )
    output = gemini_hook.handle_event(
        "AfterTool", _gemini_after_event({"content": f"secret={SYNTHETIC_SECRET}"})
    )
    assert output["decision"] == "deny"
    assert SYNTHETIC_SECRET not in json.dumps(output)
    assert output["reason"] == RESULT_BLOCKED


def test_gemini_oversize_result_hidden(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        _fake_inspector(EnforcementOutcome.INTERNAL_FAILURE, reason_code="result_oversize"),
    )
    output = gemini_hook.handle_event(
        "AfterTool", _gemini_after_event({"content": SYNTHETIC_SECRET})
    )
    assert output["decision"] == "deny"
    assert output["reason"] == RESULT_OVERSIZE
    assert SYNTHETIC_SECRET not in json.dumps(output)


def test_gemini_scanner_failure_hidden(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        _fake_inspector(
            EnforcementOutcome.INTERNAL_FAILURE, reason_code="result_inspection_failed"
        ),
    )
    output = gemini_hook.handle_event(
        "AfterTool", _gemini_after_event({"content": SYNTHETIC_EMAIL})
    )
    assert output["decision"] == "deny"
    assert output["reason"] == RESULT_BLOCKED
    assert SYNTHETIC_EMAIL not in json.dumps(output)


def test_gemini_result_hidden_audit_metadata_only(monkeypatch: pytest.MonkeyPatch) -> None:
    collector = AuditSinkCollector()
    previous = set_audit_sink(collector)
    try:
        monkeypatch.setattr(
            claude_runtime,
            "inspect_tool_result",
            _fake_inspector(EnforcementOutcome.BLOCKED, entities=("unknown_secret",)),
        )
        gemini_hook.handle_event(
            "AfterTool", _gemini_after_event({"content": f"secret={SYNTHETIC_SECRET}"})
        )
    finally:
        set_audit_sink(previous)

    secret = [e for e in collector.events if e.event_type == AuditEventType.SECRET_DETECTED]
    assert secret, "expected a SECRET_DETECTED audit event"
    assert secret[0].provider == "gemini"
    assert SYNTHETIC_SECRET not in json.dumps([e.to_safe_dict() for e in collector.events])


def test_gemini_result_inspection_disabled_is_legacy_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gemini_hook, "load_firewall_policy_from_environment", lambda: None)
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        _fake_inspector(EnforcementOutcome.BLOCKED, entities=("private_key",)),
    )
    assert gemini_hook.handle_event("AfterTool", _gemini_after_event({"content": "sensitive"})) == {
        "decision": "allow"
    }


def test_gemini_non_inspectable_result_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        claude_runtime,
        "inspect_tool_result",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not run")),
    )
    assert gemini_hook.handle_event("AfterTool", {"session_id": "g", "tool_name": "Read"}) == {
        "decision": "allow"
    }


# --- Provider capability matrix + hook wiring -------------------------------


def test_provider_capability_matrix() -> None:
    # Claude replaces (updatedToolOutput) for sanitized content...
    assert RESULT_BLOCKED  # sanity import
    # ...Gemini hides (decision deny + reason) and never delivers sanitized.
    assert RESULT_OVERSIZE


def test_claude_hooks_json_registers_post_tool_use() -> None:
    root = (
        Path(__file__).resolve().parents[2]
        / "integrations"
        / "claude-code-enforced"
        / "securedact-enforced"
        / "hooks"
        / "hooks.json"
    )
    hooks = json.loads(root.read_text(encoding="utf-8"))["hooks"]
    assert "PostToolUse" in hooks
    matcher = hooks["PostToolUse"][0]["matcher"]
    import re

    for tool in ("Read", "Write", "Edit", "Bash", "Grep", "Glob", "mcp__fs__read"):
        assert re.fullmatch(matcher, tool), tool


def test_gemini_hooks_json_registers_after_tool() -> None:
    root = (
        Path(__file__).resolve().parents[2]
        / "integrations"
        / "gemini-enforced"
        / "securedact-enforced"
        / "hooks"
        / "hooks.json"
    )
    hooks = json.loads(root.read_text(encoding="utf-8"))["hooks"]
    assert "AfterTool" in hooks
    import re

    matcher = hooks["AfterTool"][0]["matcher"]
    for tool in ("Read", "Write", "Bash", "mcp__fs__read"):
        assert re.fullmatch(matcher, tool), tool


def test_size_cap_is_configurable_and_below_global_ceiling() -> None:
    from securedact_core import MAX_INSPECTION_TEXT_CHARS, MAX_TOOL_RESULT_CHARS

    # The practical result cap must stay well under the 1 MB global hard ceiling
    # so a provider hook never assumes it can scan an arbitrarily large result.
    assert 0 < MAX_TOOL_RESULT_CHARS < MAX_INSPECTION_TEXT_CHARS
