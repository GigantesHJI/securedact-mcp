"""Privacy-preserving audit-event tests for the Agent Privacy Firewall (FW-033).

These tests assert that audit events are emitted for security-relevant firewall
actions and that no raw sensitive value (password, API key, token, PII text, or
redaction mapping) can appear in the serialized event output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from securedact_core import (
    AuditEvent,
    AuditEventType,
    AuditSinkCollector,
    build_audit_event,
    capture_audit_events,
    default_firewall_policy,
)
from securedact_core.audit import emit_audit_event, set_audit_sink
from securedact_core.detectors import RegexDetector
from securedact_enforced.provider_hook import handle_event as claude_handle_event

SYNTHETIC_SECRET = "SUPER_SECRET_TEST_VALUE_93kLmNoPqRsTuVwXyZ"  # noqa: S105
SYNTHETIC_EMAIL = "jan.jansen@example.test"


def _securedact_core():
    return __import__("securedact_core")


def test_raw_value_cannot_appear_in_serialized_event() -> None:
    event = build_audit_event(
        AuditEventType.SECRET_DETECTED,
        action="block",
        reason_code="content_blocked",
        entity_types=("unknown_secret",),
        count=1,
        source="config.txt",
        # A developer mistakenly tries to stash the raw value here.
        metadata={"value": SYNTHETIC_SECRET, "secret": SYNTHETIC_SECRET, "count": 1},
    )
    serialized = event.to_safe_dict()
    rendered = __import__("json").dumps(serialized, sort_keys=True)
    assert SYNTHETIC_SECRET not in rendered
    assert "value" not in serialized.get("metadata", {})
    assert "secret" not in serialized.get("metadata", {})
    # Safe scalar metadata survives.
    assert serialized["metadata"]["count"] == 1


def test_nested_non_scalar_metadata_is_dropped() -> None:
    event = build_audit_event(
        AuditEventType.PII_REDACTED,
        action="redact",
        metadata={"count": 3, "leak": {"raw": SYNTHETIC_EMAIL}},
    )
    serialized = event.to_safe_dict()
    assert SYNTHETIC_EMAIL not in __import__("json").dumps(serialized)
    assert "leak" not in serialized.get("metadata", {})


def test_emit_never_raises_on_broken_sink() -> None:
    def boom(_event: AuditEvent) -> None:
        raise RuntimeError("sink failure")

    previous = set_audit_sink(boom)
    try:
        # Must not raise even though the sink explodes.
        emit_audit_event(build_audit_event(AuditEventType.FILE_BLOCKED, action="block"))
    finally:
        set_audit_sink(previous)


def test_securedact_read_file_env_blocked_emits_file_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECUREDACT_REQUIRE_FLAIR", "0")
    engine = _securedact_core().SecuredactEngine.with_detectors([RegexDetector()])

    secret = tmp_path / ".env"
    secret.write_text(f"TOKEN={SYNTHETIC_SECRET}", encoding="utf-8")

    with capture_audit_events() as collector:
        result = engine.read_file(str(secret))
    assert not result.ok
    assert result.reason_code == "protected_path_blocked"

    events = [e for e in collector.events if e.event_type == AuditEventType.FILE_BLOCKED]
    assert events, "expected a FILE_BLOCKED audit event"
    assert len(events) == 1
    rendered = __import__("json").dumps([e.to_safe_dict() for e in events], sort_keys=True)
    assert SYNTHETIC_SECRET not in rendered


def test_securedact_read_file_pii_redacted_emits_pii_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECUREDACT_REQUIRE_FLAIR", "0")
    engine = _securedact_core().SecuredactEngine.with_detectors([RegexDetector()])

    doc = tmp_path / "doc.txt"
    doc.write_text(f"Contact {SYNTHETIC_EMAIL} for details", encoding="utf-8")

    with capture_audit_events() as collector:
        result = engine.read_file(str(doc))
    assert result.ok
    assert "[EMAIL" in result.sanitized_text

    pii = [e for e in collector.events if e.event_type == AuditEventType.PII_REDACTED]
    assert pii, "expected a PII_REDACTED audit event"
    rendered = __import__("json").dumps([e.to_safe_dict() for e in pii], sort_keys=True)
    assert SYNTHETIC_EMAIL not in rendered
    assert "email" in pii[0].entity_types


def test_securedact_read_file_unknown_secret_emits_secret_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECUREDACT_REQUIRE_FLAIR", "0")
    from securedact_core import build_production_engine

    engine = _securedact_core().SecuredactEngine(build_production_engine(require_contextual=False))

    config = tmp_path / "config.txt"
    config.write_text(f"INTERNAL_API_SECRET={SYNTHETIC_SECRET}", encoding="utf-8")

    with capture_audit_events() as collector:
        result = engine.read_file(str(config))
    assert not result.ok
    assert result.reason_code == "content_blocked"

    secret_events = [e for e in collector.events if e.event_type == AuditEventType.SECRET_DETECTED]
    assert secret_events, "expected a SECRET_DETECTED audit event"
    assert "unknown_secret" in secret_events[0].entity_types
    rendered = __import__("json").dumps(
        [e.to_safe_dict() for e in collector.events], sort_keys=True
    )
    assert SYNTHETIC_SECRET not in rendered


def test_securedact_read_file_benign_emits_no_security_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECUREDACT_REQUIRE_FLAIR", "0")
    engine = _securedact_core().SecuredactEngine.with_detectors([RegexDetector()])

    doc = tmp_path / "notes.txt"
    doc.write_text("Just some harmless project notes.", encoding="utf-8")

    with capture_audit_events() as collector:
        result = engine.read_file(str(doc))
    assert result.ok
    security_events = [
        e
        for e in collector.events
        if e.event_type
        in {
            AuditEventType.FILE_BLOCKED,
            AuditEventType.SECRET_DETECTED,
            AuditEventType.PII_REDACTED,
        }
    ]
    assert not security_events, "benign read must not raise a false security event"


def test_claude_hook_blocks_env_and_emits_tool_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collector = AuditSinkCollector()
    previous = set_audit_sink(collector)
    try:
        output = claude_handle_event(
            {
                "session_id": "session-audit",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": ".env"},
            },
            firewall_policy=default_firewall_policy(),
        )
    finally:
        set_audit_sink(previous)

    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    tool_blocked = [e for e in collector.events if e.event_type == AuditEventType.TOOL_BLOCKED]
    assert tool_blocked, "expected a TOOL_BLOCKED audit event"
    assert tool_blocked[0].provider == "claude"
    assert tool_blocked[0].tool_name == "Read"
    assert tool_blocked[0].operation == "file_read"


def test_gemini_hook_blocks_env_and_emits_tool_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securedact_enforced import gemini_hook

    monkeypatch.setattr(
        gemini_hook, "load_firewall_policy_from_environment", default_firewall_policy
    )
    collector = AuditSinkCollector()
    previous = set_audit_sink(collector)
    try:
        output = gemini_hook.handle_event(
            "BeforeTool",
            {
                "session_id": "gemini-audit",
                "tool_name": "Read",
                "tool_input": {"file_path": ".env"},
            },
        )
    finally:
        set_audit_sink(previous)

    assert output["decision"] == "deny"
    tool_blocked = [e for e in collector.events if e.event_type == AuditEventType.TOOL_BLOCKED]
    assert tool_blocked, "expected a TOOL_BLOCKED audit event"
    assert tool_blocked[0].provider == "gemini"


def test_requires_approval_emits_approval_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securedact_core import FirewallPolicy, FirewallRule, ToolOperation

    policy = FirewallPolicy(
        rules=[
            FirewallRule(
                id="approve_scripts",
                operations=[ToolOperation.FILE_WRITE],
                extensions=["sh"],
                action="allow",
                requires_approval=True,
            )
        ]
    )
    collector = AuditSinkCollector()
    previous = set_audit_sink(collector)
    try:
        output = claude_handle_event(
            {
                "session_id": "session-audit",
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_input": {"file_path": "deploy.sh"},
            },
            firewall_policy=policy,
        )
    finally:
        set_audit_sink(previous)

    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    approval = [e for e in collector.events if e.event_type == AuditEventType.APPROVAL_REQUIRED]
    assert approval, "expected an APPROVAL_REQUIRED audit event"
    assert approval[0].action == "review"
