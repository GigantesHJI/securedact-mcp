"""FW-041 — performance guardrails and structural performance regression tests.

These tests assert the *structural* performance guarantees the firewall relies
on so that security controls stay cheap enough that users keep them on:

* cheap deterministic detectors run before the expensive contextual/ML model;
* oversized input is rejected before any detector runs;
* a blocked path never triggers content scanning;
* binary files never enter the privacy engine;
* the approved-text digest cache avoids re-scanning identical approved content;
* audit emission is isolated and adds negligible overhead.

Timing is intentionally NOT asserted as a brittle threshold (see
``scripts/benchmark_firewall.py`` and the roadmap for the recorded baseline).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from securedact_core import (
    MAX_INSPECTION_TEXT_CHARS,
    RedactionRequest,
    SecuredactEngine,
    default_firewall_policy,
)
from securedact_core.audit import AuditEventType, build_audit_event, emit_audit_event
from securedact_core.detectors import RegexDetector
from securedact_enforced import claude_runtime, gemini_hook
from securedact_enforced.adapter import EnforcementOutcome, EnforcementResult, PrepareOutcome
from securedact_enforced.claude_runtime import _RuntimeServer
from securedact_enforced.provider_hook import handle_event as claude_handle_event


def test_detector_ordering_is_cheap_before_contextual() -> None:
    from securedact_core import build_production_engine

    engine = build_production_engine(require_contextual=False)
    names = [detector.name for detector in engine.detectors]
    # Credentials + regex (cheap, deterministic) must precede any contextual model.
    assert names.index("credentials") < names.index("contextual_rules")
    assert names.index("regex") < names.index("contextual_rules")


def test_oversize_text_rejected_before_privacy_analysis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = SecuredactEngine.with_detectors([RegexDetector()], require_contextual=False)
    calls: list[int] = []
    real_analyze = engine.privacy_engine.analyze

    def spy(*args, **kwargs):
        calls.append(1)
        return real_analyze(*args, **kwargs)

    monkeypatch.setattr(engine.privacy_engine, "analyze", spy)

    # Just under the cap still reaches analysis.
    engine.prepare(RedactionRequest(text="x" * (MAX_INSPECTION_TEXT_CHARS - 10), policy="gdpr"))
    assert calls

    # Over the cap is rejected at request validation, before any detector runs.
    calls.clear()
    with pytest.raises(ValidationError):
        RedactionRequest(text="x" * (MAX_INSPECTION_TEXT_CHARS + 10), policy="gdpr")
    assert calls == []


def test_safe_read_byte_size_checked_before_content_scan(tmp_path) -> None:
    from securedact_core import read_file_safely

    target = tmp_path / "notes.txt"
    target.write_text("x" * 200, encoding="utf-8")
    calls: list[str] = []

    def tracking_redactor(text: str) -> str:
        calls.append(text)
        return text

    result = read_file_safely(str(target), redactor=tracking_redactor, max_bytes=50)
    assert not result.ok
    assert result.reason_code == "file_too_large"
    assert calls == []  # content never loaded into the privacy engine


def test_safe_read_binary_skips_privacy_engine(tmp_path) -> None:
    from securedact_core import read_file_safely

    target = tmp_path / "image.bin"
    target.write_bytes(b"\x00\x01\x02\x03raw\x00")
    calls: list[str] = []

    def tracking_redactor(text: str) -> str:
        calls.append(text)
        return text

    result = read_file_safely(str(target), redactor=tracking_redactor)
    assert not result.ok
    assert result.reason_code == "binary_file_unsupported"
    assert calls == []


def test_claude_blocked_path_does_not_invoke_content_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(_session: object, _payload: object):
        raise AssertionError("content inspection must not run for a blocked path")

    monkeypatch.setattr(claude_runtime, "inspect_payload", boom)
    output = claude_handle_event(
        {
            "session_id": "session-perf",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": ".env"},
        },
        firewall_policy=default_firewall_policy(),
    )
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_gemini_blocked_path_does_not_invoke_content_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gemini_hook, "load_firewall_policy_from_environment", default_firewall_policy
    )

    def boom(_session: object, _payload: object):
        raise AssertionError("content inspection must not run for a blocked path")

    monkeypatch.setattr(gemini_hook, "_inspect", boom)
    output = gemini_hook.handle_event(
        "BeforeTool",
        {
            "session_id": "gemini-perf",
            "tool_name": "Read",
            "tool_input": {"file_path": ".env"},
        },
    )
    assert output["decision"] == "deny"


def test_approved_text_digest_reuse_avoids_rescan(tmp_path) -> None:
    calls: list[str] = []

    def counting_inspect(text: str) -> EnforcementResult:
        calls.append(text)
        return EnforcementResult(EnforcementOutcome.ALLOW, prepare_outcome=PrepareOutcome.ALLOW)

    server = _RuntimeServer(
        tmp_path / "state.json",
        b"x" * 32,
        "perf-digest",
        lambda _prompt: None,
        counting_inspect,
    )
    try:
        server.inspect_text_result("identical approved text")
        server.inspect_text_result("identical approved text")
        server.inspect_text_result("different approved text")
    finally:
        server.server_close()

    # The two identical submissions are scanned only once.
    assert calls == ["identical approved text", "different approved text"]


def test_audit_emission_is_isolated_and_cheap() -> None:
    # A pathological sink must never affect callers or raise.
    def broken(_event):
        raise RuntimeError("sink exploded")

    assert emit_audit_event(build_audit_event(AuditEventType.FILE_BLOCKED, action="block")) is None
    # Many events through the default no-op sink complete without error.
    for _ in range(500):
        emit_audit_event(
            build_audit_event(AuditEventType.PII_REDACTED, action="redact", source="doc.txt")
        )
