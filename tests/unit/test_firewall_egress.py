"""Egress protection (FW-030) and approval semantics (FW-032) for network tools.

These tests cover:
* reliable NETWORK_WRITE classification (HTTP verbs, webhook/upload/submit/push);
* destination extraction + internal/external/unknown scope;
* recursive outbound payload scanning reusing the privacy engine;
* known + UNKNOWN secrets blocked; PII policy-driven;
* network reads not treated as writes;
* fail-closed on oversize / scanner failure;
* metadata-only EGRESS_BLOCKED audit events;
* provider enforcement (Claude PreToolUse deny / Gemini BeforeTool deny);
* approval (REQUIRE_APPROVAL) mapping to host deny with APPROVAL_REQUIRED audit.
"""

from __future__ import annotations

import pytest

from securedact_core import (
    AuditEventType,
    DestinationScope,
    FirewallPolicy,
    FirewallRule,
    ToolOperation,
    classify_destination_scope,
    classify_tool,
    default_firewall_policy,
    normalize_destination,
)
from securedact_core.audit import AuditSinkCollector, set_audit_sink
from securedact_enforced import claude_runtime, gemini_hook
from securedact_enforced.adapter import EnforcementOutcome, PrivacyEnforcer
from securedact_enforced.provider_hook import handle_event
from tests.unit.test_confidence_pseudonymization import _engine as _core_engine

SYNTHETIC_TOKEN = "Bearer abcdef0123456789abcdef0123456789"  # noqa: S105
SYNTHETIC_EMAIL = "jan.jansen@example.test"


def _core_enforcer() -> PrivacyEnforcer:
    return PrivacyEnforcer(_core_engine())


def _use_core_inspector(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route the Claude warmed-runtime inspector at the real privacy engine.

    The daemon contract returns ``(EnforcementOutcome, sanitized)``, so unwrap
    the ``EnforcementResult`` produced by the enforcer.
    """

    def inspect(_session: object, payload: object):
        result, sanitized = _core_enforcer().inspect_payload(payload)
        return result.outcome, sanitized

    monkeypatch.setattr(claude_runtime, "inspect_payload", inspect)


# --- Destination extraction + scope (FW-030 §5, §6) ---------------------------


def test_normalize_destination_strips_path_query_and_credentials() -> None:
    assert (
        normalize_destination("https://external.example/x?token=secret#frag") == "external.example"
    )
    assert normalize_destination("http://user:pass@host.example:8080/path") == "host.example"
    assert normalize_destination("https://api.example.test:443/v1") == "api.example.test"
    assert normalize_destination("plainhost.local") == "plainhost.local"
    assert normalize_destination("") is None
    assert normalize_destination(None) is None


def test_normalize_destination_ssh_and_email_forms() -> None:
    assert normalize_destination("git@github.com:org/repo.git") == "github.com"
    assert normalize_destination("avery@example.test") == "example.test"
    assert normalize_destination("192.168.1.10") == "192.168.1.10"


def test_classify_destination_scope_internal_external_unknown() -> None:
    assert classify_destination_scope("https://localhost/api") == DestinationScope.INTERNAL
    assert classify_destination_scope("http://127.0.0.1/x") == DestinationScope.INTERNAL
    assert classify_destination_scope("http://10.0.0.5/x") == DestinationScope.INTERNAL
    assert classify_destination_scope("https://internal.corp/x") == DestinationScope.INTERNAL
    assert classify_destination_scope("https://external.example/x") == DestinationScope.EXTERNAL
    assert classify_destination_scope(None) == DestinationScope.UNKNOWN
    assert classify_destination_scope("https://anything.example") == DestinationScope.EXTERNAL


def test_classify_destination_scope_allowlist_is_internal() -> None:
    scope = classify_destination_scope(
        "https://api.internal.example/x", allowlist_domains=["internal.example"]
    )
    assert scope == DestinationScope.INTERNAL
    # Unknown destination is never silently trusted.
    assert classify_destination_scope(None, allowlist_domains=["internal.example"]) == (
        DestinationScope.UNKNOWN
    )


# --- NETWORK_WRITE classification (FW-030 §3, §4) -----------------------------


def test_classify_tool_network_write_via_http_method() -> None:
    post = classify_tool(
        "claude", "mcp__http__request", {"method": "POST", "url": "https://x.test"}
    )
    assert post.operation == ToolOperation.NETWORK_WRITE
    assert post.destination == "https://x.test"
    get = classify_tool("claude", "mcp__http__request", {"method": "GET", "url": "https://x.test"})
    assert get.operation == ToolOperation.NETWORK_READ


def test_classify_tool_network_write_aliases() -> None:
    for name in ("mcp__webhook__send", "mcp__files__upload", "mcp__form__submit", "mcp__git__push"):
        ctx = classify_tool("claude", name, {"url": "https://x.test/a"})
        assert ctx.operation == ToolOperation.NETWORK_WRITE, name


def test_classify_tool_read_vs_write_not_confused() -> None:
    search = classify_tool("claude", "WebSearch", {"query": "weather"})
    assert search.operation == ToolOperation.NETWORK_READ
    post = classify_tool("claude", "mcp__http__post", {"url": "https://x.test"})
    assert post.operation == ToolOperation.NETWORK_WRITE


def test_classify_tool_git_push_extracts_remote_destination() -> None:
    ctx = classify_tool(
        "claude", "mcp__git__push", {"remote": "git@github.com:org/repo.git", "branch": "main"}
    )
    assert ctx.operation == ToolOperation.NETWORK_WRITE
    assert ctx.destination == "git@github.com:org/repo.git"


def test_classify_tool_destination_scope_populated() -> None:
    ctx = classify_tool("claude", "mcp__http__post", {"url": "https://external.example/x"})
    assert ctx.destination_scope == DestinationScope.EXTERNAL
    local = classify_tool("claude", "mcp__http__post", {"url": "http://localhost/x"})
    assert local.destination_scope == DestinationScope.INTERNAL


def test_firewall_rule_destination_scope_blocks_external_write() -> None:
    policy = FirewallPolicy(
        rules=[
            FirewallRule(
                id="block_external_egress",
                operations=[ToolOperation.NETWORK_WRITE],
                destination_scopes=[DestinationScope.EXTERNAL],
                action="block",
            )
        ]
    )
    ctx = classify_tool("claude", "mcp__http__post", {"url": "https://external.example"})
    from securedact_core.firewall import evaluate_firewall

    assert evaluate_firewall(policy, ctx).action == "block"


# --- Claude provider enforcement (FW-030 §14, FW-032 §10) ---------------------


def test_claude_egress_post_with_token_blocked_and_no_raw_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_core_inspector(monkeypatch)
    collector = AuditSinkCollector()
    previous = set_audit_sink(collector)
    try:
        output = handle_event(
            {
                "session_id": "session-egress",
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__http__post",
                "tool_input": {
                    "url": "https://external.example/x",
                    "headers": {"Authorization": SYNTHETIC_TOKEN},
                    "json": {"email": SYNTHETIC_EMAIL},
                },
            },
            firewall_policy=default_firewall_policy(),
        )
    finally:
        set_audit_sink(previous)

    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    rendered = __import__("json").dumps(output)
    assert SYNTHETIC_TOKEN not in rendered
    assert SYNTHETIC_EMAIL not in rendered
    assert any(e.event_type == AuditEventType.EGRESS_BLOCKED for e in collector.events)


def test_claude_egress_structured_payload_recursive_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_core_inspector(monkeypatch)
    output = handle_event(
        {
            "session_id": "session-egress",
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__http__post",
            "tool_input": {
                "url": "https://external.example",
                "headers": {"Authorization": SYNTHETIC_TOKEN},
                "json": {"email": SYNTHETIC_EMAIL},
            },
        },
        firewall_policy=default_firewall_policy(),
    )
    # Secret present -> blocked, not silently redacted-and-sent.
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_egress_unknown_secret_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_core_inspector(monkeypatch)
    output = handle_event(
        {
            "session_id": "session-egress",
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__http__post",
            "tool_input": {
                "url": "https://external.example/x",
                "headers": {
                    "Authorization": "Bearer abcdef0123456789abcdef0123456789",
                    "X-Private-Key": "-----BEGIN PRIVATE KEY-----\nabcdef0123456789\n-----END PRIVATE KEY-----",
                },
            },
        },
        firewall_policy=default_firewall_policy(),
    )
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_egress_pii_external_redacted_not_sent_raw(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_core_inspector(monkeypatch)
    output = handle_event(
        {
            "session_id": "session-egress",
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__http__post",
            "tool_input": {
                "url": "https://external.example/x",
                "json": {"email": SYNTHETIC_EMAIL},
            },
        },
        firewall_policy=default_firewall_policy(),
    )
    # PII-only external write is redacted (policy-driven), not blocked.
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "allow"
    rendered = __import__("json").dumps(output)
    assert SYNTHETIC_EMAIL not in rendered
    assert "[EMAIL" in rendered


def test_claude_egress_clean_post_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_core_inspector(monkeypatch)
    output = handle_event(
        {
            "session_id": "session-egress",
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__http__post",
            "tool_input": {"url": "https://external.example/x", "json": {"status": "ok"}},
        },
        firewall_policy=default_firewall_policy(),
    )
    assert output is None


def test_claude_egress_get_search_not_treated_as_write(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_core_inspector(monkeypatch)
    output = handle_event(
        {
            "session_id": "session-egress",
            "hook_event_name": "PreToolUse",
            "tool_name": "WebSearch",
            "tool_input": {"query": f"contact {SYNTHETIC_EMAIL}"},
        },
        firewall_policy=default_firewall_policy(),
    )
    # Network read with PII is sanitized (redacted), not blocked as a write.
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert SYNTHETIC_EMAIL not in __import__("json").dumps(output)


def test_claude_egress_oversize_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        claude_runtime,
        "inspect_payload",
        lambda *_: (_ for _ in ()).throw(
            AssertionError("daemon must not be called on oversize egress")
        ),
    )
    monkeypatch.setattr(
        __import__("securedact_enforced.provider_hook", fromlist=["x"]),
        "MAX_TOOL_RESULT_CHARS",
        10,
    )
    output = handle_event(
        {
            "session_id": "session-egress",
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__http__post",
            "tool_input": {"url": "https://external.example/x", "body": "x" * 50},
        },
        firewall_policy=default_firewall_policy(),
    )
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_egress_scanner_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        claude_runtime,
        "inspect_payload",
        lambda _s, _p: (EnforcementOutcome.INTERNAL_FAILURE, None),
    )
    output = handle_event(
        {
            "session_id": "session-egress",
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__http__post",
            "tool_input": {"url": "https://external.example/x", "body": "data"},
        },
        firewall_policy=default_firewall_policy(),
    )
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_egress_external_pii_requires_approval_when_policy_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_core_inspector(monkeypatch)
    policy = default_firewall_policy()
    object.__setattr__(policy, "egress_external_require_approval", True)
    collector = AuditSinkCollector()
    previous = set_audit_sink(collector)
    try:
        output = handle_event(
            {
                "session_id": "session-egress",
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__http__post",
                "tool_input": {
                    "url": "https://external.example/x",
                    "json": {"email": SYNTHETIC_EMAIL},
                },
            },
            firewall_policy=policy,
        )
    finally:
        set_audit_sink(previous)
    # External PII write requires approval -> host deny (user override).
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert any(e.event_type == AuditEventType.APPROVAL_REQUIRED for e in collector.events)


def test_claude_egress_internal_pii_not_upgraded_when_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_core_inspector(monkeypatch)
    policy = default_firewall_policy()
    object.__setattr__(policy, "egress_external_require_approval", True)
    object.__setattr__(policy, "egress_allowlist_domains", ["internal.example"])
    output = handle_event(
        {
            "session_id": "session-egress",
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__http__post",
            "tool_input": {
                "url": "https://api.internal.example/x",
                "json": {"email": SYNTHETIC_EMAIL},
            },
        },
        firewall_policy=policy,
    )
    # Internal/allowlisted destination is trusted: redacted-and-sent, not approval.
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert SYNTHETIC_EMAIL not in __import__("json").dumps(output)


# --- Gemini provider enforcement (FW-030 §14) ---------------------------------


def _gemini_core_inspector(monkeypatch: pytest.MonkeyPatch) -> None:
    def inspect(_session: object, payload: object):
        result, sanitized = _core_enforcer().inspect_payload(payload)
        return result.outcome, result.prepare_outcome, sanitized

    monkeypatch.setattr(gemini_hook, "_inspect", inspect)


def test_gemini_egress_post_with_token_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    _gemini_core_inspector(monkeypatch)
    monkeypatch.setattr(
        gemini_hook, "load_firewall_policy_from_environment", default_firewall_policy
    )
    collector = AuditSinkCollector()
    previous = set_audit_sink(collector)
    try:
        output = gemini_hook.handle_event(
            "BeforeTool",
            {
                "session_id": "gemini-egress",
                "tool_name": "mcp__http__post",
                "tool_input": {
                    "url": "https://external.example/x",
                    "headers": {"Authorization": SYNTHETIC_TOKEN},
                },
            },
        )
    finally:
        set_audit_sink(previous)
    assert output["decision"] == "deny"
    assert SYNTHETIC_TOKEN not in __import__("json").dumps(output)
    assert any(e.event_type == AuditEventType.EGRESS_BLOCKED for e in collector.events)


def test_gemini_egress_structured_payload_recursive_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    _gemini_core_inspector(monkeypatch)
    monkeypatch.setattr(
        gemini_hook, "load_firewall_policy_from_environment", default_firewall_policy
    )
    output = gemini_hook.handle_event(
        "BeforeTool",
        {
            "session_id": "gemini-egress",
            "tool_name": "mcp__http__post",
            "tool_input": {
                "url": "https://external.example",
                "headers": {"Authorization": SYNTHETIC_TOKEN},
                "json": {"email": SYNTHETIC_EMAIL},
            },
        },
    )
    assert output["decision"] == "deny"
    assert SYNTHETIC_EMAIL not in __import__("json").dumps(output)


def test_gemini_egress_clean_post_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    _gemini_core_inspector(monkeypatch)
    monkeypatch.setattr(
        gemini_hook, "load_firewall_policy_from_environment", default_firewall_policy
    )
    output = gemini_hook.handle_event(
        "BeforeTool",
        {
            "session_id": "gemini-egress",
            "tool_name": "mcp__http__post",
            "tool_input": {"url": "https://external.example/x", "json": {"status": "ok"}},
        },
    )
    assert output == {"decision": "allow"}


def test_gemini_egress_oversize_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gemini_hook,
        "_inspect",
        lambda _s, _p: (_ for _ in ()).throw(
            AssertionError("inspector must not run on oversize egress")
        ),
    )
    monkeypatch.setattr(gemini_hook, "MAX_TOOL_RESULT_CHARS", 10)
    monkeypatch.setattr(
        gemini_hook, "load_firewall_policy_from_environment", default_firewall_policy
    )
    output = gemini_hook.handle_event(
        "BeforeTool",
        {
            "session_id": "gemini-egress",
            "tool_name": "mcp__http__post",
            "tool_input": {"url": "https://external.example/x", "body": "x" * 50},
        },
    )
    assert output["decision"] == "deny"


def test_gemini_egress_external_pii_requires_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    _gemini_core_inspector(monkeypatch)
    policy = default_firewall_policy()
    object.__setattr__(policy, "egress_external_require_approval", True)
    monkeypatch.setattr(gemini_hook, "load_firewall_policy_from_environment", lambda: policy)
    collector = AuditSinkCollector()
    previous = set_audit_sink(collector)
    try:
        output = gemini_hook.handle_event(
            "BeforeTool",
            {
                "session_id": "gemini-egress",
                "tool_name": "mcp__http__post",
                "tool_input": {
                    "url": "https://external.example/x",
                    "json": {"email": SYNTHETIC_EMAIL},
                },
            },
        )
    finally:
        set_audit_sink(previous)
    assert output["decision"] == "deny"
    assert any(e.event_type == AuditEventType.APPROVAL_REQUIRED for e in collector.events)
