"""FW-042 — Agent Privacy Firewall backward-compatibility and security invariants.

This dedicated suite proves the firewall is strictly *additive*: existing
SecuRedact MCP tools, policies, detectors, and provider hook contracts keep
their previous behavior, while the new security guarantees hold. It is the
regression contract a firewall pull request must keep green.

It deliberately consolidates the invariants called out in the roadmap so they
live in one auditable place rather than scattered across feature tests.
"""

from __future__ import annotations

import json

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from securedact_core import (
    FirewallPolicy,
    FirewallRule,
    PrivacyAction,
    PrivacyEngine,
    RedactionRequest,
    SecuredactEngine,
    ToolContext,
    ToolOperation,
    build_production_engine,
    default_firewall_policy,
    evaluate_firewall,
    load_firewall_policy_from_environment,
    validate_firewall_policy,
)
from securedact_core.audit import capture_audit_events
from securedact_core.detectors import CredentialsDetector, RegexDetector
from securedact_core.policy_loader import (
    LocalPolicyLoader,
    PolicyLoadError,
    PolicyLoadErrorCode,
)
from securedact_enforced import gemini_hook
from securedact_enforced.adapter import EnforcementOutcome
from securedact_enforced.provider_hook import handle_event as claude_handle_event
from securedact_mcp.server import create_server


def _server():
    engine = PrivacyEngine([CredentialsDetector(), RegexDetector()], require_contextual=False)
    return create_server(engine)


async def _call(server, name: str, arguments: dict[str, object]):
    return await server._tool_manager._tools[name].run(arguments)


def _patch_gemini_firewall(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gemini_hook, "load_firewall_policy_from_environment", default_firewall_policy
    )


# --- 1. Original MCP tool contract is preserved (read_file is additive) --------


def test_exact_tool_registry_includes_additive_read_file() -> None:
    # The five original tools keep their names; securedact_read_file is additive.
    assert set(_server()._tool_manager._tools) == {
        "prepare_for_external_ai",
        "analyze_text",
        "redact_text",
        "restore_text",
        "create_safe_copy",
        "securedact_read_file",
    }


@pytest.mark.asyncio
async def test_original_five_tools_keep_contract() -> None:
    server = _server()
    canary = "alex.example@example.test"

    prepared = await _call(server, "prepare_for_external_ai", {"text": canary})
    assert prepared["status"] == "ok"
    assert prepared["sanitized_text"] == "[EMAIL_1]"
    assert canary not in str(prepared)
    assert "mapping" not in str(prepared)

    analyzed = await _call(server, "analyze_text", {"text": canary, "policy": "default"})
    assert analyzed["status"] == "ok"
    assert analyzed["counts"] == {"email": 1}

    redacted = await _call(server, "redact_text", {"text": f"Email {canary}; repeat {canary}"})
    assert redacted["status"] == "ok"
    assert redacted["sanitized_text"].count("[EMAIL_1]") == 2
    assert canary not in redacted["sanitized_text"]

    restored = await _call(
        server,
        "restore_text",
        {"text": "[EMAIL_1]", "mapping": {"[EMAIL_1]": canary}, "trusted_local_review": True},
    )
    assert restored["restored_text"] == canary

    with pytest.raises(ToolError):
        await _call(server, "analyze_text", {})


@pytest.mark.asyncio
async def test_securedact_read_file_blocks_protected_and_sanitizes_normal(tmp_path) -> None:
    server = _server()
    doc = tmp_path / "doc.txt"
    doc.write_text("Contact alex.example@example.test", encoding="utf-8")
    ok = await _call(server, "securedact_read_file", {"path": str(doc)})
    assert ok["status"] == "ok"
    assert "[EMAIL" in ok["sanitized_text"]

    secret = tmp_path / ".env"
    secret.write_text("TOKEN=abc", encoding="utf-8")
    blocked = await _call(server, "securedact_read_file", {"path": str(secret)})
    assert blocked["status"] == "blocked"


# --- 2. Legacy policy compatibility -------------------------------------------


def test_legacy_policy_without_firewall_section_loads(tmp_path) -> None:
    payload = {
        "schema_version": 1,
        "name": "legacy_only",
        "description": "synthetic legacy policy without a firewall section",
        "residual_validation_enabled": True,
        "residual_on_failure": "block",
        "expose_raw_values": False,
        "expose_mapping": False,
    }
    (tmp_path / "legacy.json").write_text(json.dumps(payload), encoding="utf-8")
    registry = LocalPolicyLoader(tmp_path).load()
    assert registry.get("legacy_only").firewall is None
    engine = SecuredactEngine.with_detectors(
        [CredentialsDetector(), RegexDetector()], require_contextual=False
    )
    engine.policies = registry
    result = engine.prepare(RedactionRequest(text="Contact alex.example@example.test"))
    assert result.status.value == "ok"
    assert result.sanitized_text != "Contact alex.example@example.test"


def test_firewall_defaults_follow_documented_contract() -> None:
    policy = default_firewall_policy()
    assert policy.enabled
    for path in (".env", "credentials.json", "id_rsa", ".ssh/id_rsa"):
        decision = evaluate_firewall(
            policy, ToolContext("claude", "Read", ToolOperation.FILE_READ, path=path)
        )
        assert decision.action == PrivacyAction.BLOCK, path
    normal = evaluate_firewall(
        policy, ToolContext("claude", "Read", ToolOperation.FILE_READ, path="src/app.py")
    )
    assert normal.action == PrivacyAction.ALLOW


# --- 3. Entity / detector compatibility ---------------------------------------


@pytest.mark.parametrize(
    "entity_type,text",
    [
        ("email", "Contact alex.example@example.test"),
        ("phone", "Call +1 202-555-0147"),
        ("iban", "IBAN NL91ABNA0417164300"),
        ("ipv4", "Connect to 203.0.113.10 for the synthetic service"),
        ("bsn", "BSN 123456782"),
    ],
)
def test_deterministic_detectors_still_find_core_entities(entity_type: str, text: str) -> None:
    engine = SecuredactEngine.with_detectors(
        [CredentialsDetector(), RegexDetector()], require_contextual=False
    )
    result = engine.prepare(RedactionRequest(text=text, policy="gdpr"))
    detected = set(result.counts)
    assert entity_type in detected


def test_known_credential_and_unknown_secret_still_detected() -> None:
    known = CredentialsDetector().detect(
        "aws_access_key_id=AKIAIOSFODNN7EXAMPLE password=SuperSecret123!"
    )
    assert any(
        d.entity_type.value in {"access_token", "password", "private_key", "github_token"}
        or d.rule in {"aws_access_key_id", "github_token", "private_key"}
        for d in known
    )
    assert any(
        d.entity_type.value == "unknown_secret"
        for d in CredentialsDetector().detect(
            "INTERNAL_API_SECRET=X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12"
        )
    )


def test_contextual_detector_remains_wired_unchanged() -> None:
    # PERSON / Article 9 rely on the contextual model; the firewall must not have
    # dropped or reordered it out of the production stack.
    engine = build_production_engine(require_contextual=False)
    names = [d.name for d in engine.detectors]
    assert "contextual_rules" in names
    assert names.index("credentials") < names.index("contextual_rules")


# --- 4. Firewall security invariants (Claude + Gemini) ------------------------


@pytest.mark.parametrize("path", [".env", "credentials.json", "id_rsa", ".ssh/id_rsa"])
def test_claude_hook_blocks_protected_reads(path: str) -> None:
    output = claude_handle_event(
        {
            "session_id": "session-bc",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": path},
        },
        firewall_policy=default_firewall_policy(),
    )
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_hook_allows_normal_read() -> None:
    assert (
        claude_handle_event(
            {
                "session_id": "session-bc",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "src/app.py"},
            },
            firewall_policy=default_firewall_policy(),
        )
        is None
    )


def test_claude_unknown_tool_is_inspected_not_silently_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []

    def fake_inspect(_session: object, payload: object):
        calls.append(payload)
        return EnforcementOutcome.BLOCKED, None

    monkeypatch.setattr(
        __import__("securedact_enforced").claude_runtime, "inspect_payload", fake_inspect
    )
    output = claude_handle_event(
        {
            "session_id": "session-bc",
            "hook_event_name": "PreToolUse",
            "tool_name": "MysteriousTool",
            "tool_input": {"file_path": ".env"},
        },
        firewall_policy=default_firewall_policy(),
    )
    assert calls == [{"file_path": ".env"}]
    assert output is not None
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("path", [".env", "credentials.json"])
def test_gemini_hook_blocks_protected_reads(path: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_gemini_firewall(monkeypatch)
    output = gemini_hook.handle_event(
        "BeforeTool",
        {
            "session_id": "gemini-bc",
            "tool_name": "Read",
            "tool_input": {"file_path": path},
        },
    )
    assert output["decision"] == "deny"


def test_gemini_hook_allows_normal_read(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_gemini_firewall(monkeypatch)
    assert gemini_hook.handle_event(
        "BeforeTool",
        {
            "session_id": "gemini-bc",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/app.py"},
        },
    ) == {"decision": "allow"}


def test_gemini_unknown_tool_is_inspected_not_silently_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_gemini_firewall(monkeypatch)
    calls: list[object] = []

    def fake_inspect(_session: object, _payload: object):
        calls.append(_payload)
        return EnforcementOutcome.BLOCKED, None, None

    monkeypatch.setattr(gemini_hook, "_inspect", fake_inspect)
    output = gemini_hook.handle_event(
        "BeforeTool",
        {
            "session_id": "gemini-bc",
            "tool_name": "MysteriousTool",
            "tool_input": {"file_path": ".env"},
        },
    )
    assert calls == [{"file_path": ".env"}]
    assert output["decision"] == "deny"


# --- 5. Safe-read security invariants -----------------------------------------


def test_safe_read_blocks_protected_and_traversal_and_symlink(tmp_path) -> None:
    from securedact_core import read_file_safely

    def redactor(text: str) -> str:
        return text

    secret = tmp_path / ".env"
    secret.write_text("TOKEN=abc", encoding="utf-8")
    assert (
        read_file_safely(str(secret), redactor=redactor, firewall=default_firewall_policy()).ok
        is False
    )

    nested = tmp_path / "sub"
    nested.mkdir()
    assert (
        read_file_safely(
            str(nested / ".." / ".env"), redactor=redactor, firewall=default_firewall_policy()
        ).ok
        is False
    )

    link = tmp_path / "link.env"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unsupported")
    assert (
        read_file_safely(str(link), redactor=redactor, firewall=default_firewall_policy()).ok
        is False
    )


def test_safe_read_sanitizes_normal_pii_and_blocks_unknown_secret(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECUREDACT_REQUIRE_FLAIR", "0")
    engine = SecuredactEngine(build_production_engine(require_contextual=False))

    pii = tmp_path / "doc.txt"
    pii.write_text("Contact alex.example@example.test", encoding="utf-8")
    ok = engine.read_file(str(pii))
    assert ok.ok and "[EMAIL" in ok.sanitized_text

    secret = tmp_path / "config.txt"
    secret.write_text("INTERNAL_API_SECRET=X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12", encoding="utf-8")
    blocked = engine.read_file(str(secret))
    assert not blocked.ok and blocked.reason_code == "content_blocked"


# --- 6. Policy invariant: never ALLOW a protected path ------------------------


def test_policy_allow_of_protected_path_is_rejected() -> None:
    bad = FirewallPolicy(
        rules=[
            FirewallRule(
                id="allow_env",
                operations=[ToolOperation.FILE_READ],
                names=[".env"],
                action=PrivacyAction.ALLOW,
            )
        ]
    )
    with pytest.raises(ValueError):
        validate_firewall_policy(bad)


def test_policy_loaded_allow_of_protected_path_is_invariant_violation(tmp_path) -> None:
    payload = {
        "schema_version": 1,
        "name": "fw_bad",
        "description": "synthetic firewall policy that would ALLOW a protected path",
        "firewall": {
            "enabled": True,
            "rules": [
                {
                    "id": "allow_env",
                    "operations": ["file_read"],
                    "names": [".env"],
                    "action": "allow",
                }
            ],
        },
        "residual_validation_enabled": True,
        "residual_on_failure": "block",
        "expose_raw_values": False,
        "expose_mapping": False,
    }
    (tmp_path / "fw_bad.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(PolicyLoadError) as exc:
        LocalPolicyLoader(tmp_path).load()
    assert exc.value.code == PolicyLoadErrorCode.INVARIANT_VIOLATION


# --- 7. Audit no-leak invariant ----------------------------------------------


def test_audit_security_events_never_serialize_raw_secrets(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECUREDACT_REQUIRE_FLAIR", "0")
    engine = SecuredactEngine.with_detectors(
        [CredentialsDetector(), RegexDetector()], require_contextual=False
    )
    secret = "SUPER_SECRET_TEST_VALUE_93kLmNoPqRsTuVwXyZ"  # noqa: S105
    target = tmp_path / "x.txt"
    target.write_text(f"INTERNAL_API_SECRET={secret}", encoding="utf-8")
    with capture_audit_events() as collector:
        result = engine.read_file(str(target))
    assert not result.ok
    rendered = json.dumps([e.to_safe_dict() for e in collector.events])
    assert secret not in rendered


# --- 8. Firewall-disabled compatibility (distinct from privacy engine) --------


def test_firewall_disabled_keeps_legacy_host_behavior_but_privacy_still_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECUREDACT_FIREWALL_ENABLED", "0")
    assert load_firewall_policy_from_environment() is None

    # Legacy host behavior: hooks no longer enforce the path policy.
    assert (
        claude_handle_event(
            {
                "session_id": "session-bc",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": ".env"},
            }
        )
        is None
    )

    # The privacy engine itself is NOT disabled: explicit SecuRedact tools still
    # redact PII independent of the firewall switch.
    engine = SecuredactEngine.with_detectors(
        [CredentialsDetector(), RegexDetector()], require_contextual=False
    )
    result = engine.prepare(RedactionRequest(text="Contact alex.example@example.test"))
    assert result.status.value == "ok"
    assert result.sanitized_text != "Contact alex.example@example.test"
