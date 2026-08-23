"""Unit tests for the agent privacy firewall policy engine."""

from __future__ import annotations

import pytest

from securedact_core import (
    FirewallPolicy,
    FirewallRule,
    PrivacyAction,
    ToolContext,
    ToolOperation,
    classify_tool,
    default_firewall_policy,
    evaluate_firewall,
    load_firewall_policy_from_environment,
    rule_allows_protected,
    validate_firewall_policy,
)
from securedact_core.policy_loader import LocalPolicyLoader, PolicyLoadError, PolicyLoadErrorCode
from securedact_enforced.adapter import EnforcementOutcome, firewall_decision_outcome


def _ctx(tool_name: str, operation: ToolOperation, path: str | None = None) -> ToolContext:
    return ToolContext(provider="claude", tool_name=tool_name, operation=operation, path=path)


def test_default_firewall_blocks_protected_paths() -> None:
    policy = default_firewall_policy()
    for path in (
        ".env",
        ".env.local",
        "id_rsa",
        "config.pem",
        "credentials.json",
        "service-account.json",
        ".ssh/id_rsa",
        ".aws/credentials",
    ):
        decision = evaluate_firewall(policy, _ctx("Read", ToolOperation.FILE_READ, path))
        assert decision.action == PrivacyAction.BLOCK, path
    assert (
        evaluate_firewall(policy, _ctx("Read", ToolOperation.FILE_READ, "src/app.py")).action
        == PrivacyAction.ALLOW
    )
    assert (
        evaluate_firewall(policy, _ctx("Read", ToolOperation.FILE_READ, "notes.txt")).action
        == PrivacyAction.ALLOW
    )


def test_firewall_first_rule_wins_and_default_action() -> None:
    policy = FirewallPolicy(
        default_action=PrivacyAction.ALLOW,
        rules=[
            FirewallRule(
                id="allow_docs",
                operations=[ToolOperation.FILE_READ],
                path_fragments=["docs/"],
                action=PrivacyAction.ALLOW,
            ),
            FirewallRule(
                id="block_env",
                operations=[ToolOperation.FILE_READ],
                names=[".env"],
                action=PrivacyAction.BLOCK,
            ),
        ],
    )
    assert (
        evaluate_firewall(policy, _ctx("Read", ToolOperation.FILE_READ, "docs/.env")).action
        == PrivacyAction.ALLOW
    )
    assert (
        evaluate_firewall(policy, _ctx("Read", ToolOperation.FILE_READ, "secrets/.env")).action
        == PrivacyAction.BLOCK
    )
    assert (
        evaluate_firewall(policy, _ctx("Bash", ToolOperation.SHELL_EXEC, None)).action
        == PrivacyAction.ALLOW
    )


def test_firewall_requires_approval_maps_to_review_outcome() -> None:
    policy = FirewallPolicy(
        rules=[
            FirewallRule(
                id="approve_scripts",
                operations=[ToolOperation.FILE_WRITE],
                extensions=["sh"],
                action=PrivacyAction.ALLOW,
                requires_approval=True,
                message="Writing shell scripts requires approval.",
            )
        ]
    )
    decision = evaluate_firewall(policy, _ctx("Write", ToolOperation.FILE_WRITE, "deploy.sh"))
    assert decision.requires_approval is True
    assert decision.action == PrivacyAction.ALLOW
    assert firewall_decision_outcome(decision) == EnforcementOutcome.REVIEW_REQUIRED
    blocked = evaluate_firewall(
        default_firewall_policy(), _ctx("Read", ToolOperation.FILE_READ, ".env")
    )
    assert firewall_decision_outcome(blocked) == EnforcementOutcome.BLOCKED


def test_firewall_disabled_always_allows() -> None:
    policy = FirewallPolicy(enabled=False, rules=[FirewallRule(id="x", action=PrivacyAction.BLOCK)])
    assert (
        evaluate_firewall(policy, _ctx("Read", ToolOperation.FILE_READ, ".env")).action
        == PrivacyAction.ALLOW
    )


def test_classify_tool_builds_context_for_host_tools() -> None:
    assert classify_tool("claude", "Read", {"file_path": "a.txt"}) == ToolContext(
        "claude", "Read", ToolOperation.FILE_READ, path="a.txt"
    )
    bash = classify_tool("claude", "Bash", {"command": "ls -la"})
    assert bash.operation == ToolOperation.SHELL_EXEC
    assert bash.payload == "ls -la"
    edit = classify_tool("claude", "Edit", {"file_path": "x.py"})
    assert edit.operation == ToolOperation.FILE_WRITE and edit.path == "x.py"
    mcp = classify_tool("claude", "mcp__filesystem__read_file", {"path": "/etc/passwd"})
    assert mcp.operation == ToolOperation.FILE_READ and mcp.path == "/etc/passwd"
    unknown = classify_tool("claude", "TotallyUnknownTool", {"x": 1})
    assert unknown.operation == ToolOperation.UNKNOWN


def test_classify_tool_normalizes_case_and_external_markers() -> None:
    assert classify_tool("gemini", "read", {"file_path": "a"}) == ToolContext(
        "gemini", "read", ToolOperation.FILE_READ, path="a"
    )
    web = classify_tool("gemini", "WebFetch", {"url": "https://example.test"})
    assert web.operation == ToolOperation.NETWORK_READ
    assert web.destination == "https://example.test"


def test_firewall_invariants_reject_allow_of_protected_path() -> None:
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
    assert rule_allows_protected(bad.rules[0]) is True

    good = FirewallPolicy(
        rules=[
            FirewallRule(
                id="block_env",
                operations=[ToolOperation.FILE_READ],
                names=[".env"],
                action=PrivacyAction.BLOCK,
            )
        ]
    )
    validate_firewall_policy(good)
    assert rule_allows_protected(good.rules[0]) is False


def test_firewall_field_loaded_from_policy_file_is_validated(tmp_path) -> None:
    payload = {
        "schema_version": 1,
        "name": "fw_policy",
        "description": "synthetic firewall policy",
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
    (tmp_path / "fw.json").write_text(__import__("json").dumps(payload), encoding="utf-8")
    with pytest.raises(PolicyLoadError) as exc:
        LocalPolicyLoader(tmp_path).load()
    assert exc.value.code == PolicyLoadErrorCode.INVARIANT_VIOLATION


def test_firewall_field_loaded_from_policy_file_accepts_block(tmp_path) -> None:
    payload = {
        "schema_version": 1,
        "name": "fw_policy_ok",
        "description": "synthetic firewall policy",
        "firewall": {
            "enabled": True,
            "rules": [
                {
                    "id": "block_env",
                    "operations": ["file_read"],
                    "names": [".env"],
                    "action": "block",
                }
            ],
        },
        "residual_validation_enabled": True,
        "residual_on_failure": "block",
        "expose_raw_values": False,
        "expose_mapping": False,
    }
    (tmp_path / "fw.json").write_text(__import__("json").dumps(payload), encoding="utf-8")
    registry = LocalPolicyLoader(tmp_path).load()
    assert registry.get("fw_policy_ok").firewall is not None


def test_firewall_decision_keep_privacy_action_unchanged() -> None:
    assert set(PrivacyAction) == {
        PrivacyAction.ALLOW,
        PrivacyAction.REDACT,
        PrivacyAction.REVIEW,
        PrivacyAction.BLOCK,
    }


def test_load_firewall_policy_default_when_no_config(monkeypatch) -> None:
    monkeypatch.delenv("SECUREDACT_FIREWALL_ENABLED", raising=False)
    monkeypatch.delenv("SECUREDACT_POLICY_DIR", raising=False)
    policy = load_firewall_policy_from_environment()
    assert policy is not None and policy.enabled
    assert (
        evaluate_firewall(policy, _ctx("Read", ToolOperation.FILE_READ, ".env")).action
        == PrivacyAction.BLOCK
    )


def test_load_firewall_policy_disabled_returns_none(monkeypatch) -> None:
    monkeypatch.setenv("SECUREDACT_FIREWALL_ENABLED", "0")
    assert load_firewall_policy_from_environment() is None
