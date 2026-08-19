from __future__ import annotations

import json
from pathlib import Path

import pytest

from securedact_core import (
    AUTOMATIC_PSEUDONYMIZATION_ENV,
    LocalPolicyLoader,
    PolicyLoadError,
    PolicyLoadErrorCode,
    load_policy_registry_from_environment,
)
from securedact_core.policies import PolicyRegistry


def _policy(name: str = "organization_policy") -> dict[str, object]:
    return {
        "schema_version": 1,
        "name": name,
        "description": "Synthetic organization policy",
        "category_actions": {"organization": "review", "email": "redact"},
        "residual_validation_enabled": True,
        "residual_on_failure": "block",
        "expose_raw_values": False,
        "expose_mapping": False,
    }


def test_json_and_yaml_policies_load_with_stable_digest(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.yaml"
    first.write_text(json.dumps(_policy("local_json")), encoding="utf-8")
    second.write_text(
        "schema_version: 1\nname: local_yaml\ndescription: Synthetic YAML policy\n",
        encoding="utf-8",
    )

    registry = LocalPolicyLoader(tmp_path).load()

    assert {
        "default",
        "strict_external_ai",
        "gdpr",
        "identifiers_only",
        "review_all_contextual",
    }.issubset({policy.name for policy in registry.list()})
    assert (
        registry.get("local_json").digest
        == LocalPolicyLoader(tmp_path).load().get("local_json").digest
    )
    assert registry.get("local_yaml").built_in is False


def test_policy_toggle_is_serialized_and_changes_the_policy_digest(tmp_path: Path) -> None:
    enabled_payload = _policy("automatic_enabled")
    enabled_payload["automatic_pseudonymization"] = True
    disabled_payload = _policy("automatic_disabled")
    disabled_payload["automatic_pseudonymization"] = False
    (tmp_path / "enabled.json").write_text(json.dumps(enabled_payload), encoding="utf-8")
    (tmp_path / "disabled.json").write_text(json.dumps(disabled_payload), encoding="utf-8")

    registry = LocalPolicyLoader(tmp_path).load()
    enabled = registry.get("automatic_enabled")
    disabled = registry.get("automatic_disabled")

    assert enabled.automatic_pseudonymization is True
    assert disabled.automatic_pseudonymization is False
    assert (
        disabled.digest != disabled.model_copy(update={"automatic_pseudonymization": True}).digest
    )


def test_environment_toggle_overrides_policy_and_invalid_value_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = _policy("local_disabled")
    payload["automatic_pseudonymization"] = False
    (tmp_path / "policy.json").write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("SECUREDACT_POLICY_DIR", str(tmp_path))

    monkeypatch.setenv(AUTOMATIC_PSEUDONYMIZATION_ENV, "1")
    enabled = load_policy_registry_from_environment()
    assert enabled.get("local_disabled").automatic_pseudonymization is True

    monkeypatch.setenv(AUTOMATIC_PSEUDONYMIZATION_ENV, "0")
    disabled = load_policy_registry_from_environment()
    assert disabled.get("strict_external_ai").automatic_pseudonymization is False
    assert disabled.get("local_disabled").automatic_pseudonymization is False
    assert enabled.get("strict_external_ai").digest != disabled.get("strict_external_ai").digest

    monkeypatch.setenv(AUTOMATIC_PSEUDONYMIZATION_ENV, "false")
    with pytest.raises(PolicyLoadError) as invalid:
        load_policy_registry_from_environment()
    assert invalid.value.code == PolicyLoadErrorCode.SETTING_INVALID


def test_duplicate_unknown_field_unsafe_allow_and_oversize_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "duplicate.json").write_text(json.dumps(_policy("default")), encoding="utf-8")
    with pytest.raises(PolicyLoadError) as duplicate:
        LocalPolicyLoader(tmp_path).load(PolicyRegistry())
    assert duplicate.value.code == PolicyLoadErrorCode.DUPLICATE_NAME

    (tmp_path / "duplicate.json").unlink()
    payload = _policy()
    payload["unknown"] = True
    (tmp_path / "invalid.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(PolicyLoadError) as invalid:
        LocalPolicyLoader(tmp_path).load()
    assert invalid.value.code == PolicyLoadErrorCode.FILE_INVALID

    (tmp_path / "invalid.json").unlink()
    unsafe = _policy()
    unsafe["category_actions"] = {"api_token": "allow"}
    (tmp_path / "unsafe.json").write_text(json.dumps(unsafe), encoding="utf-8")
    with pytest.raises(PolicyLoadError) as invariant:
        LocalPolicyLoader(tmp_path).load()
    assert invariant.value.code == PolicyLoadErrorCode.INVARIANT_VIOLATION

    (tmp_path / "unsafe.json").write_text("x" * 65, encoding="utf-8")
    with pytest.raises(PolicyLoadError) as oversized:
        LocalPolicyLoader(tmp_path, max_file_bytes=64).load()
    assert oversized.value.code == PolicyLoadErrorCode.FILE_TOO_LARGE


def test_policy_symlink_is_rejected_when_supported(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    link = tmp_path / "linked.json"
    target.write_text(json.dumps(_policy()), encoding="utf-8")
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is not available")

    with pytest.raises(PolicyLoadError) as unsafe:
        LocalPolicyLoader(tmp_path).load()
    assert unsafe.value.code == PolicyLoadErrorCode.FILE_UNSAFE
