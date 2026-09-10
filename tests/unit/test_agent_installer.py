# SPDX-License-Identifier: Apache-2.0
"""Customer-facing installer/bootstrap tests (AGENT-INSTALLER-TEST).

Covers the bounded bootstrap config contract, the canonical install pipeline,
and the installer's safety invariants (no arbitrary command surface, no
persisted ``srr_*`` token, no leaked secrets in logs). The proven
``deploy.install_service_from_runtime`` and ``model_installer`` code paths are
exercised through injected fakes so the policy is fully verified on any
platform (CI is non-Windows).
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import io
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from securedact_mcp.agent import deploy, installer
from securedact_mcp.agent.deploy import RunInput, RunResult
from securedact_mcp.agent.errors import AgentError
from securedact_mcp.agent.installer import (
    _ALLOWED_MODEL_IDS,
    BOOTSTRAP_SCHEMA,
    BootstrapConfig,
    BootstrapConfigError,
    InstallerStep,
    _safe_short,
    _start_heartbeat,
    _validate_token_present,
    _verify_installed_version,
    documented_bootstrap_contract,
    is_existing_registration_valid,
    load_bootstrap_config_from_path,
    parse_bootstrap_config,
    run_install,
    run_upgrade,
    sha256_of_payload,
)

# Synthetic registration token for tests. Low-entropy (repeated chars) so it
# is clearly a fixture; still matches the production srr_<id>_<secret> regex.
TEST_REGISTRATION_TOKEN = "srr_test_AAAA"  # noqa: S105

# ---------------------------------------------------------------------------
# Helpers / fakes
# ---------------------------------------------------------------------------


def _future_iso(seconds_from_now: int = 600) -> str:
    return (
        (_dt.datetime.now(_dt.UTC) + _dt.timedelta(seconds=seconds_from_now))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _valid_config_dict(**overrides: Any) -> dict[str, Any]:
    base = {
        "schema": BOOTSTRAP_SCHEMA,
        "control_plane_url": "https://www.securedact.com",
        "registration_token": TEST_REGISTRATION_TOKEN,
        "recommended_version": "0.6.0",
        "expires_at": _future_iso(),
        "installer_url": "https://www.securedact.com/download/installer-0.6.0.exe",
        "models": ["flair/ner-english-large"],
    }
    base.update(overrides)
    return base


def _write_config(tmp_path: Path, **overrides: Any) -> Path:
    cfg = _valid_config_dict(**overrides)
    p = tmp_path / "securedact-bootstrap.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    return p


class FakeInstallRunner:
    """Mimics the deploy command runner for the install pipeline.

    Records every invocation so the tests can assert that no secret material
    (registration token, credential) ever appears on argv or environment.
    """

    def __init__(
        self,
        *,
        version_probe_stdout: str = "0.6.0",
        version_probe_returncode: int = 0,
        install_payload: dict[str, Any] | None = None,
    ) -> None:
        self.calls: list[tuple[list[str], RunInput]] = []
        self._version_probe_stdout = version_probe_stdout
        self._version_probe_returncode = version_probe_returncode
        self._install_payload = install_payload or {
            "installed": True,
            "service_name": "SecuRedact Managed Agent",
            "data_dir": "C:\\ProgramData\\Securedact",
            "account": "SYSTEM",
            "running": True,
            "agent_id": "agent-test-001",
        }

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        args = list(arguments)
        self.calls.append((args, run_input))
        # Version probe: python -c "import securedact_mcp; print(...)"
        if "-c" in args and "securedact_mcp" in " ".join(args):
            return RunResult(self._version_probe_returncode, stdout=self._version_probe_stdout)
        return RunResult(0, stdout="ok")


# ---------------------------------------------------------------------------
# 1. parse_bootstrap_config / BootstrapConfigError matrix
# ---------------------------------------------------------------------------


def test_parse_bootstrap_config_happy_path() -> None:
    config = parse_bootstrap_config(_valid_config_dict())
    assert isinstance(config, BootstrapConfig)
    assert config.recommended_version == "0.6.0"
    assert config.registration_token.startswith("srr_")
    assert config.models == ("flair/ner-english-large",)
    assert config.control_plane_url == "https://www.securedact.com"


@pytest.mark.parametrize(
    "missing_field",
    [
        "control_plane_url",
        "registration_token",
        "recommended_version",
        "expires_at",
    ],
)
def test_parse_bootstrap_config_missing_required(missing_field: str) -> None:
    cfg = _valid_config_dict()
    cfg.pop(missing_field)
    with pytest.raises(BootstrapConfigError):
        parse_bootstrap_config(cfg)


def test_parse_bootstrap_config_rejects_unknown_field() -> None:
    cfg = _valid_config_dict()
    cfg["__inject__"] = "rm -rf /"  # attempted command injection
    with pytest.raises(BootstrapConfigError, match="unknown fields"):
        parse_bootstrap_config(cfg)


def test_parse_bootstrap_config_rejects_invalid_schema() -> None:
    cfg = _valid_config_dict(schema="evil.v1")
    with pytest.raises(BootstrapConfigError, match="schema"):
        parse_bootstrap_config(cfg)


def test_parse_bootstrap_config_rejects_expired() -> None:
    cfg = _valid_config_dict(expires_at="2020-01-01T00:00:00Z")
    with pytest.raises(BootstrapConfigError, match="expired"):
        parse_bootstrap_config(cfg)


@pytest.mark.parametrize("version", ["latest", "*", "0.6", "0.6.0; rm -rf /", ""])
def test_parse_bootstrap_config_rejects_invalid_or_unpinned_version(
    version: str,
) -> None:
    cfg = _valid_config_dict(recommended_version=version)
    with pytest.raises(BootstrapConfigError):
        parse_bootstrap_config(cfg)


@pytest.mark.parametrize(
    "token",
    [
        "",
        "not-a-token",
        "srr_short",
        "srr_abc_def",  # secret too short
        "srr_abc def_ghi",  # whitespace
        "sra_abc_def_ghi",  # wrong prefix (would be a credential, not a token)
    ],
)
def test_parse_bootstrap_config_rejects_invalid_token_shape(token: str) -> None:
    cfg = _valid_config_dict(registration_token=token)
    with pytest.raises(BootstrapConfigError):
        parse_bootstrap_config(cfg)


def test_parse_bootstrap_config_rejects_invalid_models() -> None:
    cfg = _valid_config_dict(models=["flair/ner-english-large", "evil/evil-model"])
    with pytest.raises(BootstrapConfigError, match="allow-list"):
        parse_bootstrap_config(cfg)


def test_parse_bootstrap_config_no_models_is_allowed() -> None:
    cfg = _valid_config_dict(models=[])
    config = parse_bootstrap_config(cfg)
    assert config.models == ()


def test_parse_bootstrap_config_strips_localhost_http() -> None:
    cfg = _valid_config_dict(control_plane_url="http://127.0.0.1:8000")
    config = parse_bootstrap_config(cfg)
    assert config.control_plane_url.startswith("http://127.0.0.1")


def test_parse_bootstrap_config_rejects_http_non_localhost() -> None:
    cfg = _valid_config_dict(control_plane_url="http://www.securedact.com")
    with pytest.raises(BootstrapConfigError):
        parse_bootstrap_config(cfg)


def test_parse_bootstrap_config_never_echoes_token_on_error() -> None:
    secret = TEST_REGISTRATION_TOKEN
    cfg = _valid_config_dict(registration_token=secret, expires_at="bad-date")
    try:
        parse_bootstrap_config(cfg)
    except BootstrapConfigError as exc:
        # The error message must NEVER contain the secret material.
        assert secret not in str(exc)


def test_parse_bootstrap_config_rejects_non_object_input() -> None:
    # A JSON array is a valid JSON value but must not be accepted as a
    # bootstrap config (it would be an injection vector for arbitrary
    # structured payloads).
    with pytest.raises(BootstrapConfigError, match="JSON object"):
        parse_bootstrap_config("[]")


def test_parse_bootstrap_config_handles_json_string() -> None:
    config = parse_bootstrap_config(json.dumps(_valid_config_dict()))
    assert config.recommended_version == "0.6.0"


# ---------------------------------------------------------------------------
# 2. Bootstrap config -> dataclass immutability + log-safe shape
# ---------------------------------------------------------------------------


def test_bootstrap_config_is_frozen() -> None:
    config = parse_bootstrap_config(_valid_config_dict())
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        config.recommended_version = "9.9.9"  # type: ignore[misc]


def test_bootstrap_config_log_safe_dict_redacts_token() -> None:
    config = parse_bootstrap_config(_valid_config_dict())
    safe = config.to_log_safe_dict()
    assert safe["registration_token"] == "<redacted-credential>"  # noqa: S105
    assert config.registration_token not in str(safe)
    # expires_at must be a string for JSON safety
    assert isinstance(safe["expires_at"], str)


# ---------------------------------------------------------------------------
# 3. Bootstrap config file discovery
# ---------------------------------------------------------------------------


def test_load_bootstrap_config_from_file_happy(tmp_path: Path) -> None:
    p = _write_config(tmp_path)
    config = load_bootstrap_config_from_path(p)
    assert config.recommended_version == "0.6.0"


def test_load_bootstrap_config_from_file_rejects_unknown_field(tmp_path: Path) -> None:
    cfg = _valid_config_dict(__inject__="x")
    p = tmp_path / "securedact-bootstrap.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    with pytest.raises(BootstrapConfigError):
        load_bootstrap_config_from_path(p)


def test_load_bootstrap_config_from_path_search_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # explicit > env > exe_dir > cwd
    p_explicit_dir = tmp_path / "explicit"
    p_explicit_dir.mkdir()
    p_explicit = _write_config(p_explicit_dir)
    p_env_dir = tmp_path / "env"
    p_env_dir.mkdir()
    p_env = _write_config(p_env_dir)
    p_cwd = _write_config(tmp_path)
    monkeypatch.chdir(p_cwd.parent)
    monkeypatch.setenv("SECUREDACT_BOOTSTRAP_CONFIG", str(p_env))
    # explicit wins
    config = load_bootstrap_config_from_path(p_explicit)
    assert config.recommended_version == "0.6.0"


def test_load_bootstrap_config_from_path_no_file_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SECUREDACT_BOOTSTRAP_CONFIG", raising=False)
    with pytest.raises(BootstrapConfigError, match="no bootstrap config file found"):
        load_bootstrap_config_from_path(None)


# ---------------------------------------------------------------------------
# 4. Step / step-validation
# ---------------------------------------------------------------------------


def test_validate_token_present_ok() -> None:
    config = parse_bootstrap_config(_valid_config_dict())
    step = _validate_token_present(config)
    assert step.state == "ok"


def test_validate_version_pin_unpinned_rejected() -> None:
    # A fresh parse with "latest" must fail-closed at parse time; assert the
    # full parse-bootstrap-config path.
    poisoned = _valid_config_dict(recommended_version="latest")
    with pytest.raises(BootstrapConfigError, match="refuses unpinned"):
        parse_bootstrap_config(poisoned)


# ---------------------------------------------------------------------------
# 5. run_install end-to-end with fakes
# ---------------------------------------------------------------------------


def test_run_install_happy_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[InstallerStep] = []

    def _progress(step: InstallerStep) -> None:
        captured.append(step)

    runner = FakeInstallRunner()

    def _fake_provision(**kwargs: Any) -> Any:
        class _PR:
            runtime_path = tmp_path / "runtime"
            runtime_python = tmp_path / "runtime" / "Scripts" / "python.exe"
            already_provisioned = False
            hardened = True

        return _PR()

    def _fake_install_service_from_runtime(**kwargs: Any) -> dict[str, Any]:
        # Assert: the registration token is passed as the `token` kwarg
        # exactly once and matches the input.
        assert kwargs.get("token", "").startswith("srr_")
        return {
            "installed": True,
            "service_name": "SecuRedact Managed Agent",
            "data_dir": str(tmp_path),
            "account": "SYSTEM",
            "running": True,
            "agent_id": "agent-test-001",
            "runtime_path": str(tmp_path / "runtime"),
            "runtime_python": str(tmp_path / "runtime" / "Scripts" / "python.exe"),
        }

    def _fake_verify_heartbeat(**kwargs: Any) -> bool:
        return True

    monkeypatch.setattr(deploy, "provision_machine_runtime", _fake_provision)
    monkeypatch.setattr(deploy, "install_service_from_runtime", _fake_install_service_from_runtime)
    monkeypatch.setattr(deploy, "verify_heartbeat", _fake_verify_heartbeat)

    config = parse_bootstrap_config(_valid_config_dict())

    result = run_install(
        config,
        data_dir=tmp_path,
        runtime_path=tmp_path / "runtime",
        command_runner=runner,
        progress=_progress,
        install_models=False,  # skip model install in this test
    )

    assert result.success
    assert result.error_code is None
    assert result.agent_id == "agent-test-001"
    assert result.installed_version == "0.6.0"
    step_names = [s.name for s in result.steps]
    assert "validate-token" in step_names
    assert "pin-version" in step_names
    assert "install-runtime" in step_names
    assert "register-agent" in step_names
    assert "verify-version" in step_names
    assert "verify-heartbeat" in step_names
    # No step must have leaked the secret token into its message.
    for step in result.steps:
        assert TEST_REGISTRATION_TOKEN not in step.message
        assert "srr_test" not in step.message


def test_run_install_version_mismatch_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = FakeInstallRunner(version_probe_stdout="0.5.0")  # wrong version

    monkeypatch.setattr(
        deploy,
        "provision_machine_runtime",
        lambda **kwargs: type(
            "_PR",
            (),
            {
                "runtime_path": tmp_path / "runtime",
                "runtime_python": tmp_path / "runtime" / "Scripts" / "python.exe",
            },
        )(),
    )
    monkeypatch.setattr(
        deploy,
        "install_service_from_runtime",
        lambda **kwargs: {
            "installed": True,
            "service_name": "X",
            "data_dir": str(tmp_path),
            "account": "SYSTEM",
            "running": True,
            "agent_id": "agent-test-002",
            "runtime_path": str(tmp_path / "runtime"),
        },
    )
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **kwargs: True)

    config = parse_bootstrap_config(_valid_config_dict(recommended_version="0.6.0"))
    result = run_install(
        config,
        data_dir=tmp_path,
        runtime_path=tmp_path / "runtime",
        command_runner=runner,
        install_models=False,
    )

    assert not result.success
    assert result.error_code == "version_mismatch"
    assert "0.5.0" in (result.error_message or "")


def test_run_install_heartbeat_failure_returns_error_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        deploy,
        "provision_machine_runtime",
        lambda **kwargs: type(
            "_PR",
            (),
            {
                "runtime_path": tmp_path / "runtime",
                "runtime_python": tmp_path / "runtime" / "Scripts" / "python.exe",
            },
        )(),
    )
    monkeypatch.setattr(
        deploy,
        "install_service_from_runtime",
        lambda **kwargs: {
            "installed": True,
            "service_name": "X",
            "data_dir": str(tmp_path),
            "account": "SYSTEM",
            "running": True,
            "agent_id": "agent-test-003",
            "runtime_path": str(tmp_path / "runtime"),
        },
    )
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **kwargs: False)

    config = parse_bootstrap_config(_valid_config_dict())
    result = run_install(
        config,
        data_dir=tmp_path,
        runtime_path=tmp_path / "runtime",
        command_runner=FakeInstallRunner(),
        install_models=False,
        heartbeat_timeout_seconds=0.1,
        sleep_fn=lambda _s: None,
    )

    assert not result.success
    assert result.error_code == "heartbeat_failed"


def test_run_install_does_not_persist_token_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No ``srr_*`` token may be written to any ProgramData file."""

    monkeypatch.setattr(
        deploy,
        "provision_machine_runtime",
        lambda **kwargs: (_ for _ in ()).throw(AgentError("simulated runtime failure")),
    )

    config = parse_bootstrap_config(_valid_config_dict())
    result = run_install(
        config,
        data_dir=tmp_path,
        runtime_path=tmp_path / "runtime",
        install_models=False,
    )
    assert not result.success
    assert result.error_code == "runtime_provision_failed"
    # The token must not appear anywhere in the result envelope.
    blob = json.dumps(result.to_dict())
    assert TEST_REGISTRATION_TOKEN not in blob


def test_run_install_no_arbitrary_command_surface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even a poisoned bootstrap config cannot inject a shell command.

    The install pipeline must not call subprocess / shell with any string from
    the bootstrap config (the only place bootstrap data goes is
    ``install_service_from_runtime.token=``).
    """

    # Provision/installation will fail fast; we just want to prove the
    # poisoned config is rejected at the parse layer.
    poisoned = _valid_config_dict()
    poisoned["shell_command"] = "calc.exe"
    poisoned["args"] = ["--evil"]
    with pytest.raises(BootstrapConfigError, match="unknown fields"):
        parse_bootstrap_config(poisoned)


# ---------------------------------------------------------------------------
# 6. UI / safe logging
# ---------------------------------------------------------------------------


def test_default_ui_printer_emits_no_token(capsys: pytest.CaptureFixture[str]) -> None:
    buf = io.StringIO()
    printer = installer.default_ui_printer(stream=buf)
    secret_token = TEST_REGISTRATION_TOKEN
    printer(InstallerStep("register-agent", "ok", f"token={secret_token}"))
    output = buf.getvalue()
    assert secret_token not in output
    assert "<redacted-credential>" in output


def test_safe_short_truncates_and_scrubs() -> None:
    long = "x" * 1000 + " srr_a_b_cccc"
    out = _safe_short(long, limit=50)
    assert len(out) <= 50
    assert "srr_a_b_cccc" not in out


# ---------------------------------------------------------------------------
# 7. Upgrade / reinstall behaviour
# ---------------------------------------------------------------------------


def test_run_upgrade_preserves_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``run_upgrade`` delegates to ``deploy.upgrade_runtime`` and never
    consumes the registration token."""

    called = {}

    def _fake_upgrade(**kwargs: Any) -> dict[str, Any]:
        called["version"] = kwargs.get("version")
        called["kwargs"] = kwargs
        return {
            "upgraded": True,
            "artifact_changed": True,
            "runtime_path": str(tmp_path / "runtime"),
            "data_dir": str(tmp_path),
            "service_started": True,
        }

    monkeypatch.setattr(deploy, "upgrade_runtime", _fake_upgrade)

    config = parse_bootstrap_config(_valid_config_dict(recommended_version="0.6.0"))
    result = run_upgrade(config, data_dir=tmp_path, runtime_path=tmp_path / "runtime")
    assert result.success
    assert called["version"] == "0.6.0"
    # The token must never have been forwarded into the upgrade call.
    assert "token" not in called["kwargs"]


def test_is_existing_registration_valid_handles_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(**kwargs: Any) -> bool:
        raise AgentError("no registration")

    monkeypatch.setattr(deploy, "_agent_already_registered", _raise)
    assert is_existing_registration_valid(data_dir=tmp_path) is False


# ---------------------------------------------------------------------------
# 8. Documented contract helpers
# ---------------------------------------------------------------------------


def test_documented_bootstrap_contract_lists_allow_list() -> None:
    contract = documented_bootstrap_contract()
    assert contract["schema"] == BOOTSTRAP_SCHEMA
    assert "control_plane_url" in contract["required_fields"]
    assert "registration_token" in contract["required_fields"]
    assert "recommended_version" in contract["required_fields"]
    assert "expires_at" in contract["required_fields"]
    assert set(contract["models_allow_list"]) == set(_ALLOWED_MODEL_IDS)


def test_sha256_of_payload_is_stable() -> None:
    a = sha256_of_payload({"a": 1, "b": 2})
    b = sha256_of_payload({"b": 2, "a": 1})  # same content, different key order
    assert a == b
    c = sha256_of_payload({"a": 1, "b": 3})
    assert a != c
    # Also works on raw bytes.
    d = sha256_of_payload(b'{"a":1,"b":2}')
    assert d == a


# ---------------------------------------------------------------------------
# 9. Internal helpers (verify_installed_version, _start_heartbeat)
# ---------------------------------------------------------------------------


def test_verify_installed_version_ok() -> None:
    runner = FakeInstallRunner(version_probe_stdout="0.6.0")
    step = _verify_installed_version(
        runtime_path=Path("./_fake"),
        expected_version="0.6.0",
        command_runner=runner,
    )
    assert step.state == "ok"


def test_verify_installed_version_mismatch_fails() -> None:
    runner = FakeInstallRunner(version_probe_stdout="0.5.0")
    step = _verify_installed_version(
        runtime_path=Path("./_fake"),
        expected_version="0.6.0",
        command_runner=runner,
    )
    assert step.state == "failed"
    assert "0.5.0" in step.message


def test_start_heartbeat_succeeds_when_online(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **kwargs: True)
    config = parse_bootstrap_config(_valid_config_dict())
    step = _start_heartbeat(
        config, data_dir=tmp_path, runtime_path=tmp_path / "runtime", sleep_fn=lambda _s: None
    )
    assert step.state == "ok"


def test_start_heartbeat_fails_when_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **kwargs: False)
    config = parse_bootstrap_config(_valid_config_dict())
    step = _start_heartbeat(
        config,
        data_dir=tmp_path,
        runtime_path=tmp_path / "runtime",
        timeout_seconds=0.1,
        sleep_fn=lambda _s: None,
    )
    assert step.state == "failed"
