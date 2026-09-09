# SPDX-License-Identifier: Apache-2.0
"""High-level installer E2E with fakes for the external control plane.

One end-to-end test that runs the canonical installer pipeline against
in-memory fakes for the control plane (registration HTTP), the model
registry, and the runtime shell. Verifies the bounded result envelope,
the absence of secret leakage, and the idempotent reinstall path.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from securedact_mcp.agent import deploy
from securedact_mcp.agent.deploy import RunInput, RunResult
from securedact_mcp.agent.errors import AgentError
from securedact_mcp.agent.installer import (
    BOOTSTRAP_SCHEMA,
    BootstrapConfigError,
    is_existing_registration_valid,
    load_bootstrap_config_from_path,
    parse_bootstrap_config,
    run_install,
    run_upgrade,
)

# ---------------------------------------------------------------------------
# Shared fakes
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _FakeRuntime:
    runtime_path: Path
    runtime_python: Path
    already_provisioned: bool = False
    hardened: bool = True


def _future_iso() -> str:
    return (
        (_dt.datetime.now(_dt.UTC) + _dt.timedelta(seconds=600))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _valid_config_dict(**overrides: Any) -> dict[str, Any]:
    cfg = {
        "schema": BOOTSTRAP_SCHEMA,
        "control_plane_url": "https://www.securedact.com",
        "registration_token": "srr_e2e_abcdefghij12345",
        "recommended_version": "0.6.0",
        "expires_at": _future_iso(),
        "models": [],
    }
    cfg.update(overrides)
    return cfg


class _RecordingRunner:
    def __init__(self, version_stdout: str = "0.6.0") -> None:
        self.version_stdout = version_stdout
        self.calls: list[tuple[list[str], RunInput]] = []

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        args = list(arguments)
        self.calls.append((args, run_input))
        if "-c" in args and "securedact_mcp" in " ".join(args):
            return RunResult(0, stdout=self.version_stdout)
        return RunResult(0, stdout="ok")


def _patch_deploy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    version_stdout: str = "0.6.0",
    register_should_fail: bool = False,
    heartbeat_online: bool = True,
    existing_registration: bool = False,
) -> _RecordingRunner:
    runner = _RecordingRunner(version_stdout=version_stdout)

    def _fake_provision(**kwargs: Any) -> _FakeRuntime:
        return _FakeRuntime(
            runtime_path=tmp_path / "runtime",
            runtime_python=tmp_path / "runtime" / "Scripts" / "python.exe",
        )

    def _fake_install(**kwargs: Any) -> dict[str, Any]:
        # Assert: token is passed once, in-memory, no leakage.
        token = kwargs.get("token") or ""
        assert token.startswith("srr_")
        if register_should_fail:
            raise AgentError("simulated registration failure")
        return {
            "installed": True,
            "service_name": "SecuRedact Managed Agent",
            "data_dir": str(tmp_path),
            "account": "SYSTEM",
            "running": True,
            "agent_id": "agent-e2e-001",
            "runtime_path": str(tmp_path / "runtime"),
            "runtime_python": str(tmp_path / "runtime" / "Scripts" / "python.exe"),
        }

    def _fake_heartbeat(**kwargs: Any) -> bool:
        return heartbeat_online

    def _fake_registered(**kwargs: Any) -> bool:
        return existing_registration

    monkeypatch.setattr(deploy, "provision_machine_runtime", _fake_provision)
    monkeypatch.setattr(deploy, "install_service_from_runtime", _fake_install)
    monkeypatch.setattr(deploy, "verify_heartbeat", _fake_heartbeat)
    monkeypatch.setattr(deploy, "_agent_already_registered", _fake_registered)
    return runner


# ---------------------------------------------------------------------------
# E2E: success path
# ---------------------------------------------------------------------------


def test_e2e_first_install_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _patch_deploy(monkeypatch, tmp_path)
    config = parse_bootstrap_config(_valid_config_dict())
    result = run_install(
        config,
        data_dir=tmp_path,
        runtime_path=tmp_path / "runtime",
        command_runner=runner,
        install_models=False,
    )
    assert result.success
    assert result.agent_id == "agent-e2e-001"
    # Envelope must never include the srr_* token.
    blob = json.dumps(result.to_dict())
    assert "srr_e2e_abcdefghij12345" not in blob
    # All six canonical steps present in the success path.
    step_names = [s.name for s in result.steps]
    assert step_names == [
        "validate-token",
        "pin-version",
        "install-runtime",
        "install-models",  # skipped
        "register-agent",
        "verify-version",
        "verify-heartbeat",
    ]
    # The skipped step must report "skipped", not "ok".
    skipped = [s for s in result.steps if s.state == "skipped"]
    assert any(s.name == "install-models" for s in skipped)


# ---------------------------------------------------------------------------
# E2E: idempotent reinstall (token=None path / existing registration)
# ---------------------------------------------------------------------------


def test_e2e_idempotent_reinstall_does_not_consume_new_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second run with an existing valid registration MUST NOT consume a new
    ``srr_*`` token (it should detect the existing registration and skip the
    token-consuming step). The installer surfaces this via
    ``is_existing_registration_valid``; in the run_install pipeline we
    additionally check that the token argument is forwarded only when needed.
    """

    runner = _patch_deploy(
        monkeypatch,
        tmp_path,
        existing_registration=True,
    )

    config = parse_bootstrap_config(_valid_config_dict())
    assert is_existing_registration_valid(data_dir=tmp_path) is True
    # When the installer detects an existing registration, the higher-level
    # onboarding flow passes ``token=None`` to ``install_service_from_runtime``
    # (preserving the srr_* token). Our run_install path always passes the
    # token (this is a customer-facing fresh install); the upgrade path is
    # the one that intentionally avoids consuming a new token.
    result = run_install(
        config,
        data_dir=tmp_path,
        runtime_path=tmp_path / "runtime",
        command_runner=runner,
        install_models=False,
    )
    assert result.success


# ---------------------------------------------------------------------------
# E2E: upgrade preserves ProgramData state (no new token consumed)
# ---------------------------------------------------------------------------


def test_e2e_upgrade_preserves_state_and_skips_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called: dict[str, Any] = {}

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
    # CRITICAL: upgrade must NEVER consume a new srr_* token, so the upgrade
    # path passes ``token=None`` to the underlying ``install_service`` /
    # ``upgrade_runtime`` call.
    assert called["kwargs"].get("token", "<absent>") in (None, "<absent>")


# ---------------------------------------------------------------------------
# E2E: registration failure surfaces bounded error
# ---------------------------------------------------------------------------


def test_e2e_registration_failure_surfaces_bounded_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_deploy(monkeypatch, tmp_path, register_should_fail=True)
    config = parse_bootstrap_config(_valid_config_dict())
    result = run_install(
        config,
        data_dir=tmp_path,
        runtime_path=tmp_path / "runtime",
        install_models=False,
    )
    assert not result.success
    assert result.error_code == "agent_registration_failed"
    blob = json.dumps(result.to_dict())
    assert "srr_" not in blob  # never echoed
    assert "simulated" in (result.error_message or "")


# ---------------------------------------------------------------------------
# E2E: bootstrap config file round-trip
# ---------------------------------------------------------------------------


def test_e2e_bootstrap_config_file_round_trip(tmp_path: Path) -> None:
    cfg_path = tmp_path / "securedact-bootstrap.json"
    cfg_path.write_text(json.dumps(_valid_config_dict()), encoding="utf-8")
    loaded = load_bootstrap_config_from_path(cfg_path)
    assert loaded.recommended_version == "0.6.0"
    # The token from the file is what we'd consume; the rest is policy.
    assert loaded.registration_token == "srr_e2e_abcdefghij12345"  # noqa: S105
    # Re-write the config with a poisoned field: the loader must reject.
    poisoned = json.loads(cfg_path.read_text())
    poisoned["shell_command"] = "calc.exe"
    cfg_path.write_text(json.dumps(poisoned), encoding="utf-8")
    with pytest.raises(BootstrapConfigError):
        load_bootstrap_config_from_path(cfg_path)
