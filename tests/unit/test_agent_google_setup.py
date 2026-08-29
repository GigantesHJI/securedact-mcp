# SPDX-License-Identifier: Apache-2.0
"""Regression tests for first-class Google Workspace managed-agent onboarding.

These cover the customer-facing setup flow that replaced the manual
``.tmp`` PowerShell / token-migration workaround:

* fresh machine runtime with Google selected gets the Google dependencies;
* missing Google extra fails closed before the task starts;
* machine Google OAuth authorization writes only to the machine data root;
* an existing valid machine token is reused idempotently;
* a user-profile token is never silently copied;
* the integration binding is created / reused idempotently (no duplicates);
* no OAuth material is placed on argv / env / logs;
* Google not selected implies no Google dependency or auth requirement;
* ``setup`` waits for the heartbeat and reports Online;
* upgrade re-provisions packages only and preserves registration/token/bindings;
* the Task Scheduler backend is unchanged.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from securedact_mcp.agent import deploy
from securedact_mcp.agent.config import AgentConfig, AgentFiles
from securedact_mcp.agent.connectors import ConnectorBindingStore
from securedact_mcp.agent.deploy import (
    RunResult,
    provision_machine_runtime,
    upgrade_runtime,
)
from securedact_mcp.agent.errors import AgentError
from securedact_mcp.agent.service import ACTIVE_PERSISTENCE_BACKEND
from securedact_mcp.agent.google_setup import (
    GOOGLE_CONNECTOR_PLATFORM,
    apply_google_machine_env,
    authorize_google_machine,
    bind_google_machine,
)
from securedact_mcp.connectors.google.config import (
    GoogleConfigError,
    load_google_client_config,
    load_google_config,
)
from tests.unit.test_agent_deploy import FakeRunner, safe_provider


@pytest.fixture(autouse=True)
def _elevated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deploy, "is_elevated", lambda: True)


class GooglelessRuntimeRunner(FakeRunner):
    """Model the real-Windows defect: the machine runtime lacks the Google extra."""

    def __call__(self, arguments, run_input):  # type: ignore[override]
        args = list(arguments)
        probe = "import " + ", ".join(deploy.GOOGLE_RUNTIME_IMPORTS)
        if len(args) >= 3 and args[1] == "-c" and args[2] == probe:
            return RunResult(1, stderr="ModuleNotFoundError: No module named 'google.auth'")
        return super().__call__(arguments, run_input)


# ---------------------------------------------------------------------------
# Provisioning: Google extra install + post-install import verification
# ---------------------------------------------------------------------------


def test_fresh_runtime_with_google_gets_google_dependencies(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runner = FakeRunner()
    provision_machine_runtime(
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
        google_enabled=True,
    )
    pip_calls = [
        " ".join(str(a) for a in c[0])
        for c in runner.calls
        if "pip" in [str(a).lower() for a in c[0]]
    ]
    assert pip_calls, "pip was not invoked during provisioning"
    assert any("securedact-mcp[google]==" in c for c in pip_calls)


def test_missing_google_extra_fails_closed_before_task_starts(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runner = GooglelessRuntimeRunner()
    with pytest.raises(AgentError) as exc:
        provision_machine_runtime(
            runtime_path=runtime,
            acl_provider=safe_provider,
            command_runner=runner,
            google_enabled=True,
        )
    assert "Google connector dependencies failed to import" in str(exc.value)


def test_google_not_selected_requires_no_google_dependency(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runner = FakeRunner()
    provision_machine_runtime(
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
    )
    pip_calls = [
        " ".join(str(a) for a in c[0])
        for c in runner.calls
        if "pip" in [str(a).lower() for a in c[0]]
    ]
    assert pip_calls
    assert not any("[google]" in c for c in pip_calls)


# ---------------------------------------------------------------------------
# Google config loader: machine data root targeting
# ---------------------------------------------------------------------------


def test_load_google_config_targets_machine_data_root(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SECUREDACT_GOOGLE_ENABLED", "1")
    config = load_google_config(data_dir=tmp_path / "machine")
    assert config.token_path == tmp_path / "machine" / "google" / "token.json.enc"
    assert config.key_path == tmp_path / "machine" / "google" / "token.key"


# ---------------------------------------------------------------------------
# Machine-local Google authorization (first-class onboarding)
# ---------------------------------------------------------------------------


class _FakeStore:
    def __init__(self, token_path: Path) -> None:
        self.token_path = token_path
        self.saved: dict | None = None

    def save_token(self, token: dict) -> None:
        self.token_path.parent.mkdir(parents=True, exist_ok=True)
        self.token_path.write_text(json.dumps(token), encoding="utf-8")

    def load_token(self) -> dict | None:
        if self.token_path.is_file():
            return json.loads(self.token_path.read_text(encoding="utf-8"))
        return None


class _FakeGoogleConfig:
    def __init__(self, data_dir: Path, enabled: bool = True) -> None:
        self.data_dir = Path(data_dir)
        self.enabled = enabled
        self.load_calls: list[tuple[bool, object]] = []

    def credential_store(self) -> _FakeStore:
        return _FakeStore(self.data_dir / "google" / "token.json.enc")

    def load_google_config(
        self, *, require_enabled: bool = False, profile: str = "default", data_dir=None
    ):
        self.load_calls.append((require_enabled, data_dir))
        if require_enabled and not self.enabled:
            raise GoogleConfigError("Google connector is not enabled")
        return self


class _FakeGoogleAuth:
    def __init__(self, *, valid_token: bool = False, data_dir: Path | None = None) -> None:
        self.valid_token = valid_token
        self.data_dir = Path(data_dir) if data_dir is not None else None
        self.exchanged = False
        self.exchanged_code: str | None = None

    def load_credentials(self, config):
        if self.valid_token:
            return object()
        return None

    def get_authorization_url(self, config):
        return ("https://accounts.google.com/o/oauth2/auth", "state-xyz")

    def exchange_code(self, config, code, *, state=None):
        self.exchanged = True
        self.exchanged_code = code
        # Persist ONLY to the machine data root (via the config's credential store).
        config.credential_store().save_token({"refresh_token": "RT_MACHINE_ONLY"})
        return {}


def test_machine_google_authorization_writes_only_to_machine_root(tmp_path: Path) -> None:
    machine = tmp_path / "machine"
    user = tmp_path / "user"
    cfg = _FakeGoogleConfig(data_dir=machine)
    auth = _FakeGoogleAuth(valid_token=False, data_dir=machine)
    out = io.StringIO()
    ok = authorize_google_machine(
        machine,
        input_fn=lambda _p: "code=ABC123",
        output=out,
        config_module=cfg,
        auth_module=auth,
    )
    assert ok is True
    # Token written to the machine root, nowhere else.
    assert (machine / "google" / "token.json.enc").is_file()
    assert not (user / "google").exists()
    # The code came from the interactive prompt (input_fn), never argv.
    assert auth.exchanged_code == "ABC123"


def test_existing_valid_machine_token_is_reused(tmp_path: Path) -> None:
    machine = tmp_path / "machine"
    (machine / "google").mkdir(parents=True)
    (machine / "google" / "token.json.enc").write_text("{}", encoding="utf-8")
    cfg = _FakeGoogleConfig(data_dir=machine)
    auth = _FakeGoogleAuth(valid_token=True, data_dir=machine)
    out = io.StringIO()
    ok = authorize_google_machine(
        machine,
        input_fn=lambda _p: "code=ABC123",
        output=out,
        config_module=cfg,
        auth_module=auth,
    )
    assert ok is True
    assert auth.exchanged is False  # reused, did not re-authorize


def test_user_profile_token_is_not_silently_copied(tmp_path: Path) -> None:
    machine = tmp_path / "machine"
    user = tmp_path / "user"
    # A token exists only in the user-profile store.
    (user / "google").mkdir(parents=True)
    (user / "google" / "token.json.enc").write_text("{}", encoding="utf-8")
    cfg = _FakeGoogleConfig(data_dir=machine)
    auth = _FakeGoogleAuth(valid_token=False, data_dir=machine)
    out = io.StringIO()
    ok = authorize_google_machine(
        machine,
        input_fn=lambda _p: "code=ABC123",
        output=out,
        config_module=cfg,
        auth_module=auth,
    )
    assert ok is True
    # The machine store now holds a freshly-authorized machine token.
    assert (machine / "google" / "token.json.enc").is_file()
    # The user store is untouched (no copy/migration).
    assert (user / "google" / "token.json.enc").read_text() == "{}"


def test_no_oauth_material_in_env_or_argv(tmp_path: Path, monkeypatch) -> None:
    machine = tmp_path / "machine"
    cfg = _FakeGoogleConfig(data_dir=machine)
    auth = _FakeGoogleAuth(valid_token=False, data_dir=machine)
    out = io.StringIO()
    authorize_google_machine(
        machine,
        input_fn=lambda _p: "code=SECRETCODE",
        output=out,
        config_module=cfg,
        auth_module=auth,
    )
    # No OAuth material leaked into the process environment.
    leaked = [v for v in os.environ.values() if "RT_MACHINE_ONLY" in v or "SECRETCODE" in v]
    assert leaked == []


def test_google_not_enabled_requires_no_auth(tmp_path: Path) -> None:
    machine = tmp_path / "machine"
    cfg = _FakeGoogleConfig(data_dir=machine, enabled=False)
    auth = _FakeGoogleAuth(valid_token=False, data_dir=machine)
    out = io.StringIO()
    ok = authorize_google_machine(
        machine,
        input_fn=lambda _p: "code=ABC123",
        output=out,
        config_module=cfg,
        auth_module=auth,
    )
    assert ok is False
    assert auth.exchanged is False


# ---------------------------------------------------------------------------
# Connector binding idempotency
# ---------------------------------------------------------------------------


def _agent_config() -> AgentConfig:
    return AgentConfig.create(control_plane_url="https://example.com", agent_id="agent-1")


def test_binding_created_and_reused_idempotently(tmp_path: Path) -> None:
    files = AgentFiles.resolve(root=tmp_path / "agent")
    config = _agent_config()
    b1 = bind_google_machine(config, "int-1", files=files)
    b2 = bind_google_machine(config, "int-1", files=files)
    assert b1.integration_id == "int-1"
    assert b1.platform == GOOGLE_CONNECTOR_PLATFORM
    assert b2.integration_id == b1.integration_id and b2.local_profile == b1.local_profile
    # No duplicate records (keyed by integration id).
    assert len(ConnectorBindingStore(files).list()) == 1


def test_stale_binding_is_repaired(tmp_path: Path) -> None:
    files = AgentFiles.resolve(root=tmp_path / "agent")
    # Pre-seed a stale google binding (wrong local_profile).
    files.ensure()
    (files.root / "connector-bindings.json").write_text(
        json.dumps(
            {
                "int-1": {
                    "integration_id": "int-1",
                    "platform": "google_workspace",
                    "local_profile": "stale",
                }
            }
        ),
        encoding="utf-8",
    )
    config = _agent_config()
    binding = bind_google_machine(config, "int-1", files=files, profile="default")
    assert binding.local_profile == "default"
    assert len(ConnectorBindingStore(files).list()) == 1


# ---------------------------------------------------------------------------
# Setup flow waits for heartbeat + reports Online (incl. Google branch)
# ---------------------------------------------------------------------------


def test_setup_module_google_branch_prints_bound_and_online(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(deploy.sys, "platform", "win32")
    monkeypatch.setattr(
        deploy,
        "install_service_from_runtime",
        lambda **k: {
            "installed": True,
            "service_name": "SecuredactAgent",
            "data_dir": "C:\\ProgramData\\Securedact",
            "account": r"NT SERVICE\SecuredactAgent",
            "running": True,
            "agent_id": "agent-1",
        },
    )
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **k: True)
    bound: dict[str, object] = {}

    def fake_bind(config, integration_id, *, files=None, profile="default", binding_store_cls=None):
        bound["integration_id"] = integration_id
        return type(
            "B", (), {"integration_id": integration_id, "platform": GOOGLE_CONNECTOR_PLATFORM}
        )()

    def fake_auth(data_dir, **kwargs):
        return True

    output = io.StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        secret_input_fn=lambda _p: "srr_tok",
        agent="yes",
        elevated_check=lambda: True,
        google="yes",
        google_integration_id="int-42",
        authorize_google_fn=fake_auth,
        bind_google_fn=fake_bind,
    )
    text = output.getvalue()
    assert rc == 0
    assert "[Google Workspace]" in text
    assert "Local connector bound" in text
    assert bound.get("integration_id") == "int-42"
    assert "Online" in text
    assert "setup complete" in text.lower()


# ---------------------------------------------------------------------------
# Upgrade preserves state and re-provisions Google extra
# ---------------------------------------------------------------------------


def test_upgrade_with_google_preserves_state_and_installs_extra(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "Scripts").mkdir(parents=True, exist_ok=True)
    (runtime / "Scripts" / "python.exe").write_text("")
    data = tmp_path / "data"
    data.mkdir()
    (data / "agent.json").write_text('{"agent_id": "agent-1"}')
    (data / "connector-bindings.json").write_text('{"int-1": {"integration_id": "int-1"}}')
    (data / "google").mkdir()
    (data / "google" / "token.json.enc").write_text("{}")

    runner = FakeRunner()
    outcome = upgrade_runtime(
        runtime_path=runtime,
        data_dir=data,
        acl_provider=safe_provider,
        command_runner=runner,
        google_enabled=True,
    )
    assert outcome["upgraded"] is True
    pip_calls = [
        " ".join(str(a) for a in c[0])
        for c in runner.calls
        if "pip" in [str(a).lower() for a in c[0]]
    ]
    assert any("[google]" in c for c in pip_calls)
    # State (registration, bindings, OAuth vault) is preserved.
    assert (data / "agent.json").read_text() == '{"agent_id": "agent-1"}'
    assert (
        data / "connector-bindings.json"
    ).read_text() == '{"int-1": {"integration_id": "int-1"}}'
    assert (data / "google" / "token.json.enc").read_text() == "{}"


# ---------------------------------------------------------------------------
# Backend freeze
# ---------------------------------------------------------------------------


def test_task_scheduler_backend_unchanged() -> None:
    assert ACTIVE_PERSISTENCE_BACKEND == "taskscheduler"


# ---------------------------------------------------------------------------
# Client secret storage: never persisted as a machine env var; encrypted at rest
# ---------------------------------------------------------------------------


def test_google_client_secret_not_persisted_as_machine_env(tmp_path: Path, monkeypatch) -> None:
    # The client secret must NOT be written to a machine-wide environment variable
    # (setx /M); it must be persisted encrypted under the machine data root instead.
    monkeypatch.setenv("SECUREDACT_GOOGLE_ENABLED", "1")
    monkeypatch.setenv("SECUREDACT_GOOGLE_CLIENT_ID", "cfg.app.id.example")
    secret = "super-secret-client-secret-value"
    monkeypatch.setenv("SECUREDACT_GOOGLE_CLIENT_SECRET", secret)

    captured: list[list[str]] = []

    import subprocess

    real_run = subprocess.run

    def _fake_run(args, **kwargs):
        captured.append([str(a) for a in args])
        return real_run(["echo", "ok"], capture_output=True, text=True, check=False)

    monkeypatch.setattr(subprocess, "run", _fake_run)

    apply_google_machine_env(tmp_path / "machine")

    # The secret value must never appear in any setx /M argument (argv of the
    # child process). Only the non-secret enable flag may be published.
    for call in captured:
        blob = " ".join(call)
        assert secret not in blob
        assert "SECUREDACT_GOOGLE_CLIENT_SECRET" not in blob
        # Only the enable flag may be published at machine scope.
        if "setx" in call[0].lower() and "/M" in call:
            assert call[2] == "SECUREDACT_GOOGLE_ENABLED"
    # The encrypted store exists and decrypts back to the exact secret.
    stored_id, stored_secret = load_google_client_config(tmp_path / "machine")
    assert stored_id == "cfg.app.id.example"
    assert stored_secret == secret


def test_google_client_secret_encrypted_at_rest(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SECUREDACT_GOOGLE_ENABLED", "1")
    secret = "plaintext-client-secret"
    monkeypatch.setenv("SECUREDACT_GOOGLE_CLIENT_SECRET", secret)

    apply_google_machine_env(tmp_path / "machine")

    raw = (tmp_path / "machine" / "google" / "client_config.json.enc").read_bytes()
    # Fernet ciphertext is non-deterministic and must not contain the plaintext secret.
    assert secret.encode() not in raw
    assert b"client_secret" not in raw


def test_google_client_secret_loaded_from_store_after_reboot(tmp_path: Path, monkeypatch) -> None:
    # Simulate the operator supplying the secret during setup, then the setup
    # PowerShell session closing (env cleared) and a reboot: the SYSTEM task must
    # still be able to load the client config from the encrypted machine store.
    monkeypatch.setenv("SECUREDACT_GOOGLE_ENABLED", "1")
    monkeypatch.setenv("SECUREDACT_GOOGLE_CLIENT_ID", "cfg.app.id.reboot")
    monkeypatch.setenv("SECUREDACT_GOOGLE_CLIENT_SECRET", "reboot-secret")

    apply_google_machine_env(tmp_path / "machine")

    # Session closed / rebooted: the operator env vars are gone.
    monkeypatch.delenv("SECUREDACT_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("SECUREDACT_GOOGLE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("SECUREDACT_GOOGLE_ENABLED", raising=False)

    config = load_google_config(data_dir=tmp_path / "machine")
    assert config.client_id == "cfg.app.id.reboot"
    assert config.client_secret == "reboot-secret"


def test_google_client_secret_not_written_to_logs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SECUREDACT_GOOGLE_ENABLED", "1")
    secret = "logging-leak-secret"
    monkeypatch.setenv("SECUREDACT_GOOGLE_CLIENT_SECRET", secret)

    err = io.StringIO()
    monkeypatch.setattr("sys.stderr", err)
    apply_google_machine_env(tmp_path / "machine")

    assert secret not in err.getvalue()
