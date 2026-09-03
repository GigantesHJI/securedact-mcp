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
from securedact_mcp.agent.connectors import ConnectorBinding, ConnectorBindingStore
from securedact_mcp.agent.deploy import (
    RunResult,
    provision_machine_runtime,
    upgrade_runtime,
)
from securedact_mcp.agent.errors import AgentError
from securedact_mcp.agent.google_setup import (
    GOOGLE_CONNECTOR_PLATFORM,
    GoogleIntegrationCandidate,
    GoogleIntegrationResolutionState,
    apply_google_machine_env,
    authorize_google_machine,
    bind_google_machine,
    resolve_google_integration,
)
from securedact_mcp.agent.service import ACTIVE_PERSISTENCE_BACKEND
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


def _seed_machine_registration(machine_root: Path) -> AgentFiles:
    """Write a valid machine-root registration (``<root>/agent/agent.json``)."""

    from securedact_mcp.agent.config import save_config

    files = AgentFiles.resolve(root=Path(machine_root) / "agent")
    save_config(_agent_config(), files)
    return files


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
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setattr(deploy.sys, "platform", "win32")
    monkeypatch.setattr(
        deploy,
        "install_service_from_runtime",
        lambda **k: {
            "installed": True,
            "service_name": "SecuredactAgent",
            "data_dir": str(machine),
            "account": r"NT SERVICE\SecuredactAgent",
            "running": True,
            "agent_id": "agent-1",
        },
    )
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **k: True)

    def fake_auth(data_dir, **kwargs):
        return True

    output = io.StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        secret_input_fn=lambda _p: "srr_tok",
        agent="yes",
        data_dir=machine,
        elevated_check=lambda: True,
        google="yes",
        google_integration_id="int-42",
        authorize_google_fn=fake_auth,
        apply_google_env_fn=lambda _d, **_k: None,
    )
    text = output.getvalue()
    assert rc == 0
    assert "[Google Workspace]" in text
    assert "Local connector bound" in text
    # The REAL binding was written under the machine root with the exact id.
    bindings = machine / "agent" / "connector-bindings.json"
    assert bindings.is_file()
    assert json.loads(bindings.read_text(encoding="utf-8"))["int-42"]["integration_id"] == "int-42"
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
    secret = "super-secret-client-secret-value"  # noqa: S105
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
    secret = "plaintext-client-secret"  # noqa: S105
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
    assert config.client_secret == "reboot-secret"  # noqa: S105


def test_google_client_secret_not_written_to_logs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SECUREDACT_GOOGLE_ENABLED", "1")
    secret = "logging-leak-secret"  # noqa: S105
    monkeypatch.setenv("SECUREDACT_GOOGLE_CLIENT_SECRET", secret)

    err = io.StringIO()
    monkeypatch.setattr("sys.stderr", err)
    apply_google_machine_env(tmp_path / "machine")

    assert secret not in err.getvalue()


# ---------------------------------------------------------------------------
# Regression: the clean normal `setup` flow must create the machine binding
# ---------------------------------------------------------------------------


def test_resolve_google_selection_picks_interactive_yes(tmp_path: Path) -> None:
    # A clean machine (no env flag, no detected config) answering "y" must select.
    assert (
        deploy.google_setup.resolve_google_selection(
            tmp_path / "machine",
            google=None,
            input_fn=lambda _p: "y",
            output=io.StringIO(),
        )
        is True
    )


def test_resolve_google_selection_detects_existing_machine_config(
    tmp_path: Path, monkeypatch
) -> None:
    # Detected machine-local Google config must select onboarding without a flag.
    (tmp_path / "machine" / "google").mkdir(parents=True)
    (tmp_path / "machine" / "google" / "token.json.enc").write_text("{}", encoding="utf-8")
    selected = deploy.google_setup.resolve_google_selection(
        tmp_path / "machine",
        google=None,
        input_fn=lambda _p: "n",  # operator declines, but it is still detected
        output=io.StringIO(),
    )
    assert selected is True


def test_resolve_google_selection_no_flag_not_forced(tmp_path: Path) -> None:
    # Clean machine, silent (non-interactive) run with no config must NOT select.
    assert (
        deploy.google_setup.resolve_google_selection(
            tmp_path / "machine",
            google=None,
            non_interactive=True,
            input_fn=lambda _p: "y",
            output=io.StringIO(),
        )
        is False
    )


def test_resolve_google_selection_explicit_no_wins(tmp_path: Path, monkeypatch) -> None:
    # Even on a machine with detected Google config, an explicit --google no skips.
    (tmp_path / "machine" / "google").mkdir(parents=True)
    (tmp_path / "machine" / "google" / "token.json.enc").write_text("{}", encoding="utf-8")
    assert (
        deploy.google_setup.resolve_google_selection(
            tmp_path / "machine",
            google="no",
            input_fn=lambda _p: "y",
            output=io.StringIO(),
        )
        is False
    )


def test_elevation_argv_forwards_google_selection_nonsecret_only() -> None:
    params = deploy.build_elevation_argv(google="yes", google_integration_id="9db63be0e4437be6")
    assert "--google" in params and "yes" in params
    assert "--google-integration-id" in params
    assert "9db63be0e4437be6" in params
    # No secret / token material on the elevated continuation's command line.
    assert not any("srr_" in p or "sra_" in p for p in params)
    assert not any("client_secret" in p or "refresh_token" in p for p in params)


def test_elevation_argv_rejects_malformed_integration_id() -> None:
    with pytest.raises(AgentError):
        deploy.build_elevation_argv(google="yes", google_integration_id="bad id;rm")


def test_run_managed_agent_module_creates_machine_binding_under_programdata(
    tmp_path, monkeypatch
) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setattr(deploy.sys, "platform", "win32")
    monkeypatch.setattr(
        deploy,
        "install_service_from_runtime",
        lambda **k: {
            "installed": True,
            "service_name": "SecuredactAgent",
            "data_dir": str(machine),
            "account": r"NT SERVICE\SecuredactAgent",
            "running": True,
            "agent_id": "agent-1",
        },
    )
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **k: True)

    output = io.StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        secret_input_fn=lambda _p: "srr_tok",
        agent="yes",
        data_dir=machine,
        elevated_check=lambda: True,
        google="yes",
        google_integration_id="9db63be0e4437be6c21816bdde91942f",
        authorize_google_fn=lambda *_a, **_k: True,
        apply_google_env_fn=lambda _d, **_k: None,
        verify_google_binding_fn=lambda *_a, **_k: True,
    )
    assert rc == 0
    binding_file = machine / "agent" / "connector-bindings.json"
    assert binding_file.is_file()
    payload = json.loads(binding_file.read_text(encoding="utf-8"))
    assert "9db63be0e4437be6c21816bdde91942f" in payload
    assert payload["9db63be0e4437be6c21816bdde91942f"]["platform"] == GOOGLE_CONNECTOR_PLATFORM
    assert "Local connector bound" in output.getvalue()


def test_run_managed_agent_module_reuses_existing_valid_binding(tmp_path, monkeypatch) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    binding = machine / "agent" / "connector-bindings.json"
    binding.parent.mkdir(parents=True, exist_ok=True)
    binding.write_text(
        json.dumps(
            {
                "int-1": {
                    "integration_id": "int-1",
                    "platform": "google_workspace",
                    "local_profile": "default",
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(deploy.sys, "platform", "win32")
    monkeypatch.setattr(
        deploy,
        "install_service_from_runtime",
        lambda **k: {
            "installed": True,
            "service_name": "SecuredactAgent",
            "data_dir": str(machine),
            "account": r"NT SERVICE\SecuredactAgent",
            "running": True,
            "agent_id": "agent-1",
        },
    )
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **k: True)

    output = io.StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        secret_input_fn=lambda _p: "srr_tok",
        agent="yes",
        data_dir=machine,
        elevated_check=lambda: True,
        google="yes",
        google_integration_id="int-1",
        authorize_google_fn=lambda *_a, **_k: True,
        apply_google_env_fn=lambda _d, **_k: None,
    )
    assert rc == 0
    # The existing valid binding was reused idempotently: exactly one record, no
    # duplicate was written, and the recorded id matches.
    payload = json.loads(binding.read_text(encoding="utf-8"))
    assert list(payload.keys()) == ["int-1"]
    assert payload["int-1"]["platform"] == GOOGLE_CONNECTOR_PLATFORM
    assert "Local connector bound" in output.getvalue()


def test_missing_binding_cannot_be_silently_skipped_when_google_selected(
    tmp_path, monkeypatch
) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setattr(deploy.sys, "platform", "win32")
    monkeypatch.setattr(
        deploy,
        "install_service_from_runtime",
        lambda **k: {
            "installed": True,
            "service_name": "SecuredactAgent",
            "data_dir": str(machine),
            "account": r"NT SERVICE\SecuredactAgent",
            "running": True,
            "agent_id": "agent-1",
        },
    )
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **k: True)

    # Authorization succeeds and the operator supplies an integration id, but the
    # binding step fails to leave a verifiable on-disk record. The wizard must NOT
    # report success: it must refuse readiness with rc == 2.
    def fake_bind(config, integration_id, *, files=None, profile="default", binding_store_cls=None):
        # Pretend to bind, but the verifier (below) finds nothing on disk.
        return type(
            "B", (), {"integration_id": integration_id, "platform": GOOGLE_CONNECTOR_PLATFORM}
        )()

    output = io.StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        secret_input_fn=lambda _p: "srr_tok",
        agent="yes",
        data_dir=machine,
        elevated_check=lambda: True,
        google="yes",
        google_integration_id="int-missing",
        authorize_google_fn=lambda *_a, **_k: True,
        bind_google_fn=fake_bind,
        apply_google_env_fn=lambda _d, **_k: None,
        # Real verifier re-reads the disk and finds no binding.
    )
    assert rc == 2
    assert "NOT ready" in output.getvalue()
    assert (machine / "agent" / "connector-bindings.json").is_file() is False


def test_google_not_selected_does_not_force_auth_or_binding(tmp_path, monkeypatch) -> None:
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setattr(deploy.sys, "platform", "win32")
    monkeypatch.setattr(
        deploy,
        "install_service_from_runtime",
        lambda **k: {
            "installed": True,
            "service_name": "SecuredactAgent",
            "data_dir": str(machine),
            "account": r"NT SERVICE\SecuredactAgent",
            "running": True,
            "agent_id": "agent-1",
        },
    )
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **k: True)

    authorize_calls = []
    bind_calls = []

    def fake_auth(*_a, **_k):
        authorize_calls.append(1)
        return True

    def fake_bind(config, integration_id, *, files=None, profile="default", binding_store_cls=None):
        bind_calls.append(integration_id)
        return type(
            "B", (), {"integration_id": integration_id, "platform": GOOGLE_CONNECTOR_PLATFORM}
        )()

    output = io.StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        secret_input_fn=lambda _p: "srr_tok",
        agent="yes",
        data_dir=machine,
        elevated_check=lambda: True,
        google="no",
        authorize_google_fn=fake_auth,
        bind_google_fn=fake_bind,
    )
    assert rc == 0
    assert authorize_calls == []
    assert bind_calls == []
    assert "[Google Workspace]" not in output.getvalue()
    # No binding was written.
    assert (machine / "agent" / "connector-bindings.json").is_file() is False
    assert "setup complete" in output.getvalue().lower()


def test_uac_resumed_setup_still_executes_google_onboarding(tmp_path, monkeypatch) -> None:
    # Simulate the elevated continuation of a UAC hand-off (marker inherited), with
    # an explicit --google yes forwarded across the boundary. It must perform the
    # Google onboarding and create the machine binding before reporting ready.
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setattr(deploy.sys, "platform", "win32")
    monkeypatch.setattr(
        deploy,
        "install_service_from_runtime",
        lambda **k: {
            "installed": True,
            "service_name": "SecuredactAgent",
            "data_dir": str(machine),
            "account": r"NT SERVICE\SecuredactAgent",
            "running": True,
            "agent_id": "agent-1",
        },
    )
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **k: True)
    monkeypatch.setenv(deploy.AGENT_ELEVATED_ENV, "1")

    output = io.StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        secret_input_fn=lambda _p: "srr_tok",
        agent="yes",
        agent_elevated=True,
        data_dir=machine,
        elevated_check=lambda: True,
        google="yes",
        google_integration_id="int-uac",
        authorize_google_fn=lambda *_a, **_k: True,
        apply_google_env_fn=lambda _d, **_k: None,
        verify_google_binding_fn=lambda *_a, **_k: True,
    )
    assert rc == 0
    assert (machine / "agent" / "connector-bindings.json").is_file()
    assert "Local connector bound" in output.getvalue()


def test_setup_does_not_report_ready_before_binding_exists(tmp_path, monkeypatch) -> None:
    # When Google deps are present and auth succeeds but no integration id is
    # discoverable (non-interactive run), the binding cannot be created: the wizard
    # must refuse final readiness (rc == 2) rather than print "setup complete".
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    monkeypatch.setattr(deploy.sys, "platform", "win32")
    monkeypatch.setattr(
        deploy,
        "install_service_from_runtime",
        lambda **k: {
            "installed": True,
            "service_name": "SecuredactAgent",
            "data_dir": str(machine),
            "account": r"NT SERVICE\SecuredactAgent",
            "running": True,
            "agent_id": "agent-1",
        },
    )
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **k: True)

    output = io.StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        secret_input_fn=lambda _p: "srr_tok",
        agent="yes",
        data_dir=machine,
        elevated_check=lambda: True,
        google="yes",
        non_interactive=True,  # no interactive fallback for the integration id
        authorize_google_fn=lambda *_a, **_k: True,
        apply_google_env_fn=lambda _d, **_k: None,
    )
    assert rc == 2
    assert "setup complete" not in output.getvalue().lower()
    assert "NOT ready" in output.getvalue()


# ---------------------------------------------------------------------------
# Integration-resolution abstraction (single source of truth for which dashboard
# Google Workspace integration a machine binds). Normal customers are never asked
# for a raw integration id; the only manual surface is --google-integration-id.
# ---------------------------------------------------------------------------


CLEAN_LAPTOP_BINDING = "9db63be0e4437be6c21816bdde91942f"


def _seed_google_binding(machine_root: Path, integration_id: str = CLEAN_LAPTOP_BINDING) -> None:
    files = AgentFiles.resolve(root=Path(machine_root) / "agent")
    files.ensure()
    ConnectorBindingStore(files).bind(
        ConnectorBinding(
            integration_id=integration_id,
            platform=GOOGLE_CONNECTOR_PLATFORM,
            local_profile="default",
        )
    )


def _fail_if_prompted(_prompt: str) -> str:
    raise AssertionError(f"integration resolver must not prompt, but asked: {_prompt!r}")


class _FakeIntegrationSource:
    """Stand-in for the future tenant-scoped control-plane endpoint."""

    def __init__(self, candidates: list[GoogleIntegrationCandidate]) -> None:
        self.candidates = candidates
        self.calls = 0
        self.last_agent_identity: str | None = None

    def list_eligible_google_integrations(self, *, agent_identity: str | None = None):
        self.calls += 1
        self.last_agent_identity = agent_identity
        return list(self.candidates)


def test_resolver_explicit_id_resolves_directly() -> None:
    res = resolve_google_integration(explicit_id="int-abc123")
    assert res.state == GoogleIntegrationResolutionState.RESOLVED_EXPLICIT
    assert res.integration_id == "int-abc123"


def test_resolver_malformed_explicit_id_fails_safely() -> None:
    # A malformed raw id (shell metacharacters / whitespace) must fail closed,
    # never be forwarded to a binding or the elevated continuation's argv.
    res = resolve_google_integration(explicit_id="bad id;rm -rf")
    assert res.state == GoogleIntegrationResolutionState.UNAVAILABLE
    assert res.integration_id is None


def test_resolver_existing_binding_reused_without_prompt(tmp_path: Path) -> None:
    machine = tmp_path / "machine"
    _seed_google_binding(machine)
    res = resolve_google_integration(data_dir=machine, input_fn=_fail_if_prompted)
    assert res.state == GoogleIntegrationResolutionState.RESOLVED_EXISTING_BINDING
    assert res.integration_id == CLEAN_LAPTOP_BINDING


def test_resolver_wrong_platform_binding_not_reused(tmp_path: Path) -> None:
    machine = tmp_path / "machine"
    files = AgentFiles.resolve(root=machine / "agent")
    files.ensure()
    # Seed a binding for a platform that is NOT google_workspace directly (the store
    # would reject binding an unsupported platform, so write the record as the
    # runtime would never do for a bound integration).
    (files.connector_bindings).write_text(
        json.dumps(
            {
                "ms-1": {
                    "integration_id": "ms-1",
                    "platform": "microsoft365",
                    "local_profile": "default",
                }
            }
        ),
        encoding="utf-8",
    )
    res = resolve_google_integration(data_dir=machine, input_fn=_fail_if_prompted)
    assert res.state == GoogleIntegrationResolutionState.UNAVAILABLE
    assert res.integration_id is None


def test_resolver_does_not_invent_id(tmp_path: Path) -> None:
    # Clean machine, no existing binding, no control-plane source: must NOT invent
    # an id and must NOT prompt.
    res = resolve_google_integration(data_dir=tmp_path / "machine", input_fn=_fail_if_prompted)
    assert res.state == GoogleIntegrationResolutionState.UNAVAILABLE
    assert res.integration_id is None


def test_resolver_does_not_infer_from_token_or_logs(tmp_path: Path) -> None:
    # A valid machine OAuth token on disk (but no binding, no control plane) must
    # NOT be used to infer an integration id. No scan/job-history/log parsing.
    machine = tmp_path / "machine"
    (machine / "google").mkdir(parents=True)
    (machine / "google" / "token.json.enc").write_text("{}", encoding="utf-8")
    res = resolve_google_integration(data_dir=machine, input_fn=_fail_if_prompted)
    assert res.state == GoogleIntegrationResolutionState.UNAVAILABLE
    assert res.integration_id is None


def test_resolver_existing_binding_short_circuits_control_plane(tmp_path: Path) -> None:
    machine = tmp_path / "machine"
    _seed_google_binding(machine)
    source = _FakeIntegrationSource([])
    res = resolve_google_integration(
        data_dir=machine, control_plane_client=source, input_fn=_fail_if_prompted
    )
    assert res.state == GoogleIntegrationResolutionState.RESOLVED_EXISTING_BINDING
    assert source.calls == 0


def test_resolver_accepts_future_control_plane_result() -> None:
    source = _FakeIntegrationSource([])
    resolve_google_integration(control_plane_client=source, agent_identity="agent-1")
    assert source.calls == 1
    assert source.last_agent_identity == "agent-1"


def test_resolver_one_eligible_control_plane_autoresolves() -> None:
    source = _FakeIntegrationSource(
        [GoogleIntegrationCandidate(id="g-1", platform="google_workspace", display_name="My WS")]
    )
    res = resolve_google_integration(control_plane_client=source)
    assert res.state == GoogleIntegrationResolutionState.RESOLVED_CONTROL_PLANE
    assert res.integration_id == "g-1"


def test_resolver_filters_non_google_candidates() -> None:
    source = _FakeIntegrationSource(
        [
            GoogleIntegrationCandidate(id="ms-1", platform="microsoft365"),
            GoogleIntegrationCandidate(id="g-1", platform="google_workspace"),
        ]
    )
    res = resolve_google_integration(control_plane_client=source)
    assert res.state == GoogleIntegrationResolutionState.RESOLVED_CONTROL_PLANE
    assert res.integration_id == "g-1"


def test_resolver_zero_eligible_control_plane_unavailable() -> None:
    source = _FakeIntegrationSource([])
    res = resolve_google_integration(control_plane_client=source)
    assert res.state == GoogleIntegrationResolutionState.UNAVAILABLE
    assert res.integration_id is None


def test_resolver_many_eligible_ambiguous_noninteractive() -> None:
    source = _FakeIntegrationSource(
        [
            GoogleIntegrationCandidate(
                id="g-1", platform="google_workspace", display_name="Company"
            ),
            GoogleIntegrationCandidate(id="g-2", platform="google_workspace", display_name="Test"),
        ]
    )
    # Non-interactive: must not pick arbitrarily; reports ambiguous, no prompt.
    res = resolve_google_integration(control_plane_client=source, interactive=False)
    assert res.state == GoogleIntegrationResolutionState.AMBIGUOUS
    assert res.integration_id is None
    assert res.candidates is not None and len(res.candidates) == 2


def test_resolver_many_eligible_interactive_prompts_choices() -> None:
    source = _FakeIntegrationSource(
        [
            GoogleIntegrationCandidate(
                id="g-1", platform="google_workspace", display_name="Company"
            ),
            GoogleIntegrationCandidate(id="g-2", platform="google_workspace", display_name="Test"),
        ]
    )
    out = io.StringIO()
    # Operator gives no valid selection -> ambiguous, but the human-readable choices
    # were offered (the id stays hidden/internal).
    res = resolve_google_integration(
        control_plane_client=source, interactive=True, input_fn=lambda _p: "", output=out
    )
    assert res.state == GoogleIntegrationResolutionState.AMBIGUOUS
    assert res.integration_id is None
    text = out.getvalue()
    assert "Which Google Workspace integration should this computer use?" in text
    assert "1. Company" in text and "2. Test" in text


def test_resolver_many_eligible_interactive_selection() -> None:
    source = _FakeIntegrationSource(
        [
            GoogleIntegrationCandidate(
                id="g-1", platform="google_workspace", display_name="Company"
            ),
            GoogleIntegrationCandidate(id="g-2", platform="google_workspace", display_name="Test"),
        ]
    )
    out = io.StringIO()
    res = resolve_google_integration(
        control_plane_client=source, interactive=True, input_fn=lambda _p: "2", output=out
    )
    assert res.state == GoogleIntegrationResolutionState.RESOLVED_CONTROL_PLANE
    assert res.integration_id == "g-2"


# ---------------------------------------------------------------------------
# Setup-level behavior: the normal wizard must never ask for a raw integration id
# ---------------------------------------------------------------------------


def _setup_google_module(
    machine: Path,
    *,
    google: str = "yes",
    google_integration_id: str | None = None,
    non_interactive: bool = False,
    authorize: bool = True,
    input_side_effects: list[str] | None = None,
) -> tuple[int, str]:
    """Drive ``run_managed_agent_module`` for a registered machine and return (rc, output)."""

    recorded: list[str] = input_side_effects if input_side_effects is not None else []

    def _input(prompt: str) -> str:
        recorded.append(prompt)
        # The only legitimate prompts are the agent-confirm / registration token
        # prompts; the integration-id prompt must never appear in the normal flow.
        return "y"

    out = io.StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=_input,
        output=out,
        secret_input_fn=lambda _p: "srr_tok",
        agent="yes",
        data_dir=machine,
        elevated_check=lambda: True,
        google=google,
        google_integration_id=google_integration_id,
        non_interactive=non_interactive,
        authorize_google_fn=lambda *_a, **_k: authorize,
        apply_google_env_fn=lambda _d, **_k: None,
        verify_google_binding_fn=lambda *_a, **_k: True,
    )
    return rc, out.getvalue()


def _patch_install_and_heartbeat(monkeypatch, machine: Path) -> None:
    monkeypatch.setattr(deploy.sys, "platform", "win32")

    def mock_install_service_from_runtime(*, data_dir, **kwargs):
        # Simulate registration by creating agent.json
        from securedact_mcp.agent.config import AgentConfig, AgentFiles, save_config

        files = AgentFiles.resolve(root=Path(data_dir) / "agent")
        files.ensure()
        config = AgentConfig.create(
            control_plane_url="https://www.securedact.com",
            agent_id="agent-1",
            display_name="test-agent",
            runtime_platform="win32",
            agent_version="0.1.0",
        )
        save_config(config, files)

        return {
            "installed": True,
            "service_name": "SecuredactAgent",
            "data_dir": str(data_dir),
            "account": r"NT SERVICE\SecuredactAgent",
            "running": True,
            "agent_id": "agent-1",
        }

    monkeypatch.setattr(deploy, "install_service_from_runtime", mock_install_service_from_runtime)
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **k: True)


def test_normal_setup_without_binding_prompts_no_raw_id(tmp_path, monkeypatch) -> None:
    machine = tmp_path / "machine"
    _patch_install_and_heartbeat(monkeypatch, machine)

    prompts: list[str] = []
    rc, text = _setup_google_module(machine, input_side_effects=prompts)
    assert rc == 2
    # The old "Find the integration ID in your SecuRedact dashboard" prompt is gone.
    assert "Find the integration ID" not in text
    assert "Dashboard -> Integrations -> Google Workspace -> integration ID" not in text
    # Instead it reports automatic resolution unavailable (control plane lookup failed)
    # + the advanced escape hatch.
    assert "Could not look up eligible integrations" in text
    assert "securedact-mcp setup --agent --google yes --google-integration-id <id>" in text
    assert "NOT ready" in text
    # And it never asked the operator for a raw integration id.
    assert not any("integration ID" in p.lower() and "dashboard" in p.lower() for p in prompts)


def test_google_oauth_success_without_binding_not_ready(tmp_path, monkeypatch) -> None:
    machine = tmp_path / "machine"
    _patch_install_and_heartbeat(monkeypatch, machine)

    # OAuth authorized but no binding/integration resolvable -> NOT ready.
    rc, text = _setup_google_module(machine, authorize=True)
    assert rc == 2
    assert (
        "Managed Agent: NOT ready - Google Workspace authorization succeeded but no "
        "dashboard integration is bound." in text
    )


def test_existing_binding_and_oauth_reuses_without_prompt(tmp_path, monkeypatch) -> None:
    # Clean-laptop regression: connector-bindings.json already holds the integration,
    # Google OAuth already authorized (injected as success = reused), rerun with no
    # --google-integration-id must reuse the binding, ask nothing, and reach Online.
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    _seed_google_binding(machine)
    (machine / "google").mkdir(parents=True, exist_ok=True)
    (machine / "google" / "token.json.enc").write_text("{}", encoding="utf-8")
    _patch_install_and_heartbeat(monkeypatch, machine)

    prompts: list[str] = []
    rc, text = _setup_google_module(
        machine,
        google_integration_id=None,
        input_side_effects=prompts,
    )
    assert rc == 0
    assert "Google Workspace integration already bound locally" in text
    assert "Online" in text
    assert "setup complete" in text.lower()
    # No integration-id prompt of any kind.
    assert not any("integration ID" in p.lower() for p in prompts)
    # The binding file still holds exactly the clean-laptop integration, no duplicate.
    binding_file = machine / "agent" / "connector-bindings.json"
    payload = json.loads(binding_file.read_text(encoding="utf-8"))
    assert list(payload.keys()) == [CLEAN_LAPTOP_BINDING]
    assert payload[CLEAN_LAPTOP_BINDING]["platform"] == GOOGLE_CONNECTOR_PLATFORM


def test_resolver_reports_unavailable_advisory(tmp_path, monkeypatch) -> None:
    # The onboarding prints the dashboard/control-plane advisory when automatic
    # resolution is unavailable (no invented id, no raw-id prompt).
    machine = tmp_path / "machine"
    _seed_machine_registration(machine)
    _patch_install_and_heartbeat(monkeypatch, machine)

    out = io.StringIO()
    deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=out,
        secret_input_fn=lambda _p: "srr_tok",
        agent="yes",
        data_dir=machine,
        elevated_check=lambda: True,
        google="yes",
        authorize_google_fn=lambda *_a, **_k: True,
        apply_google_env_fn=lambda _d, **_k: None,
        verify_google_binding_fn=lambda *_a, **_k: True,
    )
    text = out.getvalue()
    assert (
        "Automatic tenant-scoped integration selection will be supported by the "
        "dashboard/control plane." in text
    )
