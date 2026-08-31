# SPDX-License-Identifier: Apache-2.0
"""Regression tests for machine-root managed-agent registration (RC clean-machine Finding 2).

These pin the fix for the acceptance-test defect where the managed-agent
registration was written to the interactive user's ``%LOCALAPPDATA%\\Securedact``
profile instead of the authoritative machine root ``C:\\ProgramData\\Securedact``,
so the SYSTEM-run scheduled task (which uses the machine root) could never find
its registration and never heart-beat Online.

The managed-agent lifecycle must use ONE authoritative machine data root
(``C:\\ProgramData\\Securedact``) for: registration metadata, the credential
vault, Google machine OAuth/config, connector bindings, logs, and the scheduled
background process. Interactive SecuRedact/MCP/model storage is unaffected.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from securedact_mcp.agent import agent_runner, deploy, service
from securedact_mcp.agent.config import AgentConfig, AgentFiles, load_config, save_config
from securedact_mcp.agent.errors import AgentError
from securedact_mcp.agent.service_taskscheduler import (
    SchtasksResult,
    install_windows_service,
)


def _machine_root(tmp_path: Path) -> Path:
    pd = tmp_path / "ProgramData"
    return pd / "Securedact"


def _make_runtime(tmp_path: Path, machine_root: Path) -> Path:
    runtime = machine_root / "runtime"
    (runtime / "Scripts").mkdir(parents=True, exist_ok=True)
    (runtime / "Scripts" / "python.exe").write_text("")
    return runtime / "Scripts" / "python.exe"


class FakeSchtasks:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, arguments: list[str]) -> SchtasksResult:
        self.calls.append(list(arguments))
        return SchtasksResult(0, "", "")


class RecordingRegister:
    """Stand-in for agent_runner.register_agent that persists a real config.

    Records the ``files`` root it was asked to register under so we can prove the
    registration lands in the machine root, not the user profile.
    """

    def __init__(self, events: list[tuple[object, str | None]] | None = None) -> None:
        self.events = events if events is not None else []
        self.files_root: Path | None = None
        self.calls: list[str] = []

    def __call__(
        self,
        token: str,
        *,
        control_plane_url: str | None = None,
        display_name: str | None = None,
        files=None,
    ) -> AgentConfig:
        from securedact_mcp.agent.config import AgentFiles

        self.calls.append(token)
        self.files_root = Path(files.root) if files is not None else None
        self.events.append(("register", token))
        cfg = AgentConfig.create(
            control_plane_url=control_plane_url or "https://www.securedact.com",
            agent_id="agent-machine-1",
            display_name=display_name or "agent",
        )
        # Persist the same way the real register_agent does, under the supplied root.
        save_config(cfg, AgentFiles.resolve(root=Path(files.root)) if files is not None else None)
        return cfg


# ---------------------------------------------------------------------------
# 1. Clean setup writes registration under the explicit machine root
# ---------------------------------------------------------------------------


def test_registration_written_to_machine_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine_root = _machine_root(tmp_path)
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))
    runtime = _make_runtime(tmp_path, machine_root)
    register = RecordingRegister()

    result = install_windows_service(
        data_dir=machine_root,
        token="srr_topsecret",  # noqa: S106
        runtime_python=runtime,
        command_runner=FakeSchtasks(),
        register_fn=register,
    )
    assert result["installed"] is True
    assert result["agent_id"] == "agent-machine-1"
    # Registration config persisted under the machine root's agent dir.
    assert (machine_root / "agent" / "agent.json").is_file()
    # The register call was given the machine-root AgentFiles.
    assert register.files_root == machine_root / "agent"


# ---------------------------------------------------------------------------
# 2. Setup does NOT write registration to %LOCALAPPDATA%\Securedact
# ---------------------------------------------------------------------------


def test_registration_not_written_to_user_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine_root = _machine_root(tmp_path)
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))
    # Point the user-profile root at a controlled location.
    user_root = tmp_path / "Users" / "Katici" / "AppData" / "Local" / "Securedact"
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Users" / "Katici" / "AppData" / "Local"))
    runtime = _make_runtime(tmp_path, machine_root)
    register = RecordingRegister()

    install_windows_service(
        data_dir=machine_root,
        token="srr_topsecret",  # noqa: S106
        runtime_python=runtime,
        command_runner=FakeSchtasks(),
        register_fn=register,
    )
    # The user-profile location must be untouched.
    assert not (user_root / "agent" / "agent.json").exists()
    # The machine root holds the only registration.
    assert (machine_root / "agent" / "agent.json").is_file()


# ---------------------------------------------------------------------------
# 3. An existing user-profile agent.json is ignored for machine registration
# ---------------------------------------------------------------------------


def test_user_profile_registration_ignored_for_machine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine_root = _machine_root(tmp_path)
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Users" / "Katici" / "AppData" / "Local"))

    # A stale user-profile registration exists.
    user_agent = tmp_path / "Users" / "Katici" / "AppData" / "Local" / "Securedact" / "agent"
    user_agent.mkdir(parents=True)
    save_config(
        AgentConfig.create(
            control_plane_url="https://www.securedact.com", agent_id="agent-user-stale"
        ),
        AgentFiles.resolve(root=user_agent),
    )
    # No machine registration yet.
    assert not (machine_root / "agent" / "agent.json").exists()

    # The machine-registration check must NOT treat the user profile as registered.
    assert deploy._agent_already_registered(data_dir=machine_root) is False


# ---------------------------------------------------------------------------
# 4. An existing valid machine agent.json is reused (no new token consumed)
# ---------------------------------------------------------------------------


def test_existing_machine_registration_is_reused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine_root = _machine_root(tmp_path)
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))
    machine_agent = machine_root / "agent"
    machine_agent.mkdir(parents=True)
    save_config(
        AgentConfig.create(
            control_plane_url="https://www.securedact.com", agent_id="agent-machine-1"
        ),
        AgentFiles.resolve(root=machine_agent),
    )
    # The machine-registration check finds the existing machine registration.
    assert deploy._agent_already_registered(data_dir=machine_root) is True


def test_reuse_does_not_consume_token_in_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine_root = _machine_root(tmp_path)
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))
    machine_agent = machine_root / "agent"
    machine_agent.mkdir(parents=True)
    save_config(
        AgentConfig.create(
            control_plane_url="https://www.securedact.com", agent_id="agent-machine-1"
        ),
        AgentFiles.resolve(root=machine_agent),
    )
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        deploy,
        "install_service_from_runtime",
        lambda **k: (
            captured.update(k)
            or {
                "installed": True,
                "service_name": "SecuRedact Managed Agent",
                "data_dir": str(machine_root),
                "account": "SYSTEM",
                "running": True,
                "agent_id": "agent-machine-1",
            }
        ),
    )
    monkeypatch.setenv(deploy.AGENT_ELEVATED_ENV, "1")

    output = __import__("io").StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        agent="yes",
        data_dir=machine_root,
        # This test covers token reuse only; decline Google explicitly so the
        # wizard never reads/writes machine-local Google state.
        google="no",
        elevated_check=lambda: True,
        secret_input_fn=lambda _p: "srr_should_not_be_used",
    )
    assert rc == 0
    # The existing machine registration was reused; no new token was forwarded.
    assert captured.get("token") is None


# ---------------------------------------------------------------------------
# 5. Registration and Task Scheduler runtime resolve exactly the same data root
# ---------------------------------------------------------------------------


def test_registration_and_runtime_share_machine_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine_root = _machine_root(tmp_path)
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))
    runtime = _make_runtime(tmp_path, machine_root)
    register = RecordingRegister()

    install_windows_service(
        data_dir=machine_root,
        token="srr_topsecret",  # noqa: S106
        runtime_python=runtime,
        command_runner=FakeSchtasks(),
        register_fn=register,
    )
    # The service resolves the same authoritative machine root.
    assert service.resolve_service_data_dir(machine_root) == machine_root
    # The runtime/launcher and registration both live under it.
    assert register.files_root == machine_root / "agent"
    # The scheduled task's working/root directory is the machine root.
    assert (machine_root / "runtime" / "Scripts" / "securedact_agent_loop.py").is_file()


# ---------------------------------------------------------------------------
# 6. Credential storage uses the machine root
# ---------------------------------------------------------------------------


def test_credential_vault_uses_machine_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.unit.test_agent_runner import _runner_transport

    machine_root = _machine_root(tmp_path)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Users" / "Katici" / "AppData" / "Local"))
    transport = _runner_transport({"n": 0}, [])
    files = AgentFiles.resolve(root=machine_root / "agent")
    cfg = agent_runner.register_agent(
        "srr_topsecret",
        control_plane_url="https://www.securedact.com",
        files=files,
        transport=transport,
    )
    # Both the config and the encrypted credential vault live under the machine root.
    assert (machine_root / "agent" / "agent.json").is_file()
    assert (machine_root / "agent" / "credentials.db").is_file()
    # The user profile is untouched.
    user_root = tmp_path / "Users" / "Katici" / "AppData" / "Local" / "Securedact"
    assert not (user_root / "agent" / "agent.json").exists()
    # The credential can be loaded back from the machine root.
    from securedact_mcp.agent.credentials import AgentCredentialStore

    store = AgentCredentialStore(cfg.agent_id, root=machine_root / "agent")
    assert store.get() is not None


# ---------------------------------------------------------------------------
# 7. Google machine binding continues using the same root
# ---------------------------------------------------------------------------


def test_google_binding_uses_machine_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from securedact_mcp.agent import google_setup

    machine_root = _machine_root(tmp_path)
    machine_agent = machine_root / "agent"
    machine_agent.mkdir(parents=True)
    cfg = AgentConfig.create(
        control_plane_url="https://www.securedact.com", agent_id="agent-machine-1"
    )
    save_config(cfg, AgentFiles.resolve(root=machine_agent))

    binding = google_setup.bind_google_machine(
        cfg,
        "integration-123",
        files=AgentFiles.resolve(root=machine_agent),
    )
    assert binding.integration_id == "integration-123"
    # The binding is persisted under the machine root, not the user profile.
    assert (machine_root / "agent" / "connector-bindings.json").is_file()


# ---------------------------------------------------------------------------
# 8. Registration failure leaves no partially-valid machine state
# ---------------------------------------------------------------------------


def test_registration_failure_leaves_no_machine_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine_root = _machine_root(tmp_path)
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))
    runtime = _make_runtime(tmp_path, machine_root)

    def _boom(token, *, control_plane_url=None, display_name=None, files=None):
        raise AgentError("registration failed safely during task install")

    with pytest.raises(AgentError):
        install_windows_service(
            data_dir=machine_root,
            token="srr_topsecret",  # noqa: S106
            runtime_python=runtime,
            command_runner=FakeSchtasks(),
            register_fn=_boom,
        )
    # No agent.json was written to the machine root on failure.
    assert not (machine_root / "agent" / "agent.json").exists()


# ---------------------------------------------------------------------------
# 9. Scheduled-agent startup can consume the new machine registration
# ---------------------------------------------------------------------------


def test_scheduled_agent_startup_consumes_machine_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from securedact_mcp.agent.credentials import AgentCredentialStore

    machine_root = _machine_root(tmp_path)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Users" / "Katici" / "AppData" / "Local"))
    from tests.unit.test_agent_runner import _runner_transport

    transport = _runner_transport({"n": 0}, [])
    files = AgentFiles.resolve(root=machine_root / "agent")
    cfg = agent_runner.register_agent(
        "srr_topsecret",
        control_plane_url="https://www.securedact.com",
        files=files,
        transport=transport,
    )
    # The SYSTEM-run loop resolves its config from the machine root (the same root
    # persisted at setup, via SECUREDACT_APP_DATA_DIR). It must load identically.
    loaded = load_config(AgentFiles.resolve(root=machine_root / "agent"))
    assert loaded.agent_id == cfg.agent_id
    assert AgentCredentialStore(cfg.agent_id, root=machine_root / "agent").get() is not None


# ---------------------------------------------------------------------------
# 10. Heartbeat reaches Online from the machine registration
# ---------------------------------------------------------------------------


def test_heartbeat_online_from_machine_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine_root = _machine_root(tmp_path)
    _make_runtime(tmp_path, machine_root)

    class HBRunner:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        def __call__(self, arguments: list[str], run_input):  # type: ignore[no-untyped-def]
            self.calls.append(list(arguments))
            # The heartbeat subcommand resolves the same machine root via env.
            assert run_input.env.get("SECUREDACT_APP_DATA_DIR") == str(machine_root)
            return __import__("securedact_mcp.agent.deploy", fromlist=["x"]).RunResult(
                0, stdout=__import__("json").dumps({"agent_id": "agent-machine-1"})
            )

    # Register under the machine root first (the scheduled task's data dir).
    from tests.unit.test_agent_runner import _runner_transport

    transport = _runner_transport({"n": 0}, [])
    agent_runner.register_agent(
        "srr_topsecret",
        control_plane_url="https://www.securedact.com",
        files=AgentFiles.resolve(root=machine_root / "agent"),
        transport=transport,
    )
    # The heartbeat verification (used by setup and the running agent) resolves the
    # machine root and reports Online.
    assert (
        deploy.verify_heartbeat(
            data_dir=machine_root, runtime_path=machine_root / "runtime", command_runner=HBRunner()
        )
        is True
    )
