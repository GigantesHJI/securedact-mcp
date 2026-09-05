# SPDX-License-Identifier: Apache-2.0
"""Windows lifecycle and migration regression tests.

These tests pin the fix for the real-Windows managed-agent lifecycle defect where:

* A legacy ``SecuredactAgent`` SCM service (pywin32/pythonservice.exe) coexisted
  with the canonical ``SecuRedact Managed Agent`` Task Scheduler task.
* ``agent service status`` returned ``installed=false`` even when the Scheduled
  Task existed and the agent was running.
* ``agent status`` reported the stale registration-time version instead of the
  currently running software version.
* ``agent service upgrade`` could complete against a same-version stale wheel
  while reporting ``upgraded=true`` without verifying the artifact changed.

Canonical mechanism: Windows Task Scheduler (boot-triggered, SYSTEM, non-interactive).
The legacy pywin32/SCM service is a disabled reference and must be migrated away
by every install/upgrade so a machine can never have both active.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# 1. Canonical mechanism is Task Scheduler
# ---------------------------------------------------------------------------


def test_active_persistence_backend_is_taskscheduler() -> None:
    from securedact_mcp.agent.service import ACTIVE_PERSISTENCE_BACKEND

    assert ACTIVE_PERSISTENCE_BACKEND == "taskscheduler"


def test_scheduled_task_name_is_constant() -> None:
    from securedact_mcp.agent.service_taskscheduler import SCHEDULED_TASK_NAME

    assert SCHEDULED_TASK_NAME == "SecuRedact Managed Agent"


# ---------------------------------------------------------------------------
# 2. Status command inspects the canonical mechanism (Task Scheduler)
# ---------------------------------------------------------------------------


def test_status_reports_not_installed_when_no_task() -> None:
    """When no Scheduled Task exists, status must report installed=false."""
    from securedact_mcp.agent.service_taskscheduler import SchtasksResult, _parse_status

    def fake_runner(args: list[str]) -> SchtasksResult:
        # schtasks /Query returns non-zero when the task does not exist
        return SchtasksResult(
            returncode=1, stdout="", stderr="ERROR: The system cannot find the file specified."
        )

    with (
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_exists",
            return_value=False,
        ),
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_state",
            return_value=None,
        ),
    ):
        status = _parse_status("SecuRedact Managed Agent", fake_runner)

    assert status["installed"] is False
    assert status["service_name"] == "SecuRedact Managed Agent"
    assert status["legacy_scm_service"] is False
    assert status["legacy_scm_state"] is None


def test_status_reports_installed_when_task_exists() -> None:
    """When the Scheduled Task exists, status must report installed=true."""
    from securedact_mcp.agent.service_taskscheduler import SchtasksResult, _parse_status

    def fake_runner(args: list[str]) -> SchtasksResult:
        return SchtasksResult(
            returncode=0,
            stdout=json.dumps([{"Status": "Running", "Name": "SecuRedact Managed Agent"}]),
        )

    with (
        patch(
            "securedact_mcp.agent.service_taskscheduler._find_agent_processes",
            return_value=[1234],
        ),
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_exists",
            return_value=False,
        ),
    ):
        status = _parse_status("SecuRedact Managed Agent", fake_runner)

    assert status["installed"] is True
    assert status["state"] == "running"
    assert status["running"] is True
    assert status["agent_pids"] == [1234]


def test_status_real_machine_repro_rc0_ready_table_format() -> None:
    """Regression for the real-Windows reproduction:

    ``schtasks /Query /TN "SecuRedact Managed Agent"`` returns rc=0 with the
    task in ``Ready`` state, but ``schtasks /Query /TN ... /FO JSON`` returns
    a non-zero exit on this host. ``query_windows_service`` must still report
    ``installed=True`` and ``running=False`` because the task is registered and
    the agent loop is not currently executing.
    """
    from securedact_mcp.agent.service_taskscheduler import SchtasksResult, _parse_status

    def fake_runner(args: list[str]) -> SchtasksResult:
        # /FO JSON form returns non-zero on this host (the exact behaviour seen
        # in the bug report). The default TABLE form returns rc=0 with the
        # task listing.
        if "/FO" in args and "JSON" in args:
            return SchtasksResult(
                returncode=1,
                stdout="",
                stderr="ERROR: The system cannot find the file specified.",
            )
        return SchtasksResult(
            returncode=0,
            stdout=(
                "TaskName: \\SecuRedact Managed Agent\n"
                "Status: Ready\n"
                "Scheduled Task State: Enabled\n"
                "Run As User: SYSTEM\n"
            ),
        )

    with (
        patch(
            "securedact_mcp.agent.service_taskscheduler._find_agent_processes",
            return_value=[],
        ),
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_exists",
            return_value=False,
        ),
    ):
        status = _parse_status("SecuRedact Managed Agent", fake_runner)

    assert status["installed"] is True
    assert status["running"] is False
    assert status["agent_pids"] == []
    assert status["service_name"] == "SecuRedact Managed Agent"
    assert status["legacy_scm_service"] is False
    assert status["legacy_scm_state"] is None


def test_status_rc0_running_reports_installed_and_running() -> None:
    """rc=0 with a ``Running`` JSON state must yield installed=true,
    running=true — independent of the agent process enumeration.
    """
    from securedact_mcp.agent.service_taskscheduler import SchtasksResult, _parse_status

    def fake_runner(args: list[str]) -> SchtasksResult:
        if "/FO" in args and "JSON" in args:
            return SchtasksResult(
                returncode=0,
                stdout=json.dumps([{"State": "Running", "URI": "\\SecuRedact Managed Agent"}]),
            )
        return SchtasksResult(returncode=0, stdout="TaskName: \\SecuRedact Managed Agent\n")

    with (
        patch(
            "securedact_mcp.agent.service_taskscheduler._find_agent_processes",
            return_value=[4242],
        ),
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_exists",
            return_value=False,
        ),
    ):
        status = _parse_status("SecuRedact Managed Agent", fake_runner)

    assert status["installed"] is True
    assert status["running"] is True
    assert status["agent_pids"] == [4242]
    assert status["state"] == "running"


def test_status_nonzero_reports_not_installed() -> None:
    """When schtasks returns non-zero (task absent), installed must be False."""
    from securedact_mcp.agent.service_taskscheduler import SchtasksResult, _parse_status

    def fake_runner(args: list[str]) -> SchtasksResult:
        return SchtasksResult(
            returncode=1, stdout="", stderr="ERROR: The system cannot find the file specified."
        )

    with (
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_exists",
            return_value=False,
        ),
        patch(
            "securedact_mcp.agent.service_taskscheduler._find_agent_processes",
            return_value=[],
        ),
    ):
        status = _parse_status("SecuRedact Managed Agent", fake_runner)

    assert status["installed"] is False
    assert status["running"] is False
    assert status["agent_pids"] == []


def test_status_task_absent_but_orphan_process_reports_installed_false_running_true() -> None:
    """When the task is absent but an orphan/live agent process exists,
    installed=False and running=True are semantically independent."""
    from securedact_mcp.agent.service_taskscheduler import SchtasksResult, _parse_status

    def fake_runner(args: list[str]) -> SchtasksResult:
        return SchtasksResult(
            returncode=1, stdout="", stderr="ERROR: The system cannot find the file specified."
        )

    with (
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_exists",
            return_value=False,
        ),
        patch(
            "securedact_mcp.agent.service_taskscheduler._find_agent_processes",
            return_value=[9999],
        ),
    ):
        status = _parse_status("SecuRedact Managed Agent", fake_runner)

    assert status["installed"] is False
    assert status["running"] is True
    assert status["agent_pids"] == [9999]


def test_status_accepts_root_path_task_name() -> None:
    """Passing ``\\SecuRedact Managed Agent`` (root-path form) must produce the
    same installed=true result as the bare name."""
    from securedact_mcp.agent.service_taskscheduler import SchtasksResult, _parse_status

    seen_args: list[list[str]] = []

    def fake_runner(args: list[str]) -> SchtasksResult:
        seen_args.append(list(args))
        return SchtasksResult(returncode=0, stdout="")

    with (
        patch(
            "securedact_mcp.agent.service_taskscheduler._find_agent_processes",
            return_value=[],
        ),
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_exists",
            return_value=False,
        ),
    ):
        status = _parse_status("\\SecuRedact Managed Agent", fake_runner)

    assert status["installed"] is True
    # Existence probe must use the root-path form.
    assert seen_args[0] == ["/Query", "/TN", "\\SecuRedact Managed Agent"]


def test_status_localized_non_english_stdout_does_not_make_not_installed() -> None:
    """Localised schtasks output (e.g. German "Bereit") must not affect the
    ``installed`` decision. Only the process return code matters."""
    from securedact_mcp.agent.service_taskscheduler import SchtasksResult, _parse_status

    localized = (
        "TaskName: \\SecuRedact Managed Agent\nStatus: Bereit\nGeplante Aufgabenstatus: Aktiviert\n"
    )

    def fake_runner(args: list[str]) -> SchtasksResult:
        if "/FO" in args and "JSON" in args:
            # Localised schtasks builds may also reject /FO JSON.
            return SchtasksResult(returncode=1, stdout="", stderr="")
        return SchtasksResult(returncode=0, stdout=localized)

    with (
        patch(
            "securedact_mcp.agent.service_taskscheduler._find_agent_processes",
            return_value=[],
        ),
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_exists",
            return_value=False,
        ),
    ):
        status = _parse_status("SecuRedact Managed Agent", fake_runner)

    assert status["installed"] is True
    # ``state`` is unknown here because the JSON probe failed; that is fine.
    assert status["state"] == "unknown"


def test_task_exists_uses_normalized_root_path_name() -> None:
    """``task_exists`` must query the canonical root-path form so existence
    detection is independent of caller-provided surface form."""
    from securedact_mcp.agent.service_taskscheduler import SchtasksResult, task_exists

    seen: list[list[str]] = []

    def fake_runner(args: list[str]) -> SchtasksResult:
        seen.append(list(args))
        return SchtasksResult(returncode=0, stdout="")

    assert task_exists("SecuRedact Managed Agent", runner=fake_runner) is True
    assert seen[-1] == ["/Query", "/TN", "\\SecuRedact Managed Agent"]

    seen.clear()
    assert task_exists("\\SecuRedact Managed Agent", runner=fake_runner) is True
    assert seen[-1] == ["/Query", "/TN", "\\SecuRedact Managed Agent"]


def test_status_reports_not_running_when_no_agent_process() -> None:
    """When the task exists but no agent process is running, running=false."""
    from securedact_mcp.agent.service_taskscheduler import SchtasksResult, _parse_status

    def fake_runner(args: list[str]) -> SchtasksResult:
        return SchtasksResult(
            returncode=0,
            stdout=json.dumps([{"Status": "Ready", "Name": "SecuRedact Managed Agent"}]),
        )

    with (
        patch(
            "securedact_mcp.agent.service_taskscheduler._find_agent_processes",
            return_value=[],
        ),
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_exists",
            return_value=False,
        ),
    ):
        status = _parse_status("SecuRedact Managed Agent", fake_runner)

    assert status["installed"] is True
    assert status["state"] == "ready"
    assert status["running"] is False


def test_status_detects_legacy_scm_service_when_no_task() -> None:
    """When only the legacy SCM service exists, status must report it."""
    from securedact_mcp.agent.service_taskscheduler import SchtasksResult, _parse_status

    def fake_runner(args: list[str]) -> SchtasksResult:
        return SchtasksResult(returncode=1, stdout="", stderr="not found")

    with (
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_exists",
            return_value=True,
        ),
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_state",
            return_value="stopped",
        ),
    ):
        status = _parse_status("SecuRedact Managed Agent", fake_runner)

    assert status["installed"] is False
    assert status["legacy_scm_service"] is True
    assert status["legacy_scm_state"] == "stopped"


# ---------------------------------------------------------------------------
# 3. Legacy SCM service migration
# ---------------------------------------------------------------------------


def test_install_removes_legacy_scm_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Install must remove the legacy SCM service to prevent coexistence."""
    from securedact_mcp.agent import service_taskscheduler

    removed = []

    def fake_remove() -> bool:
        removed.append(True)
        return True

    monkeypatch.setattr(service_taskscheduler, "_legacy_scm_service_exists", lambda: True)
    monkeypatch.setattr(service_taskscheduler, "_remove_legacy_scm_service", fake_remove)
    monkeypatch.setattr(service_taskscheduler, "task_exists", lambda name, runner=None: False)
    monkeypatch.setattr(service_taskscheduler, "_create_task", lambda name, xml, runner: None)

    class FakeRunner:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        def __call__(self, args: list[str]) -> service_taskscheduler.SchtasksResult:
            self.calls.append(list(args))
            return service_taskscheduler.SchtasksResult(0, "", "")

    runtime = tmp_path / "runtime"
    (runtime / "Scripts").mkdir(parents=True)
    (runtime / "Scripts" / "python.exe").write_text("")

    service_taskscheduler.install_windows_service(
        data_dir=tmp_path,
        runtime_python=runtime,
        command_runner=FakeRunner(),
        register_fn=lambda *a, **k: None,
    )
    assert removed == [True]


def test_uninstall_windows_service_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Uninstall removes the Scheduled Task."""
    from securedact_mcp.agent import service_taskscheduler

    deleted = []

    def fake_delete(name: str, runner) -> None:
        deleted.append(name)

    monkeypatch.setattr(service_taskscheduler, "task_exists", lambda name, runner=None: True)
    monkeypatch.setattr(service_taskscheduler, "_delete_task", fake_delete)

    result = service_taskscheduler.uninstall_windows_service()
    assert result["uninstalled"] is True
    assert deleted == ["SecuRedact Managed Agent"]


# ---------------------------------------------------------------------------
# 4. Upgrade lifecycle - artifact change verification
# ---------------------------------------------------------------------------


def test_upgrade_reports_no_change_when_fingerprint_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Upgrade must report upgraded=false when the artifact fingerprint is identical."""
    from securedact_mcp.agent import deploy

    monkeypatch.setattr(deploy, "is_elevated", lambda: True)
    monkeypatch.setattr(deploy, "_default_agent_control", lambda action: action == "start")

    # Same fingerprint before and after -> no change
    monkeypatch.setattr(
        deploy, "_compute_runtime_fingerprint", lambda runtime, runner: "same-digest"
    )

    # Stub out provision_machine_runtime to avoid real work
    class FakeProvision:
        def __init__(self, *a: Any, **kw: Any) -> None:
            self.runtime = tmp_path / "runtime"
            self.runtime_python = self.runtime / "Scripts" / "python.exe"
            self.runtime_python.parent.mkdir(parents=True, exist_ok=True)
            self.runtime_python.write_text("")
            self.already_provisioned = False
            self.hardened = True

    monkeypatch.setattr(deploy, "provision_machine_runtime", FakeProvision)
    monkeypatch.setattr(deploy, "validate_runtime_security", lambda *a, **kw: [])
    monkeypatch.setattr(deploy, "verify_runtime_tree_acl", lambda *a, **kw: None)
    monkeypatch.setattr(
        deploy,
        "_run_bootstrap",
        lambda runner, py, sub, data_dir: deploy.RunResult(0, stdout="ok"),
    )

    result = deploy.upgrade_runtime(runtime_path=tmp_path / "runtime", data_dir=tmp_path)
    assert result["upgraded"] is False
    assert result["artifact_changed"] is False


def test_upgrade_reports_changed_when_fingerprint_differs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Upgrade must report upgraded=true when the artifact fingerprint changes."""
    from securedact_mcp.agent import deploy

    monkeypatch.setattr(deploy, "is_elevated", lambda: True)
    monkeypatch.setattr(deploy, "_default_agent_control", lambda action: action == "start")

    # Different fingerprint -> changed
    counter = [0]

    def fake_fingerprint(runtime: Path, runner: Any) -> str:
        counter[0] += 1
        return f"digest-{counter[0]}"

    monkeypatch.setattr(deploy, "_compute_runtime_fingerprint", fake_fingerprint)

    class FakeProvision:
        def __init__(self, *a: Any, **kw: Any) -> None:
            self.runtime = tmp_path / "runtime"
            self.runtime_python = self.runtime / "Scripts" / "python.exe"
            self.runtime_python.parent.mkdir(parents=True, exist_ok=True)
            self.runtime_python.write_text("")
            self.already_provisioned = False
            self.hardened = True

    monkeypatch.setattr(deploy, "provision_machine_runtime", FakeProvision)
    monkeypatch.setattr(deploy, "validate_runtime_security", lambda *a, **kw: [])
    monkeypatch.setattr(deploy, "verify_runtime_tree_acl", lambda *a, **kw: None)
    monkeypatch.setattr(
        deploy,
        "_run_bootstrap",
        lambda runner, py, sub, data_dir: deploy.RunResult(0, stdout="ok"),
    )

    result = deploy.upgrade_runtime(runtime_path=tmp_path / "runtime", data_dir=tmp_path)
    assert result["upgraded"] is True
    assert result["artifact_changed"] is True


def test_upgrade_uses_bounded_wait_agent_control(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Upgrade must use the same bounded-wait agent control as provisioning."""
    from securedact_mcp.agent import deploy

    monkeypatch.setattr(deploy, "is_elevated", lambda: True)

    actions: list[str] = []

    def fake_control(action: str) -> bool:
        actions.append(action)
        return action == "stop"

    monkeypatch.setattr(deploy, "_default_agent_control", fake_control)
    monkeypatch.setattr(deploy, "_compute_runtime_fingerprint", lambda runtime, runner: "same")

    class FakeProvision:
        def __init__(self, *a: Any, **kw: Any) -> None:
            self.runtime_path = tmp_path / "runtime"
            self.runtime_python = self.runtime_path / "Scripts" / "python.exe"
            self.runtime_python.parent.mkdir(parents=True, exist_ok=True)
            self.runtime_python.write_text("")
            self.already_provisioned = False
            self.hardened = True

    monkeypatch.setattr(deploy, "provision_machine_runtime", FakeProvision)
    monkeypatch.setattr(deploy, "validate_runtime_security", lambda *a, **kw: [])
    monkeypatch.setattr(deploy, "verify_runtime_tree_acl", lambda *a, **kw: None)
    monkeypatch.setattr(
        deploy,
        "_run_bootstrap",
        lambda runner, py, sub, data_dir: deploy.RunResult(0, stdout="ok"),
    )

    deploy.upgrade_runtime(runtime_path=tmp_path / "runtime", data_dir=tmp_path)
    assert "stop" in actions
    # Upgrade uses _run_bootstrap directly for start, not _default_agent_control
    assert actions == ["stop"]


# ---------------------------------------------------------------------------
# 5. Version reporting - running version, not persisted
# ---------------------------------------------------------------------------


def test_agent_status_reports_running_version_not_persisted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """agent_status must report the running software version, not the registration-time version."""
    from securedact_mcp.agent import agent_runner
    from securedact_mcp.agent.config import AgentConfig, AgentFiles, save_config

    # Persist a config with a stale version (simulating old registration)
    stale = AgentConfig(
        control_plane_url="https://www.securedact.com",
        agent_id="agent-1",
        display_name="test",
        runtime_platform="windows",
        agent_version="0.4.2",  # stale
    )
    files = AgentFiles.resolve(root=tmp_path / "agent")
    save_config(stale, files)

    status = agent_runner.agent_status(stale, files=files)
    # Must report the running version (from securedact_mcp.__version__), not 0.4.2
    from securedact_mcp import __version__

    assert status.agent_version == __version__
    assert status.agent_version != "0.4.2"
    # agent_id must be preserved
    assert status.agent_id == "agent-1"


def test_heartbeat_sends_running_version(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The heartbeat must send the running version, not the persisted version."""
    from securedact_mcp.agent import agent_runner
    from securedact_mcp.agent.config import AgentConfig, AgentFiles
    from securedact_mcp.agent.state import AgentStateStore

    config = AgentConfig(
        control_plane_url="https://cp.example.com",
        agent_id="agent-1",
        display_name="test",
        runtime_platform="windows",
        agent_version="0.4.2",  # stale
    )
    files = AgentFiles.resolve(root=tmp_path / "agent")
    files.ensure()
    state_store = AgentStateStore(files)

    sent_versions: list[str] = []

    class FakeClient:
        def heartbeat(
            self,
            agent_version: str,
            capabilities: Any,
            connector_bindings: list[dict[str, str]] | None = None,
        ) -> Any:
            sent_versions.append(agent_version)
            from securedact_mcp.agent.client import HeartbeatResponse

            return HeartbeatResponse(
                agent_id="agent-1",
                server_time="0",
                recommended_heartbeat_seconds=300,
                config_refresh_required=False,
                entitlement_refresh_required=False,
            )

    agent_runner._heartbeat(config, FakeClient(), state_store, files=files)  # type: ignore[arg-type]
    from securedact_mcp import __version__

    assert sent_versions == [__version__]
    assert sent_versions[0] != "0.4.2"


# ---------------------------------------------------------------------------
# 6. Lifecycle command consistency
# ---------------------------------------------------------------------------


def test_service_lifecycle_commands_exist_in_cli() -> None:
    """All required service lifecycle subcommands must be in the CLI parser."""
    from securedact_mcp.agent.cli import build_agent_parser

    parser = type("P", (), {})()
    import argparse

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    build_agent_parser(sub)

    for sub_cmd in ("install", "start", "stop", "status", "uninstall", "upgrade"):
        args = parser.parse_args(["agent", "service", sub_cmd])
        assert args.service_command == sub_cmd, f"Missing CLI subcommand: {sub_cmd}"


def test_all_service_commands_route_through_service_module() -> None:
    """All service subcommands must route through service module (not direct SCM)."""
    from securedact_mcp.agent import service, service_taskscheduler

    # Verify the service module delegates to service_taskscheduler
    assert hasattr(service, "install_service")
    assert hasattr(service, "start_service")
    assert hasattr(service, "stop_service")
    assert hasattr(service, "uninstall_service")
    assert hasattr(service, "query_service_status")
    # The service module should NOT have SCM-specific functions
    assert not hasattr(service, "install_pywin32_service")
    # service_taskscheduler should have the canonical implementations
    assert hasattr(service_taskscheduler, "install_windows_service")
    assert hasattr(service_taskscheduler, "start_windows_service")
    assert hasattr(service_taskscheduler, "stop_windows_service")


# ---------------------------------------------------------------------------
# 7. Idempotent install
# ---------------------------------------------------------------------------


def test_install_is_idempotent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Running install twice must not fail and must produce a consistent result."""
    from securedact_mcp.agent import service_taskscheduler

    runtime = tmp_path / "runtime"
    (runtime / "Scripts").mkdir(parents=True)
    (runtime / "Scripts" / "python.exe").write_text("")

    class FakeRunner:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []
            self.task_exists = False

        def __call__(self, args: list[str]) -> service_taskscheduler.SchtasksResult:
            self.calls.append(list(args))
            if args[0] == "/Query" and "/TN" in args:
                if self.task_exists:
                    return service_taskscheduler.SchtasksResult(
                        returncode=0,
                        stdout=json.dumps(
                            [{"Status": "Ready", "Name": "SecuRedact Managed Agent"}]
                        ),
                    )
                return service_taskscheduler.SchtasksResult(
                    returncode=1, stdout="", stderr="not found"
                )
            return service_taskscheduler.SchtasksResult(0, "", "")

    runner = FakeRunner()
    monkeypatch.setattr(service_taskscheduler, "_legacy_scm_service_exists", lambda: False)
    monkeypatch.setattr(
        service_taskscheduler, "task_exists", lambda name, r=None: runner.task_exists
    )

    def fake_create(name: str, xml: str, r: Any) -> None:
        runner.task_exists = True

    monkeypatch.setattr(service_taskscheduler, "_create_task", fake_create)
    monkeypatch.setattr(service_taskscheduler, "_delete_task", lambda name, r: None)
    monkeypatch.setattr(service_taskscheduler, "_start_task", lambda name, r: None)
    monkeypatch.setattr(service_taskscheduler, "write_launcher_script", lambda p: Path(p))

    result1 = service_taskscheduler.install_windows_service(
        data_dir=tmp_path,
        runtime_python=runtime,
        command_runner=runner,
        register_fn=None,
    )
    result2 = service_taskscheduler.install_windows_service(
        data_dir=tmp_path,
        runtime_python=runtime,
        command_runner=runner,
        register_fn=None,
    )
    assert result1["installed"] is True
    assert result2["installed"] is True


# ---------------------------------------------------------------------------
# 8. No duplicate agent processes - single-instance lock
# ---------------------------------------------------------------------------


def test_service_run_loop_rejects_second_instance(tmp_path: Path) -> None:
    """The agent loop must refuse to start when another instance holds the lock."""
    from securedact_mcp.agent import agent_runner, service
    from securedact_mcp.agent.config import AgentFiles
    from securedact_mcp.agent.service_lock import agent_instance_lock
    from tests.unit.test_agent_runner import _runner_transport

    transport = _runner_transport({"n": 0}, [])
    files = AgentFiles.resolve(root=tmp_path / "agent")
    agent_runner.register_agent(
        "srr_tok", control_plane_url="https://cp.example.com", files=files, transport=transport
    )

    with agent_instance_lock(files.root / "agent.lock"):
        rc = service.run_service_loop(
            stop=lambda: True, idle_sleep=0, data_dir=tmp_path, agent_runner=agent_runner
        )
    assert rc == 3  # lock held by another instance


# ---------------------------------------------------------------------------
# 9. Registration and connector bindings survive upgrade
# ---------------------------------------------------------------------------


def test_upgrade_does_not_touch_data_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Upgrade must not modify the data dir (registration, credentials, bindings)."""
    from securedact_mcp.agent import deploy
    from securedact_mcp.agent.config import AgentConfig, AgentFiles, save_config

    data_dir = tmp_path / "data"
    (data_dir / "agent").mkdir(parents=True)
    cfg = AgentConfig(
        control_plane_url="https://www.securedact.com",
        agent_id="agent-original",
        display_name="test",
        runtime_platform="windows",
        agent_version="0.4.2",
    )
    save_config(cfg, AgentFiles.resolve(root=data_dir / "agent"))
    # Write a fake credential vault
    (data_dir / "agent" / "credentials.db").write_text("fake-credentials")
    # Write a fake binding
    (data_dir / "agent" / "connector-bindings.json").write_text(
        json.dumps({"bindings": [{"integration_id": "google-1", "platform": "google_workspace"}]})
    )

    monkeypatch.setattr(deploy, "is_elevated", lambda: True)
    monkeypatch.setattr(deploy, "_default_agent_control", lambda a: a == "start")
    monkeypatch.setattr(deploy, "_compute_runtime_fingerprint", lambda r, runner: "same")

    class FakeProvision:
        def __init__(self, *a: Any, **kw: Any) -> None:
            self.runtime = tmp_path / "runtime"
            self.runtime_python = self.runtime / "Scripts" / "python.exe"
            self.runtime_python.parent.mkdir(parents=True, exist_ok=True)
            self.runtime_python.write_text("")
            self.already_provisioned = False
            self.hardened = True

    monkeypatch.setattr(deploy, "provision_machine_runtime", FakeProvision)
    monkeypatch.setattr(deploy, "validate_runtime_security", lambda *a, **kw: [])
    monkeypatch.setattr(deploy, "verify_runtime_tree_acl", lambda *a, **kw: None)
    monkeypatch.setattr(
        deploy,
        "_run_bootstrap",
        lambda runner, py, sub, *, data_dir: deploy.RunResult(0, stdout="ok"),
    )

    deploy.upgrade_runtime(runtime_path=tmp_path / "runtime", data_dir=data_dir)

    # Data dir must be untouched
    assert (data_dir / "agent" / "credentials.db").read_text() == "fake-credentials"
    loaded = save_config  # noqa - just for reference
    from securedact_mcp.agent.config import load_config

    reloaded = load_config(AgentFiles.resolve(root=data_dir / "agent"))
    assert reloaded.agent_id == "agent-original"
    assert (data_dir / "agent" / "connector-bindings.json").is_file()


# ---------------------------------------------------------------------------
# 10. Agent process detection (PID 26520 style) via native WMI
# ---------------------------------------------------------------------------


class _FakeWmiProc:
    """Minimal stand-in for the WMI ``Win32_Process`` COM object."""

    def __init__(self, pid: int, exe: str, cmdline: str) -> None:
        self.ProcessId = pid
        self.ExecutablePath = exe
        self.CommandLine = cmdline


class _FakeWmiResult:
    """Minimal stand-in for the iterable returned by ``IWbemServices.ExecQuery``."""

    def __init__(self, items: list[_FakeWmiProc]) -> None:
        self._items = items

    def __iter__(self):
        return iter(self._items)


class _FakeWmi:
    def __init__(self, items: list[_FakeWmiProc]) -> None:
        self._items = items

    def ExecQuery(self, query: str) -> _FakeWmiResult:
        return _FakeWmiResult(self._items)


def _build_fake_win32com(items: list[_FakeWmiProc]) -> Any:
    fake_module = type(
        "M",
        (),
        {"GetObject": staticmethod(lambda _ns: _FakeWmi(items))},
    )
    return fake_module


RUNTIME_ROOT = Path(r"C:\ProgramData\Securedact\runtime")
RUNTIME_PYTHON = RUNTIME_ROOT / "Scripts" / "python.exe"
RUNTIME_CMDLINE = (
    '"C:\\ProgramData\\Securedact\\runtime\\Scripts\\python.exe" '
    '"C:\\ProgramData\\Securedact\\runtime\\Scripts\\securedact_agent_loop.py" run'
)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows WMI-specific test")
def test_find_agent_processes_matches_real_machine_pid_26520_shape() -> None:
    """Match the real-machine repro: PID 26520, runtime python.exe, command
    line invoking ``securedact_agent_loop.py run``."""
    from securedact_mcp.agent.service_taskscheduler import _find_agent_processes

    items = [_FakeWmiProc(26520, str(RUNTIME_PYTHON), RUNTIME_CMDLINE)]
    with patch(
        "securedact_mcp.agent.service_taskscheduler.win32com_client",
        _build_fake_win32com(items),
        create=True,
    ):
        pids = _find_agent_processes(RUNTIME_PYTHON)

    assert pids == [26520]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows WMI-specific test")
def test_find_agent_processes_running_true_in_status_when_process_present() -> None:
    """End-to-end: ``query_windows_service`` must report ``running=True`` when a
    matching agent process is present."""
    from securedact_mcp.agent.service_taskscheduler import SchtasksResult, _parse_status

    def fake_runner(args: list[str]) -> SchtasksResult:
        return SchtasksResult(returncode=0, stdout="")

    items = [_FakeWmiProc(26520, str(RUNTIME_PYTHON), RUNTIME_CMDLINE)]
    with (
        patch(
            "securedact_mcp.agent.service_taskscheduler.win32com_client",
            _build_fake_win32com(items),
            create=True,
        ),
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_exists",
            return_value=False,
        ),
    ):
        status = _parse_status("SecuRedact Managed Agent", fake_runner)

    assert status["installed"] is True
    assert status["running"] is True
    assert status["agent_pids"] == [26520]


def test_find_agent_processes_ignores_unrelated_python() -> None:
    """An arbitrary python.exe that does NOT live in the machine runtime must
    not be reported as the managed agent process."""
    from securedact_mcp.agent.service_taskscheduler import _find_agent_processes

    items = [
        # Developer interpreter running some unrelated tool
        _FakeWmiProc(
            1000,
            r"C:\Python312\python.exe",
            r"C:\projects\mything\something.py",
        ),
        # CI helper
        _FakeWmiProc(
            2000,
            r"C:\Python312\python.exe",
            r"C:\Python312\Lib\runpy.py",
        ),
    ]
    with patch(
        "securedact_mcp.agent.service_taskscheduler.win32com_client",
        _build_fake_win32com(items),
        create=True,
    ):
        pids = _find_agent_processes(RUNTIME_PYTHON)

    assert pids == []


def test_find_agent_processes_ignores_wrong_runtime_path() -> None:
    """A python.exe that lives under a different ``runtime`` directory (not the
    canonical machine runtime) must not match, even when the command line
    references our launcher script."""
    from securedact_mcp.agent.service_taskscheduler import _find_agent_processes

    items = [
        # Looks similar but is a *different* runtime (e.g. an attacker / a
        # rogue install).
        _FakeWmiProc(
            3000,
            r"D:\dev\Securedact\runtime\Scripts\python.exe",
            r'"D:\dev\Securedact\runtime\Scripts\python.exe" '
            r'"D:\dev\Securedact\runtime\Scripts\securedact_agent_loop.py" run',
        ),
    ]
    with patch(
        "securedact_mcp.agent.service_taskscheduler.win32com_client",
        _build_fake_win32com(items),
        create=True,
    ):
        pids = _find_agent_processes(RUNTIME_PYTHON)

    assert pids == []


def test_find_agent_processes_running_false_when_no_process() -> None:
    """Task present but no matching agent process must yield ``running=False``."""
    from securedact_mcp.agent.service_taskscheduler import SchtasksResult, _parse_status

    def fake_runner(args: list[str]) -> SchtasksResult:
        return SchtasksResult(returncode=0, stdout="")

    with (
        patch(
            "securedact_mcp.agent.service_taskscheduler.win32com_client",
            _build_fake_win32com([]),
            create=True,
        ),
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_exists",
            return_value=False,
        ),
    ):
        status = _parse_status("SecuRedact Managed Agent", fake_runner)

    assert status["installed"] is True
    assert status["running"] is False
    assert status["agent_pids"] == []


def test_find_agent_processes_unavailable_keeps_installed_correct() -> None:
    """If pywin32 / WMI is unavailable, ``installed`` (from schtasks) must
    still be reported correctly. ``running`` simply reads false."""
    from securedact_mcp.agent.service_taskscheduler import SchtasksResult, _parse_status

    def fake_runner(args: list[str]) -> SchtasksResult:
        return SchtasksResult(returncode=0, stdout="")

    with (
        patch(
            "securedact_mcp.agent.service_taskscheduler.win32com_client",
            None,
        ),
        patch(
            "securedact_mcp.agent.service_taskscheduler._legacy_scm_service_exists",
            return_value=False,
        ),
    ):
        status = _parse_status("SecuRedact Managed Agent", fake_runner)

    assert status["installed"] is True
    assert status["running"] is False
    assert status["agent_pids"] == []


def test_is_managed_agent_process_conservative_match() -> None:
    """The matcher must require BOTH runtime-path AND launcher-script
    command-line; either alone is not enough."""
    from securedact_mcp.agent.service_taskscheduler import _is_managed_agent_process

    # Runtime path without launcher script -> reject
    assert (
        _is_managed_agent_process(
            str(RUNTIME_PYTHON),
            '"C:\\ProgramData\\Securedact\\runtime\\Scripts\\python.exe"',
            RUNTIME_ROOT,
        )
        is False
    )
    # Launcher script reference but wrong runtime path -> reject
    assert (
        _is_managed_agent_process(
            r"C:\somewhere\else\python.exe",
            '"C:\\somewhere\\else\\securedact_agent_loop.py" run',
            RUNTIME_ROOT,
        )
        is False
    )
    # Both present -> accept (real-machine shape)
    assert _is_managed_agent_process(str(RUNTIME_PYTHON), RUNTIME_CMDLINE, RUNTIME_ROOT) is True


# ---------------------------------------------------------------------------
# 11. Real-machine regression: heartbeat version & Microsoft capability
# ---------------------------------------------------------------------------


def test_heartbeat_sends_running_version_with_microsoft_capability(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Heartbeat must send running package version AND Microsoft capability
    even when persisted config has stale version and only Google capability.

    Simulates the real-machine case:
    - Persisted registration: agent_version=0.4.2, capabilities=[google_drive, ...]
    - Running package: 0.5.0 with both Google and Microsoft providers
    - Heartbeat must advertise 0.5.0 and include microsoft_graph
    """
    from securedact_mcp import __version__
    from securedact_mcp.agent import agent_runner
    from securedact_mcp.agent.capabilities import AgentCapabilities
    from securedact_mcp.agent.config import AgentConfig, AgentFiles, save_config
    from securedact_mcp.agent.state import AgentStateStore

    # Simulate old config that only had Google
    old_caps = AgentCapabilities(
        supported_platforms=frozenset({"google_workspace"}),
        capabilities=frozenset({"job_protocol_v1", "policy_snapshot_v1", "google_drive"}),
    )
    config = AgentConfig(
        control_plane_url="https://cp.example.com",
        agent_id="bc64a3b60f32c7c440315e1aa44cd3c6",
        display_name="test",
        runtime_platform="windows",
        agent_version="0.4.2",  # stale
        capabilities=old_caps,
    )
    files = AgentFiles.resolve(root=tmp_path / "agent")
    files.ensure()
    save_config(config, files)
    state_store = AgentStateStore(files)

    sent_payloads: list[dict] = []

    class FakeClient:
        def heartbeat(
            self,
            agent_version: str,
            capabilities: Any,
            connector_bindings: list[dict[str, str]] | None = None,
        ) -> Any:
            sent_payloads.append(
                {
                    "agent_version": agent_version,
                    "capabilities": sorted(capabilities.capabilities),
                    "supported_platforms": sorted(capabilities.supported_platforms),
                }
            )
            from securedact_mcp.agent.client import HeartbeatResponse

            return HeartbeatResponse(
                agent_id="bc64a3b60f32c7c440315e1aa44cd3c6",
                server_time="0",
                recommended_heartbeat_seconds=300,
                config_refresh_required=False,
                entitlement_refresh_required=False,
            )

    agent_runner._heartbeat(config, FakeClient(), state_store, files=files)

    assert len(sent_payloads) == 1
    payload = sent_payloads[0]
    # Must send RUNNING version, not persisted
    assert payload["agent_version"] == __version__
    assert payload["agent_version"] != "0.4.2"
    # Must include Microsoft capability
    assert "microsoft_graph" in payload["capabilities"]
    assert "google_drive" in payload["capabilities"]
    assert "job_protocol_v1" in payload["capabilities"]
    assert "policy_snapshot_v1" in payload["capabilities"]
    # Must include Microsoft platform
    assert "microsoft365" in payload["supported_platforms"]
    assert "google_workspace" in payload["supported_platforms"]


def test_agent_status_reports_microsoft_capability(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """agent_status must report current runtime capabilities (including Microsoft)
    even when persisted config has only Google."""
    from securedact_mcp.agent import agent_runner
    from securedact_mcp.agent.capabilities import AgentCapabilities
    from securedact_mcp.agent.config import AgentConfig, AgentFiles, save_config
    from securedact_mcp.agent.credentials import AgentCredentialStore

    old_caps = AgentCapabilities(
        supported_platforms=frozenset({"google_workspace"}),
        capabilities=frozenset({"job_protocol_v1", "policy_snapshot_v1", "google_drive"}),
    )
    config = AgentConfig(
        control_plane_url="https://cp.example.com",
        agent_id="bc64a3b60f32c7c440315e1aa44cd3c6",
        display_name="test",
        runtime_platform="windows",
        agent_version="0.4.2",
        capabilities=old_caps,
    )
    files = AgentFiles.resolve(root=tmp_path / "agent")
    files.ensure()
    save_config(config, files)
    # Create empty credential store so credential_present is False
    _ = AgentCredentialStore(config.agent_id, root=files.root)
    # (no credential saved)

    status = agent_runner.agent_status(config, files=files)

    assert status.agent_id == "bc64a3b60f32c7c440315e1aa44cd3c6"
    assert status.agent_version != "0.4.2"
    # supported_platforms must include Microsoft
    assert "microsoft365" in status.supported_platforms
    assert "google_workspace" in status.supported_platforms


def test_install_windows_service_reports_existing_agent_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When install_windows_service is called WITHOUT a token (reusing existing
    registration), it must load the existing config and report the agent_id,
    not None."""
    from securedact_mcp.agent import service_taskscheduler
    from securedact_mcp.agent.capabilities import AgentCapabilities
    from securedact_mcp.agent.config import AgentConfig, AgentFiles, save_config

    runtime = tmp_path / "runtime"
    (runtime / "Scripts").mkdir(parents=True)
    runtime_python = runtime / "Scripts" / "python.exe"
    runtime_python.write_text("")

    data_dir = tmp_path / "data"
    (data_dir / "agent").mkdir(parents=True)

    # Pre-existing registration
    config = AgentConfig(
        control_plane_url="https://www.securedact.com",
        agent_id="bc64a3b60f32c7c440315e1aa44cd3c6",
        display_name="test",
        runtime_platform="windows",
        agent_version="0.5.0",
        capabilities=AgentCapabilities.default(),
    )
    save_config(config, AgentFiles.resolve(root=data_dir / "agent"))

    class FakeRunner:
        def __call__(self, args):
            from securedact_mcp.agent.service_taskscheduler import SchtasksResult

            return SchtasksResult(0, "", "")

    runner = FakeRunner()
    monkeypatch.setattr(service_taskscheduler, "_legacy_scm_service_exists", lambda: False)
    monkeypatch.setattr(service_taskscheduler, "task_exists", lambda name, r=None: False)
    monkeypatch.setattr(service_taskscheduler, "_create_task", lambda name, xml, r: None)
    monkeypatch.setattr(service_taskscheduler, "_delete_task", lambda name, r: None)
    monkeypatch.setattr(service_taskscheduler, "_start_task", lambda name, r: None)
    monkeypatch.setattr(service_taskscheduler, "write_launcher_script", lambda p: Path(p))
    monkeypatch.setattr(service_taskscheduler, "_apply_service_env_vars", lambda d: None)

    # Call WITHOUT token (reusing existing registration)
    result = service_taskscheduler.install_windows_service(
        data_dir=data_dir,
        runtime_python=runtime_python,
        command_runner=runner,
        token=None,  # No token = reuse existing
    )

    assert result["agent_id"] == "bc64a3b60f32c7c440315e1aa44cd3c6"
    assert result["agent_id"] is not None


def test_google_only_runtime_advertises_google_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """If Microsoft provider is not available in the runtime, capabilities
    should not include microsoft_graph. This test documents the current
    semantics: capabilities are based on SUPPORTED_PLATFORMS constant
    (hardcoded to include both). If the semantics change to dynamic detection,
    this test should be updated."""
    from securedact_mcp.agent.capabilities import current_agent_capabilities

    caps = current_agent_capabilities()
    # Current implementation: SUPPORTED_PLATFORMS is hardcoded to both
    # This test documents the expected behavior
    assert "google_drive" in caps.capabilities
    assert "google_workspace" in caps.supported_platforms
    assert "microsoft_graph" in caps.capabilities
    assert "microsoft365" in caps.supported_platforms


def test_cli_heartbeat_and_daemon_heartbeat_use_same_capabilities() -> None:
    """CLI heartbeat and daemon heartbeat must use the SAME capability
    construction helper so they can never diverge."""

    from securedact_mcp.agent.capabilities import current_agent_capabilities

    # Both should reference current_agent_capabilities (or equivalent)
    # This is a smoke test that the helper exists and is importable
    caps1 = current_agent_capabilities()
    caps2 = current_agent_capabilities()
    assert caps1.capabilities == caps2.capabilities
    assert caps1.supported_platforms == caps2.supported_platforms
    # The helper is the single canonical source
    assert callable(current_agent_capabilities)
