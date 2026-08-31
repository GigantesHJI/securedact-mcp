# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the production upgrade/reinstall lifecycle fix (Task E).

The defect: ``provision_machine_runtime`` rebuilds the machine-owned runtime via
``python -m venv``. When a managed-agent scheduled task is already registered and
running, it holds ``runtime\\Scripts\\python.exe`` (and the DLLs) open, so the venv
create fails with ``Permission denied`` — observed during RC development/reprovisioning.

The fix stops the existing scheduled agent (and waits boundedly for it to release the
runtime files) *before* rebuilding, then restarts it only after a *successful*
provisioning. Registration / OAuth / binding live in the data dir, not the runtime, so
they survive untouched. The control hook is injectable so this stays hermetic on any OS.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from securedact_mcp.agent import deploy
from securedact_mcp.agent.deploy import (
    ProvisionResult,
    RunInput,
    RunResult,
    provision_machine_runtime,
)
from securedact_mcp.agent.errors import AgentError


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        args = [str(a) for a in arguments]
        self.calls.append(args)
        if args[-1] in {"stop", "start", "status", "uninstall"}:
            return RunResult(0, stdout="ok")
        return RunResult(0, stdout="ok")


class RecordingAgentControl:
    """Injectable stand-in for the running scheduled-agent stop/start control."""

    def __init__(
        self,
        *,
        present: bool = True,
        stop_raises: bool = False,
        state_after_stop: str = "ready",
    ) -> None:
        self.present = present
        self.stop_raises = stop_raises
        self.state_after_stop = state_after_stop
        self.actions: list[str] = []

    def __call__(self, action: str) -> bool:
        if action == "stop":
            if not self.present:
                return False
            self.actions.append(action)
            if self.stop_raises:
                raise AgentError("injected: agent did not stop in time")
            return True
        if action == "start":
            if not self.present:
                return False
            self.actions.append(action)
            return True
        raise AgentError(f"unknown action {action!r}")


def _safe_provider(path: Path) -> list[tuple[str, str, set[str]]]:
    from tests.unit.test_agent_deploy import ace

    return [
        ace("S-1-5-18", "write", "modify", "owner", "dac"),
        ace("S-1-5-32-544", "write", "modify", "owner", "dac"),
        ace("S-1-5-32-545", "read"),
    ]


@pytest.fixture(autouse=True)
def _elevated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deploy, "is_elevated", lambda: True)


def test_upgrade_stops_running_agent_before_rebuild_and_restarts_after(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "Scripts").mkdir(parents=True, exist_ok=True)
    # The interpreter is "in use" by the running agent; venv would fail without a stop.
    (runtime / "Scripts" / "python.exe").write_text("")

    control = RecordingAgentControl(present=True)
    runner = FakeRunner()

    result = provision_machine_runtime(
        runtime_path=runtime,
        acl_provider=_safe_provider,
        command_runner=runner,
        force=True,  # force a rebuild over the existing (live) runtime
        _agent_control=control,
    )

    assert isinstance(result, ProvisionResult)
    assert result.already_provisioned is False
    # The agent was stopped, then the runtime was rebuilt, then it was restarted.
    assert control.actions == ["stop", "start"]
    # A rebuild really occurred (venv into the runtime).
    assert any("venv" in " ".join(c) for c in runner.calls)


def test_upgrade_fails_closed_if_agent_will_not_stop(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "Scripts").mkdir(parents=True, exist_ok=True)
    (runtime / "Scripts" / "python.exe").write_text("")

    control = RecordingAgentControl(present=True, stop_raises=True)
    runner = FakeRunner()

    with pytest.raises(AgentError):
        provision_machine_runtime(
            runtime_path=runtime,
            acl_provider=_safe_provider,
            command_runner=runner,
            force=True,
            _agent_control=control,
        )

    # Stop was attempted, but the runtime was never rebuilt and never restarted.
    assert control.actions == ["stop"]
    assert not any("venv" in " ".join(c) for c in runner.calls)


def test_initial_install_without_agent_is_unchanged(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"  # does not exist yet -> initial provisioning

    control = RecordingAgentControl(present=False)
    runner = FakeRunner()

    result = provision_machine_runtime(
        runtime_path=runtime,
        acl_provider=_safe_provider,
        command_runner=runner,
        _agent_control=control,
    )

    assert isinstance(result, ProvisionResult)
    # No scheduled task exists, so neither stop nor start is emitted.
    assert control.actions == []
    assert any("venv" in " ".join(c) for c in runner.calls)
