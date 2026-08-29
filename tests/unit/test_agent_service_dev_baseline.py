# SPDX-License-Identifier: Apache-2.0
"""DEV-ONLY baseline mode tests for the Windows managed-agent service.

These tests pin the behaviour of ``SECUREDACT_AGENT_SERVICE_DEV_BASELINE=1``:

* It is ONLY active when the env var is exactly ``"1"`` — never by default and
  never for any other value (so it cannot be flipped on by accident).
* When active it bypasses the custom Windows hardening (ProgramData DACL,
  runtime-tree ACL, code-path integrity gate, vSA ACL/SID validation, pre-start
  ACL assertions) and installs under the simplest viable identity (LocalSystem).
* When inactive the hardened production path is unchanged (still hardens, still
  resolves the vSA SID, still refuses an unreadable ACL provider).
* Application/protocol security is preserved in baseline: the one-time
  registration token is never leaked to argv/env/logs.

All SCM / ACL / sid-resolution primitives are injected, so the policy is fully
verified on any platform (CI is non-Windows).
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from securedact_mcp.agent.deploy import RunInput, RunResult
from securedact_mcp.agent.errors import AgentError
from securedact_mcp.agent.service_security import DEV_BASELINE_ENV, is_dev_baseline_enabled
from securedact_legacy.service_windows import (
    DEV_BASELINE_WARNING,
    install_windows_service,
)

VSA = r"NT SERVICE\SecuredactAgent"


def ace(sid: str, *rights: str, atype: str = "allow") -> tuple[str, str, set[str]]:
    return (sid, atype, set(rights))


def safe_provider(path: Path) -> list[tuple[str, str, set[str]]]:
    return [
        ace("S-1-5-18", "write", "modify", "owner", "dac"),
        ace("S-1-5-32-544", "write"),
        ace("S-1-5-32-545", "read"),
    ]


def user_writable_provider(path: Path) -> list[tuple[str, str, set[str]]]:
    # Would FAIL the integrity gate in production (untrusted writer present).
    return [
        ace("S-1-5-18", "write", "modify", "owner", "dac"),
        ace("S-1-5-32-544", "write"),
        ace("S-1-5-21-1000", "write", "modify", "owner", "dac"),
    ]


class RecordingSCM:
    """Fake SCMController that records an ordered event log."""

    def __init__(self, events: list[tuple[str, Any]]) -> None:
        self.events = events
        self.installed = False
        self.started = False
        self.configured_account: str | None = None
        self.module_class: str | None = None

    def exists(self) -> bool:
        self.events.append(("scm.exists", self.installed))
        return self.installed

    def install(
        self, module_class: str, name: str, display: str, desc: str, start_type: int
    ) -> None:
        self.events.append(("scm.install", name))
        self.installed = True
        self.module_class = module_class

    def remove(self) -> None:
        self.events.append(("scm.remove", None))
        self.installed = False

    def start(self) -> None:
        self.events.append(("scm.start", None))
        self.started = True

    def stop(self) -> None:
        self.events.append(("scm.stop", None))

    def configure_account(self, account: str) -> None:
        self.events.append(("scm.configure_account", account))
        self.configured_account = account

    def set_environment(self, data_dir: Path) -> None:
        self.events.append(("scm.set_environment", str(data_dir)))

    def set_failure_actions(self) -> None:
        self.events.append(("scm.set_failure_actions", None))

    def query_config(self) -> dict[str, object]:
        return {"service_start_name": self.configured_account or ""}

    def query_status(self) -> dict[str, object]:
        return {"state": "running" if self.started else "stopped"}


class WindowsLikeRunner:
    """Command runner; returns icacls 1332 for an unresolved vSA (real-Windows)."""

    def __init__(self, events: list[tuple[str, Any]], scm: RecordingSCM) -> None:
        self.events = events
        self.scm = scm
        self.calls: list[tuple[list[str], RunInput]] = []
        self.results: list[RunResult] = []

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        args = [str(a) for a in arguments]
        self.calls.append((args, run_input))
        self.events.append(("cmd", (args, run_input)))
        if args and "icacls" in args[0].lower():
            joined = " ".join(args)
            if VSA in joined and not self.scm.installed:
                result = RunResult(
                    1332, stderr="No mapping between account names and security IDs was done."
                )
                self.results.append(result)
                return result
        result = RunResult(0)
        self.results.append(result)
        return result


class RecordingRegister:
    def __init__(self, events: list[tuple[str, Any]]) -> None:
        self.events = events
        self.calls: list[str] = []

    def __call__(
        self, token: str, *, control_plane_url: str | None = None, display_name: str | None = None
    ):
        self.calls.append(token)
        self.events.append(("register", token))
        return _FakeAgentConfig()


class _FakeAgentConfig:
    agent_id = "agent-xyz"


class RecordingSidResolver:
    """SID resolver that records its invocations (mirrors the production gate)."""

    def __init__(self, events: list[tuple[str, Any]], *, fail: bool = False) -> None:
        self.events = events
        self.calls: list[str] = []
        self.fail = fail

    def __call__(self, account: str) -> str:
        self.calls.append(account)
        self.events.append(("sid.resolve", account))
        if self.fail:
            raise AgentError(f"service account SID not resolvable ({account})")
        return "S-1-5-80-1111111111"


def _icacls_calls(runner: WindowsLikeRunner) -> list[tuple[list[str], RunInput]]:
    return [c for c in runner.calls if "icacls" in str(c[0][0]).lower()]


@pytest.fixture
def program_data_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    pd = tmp_path / "ProgramData"
    monkeypatch.setenv("ProgramData", str(pd))
    return pd


# ---------------------------------------------------------------------------
# Flag-activation safety: the baseline CANNOT be enabled by accident
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "val",
    ["", "0", "false", "FALSE", "true", "yes", "on", "y", "2", "10", "one", " 1", "1 "],
)
def test_dev_baseline_not_enabled_for_other_values(
    monkeypatch: pytest.MonkeyPatch, val: str
) -> None:
    # Whitespace / truthy-but-not-literal values must NOT enable the mode.
    monkeypatch.setenv(DEV_BASELINE_ENV, val)
    assert is_dev_baseline_enabled() is False


def test_dev_baseline_disabled_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(DEV_BASELINE_ENV, raising=False)
    assert is_dev_baseline_enabled() is False


def test_dev_baseline_enabled_only_for_literal_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DEV_BASELINE_ENV, "1")
    assert is_dev_baseline_enabled() is True


# ---------------------------------------------------------------------------
# Baseline mode bypasses hardening and installs under LocalSystem
# ---------------------------------------------------------------------------


def test_dev_baseline_bypasses_all_hardening(
    tmp_path: Path, program_data_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(DEV_BASELINE_ENV, "1")
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    # A provider that WOULD fail the integrity gate (untrusted writer present).
    # In baseline mode validation is skipped, so the install must still succeed.
    result = install_windows_service(
        data_dir=tmp_path / "data",
        command_runner=runner,
        acl_provider=user_writable_provider,
        sid_resolver=lambda a: "S-1-5-18",
        scm=scm,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )

    # No icacls hardening executed at all.
    assert _icacls_calls(runner) == []
    # vSA SID resolution / code-path integrity gate did not run.
    assert all(k != "sid.resolve" for k, _ in events)
    # Service installed and started under the simplest viable identity.
    assert scm.installed and scm.started
    assert result["installed"] is True
    assert result["account"] == "LocalSystem"
    assert result["dev_baseline"] is True
    assert result.get("warning") == DEV_BASELINE_WARNING


def test_dev_baseline_installs_without_acl_provider(
    tmp_path: Path, program_data_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Production fails closed when no ACL provider is available (cannot prove
    # code paths are safe). Baseline bypasses that gate and still installs.
    monkeypatch.setenv(DEV_BASELINE_ENV, "1")
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    result = install_windows_service(
        data_dir=tmp_path / "data",
        command_runner=runner,
        acl_provider=None,  # would fail-closed in production
        sid_resolver=lambda a: "S-1-5-18",
        scm=scm,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )
    assert result["installed"] is True
    assert result["account"] == "LocalSystem"
    assert result["dev_baseline"] is True


def test_dev_baseline_keeps_registration_token_secret(
    tmp_path: Path, program_data_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Application/protocol security is preserved: the one-time token must never
    # appear in argv / env / logs, only in the in-memory registration call.
    monkeypatch.setenv(DEV_BASELINE_ENV, "1")
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)
    token = "srr_baseline_secret_token"  # noqa: S105 - synthetic test token
    register = RecordingRegister(events)

    install_windows_service(
        data_dir=tmp_path / "data",
        token=token,
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=lambda a: "S-1-5-18",
        scm=scm,
        register_fn=register,
        installing_user="alice",
        code_paths=[],
    )

    for kind, val in events:
        # The in-memory registration call legitimately receives the token by design.
        if kind == "register":
            continue
        if kind == "cmd":
            blob = " ".join(str(a) for a in val[0])
            if val[1].env:
                blob += " " + " ".join(str(v) for v in val[1].env.values())
        else:
            blob = str(val)
        assert token not in blob
    assert register.calls == [token]


# ---------------------------------------------------------------------------
# Regression: with the flag OFF, production hardening is fully intact
# ---------------------------------------------------------------------------


def test_non_baseline_still_hardens_by_default(
    tmp_path: Path, program_data_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(DEV_BASELINE_ENV, raising=False)
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    result = install_windows_service(
        data_dir=tmp_path / "data",
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=RecordingSidResolver(events),
        scm=scm,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )

    # Production path still applies the ACL hardening.
    assert _icacls_calls(runner), "production path must still harden the ACLs"
    # Production path still resolves the vSA SID.
    assert any(k == "sid.resolve" for k, _ in events)
    # Production path still uses the least-privilege vSA identity.
    assert result["account"] == VSA
    assert result["dev_baseline"] is False


def _event_index(events: list[tuple[str, Any]], kind: str) -> int:
    for i, (k, _v) in enumerate(events):
        if k == kind:
            return i
    return -1


# ---------------------------------------------------------------------------
# Regression: the DEV baseline must be genuinely minimal — no LocalSystem ->
# LocalSystem reconfiguration, while production still performs the real
# transition.
# ---------------------------------------------------------------------------


def test_dev_baseline_never_calls_configure_account(
    tmp_path: Path, program_data_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The whole point of the fix: baseline InstallService keeps the LocalSystem
    # identity that win32serviceutil.InstallService already created and must NOT
    # call configure_account / ChangeServiceConfig at all.
    monkeypatch.setenv(DEV_BASELINE_ENV, "1")
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    result = install_windows_service(
        data_dir=tmp_path / "data",
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=lambda a: "S-1-5-18",
        scm=scm,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )

    assert result["installed"] is True
    assert result["account"] == "LocalSystem"
    assert result["dev_baseline"] is True
    # The identity was never re-applied via ChangeServiceConfig.
    assert all(k != "scm.configure_account" for k, _ in events)
    assert scm.configured_account is None


def test_production_still_calls_configure_account_vsa(
    tmp_path: Path, program_data_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Production must still perform the LocalSystem -> vSA transition.
    monkeypatch.delenv(DEV_BASELINE_ENV, raising=False)
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    result = install_windows_service(
        data_dir=tmp_path / "data",
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=RecordingSidResolver(events),
        scm=scm,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )

    assert result["dev_baseline"] is False
    idx = _event_index(events, "scm.configure_account")
    assert idx != -1, "production must call configure_account"
    assert events[idx][1] == VSA
    assert scm.configured_account == VSA


def test_dev_baseline_starts_only_after_registration(
    tmp_path: Path, program_data_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # In baseline mode the service must not be started until after the agent
    # registration step completes (ordering mirrors production).
    monkeypatch.setenv(DEV_BASELINE_ENV, "1")
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    install_windows_service(
        data_dir=tmp_path / "data",
        token="srr_baseline_order_token",  # noqa: S105 - synthetic test token
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=lambda a: "S-1-5-18",
        scm=scm,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )

    reg_idx = _event_index(events, "register")
    start_idx = _event_index(events, "scm.start")
    assert reg_idx != -1
    assert start_idx != -1
    # Registration must be recorded before the service is started.
    assert reg_idx < start_idx
    # And no identity reconfiguration may have slipped in between.
    assert "scm.configure_account" not in [k for k, _ in events]


def test_dev_baseline_failure_rolls_back(
    tmp_path: Path, program_data_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # If a later baseline step (here: registration) fails, the incomplete
    # service must be rolled back and left as no service / unregistered.
    monkeypatch.setenv(DEV_BASELINE_ENV, "1")
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    class _FailingRegister:
        def __init__(self, events: list[tuple[str, Any]]) -> None:
            self.events = events

        def __call__(self, token: str, *, control_plane_url=None, display_name=None):
            self.events.append(("register", token))
            raise AgentError("registration failed during service install")

    with pytest.raises(AgentError) as excinfo:
        install_windows_service(
            data_dir=tmp_path / "data",
            token="srr_baseline_rollback",  # noqa: S105 - synthetic test token
            command_runner=runner,
            acl_provider=safe_provider,
            sid_resolver=lambda a: "S-1-5-18",
            scm=scm,
            register_fn=_FailingRegister(events),
            installing_user="alice",
            code_paths=[],
        )

    # Rollback removed the incompletely installed service.
    assert "managed-agent service install failed safely" in str(excinfo.value)
    assert scm.installed is False
    assert ("scm.remove", None) in events
    # No identity reconfiguration happened and the service was never started.
    assert all(k != "scm.configure_account" for k, _ in events)
    assert all(k != "scm.start" for k, _ in events)


def test_unset_flag_never_takes_baseline_path(
    tmp_path: Path, program_data_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With the flag unset (the default), the install must NOT take the baseline
    # path: it must harden, resolve the vSA SID, and apply the vSA identity.
    monkeypatch.delenv(DEV_BASELINE_ENV, raising=False)
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    result = install_windows_service(
        data_dir=tmp_path / "data",
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=RecordingSidResolver(events),
        scm=scm,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )

    assert result["dev_baseline"] is False
    assert result["account"] == VSA
    # Production applied the real identity transition (never skipped).
    assert any(k == "scm.configure_account" for k, _ in events)
    assert any(k == "sid.resolve" for k, _ in events)
    assert _icacls_calls(runner), "production must still harden the ACLs"


def test_non_baseline_fails_closed_without_acl_provider(
    tmp_path: Path, program_data_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without the baseline flag, an unreadable ACL provider must still abort.
    monkeypatch.delenv(DEV_BASELINE_ENV, raising=False)
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    with pytest.raises(AgentError):
        install_windows_service(
            data_dir=tmp_path / "data",
            command_runner=runner,
            acl_provider=None,
            sid_resolver=lambda a: "S-1-5-18",
            scm=scm,
            register_fn=RecordingRegister(events),
            installing_user="alice",
            code_paths=[],
        )
    # No service was left behind and no registration token was consumed.
    assert scm.installed is False
    assert all(k != "register" for k, _ in events)
