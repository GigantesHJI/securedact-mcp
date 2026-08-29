# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the two-phase Windows managed-agent provisioning order.

These tests pin the fix for the real-Windows ``icacls`` exit 1332
(ERROR_NONE_MAPPED) failure: the virtual-service-account SID
``NT SERVICE\\SecuredactAgent`` is not resolvable until the SCM service is
registered, so the vSA ACE must NOT be applied before service creation.

All SCM / ACL / sid-resolution primitives are injected, so the ordering policy is
fully verified on any platform (CI is non-Windows).
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from securedact_mcp.agent import deploy, service_security
from securedact_mcp.agent.deploy import RunInput, RunResult
from securedact_mcp.agent.errors import AgentError
from securedact_legacy.service_windows import (
    WindowsAgentService,
    WinSCMController,
    _build_failure_actions,
    _service_account_password,
    install_windows_service,
)

VSA = r"NT SERVICE\SecuredactAgent"


# ---------------------------------------------------------------------------
# ACL providers + runners + SCM/Fake backends
# ---------------------------------------------------------------------------


def ace(sid: str, *rights: str, atype: str = "allow") -> tuple[str, str, set[str]]:
    return (sid, atype, set(rights))


def safe_provider(path: Path) -> list[tuple[str, str, set[str]]]:
    return [
        ace("S-1-5-18", "write", "modify", "owner", "dac"),
        ace("S-1-5-32-544", "write"),
        ace("S-1-5-32-545", "read"),
    ]


def user_writable_provider(path: Path) -> list[tuple[str, str, set[str]]]:
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


class FailingConfigureAccountSCM(RecordingSCM):
    """SCM controller whose LocalSystem -> vSA identity transition (ChangeServiceConfig) fails."""

    def configure_account(self, account: str) -> None:
        raise AgentError(
            "failed to apply least-privilege service identity "
            f"(ChangeServiceConfig LocalSystem -> {account}): "
            "(5, 'ChangeServiceConfig', 'Access is denied.')"
        )


class FailingFailureActionsSCM(RecordingSCM):
    """SCM controller whose ChangeServiceConfig2(SERVICE_CONFIG_FAILURE_ACTIONS) fails."""

    def set_failure_actions(self) -> None:
        raise AgentError(
            "managed-agent service install failed safely: machine-runtime service install failed: "
            "managed-agent service install failed safely: "
            "SERVICE_FAILURE_ACTIONS must be a dictionary containing "
            "{'ResetPeriod':int,'RebootMsg':unicode,'Command':unicode,"
            "'Actions':sequence of 2 tuples(int,int)}"
        )


class WindowsLikeRunner:
    """Command runner modeling real-Windows icacls 1332 for an unresolved vSA.

    Any ``icacls`` command that references the vSA SID *before* the SCM service
    exists returns exit code 1332 (ERROR_NONE_MAPPED) - exactly the production
    failure. After the service is installed, the same ACE applies successfully.
    """

    def __init__(
        self,
        events: list[tuple[str, Any]],
        scm: RecordingSCM,
        *,
        fail_final_acl: bool = False,
    ) -> None:
        self.events = events
        self.scm = scm
        self.fail_final_acl = fail_final_acl
        self.calls: list[tuple[list[str], RunInput]] = []
        self.results: list[RunResult] = []

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        args = [str(a) for a in arguments]
        self.calls.append((args, run_input))
        self.events.append(("cmd", (args, run_input)))
        if args and "icacls" in args[0].lower():
            joined = " ".join(args)
            if "NT SERVICE\\SecuredactAgent" in joined and not self.scm.installed:
                # Real-Windows behavior: name->SID lookup fails pre-creation.
                result = RunResult(
                    1332, stderr="No mapping between account names and security IDs was done."
                )
                self.results.append(result)
                return result
            if self.fail_final_acl and "NT SERVICE\\SecuredactAgent" in joined:
                result = RunResult(1, stderr="final ACL hardening failed")
                self.results.append(result)
                return result
        result = RunResult(0)
        self.results.append(result)
        return result


class SidResolver:
    def __init__(self, events: list[tuple[str, Any]], *, fail_after_install: bool = False) -> None:
        self.events = events
        self.fail_after_install = fail_after_install
        self.calls: list[str] = []

    def __call__(self, account: str) -> str:
        self.calls.append(account)
        self.events.append(("sid.resolve", account))
        if self.fail_after_install:
            raise AgentError(f"service account SID not resolvable ({account})")
        return "S-1-5-80-1111111111"


class _FakeAgentConfig:
    agent_id = "agent-xyz"


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


class _RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], RunInput]] = []

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        self.calls.append(([str(a) for a in arguments], run_input))
        return RunResult(0)


def _event_index(events: list[tuple[str, Any]], kind: str) -> int:
    for i, (k, _v) in enumerate(events):
        if k == kind:
            return i
    return -1


def _first_icacls_with_vsa_index(events: list[tuple[str, Any]]) -> int:
    for i, (k, v) in enumerate(events):
        if k == "cmd" and "icacls" in str(v[0][0]).lower() and VSA in " ".join(v[0]):
            return i
    return -1


@pytest.fixture(autouse=True)
def _elevated(monkeypatch: pytest.MonkeyPatch) -> None:
    # Provisioning requires elevation; simulate it for happy paths.
    monkeypatch.setattr(deploy, "is_elevated", lambda: True)


@pytest.fixture
def program_data_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    pd = tmp_path / "ProgramData"
    monkeypatch.setenv("ProgramData", str(pd))
    return pd


# ---------------------------------------------------------------------------
# 1. vSA ACL is NOT attempted before SCM service creation
# ---------------------------------------------------------------------------


def test_vsa_acl_not_attempted_before_scm_service_creation(
    tmp_path: Path, program_data_env: Path
) -> None:
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    install_windows_service(
        data_dir=tmp_path / "data",
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=SidResolver(events),
        scm=scm,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )

    vsa_icacls = _first_icacls_with_vsa_index(events)
    install_idx = _event_index(events, "scm.install")
    assert install_idx != -1
    assert vsa_icacls != -1
    # The vSA ACE is only written AFTER the SCM service exists.
    assert vsa_icacls > install_idx


# ---------------------------------------------------------------------------
# 2. Initial runtime ACL contains no untrusted writer (no vSA)
# ---------------------------------------------------------------------------


def test_provision_runtime_initial_acl_without_vsa(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runner = _RecordingRunner()

    deploy.provision_machine_runtime(
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
        include_service_acl=False,
    )

    icacls = [c for c in runner.calls if "icacls" in str(c[0][0]).lower()]
    assert icacls, "runtime was not hardened"
    joined = " ".join(str(a) for a in icacls[0][0])
    assert VSA not in joined
    assert r"*S-1-5-18:(OI)(CI)F" in joined
    assert r"*S-1-5-32-544:(OI)(CI)F" in joined
    assert "Administrators:" not in joined


def test_provision_runtime_final_acl_includes_vsa_when_requested(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runner = _RecordingRunner()

    deploy.provision_machine_runtime(
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
        include_service_acl=True,
    )

    icacls = [c for c in runner.calls if "icacls" in str(c[0][0]).lower()]
    joined = " ".join(str(a) for a in icacls[0][0])
    assert f"{VSA}:(OI)(CI)RX" in joined


# ---------------------------------------------------------------------------
# 3. Service installed but not started before final ACL
# ---------------------------------------------------------------------------


def test_service_installed_not_started_before_final_acl(
    tmp_path: Path, program_data_env: Path
) -> None:
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    install_windows_service(
        data_dir=tmp_path / "data",
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=SidResolver(events),
        scm=scm,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )

    install_idx = _event_index(events, "scm.install")
    start_idx = _event_index(events, "scm.start")
    vsa_icacls = _first_icacls_with_vsa_index(events)
    assert install_idx < vsa_icacls < start_idx


# ---------------------------------------------------------------------------
# 4. vSA SID/principal resolves after service creation
# ---------------------------------------------------------------------------


def test_vsa_sid_resolves_after_service_creation(tmp_path: Path, program_data_env: Path) -> None:
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)
    resolver = SidResolver(events)

    install_windows_service(
        data_dir=tmp_path / "data",
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=resolver,
        scm=scm,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )

    # The resolver is invoked exactly once, after the service is installed.
    assert resolver.calls == [VSA]
    assert ("sid.resolve", VSA) in events
    assert _event_index(events, "sid.resolve") > _event_index(events, "scm.install")


# ---------------------------------------------------------------------------
# 5. Final runtime ACL grants vSA RX, not Full
# ---------------------------------------------------------------------------


def test_final_runtime_acl_grants_vsa_rx_not_full(tmp_path: Path, program_data_env: Path) -> None:
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    install_windows_service(
        data_dir=tmp_path / "data",
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=SidResolver(events),
        scm=scm,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )

    runtime_icacls = [
        c for c in runner.calls if "icacls" in str(c[0][0]).lower() and str(c[0][1]) == str(runtime)
    ]
    assert runtime_icacls, "runtime ACL was not applied"
    joined = " ".join(str(a) for a in runtime_icacls[0][0])
    assert f"{VSA}:(OI)(CI)RX" in joined
    assert f"{VSA}:(OI)(CI)F" not in joined


# ---------------------------------------------------------------------------
# 6. data/vault ACL grants only the permissions actually required
# ---------------------------------------------------------------------------


def test_data_acl_grants_only_required_permissions(tmp_path: Path, program_data_env: Path) -> None:
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    install_windows_service(
        data_dir=tmp_path / "data",
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=SidResolver(events),
        scm=scm,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )

    data_dir = tmp_path / "data"
    data_icacls = [
        c
        for c in runner.calls
        if "icacls" in str(c[0][0]).lower() and str(c[0][1]) == str(data_dir)
    ]
    # The data dir is hardened in three stages, each two-pass (container
    # propagation + leaf files): (1) a deterministic ``/reset`` that strips any
    # stale explicit ACE (incl. a leftover vSA from a prior install), (2) the
    # initial bootstrap (no vSA), and (3) the final harden (vSA). That is five
    # icacls calls total on the data dir.
    assert len(data_icacls) == 5
    reset = " ".join(str(a) for a in data_icacls[0][0])
    initial = " ".join(str(a) for c in data_icacls[1:3] for a in c[0])
    final = " ".join(str(a) for c in data_icacls[3:5] for a in c[0])
    # Stage 1 is a deterministic reset (removes stale ACEs) and grants nothing new.
    assert "/reset" in reset
    # The service account needs write on its own store, but NOT on the initial pass.
    assert f"{VSA}:(OI)(CI)F" in final
    assert VSA not in initial
    # The installing user is read-only (RX), never write (F).
    assert "alice:(OI)(CI)RX" in final
    assert "alice:(OI)(CI)F" not in final
    # No Everyone/Users full-control fallback.
    assert "Everyone" not in final
    assert "Users:(OI)(CI)F" not in final


# ---------------------------------------------------------------------------
# 7. ACL 1332 before service creation is reproduced/modeled
# ---------------------------------------------------------------------------


def test_acl_1332_before_service_creation_modeled(tmp_path: Path, program_data_env: Path) -> None:
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)  # installed=False => no service yet
    runner = WindowsLikeRunner(events, scm)

    # The OLD (buggy) order: harden the runtime with the vSA BEFORE creating the
    # service. On real Windows this is exactly the observed icacls 1332.
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)
    result = runner(
        [
            str(program_data_env / "System32" / "icacls.exe"),
            str(runtime),
            "/inheritance:r",
            "/T",
            "/grant:r",
            f"{VSA}:(OI)(CI)RX",
        ],
        RunInput(),
    )
    assert result.returncode == 1332
    assert "No mapping between account names" in result.stderr

    # The corrected production flow never triggers 1332: the initial harden has
    # no vSA ACE, and the final ACL only runs after the service exists.
    events.clear()
    scm2 = RecordingSCM(events)
    runner2 = WindowsLikeRunner(events, scm2)
    install_windows_service(
        data_dir=tmp_path / "data",
        command_runner=runner2,
        acl_provider=safe_provider,
        sid_resolver=SidResolver(events),
        scm=scm2,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )
    for r in runner2.results:
        if r.returncode == 1332:
            raise AssertionError("production flow unexpectedly hit icacls 1332")
    assert scm2.installed is True


# ---------------------------------------------------------------------------
# 8. Final ACL failure causes rollback/removal of incomplete service
# ---------------------------------------------------------------------------


def test_final_acl_failure_causes_rollback(tmp_path: Path, program_data_env: Path) -> None:
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm, fail_final_acl=True)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    with pytest.raises(AgentError):
        install_windows_service(
            data_dir=tmp_path / "data",
            command_runner=runner,
            acl_provider=safe_provider,
            sid_resolver=SidResolver(events),
            scm=scm,
            register_fn=RecordingRegister(events),
            installing_user="alice",
            code_paths=[],
        )

    assert _event_index(events, "scm.remove") != -1
    assert _event_index(events, "scm.start") == -1
    assert scm.installed is False  # incomplete service removed


# ---------------------------------------------------------------------------
# 9. Service start never occurs if security validation fails
# ---------------------------------------------------------------------------


class _FailingFinalProvider:
    def __init__(self, *, fail_on_call: int) -> None:
        self.calls = 0
        self.fail_on_call = fail_on_call

    def __call__(self, path: Path) -> list[tuple[str, str, set[str]]]:
        self.calls += 1
        if self.calls == self.fail_on_call:
            return [ace("S-1-5-21-1000", "write", "modify", "owner", "dac")]
        return safe_provider(path)


def test_service_start_never_occurs_if_security_validation_fails(
    tmp_path: Path, program_data_env: Path
) -> None:
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)
    # The FINAL validate_install_security call (3rd provider invocation) fails.
    provider = _FailingFinalProvider(fail_on_call=3)

    with pytest.raises(AgentError):
        install_windows_service(
            data_dir=tmp_path / "data",
            command_runner=runner,
            acl_provider=provider,
            sid_resolver=SidResolver(events),
            scm=scm,
            register_fn=RecordingRegister(events),
            installing_user="alice",
            code_paths=[],
        )

    assert _event_index(events, "scm.start") == -1
    assert _event_index(events, "scm.remove") != -1
    assert scm.installed is False


# ---------------------------------------------------------------------------
# 10. Registration token is not consumed before deterministic security prereqs
# ---------------------------------------------------------------------------


def test_registration_token_not_consumed_before_prerequisites(
    tmp_path: Path, program_data_env: Path
) -> None:
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)
    register = RecordingRegister(events)
    token = "srr_one_time_token_abc"  # noqa: S105 - synthetic test token

    install_windows_service(
        data_dir=tmp_path / "data",
        token=token,
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=SidResolver(events),
        scm=scm,
        register_fn=register,
        installing_user="alice",
        code_paths=[],
    )

    register_idx = _event_index(events, "register")
    install_idx = _event_index(events, "scm.install")
    final_acl = _first_icacls_with_vsa_index(events)
    assert register_idx != -1
    # token consumed only after service creation AND final ACL validation.
    assert register_idx > install_idx
    assert register_idx > final_acl
    assert register.calls == [token]


# ---------------------------------------------------------------------------
# 11. Rerunning after a partial failed install is idempotent
# ---------------------------------------------------------------------------


def test_provision_rerun_is_idempotent(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runner = _RecordingRunner()
    deploy.provision_machine_runtime(
        runtime_path=runtime, acl_provider=safe_provider, command_runner=runner
    )
    first_calls = len(runner.calls)
    assert first_calls > 0
    # Simulate the interpreter the provision step actually installs.
    (runtime / "Scripts").mkdir(parents=True, exist_ok=True)
    (runtime / "Scripts" / "python.exe").write_text("")

    runner2 = _RecordingRunner()
    result = deploy.provision_machine_runtime(
        runtime_path=runtime, acl_provider=safe_provider, command_runner=runner2
    )
    assert result.already_provisioned is True
    # Idempotent: no privileged provisioning side effects (venv create / pip
    # install / icacls hardening) on rerun. The read-only bootstrap-presence
    # probe may still run; that is intentional and has no side effects.
    joined = [" ".join(str(a) for a in c[0]).lower() for c in runner2.calls]
    assert not any("venv" in s for s in joined)
    assert not any("pip" in s for s in joined)
    assert not any("icacls" in s for s in joined)


def test_install_rerun_after_partial_failure_succeeds(
    tmp_path: Path, program_data_env: Path
) -> None:
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)
    data_dir = tmp_path / "data"

    # First attempt: vSA unresolvable after install -> rollback, failure.
    events1: list[tuple[str, Any]] = []
    scm1 = RecordingSCM(events1)
    with pytest.raises(AgentError):
        install_windows_service(
            data_dir=data_dir,
            command_runner=WindowsLikeRunner(events1, scm1),
            acl_provider=safe_provider,
            sid_resolver=SidResolver(events1, fail_after_install=True),
            scm=scm1,
            register_fn=RecordingRegister(events1),
            installing_user="alice",
            code_paths=[],
        )
    assert scm1.installed is False

    # Second attempt: same dir; everything resolves -> full success.
    events2: list[tuple[str, Any]] = []
    scm2 = RecordingSCM(events2)
    result = install_windows_service(
        data_dir=data_dir,
        command_runner=WindowsLikeRunner(events2, scm2),
        acl_provider=safe_provider,
        sid_resolver=SidResolver(events2),
        scm=scm2,
        register_fn=RecordingRegister(events2),
        installing_user="alice",
        code_paths=[],
    )
    assert result["installed"] is True
    assert scm2.installed is True
    assert scm2.started is True
    # Data dir (which holds credentials/state) must survive the failed attempt.
    assert data_dir.exists()


# ---------------------------------------------------------------------------
# 12. No LocalSystem fallback is introduced
# ---------------------------------------------------------------------------


def test_no_localsystem_fallback_introduced(tmp_path: Path, program_data_env: Path) -> None:
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    from securedact_mcp.agent import service_security

    assert service_security.recommended_service_account() == VSA

    install_windows_service(
        data_dir=tmp_path / "data",
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=SidResolver(events),
        scm=scm,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )

    assert scm.configured_account == VSA
    for kind, val in events:
        if kind == "cmd":
            assert "LocalSystem" not in " ".join(str(a) for a in val[0])


# ---------------------------------------------------------------------------
# 13. No secret appears in SCM ImagePath / environment / args
# ---------------------------------------------------------------------------


def test_no_secret_in_scm_imagepath_env_or_args(tmp_path: Path, program_data_env: Path) -> None:
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)
    token = "srr_topsecret_token_do_not_leak"  # noqa: S105 - synthetic test token
    register = RecordingRegister(events)

    install_windows_service(
        data_dir=tmp_path / "data",
        token=token,
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=SidResolver(events),
        scm=scm,
        register_fn=register,
        installing_user="alice",
        code_paths=[],
    )

    # The SCM ImagePath (module class) never contains the token.
    assert token not in (scm.module_class or "")
    # No command line / environment / event payload contains the token.
    for kind, val in events:
        if kind == "cmd":
            blob = " ".join(str(a) for a in val[0])
            if val[1].env:
                blob += " " + " ".join(str(v) for v in val[1].env.values())
        elif kind == "register":
            continue  # registration consumes the token in-memory only by design
        else:
            blob = str(val)
        assert token not in blob
    # The token reached registration (in-memory) but nothing else.
    assert register.calls == [token]


# ---------------------------------------------------------------------------
# 14. LocalSystem -> vSA ChangeServiceConfig failure rolls back, leaves no service
# ---------------------------------------------------------------------------


def test_failure_during_localsystem_to_vsa_change_service_config(
    tmp_path: Path, program_data_env: Path
) -> None:
    # Reproduces the real-Windows symptom: the SCM service is created as LocalSystem,
    # then the identity transition fails. Before the fix service_created was set too
    # late, so rollback was skipped and a persistent AUTO_START LocalSystem service
    # was left behind. Now the incomplete service must be removed.
    events: list[tuple[str, Any]] = []
    scm = FailingConfigureAccountSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)
    token = "srr_one_time_token_abc"  # noqa: S105 - synthetic test token
    register = RecordingRegister(events)

    with pytest.raises(AgentError) as exc:
        install_windows_service(
            data_dir=tmp_path / "data",
            token=token,
            command_runner=runner,
            acl_provider=safe_provider,
            sid_resolver=SidResolver(events),
            scm=scm,
            register_fn=register,
            installing_user="alice",
            code_paths=[],
        )

    # No persistent SCM entry remains (rolled back).
    assert scm.installed is False
    assert _event_index(events, "scm.remove") != -1
    # The service is never started.
    assert _event_index(events, "scm.start") == -1
    # The registration token is never consumed (failure precedes phase 4).
    assert register.calls == []
    # The diagnostic names the failing operation and is safe (no token leak).
    msg = str(exc.value)
    assert "ChangeServiceConfig" in msg
    assert "failed to apply least-privilege service identity" in msg
    assert token not in msg


# ---------------------------------------------------------------------------
# 15. vSA SID resolution failure rolls back, leaves no service, token unconsumed
# ---------------------------------------------------------------------------


def test_failure_resolving_vsa_sid_leaves_no_service(
    tmp_path: Path, program_data_env: Path
) -> None:
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)
    token = "srr_one_time_token_xyz"  # noqa: S105 - synthetic test token
    register = RecordingRegister(events)

    with pytest.raises(AgentError) as exc:
        install_windows_service(
            data_dir=tmp_path / "data",
            token=token,
            command_runner=runner,
            acl_provider=safe_provider,
            sid_resolver=SidResolver(events, fail_after_install=True),
            scm=scm,
            register_fn=register,
            installing_user="alice",
            code_paths=[],
        )

    assert scm.installed is False
    assert _event_index(events, "scm.remove") != -1
    assert _event_index(events, "scm.start") == -1
    assert register.calls == []  # token unconsumed
    msg = str(exc.value)
    assert "service account SID not resolvable" in msg
    assert token not in msg


# ---------------------------------------------------------------------------
# 16. Final ACL failure rolls back, leaves no service, token unconsumed
# ---------------------------------------------------------------------------


def test_final_acl_failure_leaves_no_service_token_unconsumed(
    tmp_path: Path, program_data_env: Path
) -> None:
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm, fail_final_acl=True)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)
    token = "srr_one_time_token_dfg"  # noqa: S105 - synthetic test token
    register = RecordingRegister(events)

    with pytest.raises(AgentError) as exc:
        install_windows_service(
            data_dir=tmp_path / "data",
            token=token,
            command_runner=runner,
            acl_provider=safe_provider,
            sid_resolver=SidResolver(events),
            scm=scm,
            register_fn=register,
            installing_user="alice",
            code_paths=[],
        )

    assert scm.installed is False
    assert _event_index(events, "scm.remove") != -1
    assert _event_index(events, "scm.start") == -1
    assert register.calls == []  # token unconsumed
    assert token not in str(exc.value)


# ---------------------------------------------------------------------------
# 17. Successful install ends with vSA identity before the service is started
# ---------------------------------------------------------------------------


def test_success_ends_with_vsa_account_before_start(tmp_path: Path, program_data_env: Path) -> None:
    events: list[tuple[str, Any]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    result = install_windows_service(
        data_dir=tmp_path / "data",
        command_runner=runner,
        acl_provider=safe_provider,
        sid_resolver=SidResolver(events),
        scm=scm,
        register_fn=RecordingRegister(events),
        installing_user="alice",
        code_paths=[],
    )

    # The service is configured to the least-privilege vSA, not LocalSystem.
    assert scm.configured_account == VSA
    assert result["account"] == VSA
    cfg_idx = _event_index(events, "scm.configure_account")
    start_idx = _event_index(events, "scm.start")
    assert cfg_idx != -1
    assert start_idx != -1
    # Identity transition completed (and was verified) before start was attempted.
    assert cfg_idx < start_idx
    assert _event_index(events, "scm.remove") == -1  # no rollback on success
    assert scm.installed is True


# ---------------------------------------------------------------------------
# 18. Failure-actions object passed to pywin32 has the exact required shape
# ---------------------------------------------------------------------------


def test_failure_actions_object_shape_matches_pywin32_contract() -> None:
    # Validates the EXACT object handed to win32service.ChangeServiceConfig2: a
    # dictionary (never a list/dataclass) with the exact keys/casing/types
    # pywin32 requires, and Actions as a sequence of (action_type, delay_ms)
    # 2-tuples using win32service.SC_ACTION_RESTART.
    try:
        import win32service
    except ImportError:
        win32service = None  # type: ignore[assignment]

    actions = _build_failure_actions()

    # Top-level MUST be a dict, not a list / dataclass, with the required keys.
    assert isinstance(actions, dict)
    assert set(actions) == {"ResetPeriod", "RebootMsg", "Command", "Actions"}

    # ResetPeriod is an int (seconds) — one day.
    assert isinstance(actions["ResetPeriod"], int)
    assert actions["ResetPeriod"] == 86400

    # No reboot and no arbitrary recovery command.
    assert isinstance(actions["RebootMsg"], str) and actions["RebootMsg"] == ""
    assert isinstance(actions["Command"], str) and actions["Command"] == ""

    # Actions: a sequence of exactly 3 (action_type, delay_ms) tuples.
    action_seq = actions["Actions"]
    assert isinstance(action_seq, (list, tuple))
    assert len(action_seq) == 3
    for entry in action_seq:
        assert isinstance(entry, tuple) and len(entry) == 2
        action_type, delay_ms = entry
        assert isinstance(action_type, int)
        assert isinstance(delay_ms, int)
        if win32service is not None:
            assert action_type == win32service.SC_ACTION_RESTART
        assert delay_ms == 1000
        # Guards against the previous swapped-order bug (delay, action) == (1000, 1).
        assert action_type != delay_ms


# ---------------------------------------------------------------------------
# 19. Real pywin32 accepts and round-trips the failure-actions dictionary
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only real API contract")
def test_failure_actions_accepted_by_real_pywin32() -> None:
    # Drives the INSTALLED pywin32 (not a mock): create a throwaway service,
    # apply _build_failure_actions() via ChangeServiceConfig2, then read it back
    # with QueryServiceConfig2 to prove the exact dict is accepted and round-trips.
    import ctypes

    import win32service

    if not ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
        pytest.skip("requires elevation")

    name = "SecuredactFailureActionsContract"
    hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CREATE_SERVICE)
    try:
        hs = win32service.CreateService(
            hscm,
            name,
            name,
            win32service.SERVICE_ALL_ACCESS,
            win32service.SERVICE_WIN32_OWN_PROCESS,
            win32service.SERVICE_DEMAND_START,
            win32service.SERVICE_ERROR_NORMAL,
            r"C:\Windows\System32\svchost.exe",  # placeholder binary; never started
            None,
            0,
            None,
            None,
            None,
        )
        try:
            win32service.ChangeServiceConfig2(
                hs, win32service.SERVICE_CONFIG_FAILURE_ACTIONS, _build_failure_actions()
            )
            cfg = win32service.QueryServiceConfig2(hs, win32service.SERVICE_CONFIG_FAILURE_ACTIONS)
            assert cfg["ResetPeriod"] == 86400
            assert cfg["RebootMsg"] == ""
            assert cfg["Command"] == ""
            assert len(cfg["Actions"]) == 3
            for action_type, delay_ms in cfg["Actions"]:
                assert action_type == win32service.SC_ACTION_RESTART
                assert delay_ms == 1000
        finally:
            win32service.DeleteService(hs)
            win32service.CloseServiceHandle(hs)
    finally:
        win32service.CloseServiceHandle(hscm)


# ---------------------------------------------------------------------------
# 20. Failure-action config failure rolls back, leaves no service, token safe
# ---------------------------------------------------------------------------


def test_failure_action_config_failure_rolls_back_token_unconsumed(
    tmp_path: Path, program_data_env: Path
) -> None:
    # If the LocalSystem -> vSA transition step set_failure_actions() fails (the
    # real-Windows SERVICE_FAILURE_ACTIONS contract error), the partially created
    # LocalSystem service must be removed and the registration token must NOT be
    # consumed (fail-closed).
    events: list[tuple[str, Any]] = []
    scm = FailingFailureActionsSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = program_data_env / "Securedact" / "runtime"
    runtime.mkdir(parents=True)
    token = "srr_one_time_token_fa"  # noqa: S105 - synthetic test token
    register = RecordingRegister(events)

    with pytest.raises(AgentError) as exc:
        install_windows_service(
            data_dir=tmp_path / "data",
            token=token,
            command_runner=runner,
            acl_provider=safe_provider,
            sid_resolver=SidResolver(events),
            scm=scm,
            register_fn=register,
            installing_user="alice",
            code_paths=[],
        )

    # Incomplete LocalSystem service removed; never started.
    assert scm.installed is False
    assert _event_index(events, "scm.remove") != -1
    assert _event_index(events, "scm.start") == -1
    # Token unconsumed; diagnostic must not leak it.
    assert register.calls == []
    assert token not in str(exc.value)


# ---------------------------------------------------------------------------
# 21. vSA password must be NULL (not "") — WinError 1057 root cause
# ---------------------------------------------------------------------------


def test_vsa_account_password_is_null_not_empty() -> None:
    # Pure unit check of the SCM password contract. A virtual service account
    # (NT SERVICE\<name>) or managed service account requires lpPassword == NULL
    # (pywin32 None); an empty string ("") makes the SCM raise WinError 1057.
    # Built-in accounts (LocalSystem/LocalService/NetworkService) use "".

    # Virtual service account (case-insensitive) and managed service account ($).
    assert _service_account_password(VSA) is None
    assert _service_account_password(VSA.upper()) is None
    assert _service_account_password(r"NT SERVICE\OtherSvc") is None
    assert _service_account_password(r"DOMAIN\svc$") is None

    # Built-in accounts use an empty string (no password).
    assert _service_account_password("LocalSystem") == ""
    assert _service_account_password(r"NT AUTHORITY\LocalService") == ""
    assert _service_account_password(r"NT AUTHORITY\NetworkService") == ""


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only real SCM contract")
def test_real_windows_vsa_account_transition_no_1057() -> None:
    # Drives the INSTALLED pywin32 (not a mock). Reproduces the real-Windows
    # LocalSystem -> NT SERVICE\SecuredactAgent transition exactly as
    # install_windows_service does, and proves ChangeServiceConfig accepts the vSA
    # (no WinError 1057). The service is created as LocalSystem (temporary) and is
    # never started; it is removed afterwards (rollback semantics preserved).
    import ctypes

    import win32serviceutil

    from securedact_mcp.agent import service as _svc

    if not ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
        pytest.skip("requires elevation")

    controller = WinSCMController(_svc.SERVICE_NAME)
    if controller.exists():
        controller.remove()
    created = False
    try:
        # Temporary LocalSystem service (matches the production install order). The
        # vSA is applied AFTER creation via ChangeServiceConfig, never at create.
        win32serviceutil.InstallService(
            f"{WindowsAgentService.__module__}.{WindowsAgentService.__name__}",
            _svc.SERVICE_NAME,
            _svc.SERVICE_DISPLAY_NAME,
            startType=1,  # SERVICE_DEMAND_START: never auto-started here
        )
        created = True
        # The LocalSystem -> vSA transition must NOT raise WinError 1057.
        controller.configure_account(service_security.DEFAULT_VIRTUAL_SERVICE_ACCOUNT)
        cfg = controller.query_config()
        # Proves the vSA was accepted as the logon identity (not LocalSystem).
        assert cfg["service_start_name"] == service_security.DEFAULT_VIRTUAL_SERVICE_ACCOUNT
    finally:
        if controller.exists():
            controller.remove()
        # Rollback guarantee: no service lingers after the test.
        assert not created or not controller.exists()
