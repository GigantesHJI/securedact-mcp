# SPDX-License-Identifier: Apache-2.0
"""Secure machine-runtime deployment + setup-wizard integration tests (AGENT-DEPLOY-TEST).

All Windows-specific primitives (subprocess execution, ACL enumeration, elevation)
are exercised through injected runners / providers / mocks, so the policy is fully
verified on any platform (CI is non-Windows).
"""

from __future__ import annotations

import importlib.metadata
import json
import zipfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

import securedact_mcp
from securedact_mcp.agent import deploy
from securedact_mcp.agent.deploy import (
    ProvisionResult,
    RunInput,
    RunResult,
    install_service_from_runtime,
    provision_machine_runtime,
    resolve_install_target,
    upgrade_runtime,
    validate_runtime_security,
    verify_heartbeat,
)
from securedact_mcp.agent.errors import AgentError

# ---------------------------------------------------------------------------
# Fake command runner + ACL providers
# ---------------------------------------------------------------------------


def ace(sid: str, *rights: str, atype: str = "allow") -> tuple[str, str, set[str]]:
    """Build a single ACL entry: (sid, allow/deny, {rights})."""

    return (sid, atype, set(rights))


def safe_provider(path: Path) -> list[tuple[str, str, set[str]]]:
    return [
        ace("S-1-5-18", "write", "modify", "owner", "dac"),
        ace("S-1-5-32-544", "write", "modify", "owner", "dac"),
        ace("S-1-5-32-545", "read"),
    ]


def user_writable_provider(path: Path) -> list[tuple[str, str, set[str]]]:
    return [
        ace("S-1-5-18", "write", "modify", "owner", "dac"),
        ace("S-1-5-32-544", "write"),
        ace("S-1-5-21-1000", "write", "modify", "owner", "dac"),
    ]


class FakeRunner:
    def __init__(self, *, install_json: dict[str, Any] | None = None) -> None:
        self.calls: list[tuple[list[str], RunInput]] = []
        self.install_json = install_json or {
            "installed": True,
            "service_name": "SecuredactAgent",
            "data_dir": "C:\\ProgramData\\Securedact",
            "account": r"NT SERVICE\SecuredactAgent",
            "running": True,
            "agent_id": "agent-123",
        }

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        args = list(arguments)
        self.calls.append((args, run_input))
        if "install-from-runtime" in args:
            return RunResult(0, stdout=json.dumps(self.install_json))
        if args[-1] in {"stop", "start", "status", "uninstall"}:
            return RunResult(0, stdout=json.dumps({"state": "running"}))
        # venv create / pip install / icacls -> success
        return RunResult(0, stdout="ok")


class StaleRuntimeRunner(FakeRunner):
    """Model the real-Windows same-version reconciliation defect.

    The existing machine runtime carries a *stale* ``securedact-mcp==0.4.2`` that
    does NOT contain ``securedact_mcp.agent.runtime_bootstrap``. The agent-bootstrap
    import probe therefore fails until the controlled local wheel has truly replaced
    the distribution. A plain ``pip install <same-version-wheel>`` is reported as
    "already satisfied" and leaves the stale distribution in place (the bug); only a
    forced reinstall flips the runtime to the agent-bearing build.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._reinforced = False

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        args = list(arguments)
        self.calls.append((args, run_input))
        lower = [str(a).lower() for a in args]
        # The agent-bootstrap import probe (``python -c "import ...runtime_bootstrap"``).
        if (
            len(args) >= 3
            and args[1] == "-c"
            and "securedact_mcp.agent.runtime_bootstrap" in args[2]
        ):
            if self._reinforced:
                return RunResult(0, stdout="")
            return RunResult(1, stderr="ModuleNotFoundError: no agent package")
        # The controlled local wheel pip install.
        if "pip" in lower and any(str(a).endswith(".whl") for a in args):
            if "--force-reinstall" in lower:
                self._reinforced = True
                return RunResult(0, stdout="")
            # Same-version wheel "already satisfied" -> pip SKIPS; stale dist survives.
            return RunResult(0, stdout="Requirement already satisfied")
        # venv create / icacls / etc -> success
        return RunResult(0, stdout="ok")


class FailingBootstrapRunner(FakeRunner):
    """Model a runtime-bootstrap child that fails during Windows service install.

    The real bootstrap emits its safe error as JSON on stdout (never the token) and
    exits non-zero; the parent must surface that diagnostic instead of stderr.
    """

    def __init__(self, *, error: str) -> None:
        super().__init__()
        self._error = error

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        args = list(arguments)
        if "install-from-runtime" in args:
            return RunResult(2, stdout=json.dumps({"error": self._error}))
        return super().__call__(arguments, run_input)


@pytest.fixture(autouse=True)
def _elevated(monkeypatch: pytest.MonkeyPatch) -> None:
    # Provisioning/upgrade require elevation; simulate it for happy paths.
    monkeypatch.setattr(deploy, "is_elevated", lambda: True)


# ---------------------------------------------------------------------------
# STEP 11: runtime security validation
# ---------------------------------------------------------------------------


def test_insecure_user_writable_runtime_rejected(tmp_path: Path) -> None:
    code = tmp_path / "code"
    issues = validate_runtime_security(
        tmp_path / "runtime", acl_provider=user_writable_provider, paths=[code]
    )
    assert any(i.startswith("writable_code_path:") for i in issues)


def test_secure_machine_runtime_accepted(tmp_path: Path) -> None:
    code = tmp_path / "code"
    issues = validate_runtime_security(
        tmp_path / "runtime", acl_provider=safe_provider, paths=[code]
    )
    assert issues == []


def test_runtime_acl_unverifiable_fails_closed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(deploy.service_security, "_default_acl_provider", lambda: None)
    issues = validate_runtime_security(tmp_path / "runtime", acl_provider=None)
    assert any(i.startswith("acl_provider_unavailable:") for i in issues)


# ---------------------------------------------------------------------------
# STEP 11: provisioning idempotency + ACL hardening
# ---------------------------------------------------------------------------


def test_provision_is_idempotent_when_runtime_present(tmp_path: Path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "Scripts").mkdir(parents=True, exist_ok=True)
    (runtime / "Scripts" / "python.exe").write_text("")  # stands in for the interpreter
    runner = FakeRunner()
    result = provision_machine_runtime(
        runtime_path=runtime, acl_provider=safe_provider, command_runner=runner
    )
    assert isinstance(result, ProvisionResult)
    assert result.already_provisioned is True
    # No privileged side effects (venv create / pip install / icacls) should have
    # happened — only the read-only bootstrap-presence probe is allowed.
    joined = [" ".join(c[0]).lower() for c in runner.calls]
    assert not any("venv" in s for s in joined)
    assert not any("pip" in s for s in joined)
    assert not any("icacls" in s for s in joined)


def test_provision_creates_runtime_and_hardens_acl(tmp_path: Path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    runner = FakeRunner()
    result = provision_machine_runtime(
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
    )
    # venv create + pip install + icacls hardening all occurred.
    subcommands = [" ".join(c[0]) for c in runner.calls]
    assert any("venv" in s for s in subcommands)
    assert any("pip" in s for s in subcommands)
    icacls = [
        c
        for c in runner.calls
        if "icacls" in c[0][0].lower() or "icacls.exe" in str(c[0][0]).lower()
    ]
    assert icacls, "icacls was not invoked to harden the runtime"
    icacls_args = " ".join(str(a) for a in icacls[0][0])
    # The INITIAL runtime harden (phase 1) must NOT include the vSA ACE: the
    # per-service SID is unresolvable until the SCM service exists (icacls 1332).
    assert r"NT SERVICE\SecuredactAgent" not in icacls_args
    # SYSTEM + Admins hold full; the installing user is read+execute only.
    assert r"*S-1-5-18:(OI)(CI)F" in icacls_args
    assert r"*S-1-5-32-544:(OI)(CI)F" in icacls_args
    assert "Administrators:" not in icacls_args
    assert "(OI)(CI)RX" in icacls_args
    # The installing user is read+execute only, never full control.
    assert "alice" not in icacls_args or "alice:(OI)(CI)RX" in icacls_args
    # No writer beyond SYSTEM/Administrators is present in the initial ACL
    # (the vSA is absent, and the user is RX only).
    assert "alice:(OI)(CI)F" not in icacls_args
    assert result.already_provisioned is False


def test_provision_rejects_user_writable_runtime(tmp_path: Path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "Scripts").mkdir(parents=True, exist_ok=True)
    (runtime / "Scripts" / "python.exe").write_text("")
    with pytest.raises(AgentError):
        provision_machine_runtime(
            runtime_path=runtime, acl_provider=user_writable_provider, command_runner=FakeRunner()
        )


def test_provision_fails_closed_without_elevation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(deploy, "is_elevated", lambda: False)
    runtime = tmp_path / "runtime"
    with pytest.raises(AgentError) as exc:
        provision_machine_runtime(
            runtime_path=runtime, acl_provider=safe_provider, command_runner=FakeRunner()
        )
    assert "elevation_required" in str(exc.value)


# ---------------------------------------------------------------------------
# STEP 11: service install from machine runtime (token handling)
# ---------------------------------------------------------------------------


def _fake_install_service(
    *, token=None, data_dir=None, control_plane_url=None, display_name=None, **_kw
):
    # Captures the exact registration hand-off into the active (Task Scheduler)
    # backend so we can prove the token is delivered in-memory only.
    _fake_install_service.last = {
        "token": token,
        "data_dir": data_dir,
        "control_plane_url": control_plane_url,
        "display_name": display_name,
    }
    return {
        "installed": True,
        "service_name": "SecuredactAgent",
        "data_dir": str(data_dir),
        "account": r"NT SERVICE\SecuredactAgent",
        "running": True,
        "agent_id": "agent-123",
    }


def test_install_service_from_runtime_passes_token_in_memory(tmp_path: Path, monkeypatch) -> None:
    # Invariant (still required): the one-time registration token is delivered
    # in-memory only — it is never placed on the service command line, in the
    # environment, or on disk. The active backend (Task Scheduler) registers the
    # agent in-process from this hand-off; the schedule XML carries no token.
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "Scripts").mkdir(parents=True, exist_ok=True)
    (runtime / "Scripts" / "python.exe").write_text("")
    monkeypatch.setattr(deploy.service, "install_service", _fake_install_service)
    runner = FakeRunner()
    result = install_service_from_runtime(
        token="srr_topsecret",  # noqa: S106 - synthetic test token
        data_dir=tmp_path / "data",
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
    )
    assert result["agent_id"] == "agent-123"
    assert result["account"] == r"NT SERVICE\SecuredactAgent"
    # The token reached the backend in-memory (not via argv/stdin/env).
    assert _fake_install_service.last["token"] == "srr_topsecret"
    # The token never appears on any privileged command line or environment.
    for args, run_input in runner.calls:
        blob = " ".join(str(a) for a in args)
        if run_input.env:
            blob += " " + " ".join(str(v) for v in run_input.env.values())
        assert "srr_topsecret" not in blob


def test_service_starts_from_machine_owned_runtime(tmp_path: Path, monkeypatch) -> None:
    # The active backend is launched from the machine-owned runtime (never a
    # user profile). install_service_from_runtime resolves the machine data dir
    # and hands it to the backend; the token is never placed on argv/env.
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "Scripts").mkdir(parents=True, exist_ok=True)
    (runtime / "Scripts" / "python.exe").write_text("")
    monkeypatch.setattr(deploy.service, "install_service", _fake_install_service)
    runner = FakeRunner()
    result = install_service_from_runtime(
        token="srr_x",  # noqa: S106 - synthetic test token
        data_dir=tmp_path / "data",
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
    )
    assert result["installed"] is True
    # The backend received the resolved machine data dir (never a user profile).
    assert _fake_install_service.last["data_dir"] is not None
    assert _fake_install_service.last["data_dir"] == deploy.service.resolve_service_data_dir(
        tmp_path / "data"
    )
    # The token never appears on any privileged command line or environment.
    for args, run_input in runner.calls:
        blob = " ".join(str(a) for a in args)
        if run_input.env:
            blob += " " + " ".join(str(v) for v in run_input.env.values())
        assert "srr_x" not in blob


def test_install_service_from_runtime_surfaces_safe_diagnostic(tmp_path: Path, monkeypatch) -> None:
    # Invariant (still required): when the backend install fails, the error
    # surfaced to the operator names the failing operation + safe Windows code
    # but never leaks the registration token.
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "Scripts").mkdir(parents=True, exist_ok=True)
    (runtime / "Scripts" / "python.exe").write_text("")
    token = "srr_topsecret_token_do_not_leak"  # noqa: S105 - synthetic test token
    error = (
        "failed to apply least-privilege service identity "
        "(ChangeServiceConfig LocalSystem -> NT SERVICE\\SecuredactAgent): "
        "(5, 'ChangeServiceConfig', 'Access is denied.')"
    )

    def _boom(**_kw):
        raise AgentError(f"managed-agent task install failed: {error}")

    monkeypatch.setattr(deploy.service, "install_service", _boom)
    runner = FakeRunner()

    with pytest.raises(AgentError) as exc:
        install_service_from_runtime(
            token=token,
            data_dir=tmp_path / "data",
            runtime_path=runtime,
            acl_provider=safe_provider,
            command_runner=runner,
        )

    msg = str(exc.value)
    # Diagnostic names the failing operation + safe Windows code.
    assert "ChangeServiceConfig" in msg
    assert "Access is denied" in msg
    # No secret leaks into the surfaced diagnostic.
    assert token not in msg


# ---------------------------------------------------------------------------
# STEP 11: heartbeat verification
# ---------------------------------------------------------------------------


def test_heartbeat_verification_success(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    (runtime / "Scripts").mkdir(parents=True, exist_ok=True)
    (runtime / "Scripts" / "python.exe").write_text("")

    class HBRunner(FakeRunner):
        def __call__(self, arguments, run_input):  # type: ignore[override]
            if arguments[-1] == "heartbeat":
                return RunResult(0, stdout=json.dumps({"agent_id": "agent-1"}))
            return super().__call__(arguments, run_input)

    assert (
        verify_heartbeat(
            data_dir=tmp_path / "data", runtime_path=runtime, command_runner=HBRunner()
        )
        is True
    )


def test_heartbeat_verification_failure(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"

    class HBRunner(FakeRunner):
        def __call__(self, arguments, run_input):  # type: ignore[override]
            if arguments[-1] == "heartbeat":
                return RunResult(2, stdout="")
            return super().__call__(arguments, run_input)

    assert (
        verify_heartbeat(
            data_dir=tmp_path / "data", runtime_path=runtime, command_runner=HBRunner()
        )
        is False
    )


# ---------------------------------------------------------------------------
# STEP 11: upgrade preserves state
# ---------------------------------------------------------------------------


def test_upgrade_stops_starts_and_preserves_state(tmp_path: Path, monkeypatch) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "Scripts").mkdir(parents=True, exist_ok=True)
    (runtime / "Scripts" / "python.exe").write_text("")
    data = tmp_path / "data"
    data.mkdir()
    (data / "agent.json").write_text('{"agent_id": "agent-1"}')  # simulated state

    runner = FakeRunner()
    outcome = upgrade_runtime(
        runtime_path=runtime,
        data_dir=data,
        acl_provider=safe_provider,
        command_runner=runner,
    )
    assert outcome["upgraded"] is True
    subcommands = [c[0][-1] for c in runner.calls]
    assert "stop" in subcommands
    assert "start" in subcommands
    assert subcommands.index("stop") < subcommands.index("start")
    # State in the data dir is untouched by the runtime re-provisioning.
    assert (data / "agent.json").read_text() == '{"agent_id": "agent-1"}'


def test_upgrade_requires_elevation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(deploy, "is_elevated", lambda: False)
    with pytest.raises(AgentError) as exc:
        upgrade_runtime(runtime_path=tmp_path / "runtime", data_dir=tmp_path / "data")
    assert "elevation_required" in str(exc.value)


# ---------------------------------------------------------------------------
# STEP 9/11: setup-wizard module behavior
# ---------------------------------------------------------------------------


class FakeAgentModule:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, *, input_fn, output, **kwargs: Any) -> int:
        self.calls.append(kwargs)
        return 0


def _run_setup(tmp_path: Path, *, agent=None, agent_only=False, fake=None):  # type: ignore[no-untyped-def]
    from securedact_mcp.onboarding import run_setup
    from tests.unit.model_install_helpers import store_at

    captured = FakeAgentModule() if fake is None else fake
    output = __import__("io").StringIO()
    result = run_setup(
        host=None,
        language="none",
        accept_upstream_terms=False,
        non_interactive=True,
        install_models=lambda **k: 0,
        verify_models=lambda _s, _o: 0,
        input_fn=lambda _p: "y",
        output=output,
        store=store_at(tmp_path / "models"),
        module_finder=lambda _n: object(),
        agent=agent,
        agent_only=agent_only,
        managed_agent_runner=captured,
    )
    return result, output.getvalue(), captured


def test_setup_wizard_exposes_managed_agent_module(tmp_path: Path) -> None:
    result, output, fake = _run_setup(tmp_path, agent=None)
    assert result == 0
    assert fake.calls  # module was invoked
    assert "Managed Agent" in output


def test_skip_agent_leaves_cli_usable(tmp_path: Path) -> None:
    result, output, fake = _run_setup(tmp_path, agent="no")
    assert result == 0
    assert fake.calls
    assert fake.calls[0].get("agent") == "no"
    assert "Managed Agent" in output


def test_setup_agent_only_reruns_agent_module(tmp_path: Path) -> None:
    result, output, fake = _run_setup(tmp_path, agent="yes", agent_only=True)
    assert result == 0
    assert fake.calls
    assert fake.calls[0].get("agent") == "yes"
    assert "Managed Agent: configured" in output


# ---------------------------------------------------------------------------
# STEP 5/11: elevation behavior of the module itself
# ---------------------------------------------------------------------------


def test_managed_agent_requires_elevation_noninteractive(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(deploy.sys, "platform", "win32")
    runner = FakeRunner()
    output = __import__("io").StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        agent="yes",
        non_interactive=True,
        elevated_check=lambda: False,
        command_runner=runner,
    )
    assert rc == 0
    # No install was attempted (no elevation).
    assert runner.calls == []
    assert "Administrator" in output.getvalue()


def test_managed_agent_non_windows_unsupported_message(tmp_path: Path, monkeypatch) -> None:
    # On a non-Windows platform the module reports unsupported cleanly.
    monkeypatch.setattr(deploy.sys, "platform", "linux")
    output = __import__("io").StringIO()
    rc = deploy.run_managed_agent_module(input_fn=lambda _p: "y", output=output, agent="yes")
    assert rc == 0
    assert "only supported on Windows" in output.getvalue()


def test_managed_agent_module_reports_online(tmp_path: Path, monkeypatch) -> None:
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
    output = __import__("io").StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        secret_input_fn=lambda _p: "srr_tok",
        agent="yes",
        elevated_check=lambda: True,
    )
    assert rc == 0
    text = output.getvalue()
    assert "Online" in text
    assert "setup complete" in text.lower()


# ---------------------------------------------------------------------------
# STEP 11: CLI surface wiring (no Windows needed)
# ---------------------------------------------------------------------------


def test_setup_parser_exposes_agent_flags() -> None:
    from securedact_mcp.cli import build_parser

    p = build_parser()
    args = p.parse_args(["setup", "--agent"])
    assert args.agent is True
    args = p.parse_args(["setup", "--no-agent"])
    assert args.no_agent is True


def test_setup_cli_maps_agent_only_flag(tmp_path, monkeypatch) -> None:
    from securedact_mcp import cli

    captured: dict[str, Any] = {}

    def fake_run_setup(**kwargs: Any) -> int:
        captured.update(kwargs)
        return 0

    from securedact_mcp import onboarding as onboarding_mod

    monkeypatch.setattr(onboarding_mod, "run_setup", fake_run_setup)
    rc = cli.main(["setup", "--agent"], output=__import__("io").StringIO())
    assert rc == 0
    assert captured["agent_only"] is True
    assert captured["agent"] == "yes"


# ---------------------------------------------------------------------------
# STEP 11: foreground run remains available
# ---------------------------------------------------------------------------


def test_foreground_run_still_in_cli() -> None:
    import argparse

    from securedact_mcp.agent.cli import build_agent_parser

    parser = argparse.ArgumentParser()
    group = parser.add_subparsers(dest="cmd")
    build_agent_parser(group)
    args = parser.parse_args(["agent", "run", "--no-lock"])
    assert args.cmd == "agent"
    assert args.agent_command == "run"
    assert args.no_lock is True


def test_agent_service_upgrade_subcommand_in_cli() -> None:
    import argparse

    from securedact_mcp.agent.cli import build_agent_parser

    parser = argparse.ArgumentParser()
    group = parser.add_subparsers(dest="cmd")
    build_agent_parser(group)
    args = parser.parse_args(["agent", "service", "upgrade", "--data-dir", "C:\\x"])
    assert args.service_command == "upgrade"
    assert args.data_dir == "C:\\x"


# ---------------------------------------------------------------------------
# STEP 11: machine-runtime package-version resolution (fail-closed, no stale pin)
# ---------------------------------------------------------------------------


def _missing_distribution(name: str) -> str:
    raise importlib.metadata.PackageNotFoundError(name)


def test_resolve_uses_running_module_version_not_stale_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The installed distribution reports a STALE 0.1.0 (the real-Windows bug);
    # the wizard code actually executing is 0.4.2. The runtime must pin the
    # running version, never the stale metadata.
    monkeypatch.setattr(importlib.metadata, "version", lambda _n: "0.1.0")
    monkeypatch.setattr(securedact_mcp, "__version__", "0.4.2")
    assert resolve_install_target() == "securedact-mcp==0.4.2"


def test_resolve_never_returns_stale_0_1_0(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(importlib.metadata, "version", lambda _n: "0.1.0")
    monkeypatch.setattr(securedact_mcp, "__version__", "0.4.2")
    target = resolve_install_target()
    assert target == "securedact-mcp==0.4.2"
    assert "0.1.0" not in target


def test_resolve_arbitrary_running_version_exact_pin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(importlib.metadata, "version", _missing_distribution)
    monkeypatch.setattr(securedact_mcp, "__version__", "5.6.7")
    assert resolve_install_target() == "securedact-mcp==5.6.7"


def test_resolve_explicit_version_is_exact_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    # An explicit controlled pin bypasses the running version entirely.
    monkeypatch.setattr(importlib.metadata, "version", lambda _n: "0.1.0")
    monkeypatch.setattr(securedact_mcp, "__version__", "0.4.2")
    assert resolve_install_target(version="1.2.3") == "securedact-mcp==1.2.3"


def test_resolve_missing_metadata_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(importlib.metadata, "version", _missing_distribution)
    monkeypatch.setattr(securedact_mcp, "__version__", "")
    with pytest.raises(AgentError):
        resolve_install_target()


def test_resolve_rejects_injected_version() -> None:
    with pytest.raises(AgentError):
        resolve_install_target(version="0.1.0; rm -rf /")
    with pytest.raises(AgentError):
        resolve_install_target(version="0.4.2 && curl evil.example")
    with pytest.raises(AgentError):
        resolve_install_target(version="0.4.2\npip install evil")


def test_resolve_rejects_remote_wheel() -> None:
    with pytest.raises(AgentError):
        resolve_install_target(wheel_path="http://evil.example/securedact.whl")
    with pytest.raises(AgentError):
        resolve_install_target(wheel_path="https://evil.example/securedact-0.4.2.whl")


def test_resolve_accepts_local_wheel(tmp_path: Path) -> None:
    wheel = tmp_path / "securedact_mcp-0.4.2-py3-none-any.whl"
    wheel.write_text("")
    assert resolve_install_target(wheel_path=str(wheel)) == str(wheel.resolve())


def test_provision_installs_exact_running_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Even when installed metadata is the stale 0.1.0, the privileged provision
    # step must pip-install the running 0.4.2 into the machine runtime.
    monkeypatch.setattr(importlib.metadata, "version", lambda _n: "0.1.0")
    monkeypatch.setattr(securedact_mcp, "__version__", "0.4.2")
    runtime = tmp_path / "runtime"
    runner = FakeRunner()
    provision_machine_runtime(
        runtime_path=runtime, acl_provider=safe_provider, command_runner=runner
    )
    pip_calls = [c for c in runner.calls if "pip" in [str(a).lower() for a in c[0]]]
    assert pip_calls, "pip install was not invoked during provisioning"
    assert any("securedact-mcp==0.4.2" in str(c[0]) for c in pip_calls)


def test_provision_rejects_injected_version_before_side_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    runner = FakeRunner()
    with pytest.raises(AgentError):
        provision_machine_runtime(
            runtime_path=runtime,
            version="0.1.0; rm -rf /",
            acl_provider=safe_provider,
            command_runner=runner,
        )
    # No pip/venv invocation carried the injected payload.
    assert not any("rm -rf" in str(c[0]) for c in runner.calls)


# ---------------------------------------------------------------------------
# STEP 11: dev/local wheel deterministically replaces a stale same-version runtime
# ---------------------------------------------------------------------------


def _make_valid_controlled_wheel(path: Path) -> Path:
    """Build a real (minimal) controlled local wheel containing the agent package."""

    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(
            "securedact_mcp/agent/runtime_bootstrap.py",
            "# SPDX-License-Identifier: Apache-2.0\n",
        )
        zf.writestr("securedact_mcp/agent/__init__.py", "")
    return path


def test_dev_wheel_replaces_stale_same_version_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Reproduce the real-Windows defect: an existing machine runtime already holds a
    # stale PyPI securedact-mcp==0.4.2 that does NOT contain the agent package. The
    # dev/local-validation path (SECUREDACT_RUNTIME_DEV_WHEEL=1) builds a 0.4.2 wheel
    # that DOES contain the agent. Setup must deterministically replace the stale
    # same-version distribution so the agent ends up importable.
    runtime = tmp_path / "runtime"
    (runtime / "Scripts").mkdir(parents=True, exist_ok=True)
    (runtime / "Scripts" / "python.exe").write_text("")

    wheel = _make_valid_controlled_wheel(tmp_path / "securedact_mcp-0.4.2+local-py3-none-any.whl")
    # Route the dev/local build through the real resolver, but return the synthetic
    # controlled wheel instead of shelling out to ``uv build`` / ``python -m build``.
    monkeypatch.setattr(deploy, "_default_wheel_builder", lambda root: wheel)

    runner = StaleRuntimeRunner()
    result = provision_machine_runtime(
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
        dev_local=True,
    )
    assert isinstance(result, ProvisionResult)
    # The machine runtime was (re)provisioned with the controlled wheel.
    assert result.already_provisioned is False
    # The pip install of the controlled wheel used an explicit reinstall strategy so
    # the same-version stale distribution could not survive.
    pip_calls = [c[0] for c in runner.calls if "pip" in [str(a).lower() for a in c[0]]]
    assert pip_calls, "pip install was not invoked during provisioning"
    assert any("--force-reinstall" in [str(a).lower() for a in c] for c in pip_calls)
    assert any(str(wheel.resolve()) == str(a) for c in pip_calls for a in c)
    # The agent must be importable from the runtime after provisioning.
    assert _runtime_has_agent_bootstrap_importable(runner) is True


def _runtime_has_agent_bootstrap_importable(runner: StaleRuntimeRunner) -> bool:
    # Mirror the engine's bootstrap-presence probe; in the model, the runner only
    # reports success once the controlled wheel was force-reinstalled.
    return runner._reinforced


def test_released_index_pin_does_not_force_reinstall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The released flow keeps its normal idempotent behaviour: pip is NOT given
    # --force-reinstall for a plain ``securedact-mcp==X.Y.Z`` pin, so the controlled
    # local-wheel reinstall strategy is scoped exactly to validated wheels.
    monkeypatch.setattr(importlib.metadata, "version", lambda _n: "0.1.0")
    monkeypatch.setattr(securedact_mcp, "__version__", "0.4.2")
    runtime = tmp_path / "runtime"
    runner = FakeRunner()
    provision_machine_runtime(
        runtime_path=runtime, acl_provider=safe_provider, command_runner=runner
    )
    pip_calls = [c[0] for c in runner.calls if "pip" in [str(a).lower() for a in c[0]]]
    assert pip_calls
    assert not any("--force-reinstall" in [str(a).lower() for a in c] for c in pip_calls)
