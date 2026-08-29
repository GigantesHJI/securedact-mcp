# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the real-Windows bootstrap-launch (WinError 5) failure.

The bootstrap is launched by the *elevated interactive administrator* (the
installing user), NOT by the virtual service account (which does not exist until
SCM phase 2 *inside* the bootstrap). The previous icacls-1332 (vSA-unresolvable)
fix hardened only the ``runtime`` subtree; the *parent* ``C:\\ProgramData\\
Securedact`` data dir was left to the inherited ``C:\\ProgramData`` ACL until the
bootstrap hardened it much later. When that inherited ACL was absent/modified the
administrator was denied traverse/execute to ``runtime\\Scripts\\python.exe`` and
``CreateProcess`` failed with ``WinError 5`` before the child started.

These tests pin the least-privilege fix: the parent data dir is explicitly
hardened (SYSTEM/Admins F + installing-user RX, no vSA, no Users/Everyone, no
LocalSystem, no F for the user) during Phase-1 provisioning, the launching
principal is fail-closed pre-checked, and a ``PermissionError``/``WinError 5`` is
converted to a concise, token-free ``AgentError`` surfaced as
``Managed Agent install failed safely: ...``.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Deferred-hardening (xfail) roadmap
# ---------------------------------------------------------------------------
# The eight ``xfail(strict=True)`` tests below target the PRODUCTION-HARDENING
# managed-agent install flow that is intentionally NOT present in the frozen
# Task Scheduler baseline used for the clean-machine RC acceptance test:
#
#   * the vSA/ACL/runtime-integrity two-phase hardening (the active backend uses
#     the DEV baseline identity SYSTEM with the runtime/data dirs hardened
#     WITHOUT the per-service SID ACE, which is applied only by the deferred
#     flow); and
#   * the secure subprocess-bootstrap launch path whose failure (WinError 5)
#     was converted to a token-free AgentError -- the active backend performs
#     in-process registration before launch, so that exact failure mode and the
#     icacls-command assertions no longer apply.
#
# These are NOT deleted: once the post-RC hardening phase reintroduces the vSA
# ACL + secure launch flow, this bucket must be re-enabled and the deferred
# flow re-tested here (do not leave them xfail permanently). Strict xfail makes
# an accidental re-pass (or a regression that silently disables the marker)
# loud. The two non-xfail tests (validate_runtime_security and the legacy
# reference backend's final-ACL assertions) remain active regression checks.
# ---------------------------------------------------------------------------
import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from securedact_mcp.agent import deploy
from securedact_mcp.agent.deploy import RunInput, RunResult
from securedact_mcp.agent.errors import AgentError
from tests.unit.test_agent_service_install import (
    VSA,
    RecordingRegister,
    RecordingSCM,
    SidResolver,
    WindowsLikeRunner,
    ace,
    safe_provider,
)

# ---------------------------------------------------------------------------
# Local runners/providers
# ---------------------------------------------------------------------------


def _is_icacls(args: Sequence[str]) -> bool:
    return bool(args) and "icacls" in str(args[0]).lower()


class RecordingRunner:
    """Records every command; succeeds for everything, emitting install JSON."""

    def __init__(self, *, install_json: dict | None = None) -> None:
        self.calls: list[tuple[list[str], RunInput]] = []
        self.install_json = install_json or {
            "installed": True,
            "service_name": "SecuredactAgent",
            "data_dir": "C:\\ProgramData\\Securedact",
            "account": VSA,
            "running": True,
            "agent_id": "agent-123",
        }

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        args = [str(a) for a in arguments]
        self.calls.append((args, run_input))
        if "install-from-runtime" in args:
            return RunResult(0, stdout=json.dumps(self.install_json))
        return RunResult(0, stdout="ok")


class PermissionRunner:
    """Succeeds at provisioning but raises WinError 5 when launching the bootstrap."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], RunInput]] = []

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        args = [str(a) for a in arguments]
        self.calls.append((args, run_input))
        if "install-from-runtime" in args:
            # Mirror subprocess.run raising PermissionError (WinError 5) in CreateProcess.
            raise PermissionError(5, "Access is denied", args[0])
        return RunResult(0, stdout="ok")


@pytest.fixture(autouse=True)
def _elevated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deploy, "is_elevated", lambda: True)


def _icacls_on(calls: list[tuple[list[str], RunInput]], target: Path) -> list[list[str]]:
    return [
        c[0] for c in calls if _is_icacls(c[0]) and Path(str(c[0][1])).resolve() == target.resolve()
    ]


# ---------------------------------------------------------------------------
# 1. Elevated installer can execute the secured runtime after Phase-1 hardening
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason="Task Scheduler vSA/runtime ACL hardening deferred until post-RC hardening phase",
)
def test_elevated_installer_can_launch_runtime_after_phase1(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    runtime = data_dir / "runtime"
    runner = RecordingRunner()
    result = deploy.install_service_from_runtime(
        token="srr_launch_token",  # noqa: S106 - synthetic
        data_dir=data_dir,
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
        installing_user="alice",
    )
    assert result["agent_id"] == "agent-123"
    # Both the runtime and its parent data dir were hardened in Phase 1.
    assert _icacls_on(runner.calls, runtime), "runtime was not hardened"
    assert _icacls_on(runner.calls, data_dir), "parent data dir was not hardened"
    # And the bootstrap was actually launched (executed by the elevated admin).
    assert any("install-from-runtime" in c[0] for c in runner.calls)


# ---------------------------------------------------------------------------
# 2. Ordinary user cannot modify runtime (provider gate)
# ---------------------------------------------------------------------------


def test_ordinary_user_cannot_modify_runtime(tmp_path: Path) -> None:
    def user_writable_provider(path: Path) -> list[tuple[str, str, set[str]]]:
        return [
            ace("S-1-5-18", "write", "modify", "owner", "dac"),
            ace("S-1-5-32-544", "write"),
            ace("S-1-5-21-1000", "write", "modify", "owner", "dac"),
        ]

    code = tmp_path / "code"
    issues = deploy.validate_runtime_security(
        tmp_path / "runtime", acl_provider=user_writable_provider, paths=[code]
    )
    assert any(i.startswith("writable_code_path:") for i in issues)


# ---------------------------------------------------------------------------
# 3. Installing user has RX, never F (runtime + parent)
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason="Task Scheduler vSA/runtime ACL hardening deferred until post-RC hardening phase",
)
def test_installing_user_has_rx_never_full(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    runtime = data_dir / "runtime"
    runner = RecordingRunner()
    deploy.install_service_from_runtime(
        token="srr_x",  # noqa: S106 - synthetic
        data_dir=data_dir,
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
        installing_user="alice",
    )
    for target in (runtime, data_dir):
        joined = " ".join(str(a) for a in _icacls_on(runner.calls, target)[0])
        assert "alice:(OI)(CI)RX" in joined
        assert "alice:(OI)(CI)F" not in joined


# ---------------------------------------------------------------------------
# 4. Parent-directory traversal is sufficient (explicit RX, no /T, no vSA)
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason="Task Scheduler vSA/runtime ACL hardening deferred until post-RC hardening phase",
)
def test_parent_directory_traversal_is_sufficient(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    runtime = data_dir / "runtime"
    runner = RecordingRunner()
    deploy.install_service_from_runtime(
        token="srr_x",  # noqa: S106 - synthetic
        data_dir=data_dir,
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
        installing_user="alice",
    )
    parent_cmd = _icacls_on(runner.calls, data_dir)[0]
    joined = " ".join(str(a) for a in parent_cmd)
    # Explicit RX for the launching principal so traversal does not depend on
    # inherited C:\ProgramData ACLs.
    assert "alice:(OI)(CI)RX" in joined
    assert "/inheritance:r" in [str(a).lower() for a in parent_cmd]
    # Container-only hardening: must NOT recurse into the runtime subtree (/T).
    assert "/t" not in [str(a).lower() for a in parent_cmd]
    # The vSA is NOT yet resolvable; it must not appear in the parent Phase-1 ACL.
    assert VSA not in joined
    assert r"*S-1-5-18:(OI)(CI)F" in joined
    assert r"*S-1-5-32-544:(OI)(CI)F" in joined
    assert "Administrators:" not in joined


# ---------------------------------------------------------------------------
# 5. Runtime child can start before final vSA ACL
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason="Task Scheduler vSA/runtime ACL hardening deferred until post-RC hardening phase",
)
def test_runtime_child_starts_before_final_vsa_acl(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    runtime = data_dir / "runtime"
    runner = RecordingRunner()
    deploy.install_service_from_runtime(
        token="srr_x",  # noqa: S106 - synthetic
        data_dir=data_dir,
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
        installing_user="alice",
    )
    # Every icacls (runtime + parent) issued before the bootstrap is Phase-1 = no vSA.
    icacls_cmds = [c for c in runner.calls if _is_icacls(c[0])]
    for cmd, _ in icacls_cmds:
        assert VSA not in " ".join(str(a) for a in cmd)
    # The bootstrap launch call comes after the hardening commands.
    order = [("icacls" if _is_icacls(c[0]) else "launch") for c in runner.calls]
    last_icacls = max(i for i, kind in enumerate(order) if kind == "icacls")
    assert any("install-from-runtime" in c[0] for c in runner.calls[last_icacls + 1 :])


# ---------------------------------------------------------------------------
# 6. vSA ACL still not applied before SCM identity creation (launch path)
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason="Task Scheduler vSA/runtime ACL hardening deferred until post-RC hardening phase",
)
def test_vsa_acl_not_applied_before_scm_on_launch_path(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    runtime = data_dir / "runtime"
    runner = RecordingRunner()
    deploy.install_service_from_runtime(
        token="srr_x",  # noqa: S106 - synthetic
        data_dir=data_dir,
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
        installing_user="alice",
    )
    joined_all = " ".join(str(a) for c in runner.calls for a in c[0])
    assert VSA not in joined_all


# ---------------------------------------------------------------------------
# 7. Final ACL remains SYSTEM/Admins F + vSA/user RX (full two-phase flow)
# ---------------------------------------------------------------------------


def test_final_acl_remains_system_admins_f_vsa_user_rx(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))
    events: list[tuple[str, object]] = []
    scm = RecordingSCM(events)
    runner = WindowsLikeRunner(events, scm)
    runtime = tmp_path / "ProgramData" / "Securedact" / "runtime"
    runtime.mkdir(parents=True)

    from securedact_legacy.service_windows import install_windows_service

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
        c
        for c in runner.calls
        if _is_icacls(c[0]) and Path(str(c[0][1])).resolve() == runtime.resolve()
    ]
    data_icacls = [
        c
        for c in runner.calls
        if _is_icacls(c[0]) and Path(str(c[0][1])).resolve() == (tmp_path / "data").resolve()
    ]
    # The runtime is hardened with a two-pass scheme: pass 1 sets (OI)(CI)
    # container-propagation ACEs; pass 2 appends flag-less ACEs so existing leaf
    # files (e.g. python.exe) become executable. Check the whole command set.
    all_runtime = " ".join(str(a) for c in runtime_icacls for a in c[0])
    all_data = " ".join(str(a) for c in data_icacls for a in c[0])
    # Runtime: SYSTEM/Admins F (propagation + leaf), user RX, vSA RX (never F).
    assert r"*S-1-5-18:(OI)(CI)F" in all_runtime
    assert r"*S-1-5-18:F" in all_runtime
    assert r"*S-1-5-32-544:(OI)(CI)F" in all_runtime
    assert r"*S-1-5-32-544:F" in all_runtime
    assert f"{VSA}:(OI)(CI)RX" in all_runtime
    assert f"{VSA}:RX" in all_runtime
    assert f"{VSA}:(OI)(CI)F" not in all_runtime
    assert f"{VSA}:F" not in all_runtime
    assert "alice:(OI)(CI)RX" in all_runtime
    assert "alice:RX" in all_runtime
    assert "alice:(OI)(CI)F" not in all_runtime
    assert "alice:F" not in all_runtime
    # Data dir: SYSTEM/Admins F, vSA F (own store, propagation + leaf), user RX.
    assert f"{VSA}:(OI)(CI)F" in all_data
    assert f"{VSA}:F" in all_data
    assert "alice:(OI)(CI)F" not in all_data
    assert "alice:F" not in all_data


# ---------------------------------------------------------------------------
# 8. CreateProcess PermissionError is caught and converted to a safe AgentError
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason="Task Scheduler vSA/runtime ACL hardening deferred until post-RC hardening phase",
)
def test_createprocess_permissionerror_caught_and_safe(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    runtime = data_dir / "runtime"
    runner = PermissionRunner()
    with pytest.raises(AgentError) as exc:
        deploy.install_service_from_runtime(
            token="srr_secret_token",  # noqa: S106 - synthetic
            data_dir=data_dir,
            runtime_path=runtime,
            acl_provider=safe_provider,
            command_runner=runner,
            installing_user="alice",
        )
    message = str(exc.value)
    # Concise, safe, no traceback leaking through.
    assert "access denied" in message.lower()
    # Token must not appear anywhere in the surfaced failure.
    assert "srr_secret_token" not in message


# ---------------------------------------------------------------------------
# 9. Token is not leaked or consumed on the launch failure
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason="Task Scheduler vSA/runtime ACL hardening deferred until post-RC hardening phase",
)
def test_token_not_leaked_or_consumed_on_launch_failure(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    runtime = data_dir / "runtime"
    runner = PermissionRunner()
    token = "srr_do_not_leak"  # noqa: S105 - synthetic
    with pytest.raises(AgentError):
        deploy.install_service_from_runtime(
            token=token,
            data_dir=data_dir,
            runtime_path=runtime,
            acl_provider=safe_provider,
            command_runner=runner,
            installing_user="alice",
        )
    # The token was delivered only via stdin, never on the command line or in env.
    for args, run_input in runner.calls:
        assert token not in args
        if run_input.env:
            assert token not in " ".join(str(v) for v in run_input.env.values())
    # The single bootstrap call carried the token on stdin only and never started
    # (so it was never read/consumed by the child).
    install_calls = [c for c in runner.calls if "install-from-runtime" in c[0]]
    assert install_calls
    assert install_calls[0][1].stdin == token


# ---------------------------------------------------------------------------
# 10. No relaxation to Users / Everyone / LocalSystem
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason="Task Scheduler vSA/runtime ACL hardening deferred until post-RC hardening phase",
)
def test_no_relaxation_to_users_everyone_localsystem(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    runtime = data_dir / "runtime"
    runner = RecordingRunner()
    deploy.install_service_from_runtime(
        token="srr_x",  # noqa: S106 - synthetic
        data_dir=data_dir,
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
        installing_user="alice",
    )
    for args, _ in runner.calls:
        if not _is_icacls(args):
            continue
        joined = " ".join(str(a) for a in args)
        assert "Everyone" not in joined
        assert "Users:(OI)(CI)F" not in joined
        assert "LocalSystem" not in joined
        # Installing user is RX only, never Full.
        assert "alice:(OI)(CI)F" not in joined
