# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the managed-agent UAC elevation hand-off (RC clean-machine Finding 1).

These pin the fix for the acceptance-test defect where launching ``uv run
securedact-mcp setup`` from a normal (non-elevated) PowerShell and approving the
UAC prompt left no visible elevated continuation. The hand-off must:

* re-launch the exact RC interpreter/code that initiated setup (``sys.executable``
  + the ``-m securedact_mcp.cli`` module form) -- never the bare ``securedact-mcp``
  console command, which could resolve to a global install on PATH;
* preserve the working directory;
* supply the correct continuation arguments (no secret in argv);
* run the continuation exactly once (resume marker, no re-prompt recursion);
* treat UAC decline/failure as a safe stop (no fake-success hand-off).

All Windows primitives are exercised through injected ``runas_fn`` / fakes.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from securedact_mcp.agent import deploy


@pytest.fixture(autouse=True)
def _force_windows_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    # These tests pin Windows UAC/elevation behavior; force the Windows branch
    # hermetically so the logic is exercised on any CI host. The Windows API
    # surface is injected via the fake ctypes (no pywin32 import on Linux).
    monkeypatch.setattr(deploy.sys, "platform", "win32")


# ---------------------------------------------------------------------------
# Fake ctypes so the platform-specific ShellExecuteEx path is exercisable here.
# ---------------------------------------------------------------------------


class _FakeWintypes:
    class DWORD:
        def __init__(self, v: int = 0) -> None:
            self.value = v

    class HINSTANCE: ...

    class HKEY: ...

    class HWND: ...

    class ULONG: ...

    class LPCWSTR: ...

    class HANDLE: ...


class _CapturedInfo:
    lpDirectory = None
    hProcess = 0


class _FakeCtypes:
    sizeof = staticmethod(lambda *_a, **_k: 0)
    Structure = _CapturedInfo
    c_int = int
    c_void_p = object
    wintypes = _FakeWintypes
    byref = staticmethod(lambda x: x)

    class _Windll:
        class _Shell32:
            @staticmethod
            def ShellExecuteExW(info: _CapturedInfo) -> int:
                _FakeCtypes._last_directory = info.lpDirectory
                return 1  # non-zero => success

        class _Kernel32:
            @staticmethod
            def WaitForSingleObject(*_a, **_k) -> int:
                return 0

            @staticmethod
            def GetExitCodeProcess(*_a, **_k) -> None:
                return None

            @staticmethod
            def CloseHandle(*_a, **_k) -> None:
                return None

        windll = None  # set below

    def __init__(self) -> None:
        self.windll = self._Windll()
        self.windll.shell32 = self._Windll._Shell32()
        self.windll.kernel32 = self._Windll._Kernel32()


def _fake_ctypes() -> _FakeCtypes:
    return _FakeCtypes()


# ---------------------------------------------------------------------------
# 1. The re-launch resolves the RC interpreter + module form (no PATH hijack)
# ---------------------------------------------------------------------------


def test_elevation_target_uses_rc_interpreter_and_module(monkeypatch: pytest.MonkeyPatch) -> None:
    # A global securedact-mcp.exe on PATH must NOT be consulted.
    monkeypatch.setattr(
        deploy.shutil, "which", lambda _n: r"C:\Program Files\Python312\Scripts\securedact-mcp.exe"
    )
    exe, params = deploy.resolve_elevation_target()
    # Interpreter is the running RC venv python, not PATH-derived.
    assert exe == sys.executable
    assert params[0] == "-m"
    assert params[1] == "securedact_mcp.cli"
    assert params[2] == "setup"
    assert "--agent" in params
    # Never invokes the bare console command that a global install would own.
    assert "securedact-mcp" not in params
    assert all("securedact-mcp.exe" not in str(p) for p in params)


def test_elevation_argv_contains_resume_marker_and_no_token() -> None:
    params = deploy.build_elevation_argv()
    assert params == ["-m", "securedact_mcp.cli", "setup", "--agent", "--agent-elevated"]
    # Defensive: no secret material can leak onto the continuation command line.
    assert not any("srr_" in str(p) or "sra_" in str(p) for p in params)


# ---------------------------------------------------------------------------
# 2. Working directory is preserved across the UAC boundary
# ---------------------------------------------------------------------------


def test_elevation_preserves_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sentinel = str(tmp_path / "rc-checkout")
    monkeypatch.setattr(deploy.os, "getcwd", lambda: sentinel)
    fake = _fake_ctypes()
    monkeypatch.setattr(deploy, "ctypes", fake)
    rc = deploy._shell_execute_runas(["-m", "securedact_mcp.cli", "setup", "--agent"], cwd=sentinel)
    assert rc == 0
    assert _FakeCtypes._last_directory == sentinel


# ---------------------------------------------------------------------------
# 3. Continuation occurs exactly once (no re-prompt recursion)
# ---------------------------------------------------------------------------


class _RecordingElevate:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str]) -> int:
        self.calls.append(list(argv))
        return 0


def test_elevation_launches_continuation_exactly_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(deploy.AGENT_ELEVATED_ENV, raising=False)
    monkeypatch.setattr(deploy, "is_elevated", lambda: False)
    elevate = _RecordingElevate()
    output = __import__("io").StringIO()
    with pytest.raises(deploy._ElevationHandoff):
        deploy.run_managed_agent_module(
            input_fn=lambda _p: "y",
            output=output,
            agent="yes",
            elevated_check=lambda: False,
            elevate=elevate,
        )
    # The hand-off was requested exactly once (then control left the process).
    assert len(elevate.calls) == 1
    # And it used the RC interpreter/module form.
    argv = elevate.calls[0]
    assert Path(argv[0]) == Path(sys.executable)
    assert "securedact_mcp.cli" in argv
    assert "--agent" in argv


def test_resumed_continuation_does_not_re_elevate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Simulate the already-elevated child (marker inherited from the parent).
    monkeypatch.setenv(deploy.AGENT_ELEVATED_ENV, "1")
    monkeypatch.setattr(
        deploy,
        "install_service_from_runtime",
        lambda **k: {
            "installed": True,
            "service_name": "SecuRedact Managed Agent",
            "data_dir": str(tmp_path / "data"),
            "account": "SYSTEM",
            "running": True,
            "agent_id": "agent-1",
        },
    )
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **k: True)
    elevate = _RecordingElevate()
    output = __import__("io").StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        agent="yes",
        data_dir=tmp_path / "data",
        # This test covers elevation only; decline Google explicitly so it never
        # depends on (or touches) machine-local Google state.
        google="no",
        elevated_check=lambda: True,
        elevate=elevate,
        secret_input_fn=lambda _p: "srr_tok",
    )
    assert rc == 0
    # The resumed process must NOT request elevation again.
    assert elevate.calls == []
    assert "Online" in output.getvalue()


# ---------------------------------------------------------------------------
# 4. UAC cancellation / denial fails safely (no fake-success hand-off)
# ---------------------------------------------------------------------------


def test_uac_denial_fails_safely_without_handoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(deploy.AGENT_ELEVATED_ENV, raising=False)
    monkeypatch.setattr(deploy, "is_elevated", lambda: False)

    class _DeniedElevate:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        def __call__(self, argv: Sequence[str]) -> int:
            self.calls.append(list(argv))
            return 2  # runas declined / failed

    elevate = _DeniedElevate()
    output = __import__("io").StringIO()
    # A declined elevation must NOT raise _ElevationHandoff (which would pretend
    # success); it must stop safely and tell the operator what to do.
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        agent="yes",
        elevated_check=lambda: False,
        elevate=elevate,
    )
    assert rc == 0
    # The hand-off was attempted exactly once, then safely stopped (no hand-off).
    assert len(elevate.calls) == 1
    assert "declined" in output.getvalue().lower()


def test_noninteractive_no_elevation_attempted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(deploy.AGENT_ELEVATED_ENV, raising=False)
    monkeypatch.setattr(deploy, "is_elevated", lambda: False)
    elevate = _RecordingElevate()
    output = __import__("io").StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        agent="yes",
        non_interactive=True,
        elevated_check=lambda: False,
        elevate=elevate,
    )
    assert rc == 0
    assert elevate.calls == []
    assert "Administrator" in output.getvalue()
