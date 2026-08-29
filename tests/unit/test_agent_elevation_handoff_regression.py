# SPDX-License-Identifier: Apache-2.0
"""Regression coverage for the clean-laptop UAC elevation hand-off root cause.

Root cause: the elevated continuation was launched with
``python -m securedact_mcp.cli setup --agent --agent-elevated`` but
``securedact_mcp/cli.py`` had no ``if __name__ == "__main__"`` guard. The module
was merely imported, so the child process exited 0 immediately. Windows *did*
create the child (UAC succeeded, ``ShellExecuteEx`` returned success) but it died
instantly -- no setup continuation ever ran. The prior mocked/unit tests passed
only because they never exercised the real ``-m`` invocation.

These tests pin:

* the RC interpreter is explicit and never resolves a global ``securedact-mcp.exe``;
* ``-m securedact_mcp.cli`` now actually runs ``main()`` (real process);
* the resumed flow runs exactly once (no re-prompt / recursion);
* UAC cancellation fails safely (no fake-success hand-off);
* no secret material appears in argv / diagnostics.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from securedact_mcp.agent import deploy


def test_rc_interpreter_explicit_not_global_exe(monkeypatch: pytest.MonkeyPatch) -> None:
    # A global securedact-mcp.exe on PATH must never be consulted by the hand-off.
    monkeypatch.setattr(
        deploy.shutil,
        "which",
        lambda _n: r"C:\Program Files\Python312\Scripts\securedact-mcp.exe",
    )
    exe, params = deploy.resolve_elevation_target()
    assert exe == sys.executable
    assert Path(exe).name.lower() == "python.exe"
    assert "securedact-mcp.exe" not in exe.lower()
    assert params[0] == "-m"
    assert params[1] == "securedact_mcp.cli"
    # The bare console command (which a global install owns) is never used.
    assert not any("securedact-mcp" in str(p) for p in params)


def test_shell_execute_uses_rc_executable_and_preserves_cwd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sentinel = str(tmp_path / "rc-checkout")

    class _Cap:
        lpFile = None
        lpDirectory = None
        hProcess = 0

    class _Fake:
        sizeof = staticmethod(lambda *_a, **_k: 0)
        Structure = _Cap
        c_int = int
        c_void_p = object
        byref = staticmethod(lambda x: x)

        class wintypes:
            class DWORD:
                value = 0

            class HINSTANCE: ...

            class HKEY: ...

            class HWND: ...

            class ULONG: ...

            class LPCWSTR: ...

            class HANDLE: ...

        class _W:
            class _Shell32:
                @staticmethod
                def ShellExecuteExW(info: _Cap) -> int:
                    _Fake._cap = info
                    return 1

            class _Kernel32:
                @staticmethod
                def WaitForSingleObject(*_a: object, **_k: object) -> int:
                    return 0

                @staticmethod
                def GetExitCodeProcess(*_a: object, **_k: object) -> None:
                    return None

                @staticmethod
                def CloseHandle(*_a: object, **_k: object) -> None:
                    return None

                @staticmethod
                def GetLastError() -> int:
                    return 0

            def __init__(self) -> None:
                self.shell32 = self._Shell32()
                self.kernel32 = self._Kernel32()

        def __init__(self) -> None:
            self.windll = self._W()

    fake = _Fake()
    monkeypatch.setattr(deploy, "ctypes", fake)
    monkeypatch.setattr(deploy.os, "getcwd", lambda: sentinel)
    rc = deploy._shell_execute_runas(["-m", "securedact_mcp.cli", "setup", "--agent"], cwd=sentinel)
    assert rc == 0
    assert _Fake._cap.lpFile == sys.executable
    assert "securedact-mcp.exe" not in _Fake._cap.lpFile.lower()
    assert _Fake._cap.lpDirectory == sentinel


def test_agent_elevated_reaches_resumed_flow_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``--agent-elevated`` enters the Managed Agent flow exactly once.

    It must NOT re-prompt for elevation and must NOT re-launch a child.
    """

    monkeypatch.delenv(deploy.AGENT_ELEVATED_ENV, raising=False)
    monkeypatch.setattr(deploy, "is_elevated", lambda: False)

    def _install(**_k: object) -> dict[str, object]:
        return {
            "installed": True,
            "service_name": "SecuRedact Managed Agent",
            "data_dir": str(tmp_path / "data"),
            "account": "SYSTEM",
            "running": True,
            "agent_id": "agent-1",
        }

    monkeypatch.setattr(deploy, "install_service_from_runtime", _install)
    monkeypatch.setattr(deploy, "verify_heartbeat", lambda **_k: True)

    elevate: list[list[str]] = []
    output = __import__("io").StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        agent="yes",
        agent_elevated=True,
        data_dir=tmp_path / "data",
        elevated_check=lambda: False,
        elevate=lambda a: elevate.append(list(a)) or 0,
        secret_input_fn=lambda _p: "srr_dummy_token",
    )
    text = output.getvalue()
    assert "[Managed Agent]" in text
    assert "Relaunch setup elevated" not in text
    # The already-elevated continuation must NOT request elevation again.
    assert elevate == []
    assert "setup complete" in text
    assert rc == 0


def test_uac_cancellation_fails_safely(monkeypatch: pytest.MonkeyPatch) -> None:
    """A declined/failed elevation stops safely; it must not fake success."""

    monkeypatch.delenv(deploy.AGENT_ELEVATED_ENV, raising=False)
    monkeypatch.setattr(deploy, "is_elevated", lambda: False)

    calls: list[list[str]] = []

    def _denied(argv: Sequence[str]) -> int:
        calls.append(list(argv))
        return 2  # runas declined / failed

    output = __import__("io").StringIO()
    rc = deploy.run_managed_agent_module(
        input_fn=lambda _p: "y",
        output=output,
        agent="yes",
        elevated_check=lambda: False,
        elevate=_denied,
    )
    assert rc == 0
    assert len(calls) == 1
    assert "declined" in output.getvalue().lower()


def test_no_secrets_in_elevation_argv() -> None:
    params = deploy.build_elevation_argv()
    joined = " ".join(params)
    assert params == ["-m", "securedact_mcp.cli", "setup", "--agent", "--agent-elevated"]
    assert "srr_" not in joined and "sra_" not in joined and "token" not in joined
    assert "SECUREDACT_" not in joined


def test_child_command_executes_main_real(tmp_path: Path) -> None:
    """Real process: ``python -m securedact_mcp.cli`` now invokes ``main()``.

    This is the exact interpreter/module form the elevation hand-off launches, so
    it must not silently exit. Runs on every platform (the silent-exit defect was
    not Windows-specific in cause).
    """

    env = dict(os.environ)
    env["SECUREDACT_APP_DATA_DIR"] = str(tmp_path / "data")
    r = subprocess.run(
        [sys.executable, "-m", "securedact_mcp.cli", "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert r.returncode == 0
    assert "Securedact MCP" in (r.stdout + r.stderr)
