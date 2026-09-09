# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for the customer-facing bootstrap launcher (zero-PowerShell path).

The launcher (``scripts/install_agent_bootstrap.py``) is what a Business
customer runs after downloading the installer. These tests verify it:

* discovers a bootstrap config file
* forwards the correct env/argv to the elevated child
* does NOT place the ``srr_*`` token on argv (fail-closed)
* propagates the installer's bounded result envelope to stdout
* resolves the bundled real CPython via ``sys._MEIPASS/python.exe`` (never
  ``sys.executable`` when frozen) and fails-closed without it
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = REPO_ROOT / "scripts" / "install_agent_bootstrap.py"


def _load_launcher() -> object:
    spec = importlib.util.spec_from_file_location("bootstrap_launcher", LAUNCHER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_config(tmp_path: Path, **overrides: object) -> Path:
    import datetime as _dt

    from securedact_mcp.agent.installer import BOOTSTRAP_SCHEMA

    def _future() -> str:
        return (
            (_dt.datetime.now(_dt.UTC) + _dt.timedelta(seconds=600))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

    cfg = {
        "schema": BOOTSTRAP_SCHEMA,
        "control_plane_url": "https://www.securedact.com",
        "registration_token": "srr_abc123_def456ghi789",
        "recommended_version": "0.6.0",
        "expires_at": _future(),
        "models": [],
    }
    cfg.update(overrides)
    p = tmp_path / "securedact-bootstrap.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    return p


def test_launcher_resolves_explicit_config(tmp_path: Path) -> None:
    cfg = _write_config(tmp_path)
    launcher = _load_launcher()
    resolved = launcher._resolve_config_path(str(cfg))
    assert resolved == cfg


def test_launcher_resolves_via_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _write_config(tmp_path)
    monkeypatch.setenv("SECUREDACT_BOOTSTRAP_CONFIG", str(cfg))
    launcher = _load_launcher()
    resolved = launcher._resolve_config_path(None)
    assert resolved == cfg


def test_launcher_raises_when_no_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SECUREDACT_BOOTSTRAP_CONFIG", raising=False)
    launcher = _load_launcher()
    with pytest.raises(FileNotFoundError):
        launcher._resolve_config_path(None)


def test_launcher_main_with_skip_elevation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The launcher must run the install pipeline when elevation is skipped
    (developer / smoke-test mode) and emit the bounded result on stdout.
    No ``srr_*`` token may appear on argv at any point.
    """

    cfg = _write_config(tmp_path)
    launcher = _load_launcher()

    captured_argv: list[list[str]] = []

    def _fake_run_install(config, **kwargs):
        captured_argv.append(sys.argv)
        # Assert: the token never appears on sys.argv at any point.
        for argv_seen in captured_argv:
            joined = " ".join(argv_seen)
            assert "srr_" not in joined
        # Return a bounded result envelope.
        from securedact_mcp.agent.installer import (
            InstallerResult,
            InstallerStep,
        )

        return InstallerResult(
            success=True,
            steps=(InstallerStep("verify-heartbeat", "ok", "agent online"),),
            agent_id="agent-test-007",
            control_plane_url=config.control_plane_url,
            installed_version=config.recommended_version,
            runtime_path=None,
            error_code=None,
            error_message=None,
        )

    monkeypatch.setattr("securedact_mcp.agent.installer.run_install", _fake_run_install)
    monkeypatch.setattr("securedact_mcp.agent.installer.run_upgrade", _fake_run_install)

    rc = launcher.main(["--config", str(cfg), "--skip-elevation"])
    assert rc == 0
    # The captured_argv list contains the original sys.argv at the moment of
    # the call. None of those argv snapshots must include the token.
    for argv_seen in captured_argv:
        assert "srr_" not in " ".join(argv_seen)


def test_launcher_returns_nonzero_on_install_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _write_config(tmp_path)
    launcher = _load_launcher()

    def _fake_run_install(config, **kwargs):
        from securedact_mcp.agent.installer import (
            InstallerResult,
            InstallerStep,
        )

        return InstallerResult(
            success=False,
            steps=(InstallerStep("register-agent", "failed", "x"),),
            agent_id=None,
            control_plane_url=config.control_plane_url,
            installed_version=None,
            runtime_path=None,
            error_code="agent_registration_failed",
            error_message="x",
        )

    monkeypatch.setattr("securedact_mcp.agent.installer.run_install", _fake_run_install)
    monkeypatch.setattr("securedact_mcp.agent.installer.run_upgrade", _fake_run_install)
    rc = launcher.main(["--config", str(cfg), "--skip-elevation"])
    assert rc == 1


# ---------------------------------------------------------------------------
# Embedded Python resolution (bundled CPython find)
# ---------------------------------------------------------------------------


def test_embedded_python_resolved_from_meipass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """In onedir mode ``_MEIPASS`` points at ``_internal/`` where PyInstaller
    places the genuine ``python.exe``. The resolver must return that path."""
    fake_python = tmp_path / "python.exe"
    fake_python.write_bytes(b"MZ\x90\x00")  # minimal stub
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    launcher = _load_launcher()
    resolved = launcher._resolve_embedded_python()
    assert resolved == fake_python


def test_embedded_python_fails_closed_without_meipass(monkeypatch: pytest.MonkeyPatch) -> None:
    """A one-file build (no ``_MEIPASS``) must fail-closed — never fall back
    to ``sys.executable`` which is the bootloader stub."""
    monkeypatch.delattr(sys, "_MEIPASS", raising=False)
    os_env = os.environ
    os_env.pop("_MEIPASS", None)
    launcher = _load_launcher()
    resolved = launcher._resolve_embedded_python()
    assert resolved is None


def test_embedded_python_fails_closed_when_exe_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even when ``_MEIPASS`` is set, if ``python.exe`` is absent the resolver
    must return None (fail-closed), not fall back to the bootloader."""
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    os.environ.pop("_MEIPASS", None)
    launcher = _load_launcher()
    resolved = launcher._resolve_embedded_python()
    assert resolved is None


def test_assert_real_python_raises_when_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``assert_real_python_available`` must raise RuntimeError when the bundled
    interpreter is missing — never silently return ``sys.executable``."""
    monkeypatch.delattr(sys, "_MEIPASS", raising=False)
    os.environ.pop("_MEIPASS", None)
    launcher = _load_launcher()
    with pytest.raises(RuntimeError, match="bundled CPython"):
        launcher.assert_real_python_available()


# ---------------------------------------------------------------------------
# installer._resolve_embedded_python (fail-closed, never sys.executable)
# ---------------------------------------------------------------------------


def test_installer_resolve_embedded_python_frozen_uses_meipass_not_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When ``sys.frozen`` is True, ``_resolve_embedded_python`` must return
    ``_MEIPASS/python.exe`` — NEVER ``sys.executable`` (the bootloader stub)."""
    from securedact_mcp.agent.installer import _resolve_embedded_python

    fake_python = tmp_path / "python.exe"
    fake_python.write_bytes(b"MZ\x90\x00")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    os.environ["_MEIPASS"] = str(tmp_path)

    runner_calls: list[list[str]] = []

    def _fake_runner(args, _input, **kwargs):
        runner_calls.append(list(args))
        from securedact_mcp.agent.deploy import RunResult

        return RunResult(0, stdout="Python 3.12.10")

    resolved = _resolve_embedded_python(None, command_runner=_fake_runner)
    assert resolved == fake_python
    assert resolved != Path(sys.executable), "must never return bootloader stub"


def test_installer_resolve_embedded_python_frozen_fail_closed_no_meipass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When frozen and ``_MEIPASS`` is absent, must return None — not
    ``sys.executable``."""
    from securedact_mcp.agent.installer import _resolve_embedded_python

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.delattr(sys, "_MEIPASS", raising=False)
    os.environ.pop("_MEIPASS", None)

    resolved = _resolve_embedded_python(None)
    assert resolved is None
    assert resolved != Path(sys.executable)


def test_installer_resolve_embedded_python_unfrozen_uses_sys_executable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When NOT frozen (dev/test), ``sys.executable`` is genuine and is returned."""
    from securedact_mcp.agent.installer import _resolve_embedded_python

    monkeypatch.setattr(sys, "frozen", False, raising=False)

    resolved = _resolve_embedded_python(None)
    assert resolved == Path(sys.executable)
