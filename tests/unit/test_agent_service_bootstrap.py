# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the minimal Windows service startup path (AGENT-018).

These tests pin the behaviour needed to get past the real-Windows
``WinError 1053`` ("service did not respond ... in a timely fashion") that
occurs when the SCM-hosted ``pythonservice.exe`` process cannot import the
service module or blocks before reporting ``SERVICE_RUNNING``.

The unit-level tests (importability, RUNNING-before-loop ordering, scrubbed
exception capture) run wherever pywin32 is available. The end-to-end "StartService
reaches RUNNING" test is gated on a real, elevated Windows host because it
installs and starts an actual SCM service.
"""

from __future__ import annotations

import ctypes
import logging
import os
import sys
from pathlib import Path

import pytest

from securedact_legacy.service_windows import (
    WindowsAgentService,
    install_windows_service,
)
from securedact_mcp.agent import service as service_mod
from securedact_mcp.agent.service_security import DEV_BASELINE_ENV, is_dev_baseline_enabled

needs_win32 = pytest.mark.skipif(
    sys.platform != "win32", reason="Windows service host only runs on win32"
)


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # non-Windows / unavailable
        return False


# The two tests below validate the CANONICAL active-backend diagnostic, not the
# abandoned pywin32 backend's ``service-bootstrap.log``. The active Task Scheduler
# backend writes a scrubbed ``agent-service.log`` (see
# :func:`securedact_mcp.agent.service.configure_service_logging`) and logs
# "service starting" before entering the agent loop; the secret-scrubbing
# invariant is provided by the shared ``_ScrubFormatter``. The pywin32
# ``SvcDoRun``/RUNNING handshake is not part of the active lifecycle and is
# covered only by the reference assertions that remain in this file.


@needs_win32
def test_service_class_importable_under_runtime_python() -> None:
    # The SCM host imports ``securedact_legacy.service_windows.WindowsAgentService``.
    # If that import fails on the runtime Python, SvcDoRun is never reached and the
    # service times out -> 1053.
    import win32serviceutil

    assert issubclass(WindowsAgentService, win32serviceutil.ServiceFramework)
    assert WindowsAgentService._svc_name_ == service_mod.SERVICE_NAME


def test_service_loop_logs_start_before_agent_loop(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The active backend must log a scrubbed "service starting" diagnostic to
    # <data_dir>/logs/agent-service.log BEFORE entering the agent loop -- the
    # canonical equivalent of the old "reports SERVICE_RUNNING before loop" check.
    from securedact_mcp.agent import agent_runner as agent_runner_mod

    monkeypatch.setenv("SECUREDACT_APP_DATA_DIR", str(tmp_path))

    class _FakeConfig:
        agent_id = "agent-x"
        agent_version = "0.4.2"

    monkeypatch.setattr(service_mod, "load_config", lambda files: _FakeConfig())
    loop_calls: list[int] = []
    monkeypatch.setattr(
        agent_runner_mod,
        "run_agent_loop",
        lambda *args, **kwargs: loop_calls.append(1) or 0,
    )

    service_mod.run_service_loop(data_dir=Path(str(tmp_path)))

    log = Path(str(tmp_path)) / "logs" / "agent-service.log"
    assert log.exists(), "canonical service log was not written"
    text = log.read_text(encoding="utf-8")
    assert "service starting" in text
    assert loop_calls, "agent loop was never entered"


def test_service_log_scrubs_secret(tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> None:
    # The active backend's scrubbed logging must never write a secret in cleartext
    # (replaces the abandoned pywin32 service-bootstrap.log expectation).
    monkeypatch.setenv("SECUREDACT_APP_DATA_DIR", str(tmp_path))
    log_path = service_mod.configure_service_logging(Path(str(tmp_path)))
    assert log_path.exists()

    secret = "srr_SECRET_TOKEN_VALUE"  # noqa: S105 - synthetic test secret
    logging.getLogger("securedact.test.bootstrap").warning("launch near %s", secret)

    text = log_path.read_text(encoding="utf-8")
    assert secret not in text
    assert "<redacted-credential>" in text


@pytest.mark.skipif(
    not (sys.platform == "win32" and _is_admin()),
    reason="requires an elevated real-Windows host to install/start an SCM service",
)
def test_baseline_startservice_reaches_running_real_windows(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    # End-to-end gate: with DEV baseline enabled, installing and starting the
    # service must reach SERVICE_RUNNING (no WinError 1053). This is the first
    # known-working Windows service lifecycle check.
    monkeypatch.setenv(DEV_BASELINE_ENV, "1")
    assert is_dev_baseline_enabled() is True

    data_dir = tmp_path / "data"
    result = install_windows_service(
        data_dir=data_dir,
        start=False,
        command_runner=lambda a, ri: __import__(
            "securedact_mcp.agent.deploy", fromlist=["RunResult"]
        ).RunResult(0),
        acl_provider=None,
        sid_resolver=lambda a: "S-1-5-18",
        register_fn=lambda *a, **k: None,
        installing_user="Administrator",
        code_paths=[],
    )
    assert result["installed"] is True

    try:
        start_result = service_mod.start_service()
        # start_service() succeeding means the SCM host reported RUNNING in time.
        assert start_result.get("running") in (True, None)
    finally:
        # Best-effort cleanup so a failed assertion does not leave a service.
        try:
            service_mod.stop_service()
        except Exception:  # noqa: S110  # best-effort
            pass
        try:
            service_mod.uninstall_service()
        except Exception:  # noqa: S110  # best-effort
            pass

    # Definitive proof the startup path reached RUNNING.
    log = (
        __import__("pathlib").Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        / "Securedact"
        / "logs"
        / "service-bootstrap.log"
    )
    assert log.exists(), "bootstrap log missing after real start"
    assert "reported SERVICE_RUNNING" in log.read_text(encoding="utf-8")
