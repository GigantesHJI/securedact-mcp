# SPDX-License-Identifier: Apache-2.0
"""Tests for the managed-agent Windows service lifecycle (AGENT-TEST).

Windows-specific install/start/stop paths require elevation, pywin32, and the
native SCM, so they are guarded and skipped unless explicitly enabled. The
platform-neutral surface (unsupported-on-Linux behavior, single-instance lock,
scrubbed logging, secret-free service env, correct data-dir resolution, and the
service run loop reusing the existing agent loop) is exercised directly on every
platform.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import pytest

from securedact_mcp.agent import service
from securedact_mcp.agent.service import AgentServiceUnsupportedError, _ScrubFormatter
from securedact_mcp.agent.service_lock import agent_instance_lock

# ---------------------------------------------------------------------------
# Unsupported platform (non-Windows) surface
# ---------------------------------------------------------------------------


def test_is_windows_service_supported_reflects_platform():
    assert service.is_windows_service_supported() is (sys.platform == "win32")


def test_non_windows_lifecycle_raises_clear_error():
    if sys.platform == "win32":
        pytest.skip("Windows service is supported here")
    for fn in (
        service.install_service,
        service.start_service,
        service.stop_service,
        service.uninstall_service,
        service.query_service_status,
    ):
        with pytest.raises(AgentServiceUnsupportedError):
            fn()


def test_non_windows_require_windows_message_is_customer_readable():
    if sys.platform == "win32":
        pytest.skip("Windows service is supported here")
    with pytest.raises(AgentServiceUnsupportedError) as exc:
        service.install_service()
    assert "only supported on Windows" in str(exc.value)


# ---------------------------------------------------------------------------
# Secret-free service environment construction
# ---------------------------------------------------------------------------


def test_build_service_env_contains_no_secrets():
    env = service.build_service_env(Path("C:/ProgramData/Securedact"))
    assert env["SECUREDACT_AGENT_DATA_DIR"] == str(Path("C:/ProgramData/Securedact"))
    assert env["SECUREDACT_AGENT_SERVICE"] == "1"
    blob = " ".join(f"{k}={v}" for k, v in env.items())
    for forbidden in ("sra_", "srr_", "sl_", "Bearer ", "token"):
        assert forbidden not in blob


# ---------------------------------------------------------------------------
# Data-dir resolution
# ---------------------------------------------------------------------------


def test_resolve_service_data_dir_explicit_wins(tmp_path):
    assert service.resolve_service_data_dir(tmp_path / "x") == tmp_path / "x"


def test_resolve_service_data_dir_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SECUREDACT_APP_DATA_DIR", str(tmp_path / "env"))
    assert service.resolve_service_data_dir(None) == tmp_path / "env"


# ---------------------------------------------------------------------------
# Single-instance lock
# ---------------------------------------------------------------------------


def test_single_instance_lock_blocks_second_holder(tmp_path):
    lock = tmp_path / "agent.lock"
    with agent_instance_lock(lock) as first:
        assert first is True
        with agent_instance_lock(lock) as second:
            assert second is False


def test_single_instance_lock_released_after_block(tmp_path):
    lock = tmp_path / "agent.lock"
    with agent_instance_lock(lock):
        pass
    with agent_instance_lock(lock) as again:
        assert again is True


# ---------------------------------------------------------------------------
# Scrubbed diagnostics formatter
# ---------------------------------------------------------------------------


def test_scrub_formatter_redacts_secrets():
    fmt = _ScrubFormatter("%(message)s")
    record = logging.LogRecord(
        "t", logging.INFO, __file__, 1, "token sra_x_y leak sl_abc", None, None
    )
    out = fmt.format(record)
    assert "sra_x_y" not in out
    assert "sl_abc" not in out
    assert "<redacted-credential>" in out


def test_scrub_formatter_redacts_bearer():
    fmt = _ScrubFormatter("%(message)s")
    record = logging.LogRecord(
        "t", logging.INFO, __file__, 1, "Authorization: Bearer secretvalue", None, None
    )
    assert "secretvalue" not in fmt.format(record)


# ---------------------------------------------------------------------------
# Service run loop reuses the existing agent loop with correct paths
# ---------------------------------------------------------------------------


def test_run_service_loop_uses_data_dir_and_stops(monkeypatch, tmp_path):
    # Register an agent under the service data dir.
    from securedact_mcp.agent import agent_runner
    from securedact_mcp.agent.config import AgentFiles
    from tests.unit.test_agent_runner import _runner_transport

    transport = _runner_transport({"n": 0}, [])
    files = AgentFiles.resolve(root=tmp_path / "agent")
    agent_runner.register_agent(
        "srr_tok", control_plane_url="https://cp.example.com", files=files, transport=transport
    )

    calls: dict[str, object] = {}
    monkeypatch.setattr(agent_runner, "run_agent_loop", lambda *a, **k: calls.update(k) or 0)

    stop = {"flag": False}

    def _stop() -> bool:
        # Stop after the first iteration so the test terminates.
        stop["flag"] = True
        return True

    rc = service.run_service_loop(stop=_stop, idle_sleep=0, data_dir=tmp_path)
    assert rc == 0
    assert calls.get("files") == files
    assert calls.get("stop") is _stop
    assert calls.get("idle_sleep") == 0


def test_run_service_loop_refuses_without_registration(monkeypatch, tmp_path):
    # A missing agent.json must fail closed, not crash.
    rc = service.run_service_loop(stop=lambda: True, idle_sleep=0, data_dir=tmp_path / "empty")
    assert rc == 2


def test_run_service_loop_exits_when_another_instance_holds_lock(monkeypatch, tmp_path):
    from securedact_mcp.agent import agent_runner
    from securedact_mcp.agent.config import AgentFiles
    from tests.unit.test_agent_runner import _runner_transport

    transport = _runner_transport({"n": 0}, [])
    files = AgentFiles.resolve(root=tmp_path / "agent")
    agent_runner.register_agent(
        "srr_tok", control_plane_url="https://cp.example.com", files=files, transport=transport
    )
    # Pre-acquire the lock so the loop cannot start.
    with agent_instance_lock(files.root / "agent.lock"):
        rc = service.run_service_loop(
            stop=lambda: True, idle_sleep=0, data_dir=tmp_path, agent_runner=agent_runner
        )
    assert rc == 3


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_parser_has_service_and_install_service():
    # Reach into the agent subparser to assert commands exist.
    import argparse

    from securedact_mcp.agent.cli import build_agent_parser

    parser = argparse.ArgumentParser()
    group = parser.add_subparsers(dest="cmd")
    build_agent_parser(group)
    args = parser.parse_args(["agent", "service", "status"])
    assert args.cmd == "agent"
    assert args.service_command == "status"

    args = parser.parse_args(["agent", "register", "--token", "srr_x", "--install-service"])
    assert args.install_service is True

    args = parser.parse_args(["agent", "run", "--no-lock"])
    assert args.no_lock is True


# ---------------------------------------------------------------------------
# Windows-only integration (requires admin + pywin32)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "win32", reason="native service only on Windows")
@pytest.mark.skipif(
    "SECUREDACT_TEST_WINDOWS_SERVICE" not in os.environ,
    reason="set SECUREDACT_TEST_WINDOWS_SERVICE=1 to exercise the real SCM",
)
def test_windows_service_install_start_stop_uninstall(tmp_path):

    data_dir = tmp_path / "svc"
    result = service.install_service(data_dir=data_dir, start=True)
    assert result["installed"] is True
    assert result["account"] in ("LocalSystem", r"NT SERVICE\SecuredactAgent")
    status = service.query_service_status()
    assert status["installed"] is True
    assert status["state"] in ("running", "start_pending")
    service.stop_service()
    service.uninstall_service()
    assert service.query_service_status()["installed"] is False
