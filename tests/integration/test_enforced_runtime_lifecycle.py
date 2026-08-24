"""Real runtime lifecycle integration tests.

These exercise the production daemon end to end on the host platform: a real
detached child process is spawned via the same code path the Claude Code / Gemini
hooks use, it publishes a healthy state file, accepts authenticated inspection,
and shuts down cleanly. They must run on Linux and Windows unchanged.

The hook *logic* (gemini_hook / claude_hook) is covered hermetically in the unit
suite; this file is strictly about the real runtime lifecycle contract and must
not weaken it (fail-closed, exactly one daemon, bounded start-up).
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
import time
import uuid

import pytest

from securedact_enforced import claude_runtime as rt

_DEAD_PID = 2**31 - 1


@pytest.fixture(autouse=True)
def _flair_off(monkeypatch: pytest.MonkeyPatch) -> None:
    # The production engine fails closed without a contextual model. Integration
    # runs are model-free and consent-free, so the engine must load without it.
    monkeypatch.setenv("SECUREDACT_REQUIRE_FLAIR", "0")
    yield


def _unique_session() -> str:
    return f"integration-{uuid.uuid4().hex}"


def _is_healthy(session_id: str) -> bool:
    state_path = rt.state_path_for_session(session_id)
    digest = rt._session_digest(session_id)
    if state_path is None or digest is None:
        return False
    return rt._is_healthy(state_path, digest, timeout_seconds=1.0)


def _force_stop(pid: int) -> None:
    if pid is None or pid <= 0:
        return
    if sys.platform == "win32":
        subprocess.run(  # noqa: S603
            ["taskkill", "/PID", str(pid), "/F", "/T"],  # noqa: S607
            capture_output=True,
            check=False,
        )
    else:
        try:
            os.kill(pid, 9)
        except OSError:
            pass


@pytest.fixture
def session_id() -> str:
    sid = _unique_session()
    yield sid
    # Best-effort cleanup of any daemon left running for this session.
    try:
        rt.shutdown_runtime(sid)
    except Exception:  # noqa: S110
        pass
    state_path = rt.state_path_for_session(sid)
    if state_path is not None and state_path.exists():
        try:
            state = rt._load_state(state_path, rt._session_digest(sid))
            if state is not None and rt._pid_is_alive(state.pid):
                _force_stop(state.pid)
        except Exception:  # noqa: S110
            pass


def test_real_daemon_starts_health_checks_inspects_and_shuts_down(
    session_id: str,
) -> None:
    result = rt.ensure_runtime(session_id, startup_timeout_seconds=30)
    assert result.ready is True
    assert result.started is True

    state_path = rt.state_path_for_session(session_id)
    assert state_path is not None
    assert state_path.exists()
    # Exactly one healthy daemon owns this session.
    assert _is_healthy(session_id) is True
    assert rt.runtime_is_warming(session_id) is False

    decision = rt.inspect_prompt(session_id, "please summarize the log file")
    # The daemon answered over authenticated IPC: ``None`` is an explicit allow,
    # a mapping is a block. Either proves the runtime served the request.
    assert decision is None or isinstance(decision, dict)

    assert rt.shutdown_runtime(session_id) is True
    assert not state_path.exists()
    assert _is_healthy(session_id) is False


def test_real_daemon_reuses_a_single_runtime_across_prompt_stages(
    session_id: str,
) -> None:
    first = rt.start_runtime(session_id)
    assert first.started is True
    # A prompt stage that arrives while warming must wait for the same daemon
    # instead of spawning a competing one.
    second = rt.ensure_runtime(session_id, startup_timeout_seconds=30)
    assert second.ready is True
    assert second.started is False

    # A third call must also reuse, never duplicate.
    third = rt.ensure_runtime(session_id, startup_timeout_seconds=30)
    assert third.ready is True
    assert third.started is False

    assert rt.shutdown_runtime(session_id) is True


def test_real_daemon_recovers_from_stale_state_and_dead_warming_marker(
    session_id: str,
) -> None:
    state_path = rt.state_path_for_session(session_id)
    digest = rt._session_digest(session_id)
    assert state_path is not None and digest is not None
    rt._atomic_write_json(
        state_path,
        {
            "version": rt._PROTOCOL_VERSION,
            "port": 9,
            "pid": _DEAD_PID,
            "session_digest": digest,
            "token": base64.b64encode(b"stale" * 8).decode("ascii"),
        },
    )
    rt._write_warming(state_path, digest, pid=_DEAD_PID)

    result = rt.ensure_runtime(session_id, startup_timeout_seconds=30)
    assert result.ready is True
    assert result.started is True

    state = rt._load_state(state_path, digest)
    assert state is not None
    assert state.pid != _DEAD_PID
    assert rt.runtime_is_warming(session_id) is False

    assert rt.shutdown_runtime(session_id) is True


def test_real_daemon_fails_closed_when_it_cannot_become_ready(
    session_id: str,
) -> None:
    # Make the spawn a no-op so the daemon never publishes a healthy state file;
    # ensure_runtime must bound the whole call and fail closed rather than hang.
    # Pass the replacement explicitly: the production default is captured at
    # function-definition time, so monkeypatching the module attribute would not
    # take effect.
    def _noop_spawn(*_args: object, **_kwargs: object) -> None:
        return None

    start = time.monotonic()
    result = rt.ensure_runtime(session_id, startup_timeout_seconds=5, spawn_daemon=_noop_spawn)
    elapsed = time.monotonic() - start

    assert result.ready is False
    assert elapsed < 15.0
    assert _is_healthy(session_id) is False
