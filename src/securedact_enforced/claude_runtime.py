"""Authenticated, local-only persistent runtime for Claude Code prompt hooks.

The daemon receives prompt text only over a loopback socket and never writes it
to disk or logs.  Per-session state holds a random HMAC key and a hashed session
identifier, so a process that cannot read the user-owned state file cannot make
or forge requests to the daemon.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .provider_messages import FAIL_CLOSED, prompt_block

_PROTOCOL_VERSION = 1
_MAX_MESSAGE_BYTES = 1_048_576
_DEFAULT_REQUEST_TIMEOUT_SECONDS = 4.0
_STARTUP_TIMEOUT_SECONDS = 120.0
_LOCK_STALE_SECONDS = 180.0


@dataclass(frozen=True)
class RuntimeState:
    port: int
    pid: int
    session_digest: str
    token: bytes


@dataclass(frozen=True)
class EnsureResult:
    ready: bool
    started: bool


def _session_digest(session_id: object) -> str | None:
    if not isinstance(session_id, str) or not session_id:
        return None
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def _runtime_directory() -> Path:
    configured = os.environ.get("CLAUDE_PLUGIN_DATA")
    if configured:
        root = Path(configured)
    else:
        local_app_data = os.environ.get("LOCALAPPDATA")
        root = (
            Path(local_app_data) / "SecuRedact" / "ClaudeCode"
            if local_app_data
            else Path(tempfile.gettempdir()) / "securedact-claude"
        )
    directory = root / "runtime"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return directory


def state_path_for_session(session_id: object) -> Path | None:
    digest = _session_digest(session_id)
    return _runtime_directory() / f"{digest}.json" if digest else None


def write_hook_receipt(event: str, session_id: object, *, decision: str, elapsed_ms: int) -> None:
    """Append non-sensitive hook telemetry without affecting enforcement."""

    digest = _session_digest(session_id)
    if digest is None:
        return
    payload = {
        "event": event,
        "session_digest": digest,
        "decision": decision,
        "elapsed_ms": elapsed_ms,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        with (_runtime_directory() / "hook-receipts.jsonl").open("a", encoding="utf-8") as receipt:
            receipt.write(_canonical_json(payload).decode("utf-8") + "\n")
    except OSError:
        return


def _lock_path(state_path: Path) -> Path:
    return state_path.with_suffix(".lock")


def _canonical_json(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _authentication(token: bytes, payload: Mapping[str, object]) -> str:
    return hmac.new(token, _canonical_json(payload), hashlib.sha256).hexdigest()


def _atomic_write_json(path: Path, payload: Mapping[str, object]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_bytes(_canonical_json(payload))
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    os.replace(temporary, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _load_state(path: Path, expected_digest: str | None = None) -> RuntimeState | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, Mapping):
            return None
        port = payload.get("port")
        pid = payload.get("pid")
        session_digest = payload.get("session_digest")
        encoded_token = payload.get("token")
        if (
            not isinstance(port, int)
            or not 1 <= port <= 65535
            or not isinstance(pid, int)
            or pid <= 0
            or not isinstance(session_digest, str)
            or not isinstance(encoded_token, str)
            or (expected_digest is not None and session_digest != expected_digest)
        ):
            return None
        token = base64.b64decode(encoded_token.encode("ascii"), validate=True)
        return RuntimeState(port=port, pid=pid, session_digest=session_digest, token=token)
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _remove_state(path: Path, expected_token: bytes | None = None) -> None:
    state = _load_state(path)
    if expected_token is not None and (
        state is None or not hmac.compare_digest(state.token, expected_token)
    ):
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _read_line(connection: socket.socket) -> bytes | None:
    chunks: list[bytes] = []
    received = 0
    while received <= _MAX_MESSAGE_BYTES:
        chunk = connection.recv(min(4096, _MAX_MESSAGE_BYTES + 1 - received))
        if not chunk:
            return None
        chunks.append(chunk)
        received += len(chunk)
        joined = b"".join(chunks)
        if b"\n" in joined:
            line, _separator, _rest = joined.partition(b"\n")
            return line if len(line) <= _MAX_MESSAGE_BYTES else None
    return None


def _send_payload(connection: socket.socket, payload: Mapping[str, object]) -> None:
    connection.sendall(_canonical_json(payload) + b"\n")


class _RuntimeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(
        self,
        state_path: Path,
        token: bytes,
        session_digest: str,
        decide: Callable[[str], dict[str, object] | None],
    ) -> None:
        super().__init__(("127.0.0.1", 0), _RuntimeRequestHandler)
        self.state_path = state_path
        self.token = token
        self.session_digest = session_digest
        self.decide = decide

    def response(self, *, ok: bool, response: dict[str, object] | None = None) -> dict[str, object]:
        unsigned: dict[str, object] = {"version": _PROTOCOL_VERSION, "ok": ok, "response": response}
        return {**unsigned, "auth": _authentication(self.token, unsigned)}


class _RuntimeRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        if not isinstance(server, _RuntimeServer):
            return
        self.request.settimeout(_DEFAULT_REQUEST_TIMEOUT_SECONDS)
        raw = _read_line(self.request)
        if raw is None:
            return
        try:
            request = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        if not isinstance(request, Mapping):
            return
        operation = request.get("operation")
        supplied_auth = request.get("auth")
        unsigned = {key: value for key, value in request.items() if key != "auth"}
        if not isinstance(operation, str) or not isinstance(supplied_auth, str):
            return
        if not hmac.compare_digest(supplied_auth, _authentication(server.token, unsigned)):
            return
        if operation == "health":
            _send_payload(self.request, server.response(ok=True))
            return
        if operation == "shutdown":
            _send_payload(self.request, server.response(ok=True))
            threading.Thread(target=server.shutdown, daemon=True).start()
            return
        if operation != "inspect_prompt":
            _send_payload(self.request, server.response(ok=False))
            return
        prompt = request.get("prompt")
        if not isinstance(prompt, str):
            _send_payload(self.request, server.response(ok=False))
            return
        try:
            decision = server.decide(prompt)
        except Exception:
            decision = prompt_block("claude", FAIL_CLOSED)
        _send_payload(self.request, server.response(ok=True, response=decision))


def _serve(
    state_path: Path,
    token: bytes,
    session_digest: str,
    enforcer_factory: Callable[[], Any],
) -> None:
    """Load the contextual runtime once, then serve authenticated local requests."""

    try:
        from .provider_hook import handle_event

        enforcer = enforcer_factory()

        def decide(prompt: str) -> dict[str, object] | None:
            return handle_event(
                "claude",
                {"hook_event_name": "UserPromptSubmit", "prompt": prompt},
                enforcer_factory=lambda: enforcer,
            )

        with _RuntimeServer(state_path, token, session_digest, decide) as server:
            port = server.server_address[1]
            if not isinstance(port, int):
                return
            _atomic_write_json(
                state_path,
                {
                    "version": _PROTOCOL_VERSION,
                    "port": port,
                    "pid": os.getpid(),
                    "session_digest": session_digest,
                    "token": base64.b64encode(token).decode("ascii"),
                },
            )
            server.serve_forever(poll_interval=0.1)
    except Exception:
        return
    finally:
        _remove_state(state_path, token)


def serve_from_command_line(state_file: str, token: str, session_digest: str) -> int:
    """Daemon entry point used only by the SessionStart-spawned child process."""

    try:
        decoded_token = base64.b64decode(token.encode("ascii"), validate=True)
    except (ValueError, UnicodeDecodeError):
        return 1
    from .adapter import PrivacyEnforcer

    _serve(Path(state_file), decoded_token, session_digest, PrivacyEnforcer.from_environment)
    return 0


def _request(
    state: RuntimeState, payload: Mapping[str, object], timeout_seconds: float
) -> dict[str, object] | None:
    unsigned = {"version": _PROTOCOL_VERSION, **payload}
    request = {**unsigned, "auth": _authentication(state.token, unsigned)}
    try:
        with socket.create_connection(
            ("127.0.0.1", state.port), timeout=timeout_seconds
        ) as connection:
            connection.settimeout(timeout_seconds)
            _send_payload(connection, request)
            raw = _read_line(connection)
        if raw is None:
            return None
        response = json.loads(raw.decode("utf-8"))
        if not isinstance(response, Mapping):
            return None
        supplied_auth = response.get("auth")
        unsigned_response = {key: value for key, value in response.items() if key != "auth"}
        if not isinstance(supplied_auth, str) or not hmac.compare_digest(
            supplied_auth, _authentication(state.token, unsigned_response)
        ):
            return None
        return dict(response)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _is_healthy(state_path: Path, session_digest: str) -> bool:
    state = _load_state(state_path, session_digest)
    if state is None:
        return False
    response = _request(state, {"operation": "health"}, _DEFAULT_REQUEST_TIMEOUT_SECONDS)
    return response is not None and response.get("ok") is True


def _acquire_start_lock(state_path: Path, timeout_seconds: float) -> int | None:
    path = _lock_path(state_path)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            return os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            try:
                if time.time() - path.stat().st_mtime > _LOCK_STALE_SECONDS:
                    path.unlink()
                    continue
            except FileNotFoundError:
                continue
            time.sleep(0.05)
    return None


def _release_start_lock(state_path: Path, descriptor: int | None) -> None:
    if descriptor is not None:
        os.close(descriptor)
    try:
        _lock_path(state_path).unlink()
    except FileNotFoundError:
        pass


def _daemon_popen_kwargs(*, is_windows: bool) -> dict[str, object]:
    """Return process options that cannot retain a Claude hook handle.

    Standard streams are deliberately redirected and ``close_fds`` is enabled
    on every platform.  This matters particularly on Windows: setting
    ``close_fds=False`` allows any inheritable host pipe/console handle into
    the long-lived runtime, even if the three standard streams use DEVNULL.

    ``DETACHED_PROCESS`` is the Windows mechanism that prevents console
    inheritance.  It is intentionally not combined with ``CREATE_NO_WINDOW``:
    Windows documents the latter as ignored with a detached process.  A new
    process group also prevents the runtime from sharing Claude's console
    control group.  On POSIX, a new session is the corresponding isolation.
    """

    options: dict[str, object] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if is_windows:
        options["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    else:
        options["start_new_session"] = True
    return options


def _spawn_daemon(state_path: Path, token: bytes, session_digest: str) -> None:
    command = [
        sys.executable,
        "-m",
        "securedact_enforced.claude_runtime",
        "--serve",
        "--state-file",
        str(state_path),
        "--token",
        base64.b64encode(token).decode("ascii"),
        "--session-digest",
        session_digest,
    ]
    subprocess.Popen(  # noqa: S603 - command is a fixed module invocation with generated state arguments.
        command,
        **_daemon_popen_kwargs(is_windows=os.name == "nt"),
    )


def ensure_runtime(
    session_id: object,
    *,
    startup_timeout_seconds: float = _STARTUP_TIMEOUT_SECONDS,
    spawn_daemon: Callable[[Path, bytes, str], None] = _spawn_daemon,
) -> EnsureResult:
    """Ensure this Claude session has one warmed runtime; never load it in a prompt hook."""

    state_path = state_path_for_session(session_id)
    digest = _session_digest(session_id)
    if state_path is None or digest is None:
        return EnsureResult(ready=False, started=False)
    if _is_healthy(state_path, digest):
        return EnsureResult(ready=True, started=False)
    lock = _acquire_start_lock(state_path, startup_timeout_seconds)
    if lock is None:
        return EnsureResult(ready=False, started=False)
    try:
        if _is_healthy(state_path, digest):
            return EnsureResult(ready=True, started=False)
        _remove_state(state_path)
        token = secrets.token_bytes(32)
        spawn_daemon(state_path, token, digest)
        deadline = time.monotonic() + startup_timeout_seconds
        while time.monotonic() < deadline:
            if _is_healthy(state_path, digest):
                return EnsureResult(ready=True, started=True)
            time.sleep(0.05)
        _remove_state(state_path, token)
        return EnsureResult(ready=False, started=True)
    except Exception:
        return EnsureResult(ready=False, started=False)
    finally:
        _release_start_lock(state_path, lock)


def start_runtime(
    session_id: object,
    *,
    spawn_daemon: Callable[[Path, bytes, str], None] = _spawn_daemon,
) -> EnsureResult:
    """Launch one session daemon without waiting for model warm-up.

    Claude Code must not spend prompt-hook budget loading a contextual model.
    The session hook therefore starts the child and returns immediately. Until
    it publishes a healthy state file, ``inspect_prompt`` fails closed.
    """

    state_path = state_path_for_session(session_id)
    digest = _session_digest(session_id)
    if state_path is None or digest is None:
        return EnsureResult(ready=False, started=False)
    if _is_healthy(state_path, digest):
        return EnsureResult(ready=True, started=False)
    lock = _acquire_start_lock(state_path, 1.0)
    if lock is None:
        return EnsureResult(ready=False, started=False)
    try:
        if _is_healthy(state_path, digest):
            return EnsureResult(ready=True, started=False)
        _remove_state(state_path)
        spawn_daemon(state_path, secrets.token_bytes(32), digest)
        return EnsureResult(ready=False, started=True)
    except Exception:
        return EnsureResult(ready=False, started=False)
    finally:
        _release_start_lock(state_path, lock)


def inspect_prompt(
    session_id: object, prompt: object, *, timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS
) -> dict[str, object] | None:
    """Ask a pre-warmed daemon for the existing Claude JSON decision.

    ``None`` means allow.  Any unavailable, malformed, or unauthenticated
    runtime result becomes the normal fail-closed Claude prompt block.
    """

    state_path = state_path_for_session(session_id)
    digest = _session_digest(session_id)
    if state_path is None or digest is None or not isinstance(prompt, str):
        return prompt_block("claude", FAIL_CLOSED)
    state = _load_state(state_path, digest)
    if state is None:
        return prompt_block("claude", FAIL_CLOSED)
    response = _request(state, {"operation": "inspect_prompt", "prompt": prompt}, timeout_seconds)
    if response is None or response.get("ok") is not True:
        return prompt_block("claude", FAIL_CLOSED)
    decision = response.get("response")
    if decision is None:
        return None
    if not isinstance(decision, dict):
        return prompt_block("claude", FAIL_CLOSED)
    return decision


def shutdown_runtime(session_id: object) -> bool:
    state_path = state_path_for_session(session_id)
    digest = _session_digest(session_id)
    if state_path is None or digest is None:
        return False
    state = _load_state(state_path, digest)
    if state is None:
        return False
    response = _request(state, {"operation": "shutdown"}, _DEFAULT_REQUEST_TIMEOUT_SECONDS)
    if response is None or response.get("ok") is not True:
        return False
    deadline = time.monotonic() + _DEFAULT_REQUEST_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if not state_path.exists():
            return True
        time.sleep(0.05)
    return False


def command_line_main(argv: list[str] | None = None) -> int:
    """Minimal argument parser kept out of prompt-client imports."""

    import argparse

    parser = argparse.ArgumentParser(description="SecuRedact Claude local runtime")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--state-file")
    parser.add_argument("--token")
    parser.add_argument("--session-digest")
    args = parser.parse_args(argv)
    if not args.serve or not all((args.state_file, args.token, args.session_digest)):
        return 1
    return serve_from_command_line(args.state_file, args.token, args.session_digest)


if __name__ == "__main__":
    raise SystemExit(command_line_main())
