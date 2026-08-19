"""Authenticated, local-only persistent runtime for Claude Code prompt hooks.

The daemon receives prompt text only over a loopback socket and never writes it
to disk or logs.  Per-session state holds a random HMAC key and a hashed session
identifier, so a process that cannot read the user-owned state file cannot make
or forge requests to the daemon.
"""

from __future__ import annotations

import base64
import ctypes
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
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from securedact_core import PrepareOutcome

from .adapter import EnforcementOutcome, EnforcementResult
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


def _runtime_directory(runtime_scope: str = "claude") -> Path:
    configured = os.environ.get("CLAUDE_PLUGIN_DATA") if runtime_scope == "claude" else None
    if configured:
        root = Path(configured)
    else:
        local_app_data = os.environ.get("LOCALAPPDATA")
        product = "ClaudeCode" if runtime_scope == "claude" else "GeminiCli"
        root = (
            Path(local_app_data) / "SecuRedact" / product
            if local_app_data
            else Path(tempfile.gettempdir()) / f"securedact-{runtime_scope}"
        )
    directory = root / "runtime"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return directory


def state_path_for_session(session_id: object, *, runtime_scope: str = "claude") -> Path | None:
    digest = _session_digest(session_id)
    filename = f"{digest}.json" if runtime_scope == "claude" else f"{runtime_scope}-{digest}.json"
    return _runtime_directory(runtime_scope) / filename if digest else None


def write_hook_receipt(
    event: str,
    session_id: object,
    *,
    decision: str,
    elapsed_ms: int,
    runtime_scope: str = "claude",
    safe_metadata: Mapping[str, object] | None = None,
) -> None:
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
    if safe_metadata is not None:
        payload["metadata"] = dict(safe_metadata)
    try:
        with (_runtime_directory(runtime_scope) / "hook-receipts.jsonl").open(
            "a", encoding="utf-8"
        ) as receipt:
            receipt.write(_canonical_json(payload).decode("utf-8") + "\n")
    except OSError:
        return


def _lock_path(state_path: Path) -> Path:
    return state_path.with_suffix(".lock")


def _warming_path(state_path: Path) -> Path:
    return state_path.with_suffix(".warming")


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


def _write_warming(state_path: Path, session_digest: str) -> None:
    _atomic_write_json(
        _warming_path(state_path),
        {"version": _PROTOCOL_VERSION, "session_digest": session_digest, "status": "warming"},
    )


def _remove_warming(state_path: Path) -> None:
    try:
        _warming_path(state_path).unlink()
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
        inspect_text: Callable[[str], EnforcementResult],
    ) -> None:
        super().__init__(("127.0.0.1", 0), _RuntimeRequestHandler)
        self.state_path = state_path
        self.token = token
        self.session_digest = session_digest
        self.decide = decide
        self.inspect_text = inspect_text
        self._approved_text_digests: set[str] = set()
        self._approved_text_lock = threading.Lock()
        self._initial_model_request_text: str | None = None
        self._initial_model_transformation: tuple[str, str, PrepareOutcome] | None = None

    @staticmethod
    def _text_digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def inspect_text_result(self, text: str) -> EnforcementResult:
        digest = self._text_digest(text)
        with self._approved_text_lock:
            if digest in self._approved_text_digests:
                return EnforcementResult(
                    EnforcementOutcome.ALLOW, prepare_outcome=PrepareOutcome.ALLOW
                )
        result = self.inspect_text(text)
        if result.outcome == EnforcementOutcome.ALLOW:
            with self._approved_text_lock:
                self._approved_text_digests.add(digest)
        return result

    def approve_initial_model_request(self, text: str) -> None:
        with self._approved_text_lock:
            self._initial_model_request_text = text

    def consume_initial_model_request_approval(self, payload: object) -> bool:
        with self._approved_text_lock:
            approved_text = self._initial_model_request_text
            self._initial_model_request_text = None
        if not approved_text:
            return False
        return self._payload_contains_text(payload, approved_text)

    def cache_initial_model_transformation(
        self, source: str, sanitized: str, outcome: PrepareOutcome
    ) -> None:
        with self._approved_text_lock:
            self._initial_model_transformation = (source, sanitized, outcome)

    def consume_initial_model_transformation(
        self, payload: object
    ) -> tuple[EnforcementResult, object] | None:
        with self._approved_text_lock:
            transformation = self._initial_model_transformation
            self._initial_model_transformation = None
        if transformation is None:
            return None
        source, sanitized, outcome = transformation
        replaced, replacement_count = self._replace_payload_text(payload, source, sanitized)
        if replacement_count == 0:
            return None
        return (
            EnforcementResult(
                EnforcementOutcome.SANITIZED,
                prepare_outcome=outcome,
            ),
            replaced,
        )

    @classmethod
    def _payload_contains_text(cls, payload: object, text: str) -> bool:
        if isinstance(payload, str):
            return text in payload
        if isinstance(payload, Mapping):
            return any(cls._payload_contains_text(value, text) for value in payload.values())
        if isinstance(payload, list):
            return any(cls._payload_contains_text(value, text) for value in payload)
        return False

    @classmethod
    def _replace_payload_text(
        cls, payload: object, source: str, sanitized: str
    ) -> tuple[object, int]:
        if isinstance(payload, str):
            return payload.replace(source, sanitized), payload.count(source)
        if isinstance(payload, Mapping):
            replaced: dict[object, object] = {}
            replacements = 0
            for key, value in payload.items():
                replaced_value, count = cls._replace_payload_text(value, source, sanitized)
                replaced[key] = replaced_value
                replacements += count
            return replaced, replacements
        if isinstance(payload, list):
            replaced_items: list[object] = []
            replacements = 0
            for value in payload:
                replaced_value, count = cls._replace_payload_text(value, source, sanitized)
                replaced_items.append(replaced_value)
                replacements += count
            return replaced_items, replacements
        return payload, 0

    @staticmethod
    def _aggregate_prepare_outcomes(
        outcomes: list[PrepareOutcome | None], *, changed: bool
    ) -> PrepareOutcome | None:
        if any(outcome is None for outcome in outcomes):
            return None
        if not changed:
            return PrepareOutcome.ALLOW
        if PrepareOutcome.REDACTED in outcomes:
            return PrepareOutcome.REDACTED
        return PrepareOutcome.PSEUDONYMIZED

    def inspect_payload_result(self, payload: object) -> tuple[EnforcementResult, object | None]:
        """Inspect only uncached text; digests are in-memory and per daemon."""

        if isinstance(payload, str):
            result = self.inspect_text_result(payload)
            return (
                result,
                result.sanitized_text
                if result.outcome == EnforcementOutcome.SANITIZED
                else payload,
            )
        if isinstance(payload, Mapping):
            sanitized: dict[object, object] = {}
            changed = False
            prepare_outcomes: list[PrepareOutcome | None] = []
            for key, value in payload.items():
                if not isinstance(key, str):
                    return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE), None
                result, replacement = self.inspect_payload_result(value)
                if result.outcome not in {EnforcementOutcome.ALLOW, EnforcementOutcome.SANITIZED}:
                    return result, None
                sanitized[key] = replacement
                changed = changed or result.outcome == EnforcementOutcome.SANITIZED
                prepare_outcomes.append(result.prepare_outcome)
            return (
                EnforcementResult(
                    EnforcementOutcome.SANITIZED if changed else EnforcementOutcome.ALLOW,
                    prepare_outcome=self._aggregate_prepare_outcomes(
                        prepare_outcomes, changed=changed
                    ),
                ),
                sanitized,
            )
        if isinstance(payload, list):
            sanitized_items: list[object] = []
            changed = False
            prepare_outcomes = []
            for value in payload:
                result, replacement = self.inspect_payload_result(value)
                if result.outcome not in {EnforcementOutcome.ALLOW, EnforcementOutcome.SANITIZED}:
                    return result, None
                sanitized_items.append(replacement)
                changed = changed or result.outcome == EnforcementOutcome.SANITIZED
                prepare_outcomes.append(result.prepare_outcome)
            return (
                EnforcementResult(
                    EnforcementOutcome.SANITIZED if changed else EnforcementOutcome.ALLOW,
                    prepare_outcome=self._aggregate_prepare_outcomes(
                        prepare_outcomes, changed=changed
                    ),
                ),
                sanitized_items,
            )
        if payload is None or isinstance(payload, bool | int | float):
            return EnforcementResult(
                EnforcementOutcome.ALLOW, prepare_outcome=PrepareOutcome.ALLOW
            ), payload
        return EnforcementResult(EnforcementOutcome.INTERNAL_FAILURE), None

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
            _send_payload(
                self.request,
                server.response(ok=True, response={"session_digest": server.session_digest}),
            )
            return
        if operation == "shutdown":
            _send_payload(self.request, server.response(ok=True))
            threading.Thread(target=server.shutdown, daemon=True).start()
            return
        if operation in {"inspect_payload", "inspect_model_payload"}:
            payload = request.get("payload")
            if not isinstance(payload, dict | list):
                _send_payload(self.request, server.response(ok=False))
                return
            try:
                result: EnforcementResult
                sanitized_payload: object | None
                cached_transformation = (
                    server.consume_initial_model_transformation(payload)
                    if operation == "inspect_model_payload"
                    else None
                )
                if cached_transformation is not None:
                    result, sanitized_payload = cached_transformation
                elif (
                    operation == "inspect_model_payload"
                    and server.consume_initial_model_request_approval(payload)
                ):
                    result, sanitized_payload = (
                        EnforcementResult(
                            EnforcementOutcome.ALLOW,
                            prepare_outcome=PrepareOutcome.ALLOW,
                        ),
                        payload,
                    )
                else:
                    result, sanitized_payload = server.inspect_payload_result(payload)
                response: dict[str, object] = {"outcome": str(result.outcome)}
                if result.prepare_outcome is not None:
                    response["prepare_outcome"] = str(result.prepare_outcome)
                if result.outcome == EnforcementOutcome.SANITIZED:
                    response["sanitized_payload"] = sanitized_payload
                _send_payload(self.request, server.response(ok=True, response=response))
            except Exception:
                _send_payload(self.request, server.response(ok=False))
            return
        if operation in {"inspect_text", "inspect_before_agent_text"}:
            text = request.get("text")
            if not isinstance(text, str):
                _send_payload(self.request, server.response(ok=False))
                return
            try:
                result = server.inspect_text_result(text)
                if (
                    operation == "inspect_before_agent_text"
                    and result.outcome == EnforcementOutcome.ALLOW
                ):
                    server.approve_initial_model_request(text)
                elif (
                    operation == "inspect_before_agent_text"
                    and result.outcome == EnforcementOutcome.SANITIZED
                    and isinstance(result.sanitized_text, str)
                    and result.prepare_outcome
                    in {PrepareOutcome.PSEUDONYMIZED, PrepareOutcome.REDACTED}
                ):
                    server.cache_initial_model_transformation(
                        text,
                        result.sanitized_text,
                        result.prepare_outcome,
                    )
                _send_payload(
                    self.request,
                    server.response(
                        ok=True,
                        response={
                            "outcome": str(result.outcome),
                            **(
                                {"prepare_outcome": str(result.prepare_outcome)}
                                if result.prepare_outcome is not None
                                else {}
                            ),
                        },
                    ),
                )
            except Exception:
                _send_payload(self.request, server.response(ok=False))
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

        with _RuntimeServer(
            state_path,
            token,
            session_digest,
            decide,
            enforcer.inspect_text,
        ) as server:
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
            _remove_warming(state_path)
            server.serve_forever(poll_interval=0.1)
    except Exception:
        return
    finally:
        _remove_state(state_path, token)
        _remove_warming(state_path)


def serve_from_command_line(state_file: str, token: str, session_digest: str) -> int:
    """Daemon entry point used only by the SessionStart-spawned child process."""

    try:
        decoded_token = base64.b64decode(token.encode("ascii"), validate=True)
    except (ValueError, UnicodeDecodeError):
        return 1
    from .adapter import PrivacyEnforcer

    _serve(Path(state_file), decoded_token, session_digest, PrivacyEnforcer.from_environment)
    return 0


def _request_with_stage(
    state: RuntimeState, payload: Mapping[str, object], timeout_seconds: float
) -> tuple[dict[str, object] | None, str]:
    """Make one authenticated request and return privacy-safe transport status."""

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
            return None, "response_missing"
        response = json.loads(raw.decode("utf-8"))
        if not isinstance(response, Mapping):
            return None, "response_not_object"
        supplied_auth = response.get("auth")
        unsigned_response = {key: value for key, value in response.items() if key != "auth"}
        if not isinstance(supplied_auth, str) or not hmac.compare_digest(
            supplied_auth, _authentication(state.token, unsigned_response)
        ):
            return None, "response_hmac_invalid"
        return dict(response), "ok"
    except TimeoutError:
        return None, "ipc_timeout"
    except UnicodeDecodeError:
        return None, "response_decode_invalid"
    except json.JSONDecodeError:
        return None, "response_json_invalid"
    except OSError:
        return None, "ipc_connection_failed"


def _request(
    state: RuntimeState, payload: Mapping[str, object], timeout_seconds: float
) -> dict[str, object] | None:
    """Make one authenticated request while retaining the established API."""

    response, _stage = _request_with_stage(state, payload, timeout_seconds)
    return response


def _pid_is_alive(pid: int) -> bool:
    """Return liveness only; no process command line or other private data is read."""

    if sys.platform == "win32":
        return _windows_pid_is_alive(pid)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _windows_pid_is_alive(pid: int) -> bool:
    """Query Windows process state without emitting CTRL_C_EVENT (signal zero)."""

    if pid <= 0:
        return False
    process_query_limited_information = 0x1000
    still_active = 259
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        return False
    kernel32 = win_dll("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return False
    try:
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return False
        return exit_code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


def runtime_diagnostics(
    session_id: object,
    *,
    runtime_scope: str = "claude",
    timeout_seconds: float = 0.2,
) -> dict[str, object]:
    """Return metadata-only client/daemon readiness diagnostics.

    This deliberately excludes request bodies and the per-session secret.  It is
    used only in local hook receipts and has no bearing on an enforcement result.
    """

    state_path = state_path_for_session(session_id, runtime_scope=runtime_scope)
    digest = _session_digest(session_id)
    diagnostics: dict[str, object] = {
        "runtime_scope": runtime_scope,
        "provider": runtime_scope,
        "state_file_path": str(state_path) if state_path is not None else None,
        "warming_marker_path": str(_warming_path(state_path)) if state_path is not None else None,
        "session_reference_hash": digest,
        "secret_exists_client_side": False,
        "daemon_pid": None,
        "daemon_alive": False,
        "endpoint_port": None,
        "ready_state_flag": False,
        "daemon_sees_same_session_reference": False,
        "daemon_session_reference_reported": False,
        "health_request_success": False,
        "request_hmac_accepted": False,
        "response_hmac_verified": False,
        "response_parse_success": False,
        "failure_stage": "invalid_session_reference",
    }
    if state_path is None or digest is None:
        return diagnostics
    if not state_path.exists():
        diagnostics["failure_stage"] = (
            "warming" if _warming_path(state_path).exists() else "state_missing"
        )
        return diagnostics
    state = _load_state(state_path, digest)
    if state is None:
        diagnostics["failure_stage"] = "state_invalid_or_session_mismatch"
        return diagnostics
    diagnostics.update(
        {
            "secret_exists_client_side": bool(state.token),
            "daemon_pid": state.pid,
            "daemon_alive": _pid_is_alive(state.pid),
            "endpoint_port": state.port,
        }
    )
    response, stage = _request_with_stage(state, {"operation": "health"}, timeout_seconds)
    diagnostics["failure_stage"] = stage
    if response is None:
        return diagnostics
    diagnostics["request_hmac_accepted"] = True
    diagnostics["response_parse_success"] = True
    diagnostics["response_hmac_verified"] = True
    # A valid signed response proves that the daemon accepted the state-file
    # secret.  That secret is per session, so it is sufficient evidence of the
    # same session even when an already-running older daemon does not yet
    # report its digest in its health payload.
    diagnostics["daemon_sees_same_session_reference"] = True
    response_body = response.get("response")
    if isinstance(response_body, Mapping):
        diagnostics["daemon_session_reference_reported"] = True
        diagnostics["daemon_sees_same_session_reference"] = (
            response_body.get("session_digest") == digest
        )
    diagnostics["health_request_success"] = response.get("ok") is True
    diagnostics["ready_state_flag"] = bool(
        diagnostics["health_request_success"] and diagnostics["daemon_sees_same_session_reference"]
    )
    diagnostics["failure_stage"] = "ready" if diagnostics["ready_state_flag"] else "health_invalid"
    return diagnostics


def _is_healthy(
    state_path: Path,
    session_digest: str,
    *,
    timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
) -> bool:
    state = _load_state(state_path, session_digest)
    if state is None:
        return False
    response = _request(state, {"operation": "health"}, timeout_seconds)
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


def _spawn_windows_daemon(command: list[str]) -> None:
    """Start without any Claude handle or console inheritance on Windows."""

    subprocess.Popen(  # noqa: S603 - fixed module invocation with generated state arguments.
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=(
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        ),
    )


def _spawn_posix_daemon(command: list[str]) -> None:
    """Start in a new POSIX session without inherited Claude handles."""

    subprocess.Popen(  # noqa: S603 - fixed module invocation with generated state arguments.
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )


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
    if os.name == "nt":
        _spawn_windows_daemon(command)
    else:
        _spawn_posix_daemon(command)


def ensure_runtime(
    session_id: object,
    *,
    startup_timeout_seconds: float = _STARTUP_TIMEOUT_SECONDS,
    runtime_scope: str = "claude",
    spawn_daemon: Callable[[Path, bytes, str], None] = _spawn_daemon,
) -> EnsureResult:
    """Ensure this Claude session has one warmed runtime; never load it in a prompt hook."""

    state_path = state_path_for_session(session_id, runtime_scope=runtime_scope)
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
        _write_warming(state_path, digest)
        spawn_daemon(state_path, token, digest)
        deadline = time.monotonic() + startup_timeout_seconds
        while time.monotonic() < deadline:
            if _is_healthy(state_path, digest):
                return EnsureResult(ready=True, started=True)
            time.sleep(0.05)
        _remove_state(state_path, token)
        _remove_warming(state_path)
        return EnsureResult(ready=False, started=True)
    except Exception:
        _remove_warming(state_path)
        return EnsureResult(ready=False, started=False)
    finally:
        _release_start_lock(state_path, lock)


def start_runtime(
    session_id: object,
    *,
    runtime_scope: str = "claude",
    health_timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
    spawn_daemon: Callable[[Path, bytes, str], None] = _spawn_daemon,
) -> EnsureResult:
    """Launch one session daemon without waiting for model warm-up.

    Claude Code must not spend prompt-hook budget loading a contextual model.
    The session hook therefore starts the child and returns immediately. Until
    it publishes a healthy state file, ``inspect_prompt`` fails closed.
    """

    state_path = state_path_for_session(session_id, runtime_scope=runtime_scope)
    digest = _session_digest(session_id)
    if state_path is None or digest is None:
        return EnsureResult(ready=False, started=False)
    if _is_healthy(state_path, digest, timeout_seconds=health_timeout_seconds):
        return EnsureResult(ready=True, started=False)
    lock = _acquire_start_lock(state_path, 1.0)
    if lock is None:
        return EnsureResult(ready=False, started=False)
    try:
        if _is_healthy(state_path, digest, timeout_seconds=health_timeout_seconds):
            return EnsureResult(ready=True, started=False)
        _remove_state(state_path)
        _write_warming(state_path, digest)
        spawn_daemon(state_path, secrets.token_bytes(32), digest)
        return EnsureResult(ready=False, started=True)
    except Exception:
        _remove_warming(state_path)
        return EnsureResult(ready=False, started=False)
    finally:
        _release_start_lock(state_path, lock)


def inspect_prompt(
    session_id: object,
    prompt: object,
    *,
    timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
    runtime_scope: str = "claude",
) -> dict[str, object] | None:
    """Ask a pre-warmed daemon for the existing Claude JSON decision.

    ``None`` means allow.  Any unavailable, malformed, or unauthenticated
    runtime result becomes the normal fail-closed Claude prompt block.
    """

    state_path = state_path_for_session(session_id, runtime_scope=runtime_scope)
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


def inspect_payload_with_stage(
    session_id: object,
    payload: object,
    *,
    timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
    runtime_scope: str = "claude",
    operation: str = "inspect_payload",
) -> tuple[EnforcementOutcome, object | None, str]:
    """Inspect structured text leaves and retain a metadata-only transport stage."""

    state_path = state_path_for_session(session_id, runtime_scope=runtime_scope)
    digest = _session_digest(session_id)
    if state_path is None or digest is None or not isinstance(payload, dict | list):
        return EnforcementOutcome.INTERNAL_FAILURE, None, "invalid_request"
    state = _load_state(state_path, digest)
    if state is None:
        return EnforcementOutcome.INTERNAL_FAILURE, None, "state_missing_or_invalid"
    response, stage = _request_with_stage(
        state, {"operation": operation, "payload": payload}, timeout_seconds
    )
    if response is None or response.get("ok") is not True:
        return EnforcementOutcome.INTERNAL_FAILURE, None, stage
    value = response.get("response")
    if not isinstance(value, Mapping) or not isinstance(value.get("outcome"), str):
        return EnforcementOutcome.INTERNAL_FAILURE, None, "inspection_response_invalid"
    try:
        outcome = EnforcementOutcome(value["outcome"])
    except ValueError:
        return EnforcementOutcome.INTERNAL_FAILURE, None, "inspection_outcome_invalid"
    return outcome, value.get("sanitized_payload"), "ok"


def inspect_payload_with_prepare_outcome_stage(
    session_id: object,
    payload: object,
    *,
    timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
    runtime_scope: str = "claude",
    operation: str = "inspect_payload",
) -> tuple[EnforcementOutcome, PrepareOutcome | None, object | None, str]:
    """Inspect a payload and validate the signed provider-neutral outcome."""

    state_path = state_path_for_session(session_id, runtime_scope=runtime_scope)
    digest = _session_digest(session_id)
    if state_path is None or digest is None or not isinstance(payload, dict | list):
        return EnforcementOutcome.INTERNAL_FAILURE, None, None, "invalid_request"
    state = _load_state(state_path, digest)
    if state is None:
        return EnforcementOutcome.INTERNAL_FAILURE, None, None, "state_missing_or_invalid"
    response, stage = _request_with_stage(
        state, {"operation": operation, "payload": payload}, timeout_seconds
    )
    if response is None or response.get("ok") is not True:
        return EnforcementOutcome.INTERNAL_FAILURE, None, None, stage
    value = response.get("response")
    if (
        not isinstance(value, Mapping)
        or not isinstance(value.get("outcome"), str)
        or not isinstance(value.get("prepare_outcome"), str)
    ):
        return EnforcementOutcome.INTERNAL_FAILURE, None, None, "inspection_response_invalid"
    try:
        outcome = EnforcementOutcome(value["outcome"])
        prepare_outcome = PrepareOutcome(value["prepare_outcome"])
    except ValueError:
        return EnforcementOutcome.INTERNAL_FAILURE, None, None, "inspection_outcome_invalid"
    return outcome, prepare_outcome, value.get("sanitized_payload"), "ok"


def inspect_payload(
    session_id: object,
    payload: object,
    *,
    timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
    runtime_scope: str = "claude",
) -> tuple[EnforcementOutcome, object | None]:
    """Inspect structured text leaves through the warmed authenticated daemon."""

    outcome, sanitized, _stage = inspect_payload_with_stage(
        session_id, payload, timeout_seconds=timeout_seconds, runtime_scope=runtime_scope
    )
    return outcome, sanitized


def inspect_text_outcome_with_stage(
    session_id: object,
    text: object,
    *,
    timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
    runtime_scope: str = "claude",
    operation: str = "inspect_text",
) -> tuple[EnforcementOutcome, str]:
    """Inspect one text field and retain a metadata-only transport stage."""

    state_path = state_path_for_session(session_id, runtime_scope=runtime_scope)
    digest = _session_digest(session_id)
    if state_path is None or digest is None or not isinstance(text, str):
        return EnforcementOutcome.INTERNAL_FAILURE, "invalid_request"
    state = _load_state(state_path, digest)
    if state is None:
        return EnforcementOutcome.INTERNAL_FAILURE, "state_missing_or_invalid"
    response, stage = _request_with_stage(
        state, {"operation": operation, "text": text}, timeout_seconds
    )
    if response is None or response.get("ok") is not True:
        return EnforcementOutcome.INTERNAL_FAILURE, stage
    value = response.get("response")
    if not isinstance(value, Mapping) or not isinstance(value.get("outcome"), str):
        return EnforcementOutcome.INTERNAL_FAILURE, "inspection_response_invalid"
    try:
        return EnforcementOutcome(value["outcome"]), "ok"
    except ValueError:
        return EnforcementOutcome.INTERNAL_FAILURE, "inspection_outcome_invalid"


def inspect_text_outcome(
    session_id: object,
    text: object,
    *,
    timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_SECONDS,
    runtime_scope: str = "claude",
) -> EnforcementOutcome:
    """Inspect one text field only through the warmed authenticated daemon."""

    outcome, _stage = inspect_text_outcome_with_stage(
        session_id, text, timeout_seconds=timeout_seconds, runtime_scope=runtime_scope
    )
    return outcome


def runtime_is_warming(session_id: object, *, runtime_scope: str = "claude") -> bool:
    """Return whether a SessionStart child has published safe warming state."""

    state_path = state_path_for_session(session_id, runtime_scope=runtime_scope)
    digest = _session_digest(session_id)
    if state_path is None or digest is None or _load_state(state_path, digest) is not None:
        return False
    try:
        payload = json.loads(_warming_path(state_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        isinstance(payload, Mapping)
        and payload.get("session_digest") == digest
        and payload.get("status") == "warming"
    )


def shutdown_runtime(session_id: object, *, runtime_scope: str = "claude") -> bool:
    state_path = state_path_for_session(session_id, runtime_scope=runtime_scope)
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
