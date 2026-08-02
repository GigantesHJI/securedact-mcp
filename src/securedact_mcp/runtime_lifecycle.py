from __future__ import annotations

import os
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from securedact_core import PrivacyEngine

INITIALIZING_REASON = (
    "The required contextual model is still loading. "
    "Retry the request manually when the model is ready."
)


class RuntimeState(StrEnum):
    NOT_CONFIGURED = "not_configured"
    VALIDATING = "validating"
    LOADING = "loading"
    READY = "ready"
    FAILED = "failed"
    SHUTTING_DOWN = "shutting_down"


class RuntimeLoadFailure(RuntimeError):
    def __init__(self, failure_code: str, reason: str) -> None:
        super().__init__(reason)
        self.failure_code = failure_code
        self.reason = reason


@dataclass(frozen=True, slots=True)
class RuntimeSnapshot:
    protocol_ready: bool
    deterministic_detectors_ready: bool
    contextual_state: RuntimeState
    enabled_languages: tuple[str, ...]
    language_states: dict[str, str]
    failure_code: str | None
    load_operations: int


class RuntimeLifecycle:
    """Own one synchronized, fail-closed contextual-model load operation."""

    def __init__(
        self,
        engine: PrivacyEngine,
        *,
        enabled_languages: tuple[str, ...] = (),
        initial_error: str | None = None,
        initial_failure_code: str | None = None,
        prepare_loader: Callable[[], None] | None = None,
    ) -> None:
        self.engine = engine
        self.enabled_languages = enabled_languages
        self._initial_error = initial_error
        self._failure_reason = initial_error
        self._failure_code = initial_failure_code
        self._prepare_loader = prepare_loader
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._thread: threading.Thread | None = None
        self._shutdown_requested = False
        self._protocol_ready = False
        self._load_operations = 0
        if initial_error is not None and initial_failure_code in {
            "contextual_model_not_configured",
            "contextual_model_not_installed",
            "contextual_model_not_enabled",
        }:
            self._state = RuntimeState.NOT_CONFIGURED
        elif initial_error is not None:
            self._state = RuntimeState.FAILED
        elif not engine.deterministic_detectors_ready():
            self._state = RuntimeState.FAILED
            self._failure_code = "privacy_detector_stack_incomplete"
            self._failure_reason = (
                "The required deterministic privacy detector stack is incomplete."
            )
        elif not engine.require_contextual:
            self._state = RuntimeState.READY
        else:
            self._state = RuntimeState.VALIDATING

    def mark_protocol_ready(self) -> None:
        with self._lock:
            self._protocol_ready = True

    def start_background(self) -> None:
        with self._lock:
            if self._state in {
                RuntimeState.NOT_CONFIGURED,
                RuntimeState.READY,
                RuntimeState.FAILED,
                RuntimeState.SHUTTING_DOWN,
            }:
                return
            if self._thread is not None:
                return
            self._state = RuntimeState.LOADING
            self._load_operations += 1
            self._thread = threading.Thread(
                target=self._load,
                name="securedact-contextual-loader",
                daemon=True,
            )
            self._thread.start()

    def _load(self) -> None:
        try:
            if self._prepare_loader is not None:
                self._prepare_loader()
            self.engine.startup()
            with self._condition:
                if self._shutdown_requested:
                    self._state = RuntimeState.SHUTTING_DOWN
                elif not self.engine.deterministic_detectors_ready():
                    self._state = RuntimeState.FAILED
                    self._failure_code = "privacy_detector_stack_incomplete"
                    self._failure_reason = (
                        "The required deterministic privacy detector stack is incomplete."
                    )
                elif self.engine.full_ready():
                    self._state = RuntimeState.READY
                    self._failure_code = None
                    self._failure_reason = None
                else:
                    self._state = RuntimeState.FAILED
                    self._failure_code = (
                        self.engine.readiness_failure_code() or "contextual_model_load_failed"
                    )
                    self._failure_reason = "The required contextual model could not be loaded."
                self._condition.notify_all()
        except RuntimeLoadFailure as exc:
            with self._condition:
                self._state = RuntimeState.FAILED
                self._failure_code = exc.failure_code
                self._failure_reason = exc.reason
                self._condition.notify_all()
        except Exception:
            with self._condition:
                self._state = RuntimeState.FAILED
                self._failure_code = "contextual_model_load_failed"
                self._failure_reason = "The required contextual model could not be loaded."
                self._condition.notify_all()

    def wait_until_terminal(self, timeout: float) -> bool:
        with self._condition:
            return self._condition.wait_for(
                lambda: (
                    self._state
                    in {
                        RuntimeState.NOT_CONFIGURED,
                        RuntimeState.READY,
                        RuntimeState.FAILED,
                        RuntimeState.SHUTTING_DOWN,
                    }
                ),
                timeout=timeout,
            )

    def privacy_block(self) -> dict[str, str] | None:
        self.start_background()
        with self._lock:
            if self._state == RuntimeState.READY:
                return None
            if self._state in {RuntimeState.VALIDATING, RuntimeState.LOADING}:
                return {
                    "status": "blocked",
                    "failure_code": "contextual_model_initializing",
                    "reason": INITIALIZING_REASON,
                }
            return {
                "status": "blocked",
                "failure_code": self._failure_code or "contextual_model_load_failed",
                "reason": self._failure_reason or "The privacy runtime is unavailable.",
            }

    def _language_states(self) -> dict[str, str]:
        child_states: dict[str, str] = {}
        for detector in self.engine.detectors:
            children = getattr(detector, "detectors", None)
            if not isinstance(children, dict):
                continue
            for language, child in children.items():
                safe_state = getattr(child, "safe_state", None)
                if safe_state == "ready" or getattr(child, "ready", False):
                    child_states[str(language)] = "ready"
                elif safe_state == "failed":
                    child_states[str(language)] = "failed"
                else:
                    child_states[str(language)] = (
                        "loading" if self._state == RuntimeState.LOADING else "not_configured"
                    )
        return {
            language: child_states.get(
                language,
                "loading" if self._state == RuntimeState.LOADING else self._state.value,
            )
            for language in self.enabled_languages
        }

    def snapshot(self) -> RuntimeSnapshot:
        with self._lock:
            return RuntimeSnapshot(
                protocol_ready=self._protocol_ready,
                deterministic_detectors_ready=self.engine.deterministic_detectors_ready(),
                contextual_state=self._state,
                enabled_languages=self.enabled_languages,
                language_states=self._language_states(),
                failure_code=self._failure_code,
                load_operations=self._load_operations,
            )

    def safe_debug_diagnostic(self) -> None:
        if os.getenv("SECUREDACT_DEBUG_DIAGNOSTICS") != "1":
            return
        snapshot = self.snapshot()
        print(
            "Securedact runtime: "
            f"contextual_state={snapshot.contextual_state.value}; "
            f"failure_code={snapshot.failure_code or 'none'}; "
            f"load_operations={snapshot.load_operations}",
            file=sys.stderr,
        )

    def shutdown(self, timeout: float = 5.0) -> None:
        with self._condition:
            self._shutdown_requested = True
            self._state = RuntimeState.SHUTTING_DOWN
            thread = self._thread
            self._condition.notify_all()
        if thread is not None and thread.is_alive():
            thread.join(timeout=max(0.0, timeout))


def lifecycle_from_server(server: Any) -> RuntimeLifecycle:
    lifecycle = getattr(server, "_securedact_runtime_lifecycle", None)
    if not isinstance(lifecycle, RuntimeLifecycle):
        raise RuntimeError("Securedact runtime lifecycle is not attached")
    return lifecycle
