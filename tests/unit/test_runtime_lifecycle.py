from __future__ import annotations

import threading
import time

import pytest

from securedact_core import build_production_engine
from securedact_mcp.runtime_lifecycle import (
    RuntimeLifecycle,
    RuntimeLoadFailure,
    RuntimeState,
)


class _ControlledDetector:
    name = "controlled_contextual"
    contextual = True

    def __init__(self, gate: threading.Event | None = None) -> None:
        self.gate = gate
        self.ready = False
        self.load_calls = 0

    def load(self) -> None:
        self.load_calls += 1
        if self.gate is not None:
            assert self.gate.wait(2.0)
        self.ready = True

    def detect(self, _text: str):
        return []


def test_concurrent_calls_start_only_one_background_load() -> None:
    gate = threading.Event()
    detector = _ControlledDetector(gate)
    engine = build_production_engine([detector], require_contextual=True)
    lifecycle = RuntimeLifecycle(engine, enabled_languages=("en",))
    lifecycle.mark_protocol_ready()
    results: list[dict[str, str] | None] = []

    workers = [
        threading.Thread(target=lambda: results.append(lifecycle.privacy_block()))
        for _ in range(16)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=1.0)

    assert detector.load_calls == 1
    assert lifecycle.snapshot().load_operations == 1
    assert all(
        result and result["failure_code"] == "contextual_model_initializing" for result in results
    )

    gate.set()
    assert lifecycle.wait_until_terminal(2.0)
    assert lifecycle.snapshot().contextual_state == RuntimeState.READY
    assert lifecycle.privacy_block() is None
    assert detector.load_calls == 1


@pytest.mark.parametrize(
    "failure_code",
    [
        "contextual_model_storage_invalid",
        "contextual_model_manifest_invalid",
        "contextual_model_dependency_missing",
        "contextual_model_integrity_failed",
        "contextual_model_load_failed",
    ],
)
def test_safe_loader_failure_classification_is_preserved(failure_code: str) -> None:
    detector = _ControlledDetector()
    engine = build_production_engine([detector], require_contextual=True)

    def fail() -> None:
        raise RuntimeLoadFailure(failure_code, "Safe model readiness failure.")

    lifecycle = RuntimeLifecycle(engine, prepare_loader=fail)
    lifecycle.start_background()

    assert lifecycle.wait_until_terminal(2.0)
    assert lifecycle.privacy_block() == {
        "status": "blocked",
        "failure_code": failure_code,
        "reason": "Safe model readiness failure.",
    }
    assert detector.load_calls == 0


def test_shutdown_signals_and_joins_a_cooperative_loader() -> None:
    gate = threading.Event()
    detector = _ControlledDetector(gate)
    engine = build_production_engine([detector], require_contextual=True)
    lifecycle = RuntimeLifecycle(engine)
    lifecycle.start_background()

    release = threading.Thread(target=lambda: (time.sleep(0.05), gate.set()))
    release.start()
    lifecycle.shutdown(timeout=1.0)
    release.join(timeout=1.0)

    assert lifecycle.snapshot().contextual_state == RuntimeState.SHUTTING_DOWN


def test_debug_diagnostics_are_opt_in_sanitized_and_stderr_only(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    engine = build_production_engine(require_contextual=False)
    lifecycle = RuntimeLifecycle(engine)

    lifecycle.safe_debug_diagnostic()
    assert capsys.readouterr() == ("", "")

    monkeypatch.setenv("SECUREDACT_DEBUG_DIAGNOSTICS", "1")
    lifecycle.safe_debug_diagnostic()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "contextual_state=ready" in captured.err
    assert "failure_code=none" in captured.err
    assert "\\" not in captured.err
