# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
import platform
import statistics
import subprocess
import sys
import time
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from securedact_core import RedactionRequest, SecuredactEngine

from .quality import EvaluationConfigurationError, _engine_for_mode

SYNTHETIC_INPUT = "Contact alex.benchmark@example.test regarding case CASE-882200."


def _package_version() -> str:
    try:
        return version("securedact-mcp")
    except PackageNotFoundError:
        return "uninstalled"


def _file_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _latency_summary(values: list[int]) -> dict[str, float | int]:
    ordered = sorted(values)
    p95_index = min(len(ordered) - 1, max(0, int(0.95 * len(ordered)) - 1))
    return {
        "samples": len(ordered),
        "median_ms": statistics.median(ordered) / 1_000_000,
        "p95_ms": ordered[p95_index] / 1_000_000,
        "min_ms": ordered[0] / 1_000_000,
        "max_ms": ordered[-1] / 1_000_000,
    }


def _process_metrics() -> dict[str, float | int | None]:
    try:
        import psutil
    except ImportError:
        return {
            "steady_state_rss_bytes": None,
            "peak_observed_rss_bytes": None,
            "cpu_percent": None,
        }
    process = psutil.Process()
    memory = process.memory_info().rss
    return {
        "steady_state_rss_bytes": memory,
        "peak_observed_rss_bytes": memory,
        "cpu_percent": process.cpu_percent(interval=None),
    }


def _gpu_metrics() -> dict[str, Any]:
    command = [
        "nvidia-smi",
        "--query-gpu=name,utilization.gpu,memory.used",
        "--format=csv,noheader,nounits",
    ]
    try:
        completed = subprocess.run(  # noqa: S603
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "devices": None}
    if completed.returncode != 0:
        return {"available": False, "devices": None}
    devices: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        fields = [field.strip() for field in line.split(",")]
        if len(fields) != 3:
            continue
        try:
            devices.append(
                {
                    "name": fields[0],
                    "utilization_percent": float(fields[1]),
                    "memory_used_mib": float(fields[2]),
                }
            )
        except ValueError:
            continue
    return {"available": bool(devices), "devices": devices or None}


def cold_worker(mode: str) -> dict[str, Any]:
    started = time.perf_counter_ns()
    privacy_engine, model_identifier = _engine_for_mode(mode)
    initialized = time.perf_counter_ns()
    engine = SecuredactEngine(privacy_engine)
    first_started = time.perf_counter_ns()
    result = engine.prepare(RedactionRequest(text=SYNTHETIC_INPUT, policy="gdpr"))
    finished = time.perf_counter_ns()
    return {
        "model_identifier": model_identifier,
        "process_start_to_initialized_ms": (initialized - started) / 1_000_000,
        "first_inference_ms": (finished - first_started) / 1_000_000,
        "cold_total_ms": (finished - started) / 1_000_000,
        "status": result.status.value,
    }


def _isolated_cold(mode: str) -> dict[str, Any]:
    environment = dict(os.environ)
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "securedact_eval", "_cold_worker", "--mode", mode],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if completed.returncode != 0:
        raise EvaluationConfigurationError("cold_process_failed")
    try:
        payload: dict[str, Any] = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise EvaluationConfigurationError("cold_process_invalid_output") from exc
    return payload


def run_performance_evaluation(
    *,
    mode: str = "deterministic",
    repetitions: int = 20,
    warmups: int = 3,
) -> dict[str, Any]:
    if repetitions < 5 or repetitions > 10_000 or warmups < 0 or warmups > 1000:
        raise EvaluationConfigurationError("performance_repetition_invalid")
    cold = _isolated_cold(mode)
    initialized_started = time.perf_counter_ns()
    privacy_engine, model_identifier = _engine_for_mode(mode)
    initialized_finished = time.perf_counter_ns()
    engine = SecuredactEngine(privacy_engine)
    request = RedactionRequest(text=SYNTHETIC_INPUT, policy="gdpr")
    first_started = time.perf_counter_ns()
    first_result = engine.prepare(request)
    first_finished = time.perf_counter_ns()
    for _ in range(warmups):
        engine.prepare(request)
    latencies: list[int] = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        engine.prepare(request)
        latencies.append(time.perf_counter_ns() - started)

    scaling: dict[str, dict[str, float | int]] = {}
    for label, repeats in (("short", 1), ("medium", 20), ("long", 200)):
        scaling_request = RedactionRequest(
            text=" ".join([SYNTHETIC_INPUT] * repeats),
            policy="gdpr",
        )
        samples: list[int] = []
        for _ in range(5):
            started = time.perf_counter_ns()
            engine.prepare(scaling_request)
            samples.append(time.perf_counter_ns() - started)
        scaling[label] = {
            "characters": len(scaling_request.text),
            **_latency_summary(samples),
        }

    total_seconds = sum(latencies) / 1_000_000_000
    policy = privacy_engine.policies.get("gdpr")
    lock_path = Path(__file__).resolve().parents[2] / "uv.lock"
    return {
        "report_version": "1",
        "mode": mode,
        "definitions": {
            "cold_process": "fresh child process with unloaded models",
            "initialized_cold_request": "engine constructed before any inference",
            "first_inference": "first prediction in the initialized process",
            "warm_inference": "calls after configured warm-up runs",
        },
        "model_identifier": model_identifier,
        "cold_process": cold,
        "model_initialization_ms": (initialized_finished - initialized_started) / 1_000_000,
        "first_inference_ms": (first_finished - first_started) / 1_000_000,
        "first_status": first_result.status.value,
        "warm_inference": _latency_summary(latencies),
        "requests_per_second": repetitions / total_seconds if total_seconds else None,
        "input_scaling": scaling,
        "resources": _process_metrics(),
        "gpu": _gpu_metrics(),
        "methodology": {
            "clock": "time.perf_counter_ns",
            "warmups": warmups,
            "repetitions": repetitions,
            "synthetic_input_only": True,
            "hardware_warning": "Results vary by hardware and are not universal guarantees.",
        },
        "metadata": {
            "tool_version": _package_version(),
            "platform": platform.platform(),
            "machine": platform.machine() or None,
            "processor": platform.processor() or None,
            "python_version": sys.version.split()[0],
            "dependency_lock_digest": _file_digest(lock_path),
            "model_identifier": model_identifier,
            "policy_version": policy.schema_version,
            "policy_digest": policy.digest,
        },
    }
