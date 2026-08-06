# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .quality import QualityReport


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    threshold_version: int = 1
    mode: str
    allowed_recall_regression: float = Field(ge=0.0, le=1.0)
    allowed_false_positive_rate_increase: float = Field(ge=0.0, le=1.0)
    minimum_global_recall: float = Field(ge=0.0, le=1.0)
    minimum_high_risk_recall: float = Field(ge=0.0, le=1.0)
    maximum_false_positive_rate: float = Field(ge=0.0, le=1.0)
    minimum_mode_recall: dict[str, float]
    minimum_language_recall: dict[str, float]
    minimum_domain_recall: float = Field(ge=0.0, le=1.0)
    high_risk_entities: list[str]
    latency_ceiling_ms: float = Field(gt=0.0)
    notes: str


class GateResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    passed: bool
    failures: list[str]


def load_thresholds(path: Path) -> Thresholds:
    return Thresholds.model_validate(json.loads(path.read_text(encoding="utf-8")))


def evaluate_quality_gate(
    report: QualityReport,
    thresholds: Thresholds,
    baseline: QualityReport | None = None,
) -> GateResult:
    failures: list[str] = []
    recall = report.exact.recall
    false_positive_rate = report.exact.false_positive_rate
    if recall is None or recall < thresholds.minimum_global_recall:
        failures.append("global_recall_below_minimum")
    mode_minimum = thresholds.minimum_mode_recall.get(report.mode)
    if mode_minimum is not None and (recall is None or recall < mode_minimum):
        failures.append("mode_recall_below_minimum")
    if false_positive_rate is None or false_positive_rate > thresholds.maximum_false_positive_rate:
        failures.append("false_positive_rate_above_maximum")

    for name in thresholds.high_risk_entities:
        metric = report.per_entity.get(name)
        if metric is None or not metric.exact.support:
            continue
        if metric.exact.recall is None or metric.exact.recall < thresholds.minimum_high_risk_recall:
            failures.append(f"high_risk_recall_below_minimum:{name}")
    for language, minimum in thresholds.minimum_language_recall.items():
        metric = report.per_language.get(language)
        if metric is None or metric.exact.recall is None or metric.exact.recall < minimum:
            failures.append(f"language_recall_below_minimum:{language}")
    for domain, metric in report.per_domain.items():
        if metric.exact.support and (
            metric.exact.recall is None or metric.exact.recall < thresholds.minimum_domain_recall
        ):
            failures.append(f"domain_recall_below_minimum:{domain}")

    if baseline is not None:
        baseline_recall = baseline.exact.recall
        if baseline_recall is not None and (
            recall is None or recall < baseline_recall - thresholds.allowed_recall_regression
        ):
            failures.append("recall_regressed_from_baseline")
        baseline_fpr = baseline.exact.false_positive_rate
        if baseline_fpr is not None and (
            false_positive_rate is None
            or false_positive_rate > baseline_fpr + thresholds.allowed_false_positive_rate_increase
        ):
            failures.append("false_positive_rate_regressed_from_baseline")
    failures = sorted(set(failures))
    return GateResult(passed=not failures, failures=failures)


def evaluate_performance_gate(
    report: dict[str, Any],
    thresholds: Thresholds,
) -> GateResult:
    """Apply only the broad, hardware-tolerant warm-latency release ceiling."""

    failures: list[str] = []
    if report.get("first_status") != "ok":
        failures.append("first_inference_failed")
    cold = report.get("cold_process")
    if not isinstance(cold, dict) or cold.get("status") != "ok":
        failures.append("cold_process_failed")
    warm = report.get("warm_inference")
    p95 = warm.get("p95_ms") if isinstance(warm, dict) else None
    if not isinstance(p95, (int, float)):
        failures.append("warm_p95_unavailable")
    elif p95 > thresholds.latency_ceiling_ms:
        failures.append("warm_p95_above_ceiling")
    return GateResult(passed=not failures, failures=sorted(set(failures)))
