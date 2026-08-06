# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
import platform
import random
import sys
from dataclasses import dataclass
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from securedact_core import PrivacyEngine, build_production_engine
from securedact_core.detectors import FlairDetector

from .metrics import Metric, Span, SpanEvaluation, evaluate_spans, metric_from_counts
from .models import CorpusFile, CorpusSample


class EvaluationConfigurationError(RuntimeError):
    pass


class AverageMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    precision: float | None
    recall: float | None
    f1: float | None


class SampleResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    split: str
    language: str
    domain: str
    exact: Metric
    relaxed: Metric


class QualityReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    report_version: str = "1"
    mode: str
    sample_count: int
    support_count: int
    exact: Metric
    relaxed: Metric
    micro_average: AverageMetrics
    macro_average: AverageMetrics
    weighted_average: AverageMetrics
    per_entity: dict[str, SpanEvaluation]
    per_language: dict[str, SpanEvaluation]
    per_domain: dict[str, SpanEvaluation]
    per_split: dict[str, SpanEvaluation]
    exact_recall_bootstrap_95: tuple[float, float] | None = None
    sample_results: list[SampleResult]
    metadata: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _LoadedSample:
    split: str
    sample: CorpusSample


def _file_digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def verify_corpus_manifest(root: Path) -> str:
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise EvaluationConfigurationError("corpus_manifest_missing")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvaluationConfigurationError("corpus_manifest_invalid") from exc
    if payload.get("manifest_version") != 1 or not isinstance(payload.get("files"), dict):
        raise EvaluationConfigurationError("corpus_manifest_invalid")
    for relative, expected_digest in sorted(payload["files"].items()):
        if not isinstance(relative, str) or not isinstance(expected_digest, str):
            raise EvaluationConfigurationError("corpus_manifest_invalid")
        path = (root / relative).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError as exc:
            raise EvaluationConfigurationError("corpus_manifest_invalid") from exc
        if not path.is_file() or _file_digest(path) != expected_digest:
            raise EvaluationConfigurationError("corpus_manifest_mismatch")
    return _file_digest(manifest_path)


def load_evaluation_corpus(root: Path) -> tuple[list[_LoadedSample], str]:
    manifest_digest = verify_corpus_manifest(root)
    loaded: list[_LoadedSample] = []
    ids: set[str] = set()
    for path in sorted(root.glob("*.json")):
        if path.name == "manifest.json":
            continue
        try:
            corpus = CorpusFile.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise EvaluationConfigurationError("corpus_schema_invalid") from exc
        for sample in corpus.samples:
            if sample.id in ids:
                raise EvaluationConfigurationError("corpus_duplicate_id")
            ids.add(sample.id)
            loaded.append(_LoadedSample(corpus.split, sample))
    if not loaded:
        raise EvaluationConfigurationError("corpus_empty")
    return loaded, manifest_digest


def _engine_for_mode(mode: str) -> tuple[PrivacyEngine, str]:
    if mode == "deterministic":
        return build_production_engine(require_contextual=False), "deterministic-local-v1"
    if mode != "flair":
        raise EvaluationConfigurationError("evaluation_mode_invalid")
    model_path = os.getenv("SECUREDACT_EVAL_FLAIR_MODEL")
    if not model_path:
        raise EvaluationConfigurationError("flair_model_not_configured")
    detector = FlairDetector(model_path)
    engine = build_production_engine([detector], require_contextual=True)
    engine.startup()
    if not engine.full_ready():
        raise EvaluationConfigurationError("flair_model_unavailable")
    return engine, os.getenv("SECUREDACT_EVAL_MODEL_ID", "configured-flair")


def _spans(sample: CorpusSample) -> list[Span]:
    return [
        Span(
            item.start,
            item.end,
            item.entity_type.value,
            item.expected_action.value if item.expected_action is not None else None,
        )
        for item in sample.entities
    ]


def _aggregate(
    items: list[_LoadedSample],
    predictions: dict[str, list[Span]],
    *,
    label: str | None = None,
) -> SpanEvaluation:
    exact_counts = [0, 0, 0, 0]
    relaxed_counts = [0, 0, 0, 0]
    category_correct = 0.0
    category_total = 0
    action_correct = 0.0
    action_total = 0
    for loaded in items:
        expected = _spans(loaded.sample)
        predicted = predictions[loaded.sample.id]
        if label is not None:
            expected = [item for item in expected if item.label == label]
            predicted = [item for item in predicted if item.label == label]
        evaluation = evaluate_spans(expected, predicted)
        for target, metric in (
            (exact_counts, evaluation.exact),
            (relaxed_counts, evaluation.relaxed),
        ):
            target[0] += metric.true_positives
            target[1] += metric.false_positives
            target[2] += metric.true_negatives
            target[3] += metric.false_negatives
        if evaluation.category_accuracy is not None:
            category_correct += evaluation.category_accuracy
            category_total += 1
        if evaluation.action_accuracy is not None:
            action_correct += evaluation.action_accuracy
            action_total += 1
    return SpanEvaluation(
        exact=metric_from_counts(*exact_counts),
        relaxed=metric_from_counts(*relaxed_counts),
        category_accuracy=category_correct / category_total if category_total else None,
        action_accuracy=action_correct / action_total if action_total else None,
    )


def _averages(per_entity: dict[str, SpanEvaluation]) -> tuple[AverageMetrics, AverageMetrics]:
    supported = [item.exact for item in per_entity.values() if item.exact.support]

    def average(field: str, *, weighted: bool) -> float | None:
        values = [
            (getattr(metric, field), metric.support if weighted else 1)
            for metric in supported
            if getattr(metric, field) is not None
        ]
        denominator = sum(weight for _value, weight in values)
        return (
            sum(float(value) * weight for value, weight in values) / denominator
            if denominator
            else None
        )

    return (
        AverageMetrics(
            precision=average("precision", weighted=False),
            recall=average("recall", weighted=False),
            f1=average("f1", weighted=False),
        ),
        AverageMetrics(
            precision=average("precision", weighted=True),
            recall=average("recall", weighted=True),
            f1=average("f1", weighted=True),
        ),
    )


def _bootstrap_recall(
    samples: list[_LoadedSample],
    predictions: dict[str, list[Span]],
    *,
    repetitions: int = 1000,
) -> tuple[float, float] | None:
    components: list[tuple[int, int]] = []
    for loaded in samples:
        metric = evaluate_spans(_spans(loaded.sample), predictions[loaded.sample.id]).exact
        components.append((metric.true_positives, metric.false_negatives))
    if not sum(tp + fn for tp, fn in components):
        return None
    generator = random.Random(20260806)  # noqa: S311 - reproducible bootstrap seed
    estimates: list[float] = []
    for _ in range(repetitions):
        selected = [generator.choice(components) for _item in components]
        tp = sum(item[0] for item in selected)
        fn = sum(item[1] for item in selected)
        if tp + fn:
            estimates.append(tp / (tp + fn))
    estimates.sort()
    if not estimates:
        return None
    low = estimates[int(0.025 * (len(estimates) - 1))]
    high = estimates[int(0.975 * (len(estimates) - 1))]
    return low, high


def _package_version() -> str:
    try:
        return version("securedact-mcp")
    except PackageNotFoundError:
        return "0.1.0+source"


def run_quality_evaluation(
    root: Path,
    *,
    mode: str = "deterministic",
    engine: PrivacyEngine | None = None,
    model_identifier: str | None = None,
) -> QualityReport:
    samples, manifest_digest = load_evaluation_corpus(root)
    if engine is None:
        engine, resolved_model_identifier = _engine_for_mode(mode)
    else:
        resolved_model_identifier = model_identifier or "injected-test-detector"
    policy = engine.policies.get("gdpr")
    predictions: dict[str, list[Span]] = {}
    sample_results: list[SampleResult] = []
    for loaded in samples:
        analysis = engine.analyze(loaded.sample.text, "gdpr")
        predicted = [
            Span(
                item.start,
                item.end,
                item.entity_type.value,
                item.action.value if item.action is not None else None,
            )
            for item in analysis.entities
        ]
        predictions[loaded.sample.id] = predicted
        result = evaluate_spans(_spans(loaded.sample), predicted)
        sample_results.append(
            SampleResult(
                id=loaded.sample.id,
                split=loaded.split,
                language=loaded.sample.language,
                domain=loaded.sample.domain,
                exact=result.exact,
                relaxed=result.relaxed,
            )
        )

    global_metrics = _aggregate(samples, predictions)
    entity_names = sorted(
        {item.entity_type.value for loaded in samples for item in loaded.sample.entities}
        | {item.label for values in predictions.values() for item in values}
    )
    per_entity = {name: _aggregate(samples, predictions, label=name) for name in entity_names}
    macro, weighted = _averages(per_entity)

    def grouped(attribute: str) -> dict[str, SpanEvaluation]:
        values = sorted(
            {
                loaded.split if attribute == "split" else getattr(loaded.sample, attribute)
                for loaded in samples
            }
        )
        return {
            value: _aggregate(
                [
                    loaded
                    for loaded in samples
                    if (loaded.split if attribute == "split" else getattr(loaded.sample, attribute))
                    == value
                ],
                predictions,
            )
            for value in values
        }

    repository_root = root.parent.parent
    lock_path = repository_root / "uv.lock"
    return QualityReport(
        mode=mode,
        sample_count=len(samples),
        support_count=global_metrics.exact.support,
        exact=global_metrics.exact,
        relaxed=global_metrics.relaxed,
        micro_average=AverageMetrics(
            precision=global_metrics.exact.precision,
            recall=global_metrics.exact.recall,
            f1=global_metrics.exact.f1,
        ),
        macro_average=macro,
        weighted_average=weighted,
        per_entity=per_entity,
        per_language=grouped("language"),
        per_domain=grouped("domain"),
        per_split=grouped("split"),
        exact_recall_bootstrap_95=_bootstrap_recall(samples, predictions),
        sample_results=sorted(sample_results, key=lambda item: item.id),
        metadata={
            "tool_version": _package_version(),
            "policy_version": policy.schema_version,
            "policy_digest": policy.digest,
            "platform": platform.platform(),
            "python_version": sys.version.split()[0],
            "dependency_lock_digest": _file_digest(lock_path) if lock_path.is_file() else None,
            "model_identifier": resolved_model_identifier,
            "corpus_manifest_digest": manifest_digest,
            "evaluation_unit": "character spans; true negatives are document-level negatives",
        },
    )
