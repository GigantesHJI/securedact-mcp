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
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field

from securedact_core import (
    SPECIAL_CATEGORY_TYPES,
    FindingDecision,
    PrivacyAction,
    PrivacyEngine,
    build_production_engine,
)
from securedact_core.detectors import FlairDetector, LanguageAwareFlairDetector

from .benchmark.generator import load_jsonl
from .benchmark.manifest import verify_benchmark
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
    source: str = "legacy-curated"
    tier: str = "public"
    format: str = "plain_text"
    exact: Metric
    relaxed: Metric


class DocumentDecisionMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    unsafe_detection_accuracy: float | None
    block_or_review_accuracy: float | None
    blocked_document_accuracy: float | None
    review_required_accuracy: float | None
    residual_sensitive_value_rate: float | None
    approved_output_leak_rate: float | None
    approved_documents: int
    leaked_approved_documents: int
    audit_failure_count: int
    review_rate: float | None = None
    automatic_pseudonymization_rate: float | None = None
    sensitive_category_block_or_review_rate: float | None = None
    blocked_documents: int = 0
    review_required_documents: int = 0
    automatic_pseudonymized_documents: int = 0
    sensitive_category_documents: int = 0


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
    per_source: dict[str, SpanEvaluation] = Field(default_factory=dict)
    per_tier: dict[str, SpanEvaluation] = Field(default_factory=dict)
    per_format: dict[str, SpanEvaluation] = Field(default_factory=dict)
    per_assertion_type: dict[str, SpanEvaluation] = Field(default_factory=dict)
    per_transformation: dict[str, SpanEvaluation] = Field(default_factory=dict)
    per_mixed: dict[str, SpanEvaluation] = Field(default_factory=dict)
    per_text_length: dict[str, SpanEvaluation] = Field(default_factory=dict)
    document_decisions: DocumentDecisionMetrics | None = None
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
    try:
        raw_manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvaluationConfigurationError("corpus_manifest_invalid") from exc
    if raw_manifest.get("manifest_version") == 2:
        try:
            manifest = verify_benchmark(root)
            samples = load_jsonl(root / "corpus.jsonl")
        except ValueError as exc:
            raise EvaluationConfigurationError(str(exc)) from exc
        if len(samples) != manifest.document_count:
            raise EvaluationConfigurationError("corpus_document_count_mismatch")
        ids = [sample.id for sample in samples]
        if len(ids) != len(set(ids)):
            raise EvaluationConfigurationError("corpus_duplicate_id")
        return [
            _LoadedSample(sample.split or "unspecified", sample) for sample in samples
        ], _file_digest(root / "manifest.json")
    manifest_digest = verify_corpus_manifest(root)
    loaded: list[_LoadedSample] = []
    legacy_ids: set[str] = set()
    for path in sorted(root.glob("*.json")):
        if path.name == "manifest.json":
            continue
        try:
            corpus = CorpusFile.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise EvaluationConfigurationError("corpus_schema_invalid") from exc
        for sample in corpus.samples:
            if sample.id in legacy_ids:
                raise EvaluationConfigurationError("corpus_duplicate_id")
            legacy_ids.add(sample.id)
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
    language_paths = {
        language: path
        for language, path in (
            ("en", os.getenv("SECUREDACT_EVAL_FLAIR_MODEL_EN")),
            ("nl", os.getenv("SECUREDACT_EVAL_FLAIR_MODEL_NL")),
        )
        if path
    }
    if model_path and language_paths:
        raise EvaluationConfigurationError("flair_model_configuration_ambiguous")
    if not model_path and not language_paths:
        raise EvaluationConfigurationError("flair_model_not_configured")
    detector = (
        LanguageAwareFlairDetector(
            {language: FlairDetector(path) for language, path in language_paths.items()}
        )
        if language_paths
        else FlairDetector(cast(str, model_path))
    )
    engine = build_production_engine([detector], require_contextual=True)
    engine.startup()
    if not engine.full_ready():
        raise EvaluationConfigurationError("flair_model_unavailable")
    default_identifier = (
        "configured-flair-en+nl" if set(language_paths) == {"en", "nl"} else "configured-flair"
    )
    return engine, os.getenv("SECUREDACT_EVAL_MODEL_ID", default_identifier)


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
    category_correct = 0
    category_total = 0
    action_correct = 0
    action_total = 0
    duplicate_predictions = 0
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
        category_correct += evaluation.category_correct
        category_total += evaluation.category_total
        action_correct += evaluation.action_correct
        action_total += evaluation.action_total
        duplicate_predictions += evaluation.duplicate_predictions
    return SpanEvaluation(
        exact=metric_from_counts(*exact_counts),
        relaxed=metric_from_counts(*relaxed_counts),
        category_accuracy=category_correct / category_total if category_total else None,
        action_accuracy=action_correct / action_total if action_total else None,
        category_correct=category_correct,
        category_total=category_total,
        action_correct=action_correct,
        action_total=action_total,
        duplicate_predictions=duplicate_predictions,
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
        return "0.1.1+source"


def run_quality_evaluation(
    root: Path,
    *,
    mode: str = "deterministic",
    engine: PrivacyEngine | None = None,
    model_identifier: str | None = None,
    aggregate_only: bool = False,
) -> QualityReport:
    samples, manifest_digest = load_evaluation_corpus(root)
    tiers = {loaded.sample.tier for loaded in samples}
    if len(tiers) > 1:
        raise EvaluationConfigurationError("mixed_benchmark_tiers_forbidden")
    if engine is None:
        engine, resolved_model_identifier = _engine_for_mode(mode)
    else:
        resolved_model_identifier = model_identifier or "injected-test-detector"
    policy = engine.policies.get("gdpr")
    predictions: dict[str, list[Span]] = {}
    sample_results: list[SampleResult] = []
    unsafe_correct = 0
    disposition_correct = 0
    blocked_correct = 0
    review_correct = 0
    residual_values = 0
    expected_values = 0
    approved_documents = 0
    leaked_approved_documents = 0
    audit_failures = 0
    blocked_documents = 0
    review_required_documents = 0
    automatic_pseudonymized_documents = 0
    sensitive_category_documents = 0
    protected_sensitive_documents = 0
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
        expected_unsafe = bool(loaded.sample.entities)
        predicted_unsafe = bool(analysis.entities or analysis.assertions)
        blocked_documents += analysis.blocked
        review_required_documents += analysis.requires_review
        automatic_pseudonymized_documents += any(
            item.decision == FindingDecision.PSEUDONYMIZE for item in analysis.entities
        )
        expected_sensitive = any(
            item.entity_type in SPECIAL_CATEGORY_TYPES for item in loaded.sample.entities
        )
        sensitive_category_documents += expected_sensitive
        protected_sensitive_documents += expected_sensitive and (
            analysis.blocked or analysis.requires_review
        )
        unsafe_correct += expected_unsafe == predicted_unsafe
        disposition = analysis.blocked or analysis.requires_review or predicted_unsafe
        disposition_correct += disposition == expected_unsafe
        expected_blocked = any(
            item.expected_action == PrivacyAction.BLOCK for item in loaded.sample.entities
        )
        expected_review = any(
            item.expected_action == PrivacyAction.REVIEW for item in loaded.sample.entities
        )
        blocked_correct += analysis.blocked == expected_blocked
        review_correct += analysis.requires_review == expected_review
        expected_text = [
            item.text
            for item in loaded.sample.entities
            if item.text and item.expected_action != PrivacyAction.ALLOW
        ]
        expected_values += len(expected_text)
        try:
            audit = engine.audit(loaded.sample.text, "gdpr")
        except ValueError:
            # Unsupported/adversarial records remain in the benchmark. A failure to produce an
            # audited output is a fail-closed aggregate outcome, never an approved output.
            audit_failures += 1
            residual_values += len(expected_text)
            audit = None
        if audit is None:
            leaks = 0
            approved = False
        else:
            leaks = sum(value in audit.sanitized_text for value in expected_text)
            approved = audit.residual_scan.safe_to_send
        residual_values += leaks
        if approved:
            approved_documents += 1
            leaked_approved_documents += bool(leaks)
        if not aggregate_only and loaded.sample.tier != "restricted":
            sample_results.append(
                SampleResult(
                    id=loaded.sample.id,
                    split=loaded.split,
                    language=loaded.sample.language,
                    domain=loaded.sample.domain,
                    source=loaded.sample.source,
                    tier=loaded.sample.tier,
                    format=loaded.sample.format,
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

    def grouped_by(name: str, selector: object) -> dict[str, SpanEvaluation]:
        groups: dict[str, list[_LoadedSample]] = {}
        for loaded in samples:
            value = selector(loaded)  # type: ignore[operator]
            groups.setdefault(str(value), []).append(loaded)
        return {key: _aggregate(values, predictions) for key, values in sorted(groups.items())}

    assertion_types = sorted(
        {entity.assertion_type for loaded in samples for entity in loaded.sample.entities}
    )
    per_assertion: dict[str, SpanEvaluation] = {
        assertion_type: _aggregate(
            [
                loaded
                for loaded in samples
                if any(entity.assertion_type == assertion_type for entity in loaded.sample.entities)
            ],
            predictions,
        )
        for assertion_type in assertion_types
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
        per_source=grouped("source"),
        per_tier=grouped("tier"),
        per_format=grouped("format"),
        per_assertion_type=per_assertion,
        per_transformation=grouped("transformation"),
        per_mixed=grouped_by(
            "mixed",
            lambda loaded: (
                "negative"
                if not loaded.sample.entities
                else "mixed_entities"
                if len({item.entity_type for item in loaded.sample.entities}) > 1
                else "single_entity_type"
            ),
        ),
        per_text_length=grouped_by(
            "text_length",
            lambda loaded: (
                "short"
                if len(loaded.sample.text) < 80
                else "medium"
                if len(loaded.sample.text) < 300
                else "long"
            ),
        ),
        document_decisions=DocumentDecisionMetrics(
            unsafe_detection_accuracy=unsafe_correct / len(samples) if samples else None,
            block_or_review_accuracy=disposition_correct / len(samples) if samples else None,
            blocked_document_accuracy=blocked_correct / len(samples) if samples else None,
            review_required_accuracy=review_correct / len(samples) if samples else None,
            residual_sensitive_value_rate=(
                residual_values / expected_values if expected_values else None
            ),
            approved_output_leak_rate=(
                leaked_approved_documents / approved_documents if approved_documents else None
            ),
            approved_documents=approved_documents,
            leaked_approved_documents=leaked_approved_documents,
            audit_failure_count=audit_failures,
            review_rate=(review_required_documents / len(samples) if samples else None),
            automatic_pseudonymization_rate=(
                automatic_pseudonymized_documents / len(samples) if samples else None
            ),
            sensitive_category_block_or_review_rate=(
                protected_sensitive_documents / sensitive_category_documents
                if sensitive_category_documents
                else None
            ),
            blocked_documents=blocked_documents,
            review_required_documents=review_required_documents,
            automatic_pseudonymized_documents=automatic_pseudonymized_documents,
            sensitive_category_documents=sensitive_category_documents,
        ),
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
            "aggregate_only": aggregate_only,
            "tiers": sorted(tiers),
            "restricted_record_results_suppressed": "restricted" in tiers,
        },
    )
