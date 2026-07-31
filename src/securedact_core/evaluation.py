from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from pydantic import BaseModel, Field

from .detectors import ContextualPrivacyDetector, RegexDetector
from .engine import PrivacyEngine
from .models import Detection, EntityType


class ExpectedEntity(BaseModel):
    text: str
    type: EntityType


class ExpectedAssertion(BaseModel):
    category: EntityType
    negated: bool


class CorpusFixture(BaseModel):
    id: str
    language: str
    input: str
    expected_entities: list[ExpectedEntity]
    expected_assertions: list[ExpectedAssertion]
    expected_policy_actions: dict[EntityType, str]
    sanitized_must_not_contain: list[str]
    expected_residual_safe: bool
    provider_dispatch: str


class CategoryMetric(BaseModel):
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 1.0
    recall: float = 1.0
    f1: float = 1.0
    exact_span_accuracy: float = 1.0
    partial_span_failures: int = 0


class AssertionMetrics(BaseModel):
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 1.0
    recall: float = 1.0
    subject_linking_accuracy: float = 1.0
    negation_accuracy: float = 1.0
    general_discussion_false_positive_rate: float = 0.0


class EvaluationReport(BaseModel):
    corpus_version: int
    fixture_count: int
    fixture_counts_by_language: dict[str, int]
    fixture_counts_by_category: dict[str, int]
    stage_metrics: dict[str, dict[str, CategoryMetric]]
    assertion_metrics: AssertionMetrics
    classification_confusion_matrix: dict[str, dict[str, int]]
    failed_fixture_ids: list[str] = Field(default_factory=list)


def load_corpus(root: Path) -> list[CorpusFixture]:
    fixtures: list[CorpusFixture] = []
    for path in sorted(root.rglob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("corpus_version") != 1:
            raise ValueError(f"Unsupported privacy corpus version in {path.name}")
        fixtures.extend(CorpusFixture.model_validate(item) for item in payload["fixtures"])
    ids = [fixture.id for fixture in fixtures]
    if len(ids) != len(set(ids)):
        raise ValueError("Privacy corpus fixture IDs must be unique")
    return fixtures


def _metric(
    expected: Counter[tuple[str, EntityType]],
    actual: Counter[tuple[str, EntityType]],
    partial_failures: Counter[EntityType],
) -> dict[str, CategoryMetric]:
    categories = {category for _, category in expected} | {category for _, category in actual}
    output: dict[str, CategoryMetric] = {}
    for category in categories:
        expected_items = Counter(
            {key: count for key, count in expected.items() if key[1] == category}
        )
        actual_items = Counter({key: count for key, count in actual.items() if key[1] == category})
        tp = sum((expected_items & actual_items).values())
        fp = sum((actual_items - expected_items).values())
        fn = sum((expected_items - actual_items).values())
        precision = tp / (tp + fp) if tp + fp else 1.0
        recall = tp / (tp + fn) if tp + fn else 1.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        output[category.value] = CategoryMetric(
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1=f1,
            exact_span_accuracy=recall,
            partial_span_failures=partial_failures[category],
        )
    return output


def _counter(detections: list[Detection]) -> Counter[tuple[str, EntityType]]:
    return Counter((item.text, item.entity_type) for item in detections)


def evaluate_corpus(
    root: Path,
    engine: PrivacyEngine | None = None,
) -> EvaluationReport:
    fixtures = load_corpus(root)
    engine = engine or PrivacyEngine([RegexDetector(), ContextualPrivacyDetector()])
    regex = RegexDetector()
    contextual = ContextualPrivacyDetector()
    expected_all: Counter[tuple[str, EntityType]] = Counter()
    stage_actual: dict[str, Counter[tuple[str, EntityType]]] = {
        "deterministic": Counter(),
        "label_aware": Counter(),
        "contextual": Counter(),
        "merged": Counter(),
        "residual_scan": Counter(),
        "indirect_disclosure_scan": Counter(),
    }
    partial_failures: dict[str, Counter[EntityType]] = defaultdict(Counter)
    confusion: dict[str, Counter[str]] = defaultdict(Counter)
    failed_ids: set[str] = set()
    expected_assertions: Counter[tuple[EntityType, bool]] = Counter()
    actual_assertions: Counter[tuple[EntityType, bool]] = Counter()
    subject_total = 0
    subject_linked = 0
    negation_total = 0
    negation_correct = 0
    negative_fixtures = 0
    negative_assertion_false_positives = 0
    language_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()

    for fixture in fixtures:
        language_counts[fixture.language] += 1
        expected = Counter((item.text, item.type) for item in fixture.expected_entities)
        expected_all.update(expected)
        category_counts.update(item.type.value for item in fixture.expected_entities)
        regex_findings = regex.detect(fixture.input)
        contextual_findings = contextual.detect(fixture.input)
        merged_analysis = engine.analyze(fixture.input, "gdpr_strict")
        merged_findings = merged_analysis.entities
        stage_actual["deterministic"].update(_counter(regex_findings))
        stage_actual["label_aware"].update(
            _counter([item for item in regex_findings if item.source.value == "label"])
        )
        stage_actual["contextual"].update(_counter(contextual_findings))
        stage_actual["merged"].update(_counter(merged_findings))

        actual_by_text = defaultdict(set)
        for finding in merged_findings:
            actual_by_text[finding.text].add(finding.entity_type)
        for expected_item in fixture.expected_entities:
            if (expected_item.text, expected_item.type) not in _counter(merged_findings):
                failed_ids.add(fixture.id)
                for actual_type in actual_by_text.get(expected_item.text, set()):
                    confusion[expected_item.type.value][actual_type.value] += 1

        _, resolved_actions, _ = engine.policies.resolve_actions("gdpr_strict")
        for entity_type, expected_action in fixture.expected_policy_actions.items():
            if resolved_actions[entity_type].value != expected_action:
                failed_ids.add(fixture.id)
        if fixture.provider_dispatch == "block":
            if not merged_analysis.blocked:
                failed_ids.add(fixture.id)
        elif fixture.provider_dispatch == "review":
            if merged_analysis.blocked or not merged_analysis.requires_review:
                failed_ids.add(fixture.id)
        elif fixture.provider_dispatch == "permit":
            if merged_analysis.blocked or merged_analysis.requires_review:
                failed_ids.add(fixture.id)
        else:
            raise ValueError(f"Unsupported provider_dispatch value in fixture {fixture.id}")

        expected_assertions.update(
            (item.category, item.negated) for item in fixture.expected_assertions
        )
        actual_assertions.update(
            (item.category, item.negated) for item in merged_analysis.assertions
        )
        for expected_assertion in fixture.expected_assertions:
            negation_total += 1
            matching = [
                item
                for item in merged_analysis.assertions
                if item.category == expected_assertion.category
            ]
            if matching:
                subject_total += 1
                if matching[0].subject_entity_ids:
                    subject_linked += 1
                if matching[0].negated == expected_assertion.negated:
                    negation_correct += 1
            else:
                failed_ids.add(fixture.id)

        if not fixture.expected_assertions and not fixture.expected_entities:
            negative_fixtures += 1
            if merged_analysis.assertions:
                negative_assertion_false_positives += 1
                failed_ids.add(fixture.id)

        audit = engine.audit(fixture.input, "gdpr_strict")
        stage_actual["residual_scan"].update(_counter(audit.residual_scan.residual_findings))
        if audit.residual_scan.possible_indirect_disclosures:
            for assertion in merged_analysis.assertions:
                stage_actual["indirect_disclosure_scan"][(assertion.id, assertion.category)] += 1
        if audit.residual_scan.safe_to_send != fixture.expected_residual_safe:
            failed_ids.add(fixture.id)
        for forbidden in fixture.sanitized_must_not_contain:
            if forbidden in audit.sanitized_text:
                failed_ids.add(fixture.id)
                for expected_item in fixture.expected_entities:
                    if expected_item.text == forbidden:
                        partial_failures["merged"][expected_item.type] += 1

    assertion_tp = sum((expected_assertions & actual_assertions).values())
    assertion_fp = sum((actual_assertions - expected_assertions).values())
    assertion_fn = sum((expected_assertions - actual_assertions).values())
    assertion_precision = (
        assertion_tp / (assertion_tp + assertion_fp) if assertion_tp + assertion_fp else 1.0
    )
    assertion_recall = (
        assertion_tp / (assertion_tp + assertion_fn) if assertion_tp + assertion_fn else 1.0
    )

    stage_metrics = {
        stage: _metric(
            expected_all,
            actual,
            partial_failures[stage],
        )
        for stage, actual in stage_actual.items()
    }
    return EvaluationReport(
        corpus_version=1,
        fixture_count=len(fixtures),
        fixture_counts_by_language=dict(language_counts),
        fixture_counts_by_category=dict(category_counts),
        stage_metrics=stage_metrics,
        assertion_metrics=AssertionMetrics(
            true_positives=assertion_tp,
            false_positives=assertion_fp,
            false_negatives=assertion_fn,
            precision=assertion_precision,
            recall=assertion_recall,
            subject_linking_accuracy=subject_linked / subject_total if subject_total else 1.0,
            negation_accuracy=negation_correct / negation_total if negation_total else 1.0,
            general_discussion_false_positive_rate=(
                negative_assertion_false_positives / negative_fixtures if negative_fixtures else 0.0
            ),
        ),
        classification_confusion_matrix={
            expected: dict(values) for expected, values in confusion.items()
        },
        failed_fixture_ids=sorted(failed_ids),
    )
