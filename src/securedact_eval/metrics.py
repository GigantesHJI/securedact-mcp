# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict


@dataclass(frozen=True, slots=True)
class Span:
    start: int
    end: int
    label: str
    action: str | None = None

    def overlaps(self, other: Span) -> bool:
        return self.start < other.end and other.start < self.end

    def overlap_length(self, other: Span) -> int:
        return max(0, min(self.end, other.end) - max(self.start, other.start))


class Metric(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float | None
    recall: float | None
    f1: float | None
    false_positive_rate: float | None
    false_negative_rate: float | None
    support: int


class SpanEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    exact: Metric
    relaxed: Metric
    category_accuracy: float | None
    action_accuracy: float | None
    category_correct: int = 0
    category_total: int = 0
    action_correct: int = 0
    action_total: int = 0
    duplicate_predictions: int = 0


def metric_from_counts(tp: int, fp: int, tn: int, fn: int) -> Metric:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return Metric(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=fp / (fp + tn) if fp + tn else None,
        false_negative_rate=fn / (tp + fn) if tp + fn else None,
        support=tp + fn,
    )


def _match(
    expected: list[Span],
    predicted: list[Span],
    *,
    relaxed: bool,
) -> list[tuple[int, int]]:
    candidates: list[tuple[int, int, int, int]] = []
    for expected_index, truth in enumerate(expected):
        for predicted_index, guess in enumerate(predicted):
            if truth.label != guess.label:
                continue
            exact = truth.start == guess.start and truth.end == guess.end
            if not exact and (not relaxed or not truth.overlaps(guess)):
                continue
            candidates.append(
                (
                    0 if exact else 1,
                    -truth.overlap_length(guess),
                    expected_index,
                    predicted_index,
                )
            )
    used_expected: set[int] = set()
    used_predicted: set[int] = set()
    matches: list[tuple[int, int]] = []
    for _exact_rank, _overlap_rank, expected_index, predicted_index in sorted(candidates):
        if expected_index in used_expected or predicted_index in used_predicted:
            continue
        used_expected.add(expected_index)
        used_predicted.add(predicted_index)
        matches.append((expected_index, predicted_index))
    return matches


def _deduplicate(predicted: list[Span]) -> tuple[list[Span], int]:
    """Remove byte-for-byte equivalent detector outputs before scoring.

    Multiple detector stages can emit the same resolved span. That is useful diagnostic
    information, but it must not turn one prediction into a false positive.
    """

    unique: list[Span] = []
    seen: set[Span] = set()
    for guess in predicted:
        if guess in seen:
            continue
        seen.add(guess)
        unique.append(guess)
    return unique, len(predicted) - len(unique)


def _category_matches(expected: list[Span], predicted: list[Span]) -> list[tuple[int, int]]:
    """Pair overlapping spans without using category as a matching condition."""

    candidates: list[tuple[int, int, int, int, int]] = []
    for expected_index, truth in enumerate(expected):
        for predicted_index, guess in enumerate(predicted):
            if not truth.overlaps(guess):
                continue
            exact = truth.start == guess.start and truth.end == guess.end
            candidates.append(
                (
                    0 if exact else 1,
                    0 if truth.label == guess.label else 1,
                    -truth.overlap_length(guess),
                    expected_index,
                    predicted_index,
                )
            )
    used_expected: set[int] = set()
    used_predicted: set[int] = set()
    matches: list[tuple[int, int]] = []
    for _exact, _category, _overlap, expected_index, predicted_index in sorted(candidates):
        if expected_index in used_expected or predicted_index in used_predicted:
            continue
        used_expected.add(expected_index)
        used_predicted.add(predicted_index)
        matches.append((expected_index, predicted_index))
    return matches


def evaluate_spans(
    expected: list[Span],
    predicted: list[Span],
    *,
    document_is_negative: bool | None = None,
) -> SpanEvaluation:
    predicted, duplicate_predictions = _deduplicate(predicted)
    negative = not expected if document_is_negative is None else document_is_negative
    exact_matches = _match(expected, predicted, relaxed=False)
    relaxed_matches = _match(expected, predicted, relaxed=True)

    def counts(matches: list[tuple[int, int]]) -> Metric:
        tp = len(matches)
        fp = len(predicted) - tp
        fn = len(expected) - tp
        tn = 1 if negative and not predicted else 0
        return metric_from_counts(tp, fp, tn, fn)

    span_pairs = [
        (expected[index], predicted[predicted_index])
        for index, predicted_index in _category_matches(expected, predicted)
    ]
    category_correct = sum(truth.label == guess.label for truth, guess in span_pairs)
    category_accuracy = category_correct / len(span_pairs) if span_pairs else None
    action_pairs = [
        (expected[index], predicted[predicted_index])
        for index, predicted_index in relaxed_matches
        if expected[index].action is not None
    ]
    action_correct = sum(truth.action == guess.action for truth, guess in action_pairs)
    action_accuracy = action_correct / len(action_pairs) if action_pairs else None
    return SpanEvaluation(
        exact=counts(exact_matches),
        relaxed=counts(relaxed_matches),
        category_accuracy=category_accuracy,
        action_accuracy=action_accuracy,
        category_correct=category_correct,
        category_total=len(span_pairs),
        action_correct=action_correct,
        action_total=len(action_pairs),
        duplicate_predictions=duplicate_predictions,
    )
