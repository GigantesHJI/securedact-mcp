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


def evaluate_spans(
    expected: list[Span],
    predicted: list[Span],
    *,
    document_is_negative: bool | None = None,
) -> SpanEvaluation:
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
        (truth, guess)
        for truth in expected
        for guess in predicted
        if truth.start == guess.start and truth.end == guess.end
    ]
    category_correct = sum(truth.label == guess.label for truth, guess in span_pairs)
    category_accuracy = category_correct / len(span_pairs) if span_pairs else None
    action_pairs = [
        (expected[index], predicted[predicted_index])
        for index, predicted_index in relaxed_matches
        if expected[index].action is not None
    ]
    action_accuracy = (
        sum(truth.action == guess.action for truth, guess in action_pairs) / len(action_pairs)
        if action_pairs
        else None
    )
    return SpanEvaluation(
        exact=counts(exact_matches),
        relaxed=counts(relaxed_matches),
        category_accuracy=category_accuracy,
        action_accuracy=action_accuracy,
    )
