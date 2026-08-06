from __future__ import annotations

from securedact_eval.metrics import Span, evaluate_spans, metric_from_counts


def test_exact_and_partial_overlap_are_reported_separately() -> None:
    truth = [Span(2, 10, "person")]
    partial = [Span(4, 10, "person")]
    result = evaluate_spans(truth, partial)

    assert result.exact.true_positives == 0
    assert result.exact.false_positives == 1
    assert result.exact.false_negatives == 1
    assert result.relaxed.true_positives == 1
    assert result.relaxed.false_positives == 0
    assert result.relaxed.false_negatives == 0


def test_duplicate_nested_wrong_label_missing_and_extra_predictions() -> None:
    truth = [Span(0, 10, "person"), Span(20, 30, "email")]
    predictions = [
        Span(0, 10, "organization"),
        Span(0, 10, "person"),
        Span(1, 9, "person"),
        Span(40, 50, "phone"),
    ]
    result = evaluate_spans(truth, predictions)

    assert result.exact.true_positives == 1
    assert result.exact.false_positives == 3
    assert result.exact.false_negatives == 1
    assert result.relaxed.true_positives == 1
    assert result.category_accuracy == 0.5


def test_action_accuracy_uses_matched_annotated_spans() -> None:
    result = evaluate_spans(
        [Span(0, 5, "email", "redact"), Span(8, 12, "person", "review")],
        [Span(0, 5, "email", "redact"), Span(8, 12, "person", "redact")],
    )
    assert result.action_accuracy == 0.5


def test_no_positive_and_zero_division_metrics_are_explicit() -> None:
    result = evaluate_spans([], [])
    assert result.exact.true_negatives == 1
    assert result.exact.precision is None
    assert result.exact.recall is None
    assert result.exact.f1 is None
    assert result.exact.false_positive_rate == 0.0

    counts = metric_from_counts(0, 0, 0, 0)
    assert counts.false_positive_rate is None
    assert counts.false_negative_rate is None
