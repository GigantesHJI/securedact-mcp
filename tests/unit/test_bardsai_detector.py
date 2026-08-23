# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the optional external Article 9 ML detector (Bardsai).

These tests never import torch: the token-assembly logic is exercised with
synthetic predictions, and inference is stubbed via ``_run_inference``.
"""

from __future__ import annotations

import pytest

from securedact_core.detectors.bardsai_detector import (
    BardsaiArticle9Detector,
    _TokenRun,
)
from securedact_core.models import DetectionSource, EntityType


def _probabilities(label_ids: list[int], n_classes: int, score: float = 0.9) -> list[list[float]]:
    return [
        [score if i == label else (1.0 - score) / max(n_classes - 1, 1) for i in range(n_classes)]
        for label in label_ids
    ]


ID2LABEL = {
    0: "O",
    1: "B-ETHNIC_ORIGIN",
    2: "I-ETHNIC_ORIGIN",
    3: "B-HEALTH_DATA",
    4: "B-BIOMETRIC_DATA",
    5: "B-TRADE_UNION_MEMBERSHIP",
    6: "B-POLITICAL_OPINION",
    7: "B-RELIGION_OR_BELIEF",
    8: "B-SEXUAL_ORIENTATION",
    9: "B-PER",
    10: "B-IBAN",
}


def _detector() -> BardsaiArticle9Detector:
    return BardsaiArticle9Detector()


def test_assemble_runs_maps_bio_spans_and_drops_non_article9_labels() -> None:
    detector = _detector()
    text = "AA BB CC DD EE"
    offsets = [(0, 2), (3, 5), (6, 8), (9, 11), (12, 14)]
    word_ids = [0, 1, 2, 3, 4]
    # O, B-ETHNIC..I-ETHNIC, B-PER (dropped), B-HEALTH
    predictions = [0, 1, 2, 9, 3]
    probabilities = _probabilities(predictions, n_classes=11)

    runs = detector._assemble_runs(text, predictions, probabilities, offsets, word_ids, ID2LABEL)

    assert [(r.category, r.start, r.end) for r in runs] == [
        (EntityType.RACIAL_OR_ETHNIC_ORIGIN, 3, 8),
        (EntityType.HEALTH_DATA, 12, 14),
    ]
    # The PER label produced no run (no ordinary PII/NER leakage).
    assert all(r.category in detector.additive_categories for r in runs)


def test_detect_keeps_full_bardsai_additive_coverage_including_biometric_and_trade_union() -> None:
    # Frozen A9-SOTA-001 ``bard`` component used the full Bardsai label set and
    # actually emitted biometric_data (16x) and trade_union_membership (1-2x);
    # the older suppression tests were superseded by the frozen 0.4.0 architecture.
    detector = _detector()
    detector._run_inference = lambda _text: [  # type: ignore[method-assign]
        _TokenRun(EntityType.BIOMETRIC_DATA, 0, 4, 0.9),
        _TokenRun(EntityType.TRADE_UNION_MEMBERSHIP, 5, 9, 0.9),
        _TokenRun(EntityType.RACIAL_OR_ETHNIC_ORIGIN, 10, 20, 0.9),
    ]

    detections = detector.detect("Some text with several entities inside it.")

    types = {d.entity_type for d in detections}
    assert EntityType.BIOMETRIC_DATA in types
    assert EntityType.TRADE_UNION_MEMBERSHIP in types
    assert EntityType.RACIAL_OR_ETHNIC_ORIGIN in types
    assert all(d.source == DetectionSource.ML_ARTICLE9 for d in detections)
    assert all(d.rationale_code == "external_article9_ml_token" for d in detections)


def test_detect_below_threshold_is_dropped() -> None:
    detector = _detector()
    detector._run_inference = lambda _text: [  # type: ignore[method-assign]
        _TokenRun(EntityType.HEALTH_DATA, 0, 7, 0.3)
    ]

    assert detector.detect("diabetes here") == []


def test_detect_assertions_require_a_subject_signal_in_the_sentence() -> None:
    detector = _detector()

    # With a person name present, an assertion is emitted.
    detector._run_inference = lambda _text: [  # type: ignore[method-assign]
        _TokenRun(EntityType.HEALTH_DATA, 16, 23, 0.9)
    ]
    with_subject = detector.detect_assertions("The patient John has diabetes.")

    assert len(with_subject) == 1
    assertion = with_subject[0]
    assert assertion.category == EntityType.HEALTH_DATA
    assert assertion.requires_review is True
    assert assertion.detector == "article9_ml"
    # Evidence spans use sentence bounds, not the token span, so the engine keeps
    # the narrower ML token detection in REVIEW rather than auto-controlling it.
    assert "diabetes" in assertion.evidence_spans[0].text

    # Without a subject signal, no assertion is produced (only a review detection).
    detector._run_inference = lambda _text: [  # type: ignore[method-assign]
        _TokenRun(EntityType.HEALTH_DATA, 11, 18, 0.9)
    ]
    without_subject = detector.detect_assertions("a document mentions diabetes here.")

    assert without_subject == []


def test_load_failure_is_idempotent_and_exposes_safe_failure_code() -> None:
    detector = _detector()

    def failing_load() -> None:
        if getattr(detector, "_failed", False):
            raise RuntimeError("article9_ml detector unavailable")
        object.__setattr__(detector, "_failed", True)
        raise RuntimeError("article9_ml model could not be loaded")

    detector.load = failing_load  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="article9_ml model could not be loaded"):
        detector.load()
    assert detector.failure_code == "article9_ml_load_failed"
    # Second call must re-raise safely without a different internal error.
    with pytest.raises(RuntimeError, match="article9_ml detector unavailable"):
        detector.load()
