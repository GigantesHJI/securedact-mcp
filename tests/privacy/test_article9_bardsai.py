# SPDX-License-Identifier: Apache-2.0
"""Privacy-suite tests for the optional external Article 9 ML (Bardsai) layer.

Covers the release-critical guarantees from the integration plan: REVIEW bias,
category-aware suppression, merge precedence with supporting-source provenance,
graceful degradation when the model is unavailable, and the feature-flag wiring.
"""

from __future__ import annotations

from securedact_core import PrivacyEngine, build_production_engine
from securedact_core.detectors import (
    BardsaiArticle9Detector,
    ContextualPrivacyDetector,
    CredentialsDetector,
    RegexDetector,
)
from securedact_core.detectors.bardsai_detector import _TokenRun
from securedact_core.merge import merge_detections_with_evidence
from securedact_core.models import (
    Detection,
    DetectionSource,
    EntityType,
    PrivacyAction,
)
from securedact_core.production import PRODUCTION_DETERMINISTIC_DETECTORS


def _stubbed_detector(runs: list[_TokenRun]) -> BardsaiArticle9Detector:
    detector = BardsaiArticle9Detector()
    detector._run_inference = lambda _text: list(runs)  # type: ignore[method-assign]
    return detector


def _engine_with(detector: BardsaiArticle9Detector) -> PrivacyEngine:
    engine = PrivacyEngine(
        [detector],
        require_contextual=False,
        required_detector_names=PRODUCTION_DETERMINISTIC_DETECTORS,
    )
    engine.startup()
    return engine


def test_production_factory_honors_article9_ml_feature_flag() -> None:
    off = build_production_engine(require_contextual=False, article9_ml_enabled=False)
    assert not any(d.name == "article9_ml" for d in off.detectors)

    on = build_production_engine(require_contextual=False, article9_ml_enabled=True)
    assert any(d.name == "article9_ml" for d in on.detectors)


def test_ml_detection_is_surfaced_for_review_not_auto_redacted() -> None:
    detector = _stubbed_detector([_TokenRun(EntityType.RACIAL_OR_ETHNIC_ORIGIN, 8, 20, 0.9)])
    engine = _engine_with(detector)

    analysis = engine.analyze("The patient is Turkish-Dutch and lives here.")

    ml = [e for e in analysis.entities if e.source == DetectionSource.ML_ARTICLE9]
    assert len(ml) == 1
    assert ml[0].entity_type == EntityType.RACIAL_OR_ETHNIC_ORIGIN
    assert ml[0].requires_review is True
    assert ml[0].action == PrivacyAction.REVIEW
    assert analysis.requires_review is True


def test_full_bardsai_additive_coverage_surface_biometric_and_trade_union_for_review() -> None:
    # Frozen A9-SOTA-001 ``bard`` component used the full Bardsai label set and
    # actually emitted biometric_data and trade_union_membership; the older
    # suppression tests were superseded by the frozen 0.4.0 architecture. The
    # detector now adds (union/fallback) those categories to REVIEW, never
    # auto-redacts, and only drops non-Article-9 labels.
    detector = _stubbed_detector(
        [
            _TokenRun(EntityType.BIOMETRIC_DATA, 0, 6, 0.9),
            _TokenRun(EntityType.TRADE_UNION_MEMBERSHIP, 7, 13, 0.9),
            _TokenRun(EntityType.HEALTH_DATA, 14, 21, 0.9),
        ]
    )
    engine = _engine_with(detector)

    analysis = engine.analyze("fingerprint union health diabetes mention.")

    ml_types = {e.entity_type for e in analysis.entities if e.source == DetectionSource.ML_ARTICLE9}
    assert EntityType.BIOMETRIC_DATA in ml_types
    assert EntityType.TRADE_UNION_MEMBERSHIP in ml_types
    assert EntityType.HEALTH_DATA in ml_types


def test_non_article9_labels_never_reach_engine_via_ml() -> None:
    # Even if the model emitted a PER run, detect() drops it (suppression by label).
    detector = _stubbed_detector([_TokenRun(EntityType.PERSON, 0, 4, 0.9)])
    engine = _engine_with(detector)

    analysis = engine.analyze("John went to the clinic.")

    assert not any(e.source == DetectionSource.ML_ARTICLE9 for e in analysis.entities)


def test_merge_prefers_contextual_boundary_but_records_ml_support() -> None:
    contextual = Detection(
        start=0,
        end=12,
        text="Turkish-Dutch",
        entity_type=EntityType.RACIAL_OR_ETHNIC_ORIGIN,
        confidence=0.9,
        source=DetectionSource.CONTEXTUAL,
        rule="special_category_lexicon_v1",
    )
    ml = Detection(
        start=0,
        end=20,
        text="Turkish-Dutch heritage",
        entity_type=EntityType.RACIAL_OR_ETHNIC_ORIGIN,
        confidence=0.85,
        source=DetectionSource.ML_ARTICLE9,
        rule="bardsai_article9_token",
    )

    merged = merge_detections_with_evidence([contextual, ml])

    assert len(merged) == 1
    winner = merged[0]
    assert winner.source == DetectionSource.CONTEXTUAL
    assert winner.start == 0 and winner.end == 12
    assert DetectionSource.ML_ARTICLE9 in winner.supporting_sources


def test_model_unavailable_degrades_gracefully_with_warning() -> None:
    detector = BardsaiArticle9Detector()

    def failing_load() -> None:
        if getattr(detector, "_failed", False):
            raise RuntimeError("article9_ml detector unavailable")
        object.__setattr__(detector, "_failed", True)
        raise RuntimeError("article9_ml model could not be loaded")

    detector.load = failing_load  # type: ignore[method-assign]
    engine = PrivacyEngine(
        [RegexDetector(), CredentialsDetector(), ContextualPrivacyDetector(), detector],
        require_contextual=False,
        required_detector_names=PRODUCTION_DETERMINISTIC_DETECTORS,
    )
    engine.startup()

    assert any("article9_ml detector unavailable" in w for w in engine._startup_warnings)
    # Analysis must still succeed using the remaining stack (no ML findings here,
    # but no exception and a valid result).
    analysis = engine.analyze("The patient is Turkish-Dutch.")
    assert analysis.engine_ready is True
    assert not any(e.source == DetectionSource.ML_ARTICLE9 for e in analysis.entities)


def test_flag_off_means_no_ml_detections_in_default_engine() -> None:
    engine = build_production_engine(require_contextual=False, article9_ml_enabled=False)
    engine.startup()

    analysis = engine.analyze("The patient is Turkish-Dutch and has diabetes.")

    assert not any(e.source == DetectionSource.ML_ARTICLE9 for e in analysis.entities)
