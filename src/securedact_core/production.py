from __future__ import annotations

from collections.abc import Iterable

from .detectors import ContextualPrivacyDetector, RegexDetector
from .detectors.base import Detector
from .engine import PrivacyEngine
from .model_management import ModelManager

PRODUCTION_DETERMINISTIC_DETECTORS = frozenset({"regex", "contextual_rules"})


def build_production_engine(
    contextual_detectors: Iterable[Detector] = (),
    *,
    require_contextual: bool,
    model_manager: ModelManager | None = None,
) -> PrivacyEngine:
    """Build the one production detector stack used by runtime and release tests."""

    detectors: list[Detector] = [RegexDetector(), ContextualPrivacyDetector()]
    detectors.extend(contextual_detectors)
    return PrivacyEngine(
        detectors,
        require_contextual=require_contextual,
        model_manager=model_manager,
        required_detector_names=PRODUCTION_DETERMINISTIC_DETECTORS,
    )
