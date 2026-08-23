from __future__ import annotations

import os
from collections.abc import Iterable

from .detectors import (
    BardsaiArticle9Detector,
    ContextualPrivacyDetector,
    CredentialsDetector,
    GlinerArticle9Detector,
    RegexDetector,
)
from .detectors.base import Detector
from .detectors.semantic_proposer import BgeM3Article9Proposer
from .engine import PrivacyEngine
from .model_management import ModelManager

PRODUCTION_DETERMINISTIC_DETECTORS = frozenset({"regex", "credentials", "contextual_rules"})


def article9_ml_enabled_from_environment() -> bool:
    """Whether the validated Article 9 ML stack is enabled via config.

    Default off. Opt in per deployment with ``SECUREDACT_ARTICLE9_ML_ENABLED=1``.
    When enabled, the frozen, research-validated Article 9 ML stack is loaded:
    BardsAI + contained GLiNER + the BGE-M3 semantic proposer, layered on top of
    the deterministic/contextual/Flair base detectors. Every ML emission is routed
    fail-closed to REVIEW.
    """

    return os.getenv("SECUREDACT_ARTICLE9_ML_ENABLED") == "1"


def build_production_engine(
    contextual_detectors: Iterable[Detector] = (),
    *,
    require_contextual: bool,
    model_manager: ModelManager | None = None,
    article9_ml_enabled: bool = False,
) -> PrivacyEngine:
    """Build the one production detector stack used by runtime and release tests."""

    detectors: list[Detector] = [
        CredentialsDetector(),
        RegexDetector(),
        ContextualPrivacyDetector(),
    ]
    if article9_ml_enabled:
        detectors.append(BardsaiArticle9Detector())
        detectors.append(GlinerArticle9Detector())
        detectors.append(BgeM3Article9Proposer())
    detectors.extend(contextual_detectors)
    return PrivacyEngine(
        detectors,
        require_contextual=require_contextual,
        model_manager=model_manager,
        required_detector_names=PRODUCTION_DETERMINISTIC_DETECTORS,
    )
