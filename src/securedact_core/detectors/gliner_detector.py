# SPDX-License-Identifier: Apache-2.0
"""Production contained GLiNER Article 9 detector (optional ML layer).

This promotes the frozen, research-validated GLiNER component of the A9-SOTA-001
architecture into production. It is prompted with the nine fixed Article 9
labels at the frozen threshold (0.5) and emits one detection per extracted
span. It is OPTIONAL (default off) and lazy-loaded: importing this module never
pulls ``gliner``/``torch`` into the runtime, and a missing model fails closed.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import Detection, DetectionSource, EntityType

logger = logging.getLogger(__name__)

# Frozen zero-shot prompts (one per Article 9 category). Mirrors the research
# adapter exactly; these are the labels fed to GLiNER.
GLINER_ART9_PROMPTS: dict[EntityType, str] = {
    EntityType.RACIAL_OR_ETHNIC_ORIGIN: "racial or ethnic origin",
    EntityType.POLITICAL_OPINION: "political opinion or political affiliation",
    EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF: "religious or philosophical belief",
    EntityType.TRADE_UNION_MEMBERSHIP: "trade union membership",
    EntityType.GENETIC_DATA: "genetic data or genetic test result",
    EntityType.BIOMETRIC_DATA: "biometric data",
    EntityType.HEALTH_DATA: "health data, medical condition or disease",
    EntityType.SEX_LIFE: "sex life or sexual activity",
    EntityType.SEXUAL_ORIENTATION: "sexual orientation",
}

_PROMPT_TO_TYPE = {value: key for key, value in GLINER_ART9_PROMPTS.items()}


class GlinerArticle9Detector:
    """Zero-shot GLiNER detector prompted with the nine Article 9 categories."""

    name = "article9_gliner"
    contextual = False

    def __init__(
        self,
        *,
        model_id: str | None = None,
        revision: str | None = None,
        device: str = "cpu",
        threshold: float = 0.5,
        cache_dir: str | None = None,
    ) -> None:
        self.model_id = model_id or "urchade/gliner_multi_pii-v1"
        # Frozen architecture uses the moving "main" revision; the cached snapshot
        # captured at research time is what is resolved offline.
        self.revision = revision or "main"
        self.device = device
        self.threshold = threshold
        self.cache_dir = cache_dir
        self._model = None
        self._failed = False

    def load(self) -> None:
        if self._model is not None:
            return
        if self._failed:
            raise RuntimeError("article9_gliner detector unavailable")
        try:
            from huggingface_hub import snapshot_download

            local = Path(
                snapshot_download(
                    self.model_id,
                    revision=self.revision,
                    cache_dir=self.cache_dir,
                    local_files_only=True,
                    local_dir_use_symlinks=False,
                )
            )
            from gliner import GLiNER

            model = GLiNER.from_pretrained(str(local))
            model.eval()
            self._model = model
        except Exception as exc:
            self._failed = True
            raise RuntimeError("article9_gliner model could not be loaded") from exc

    @property
    def ready(self) -> bool:
        return self._model is not None and not self._failed

    @property
    def failure_code(self) -> str | None:
        return "article9_gliner_load_failed" if self._failed else None

    def detect(self, text: str) -> list[Detection]:
        if self._model is None:
            return []
        prompts = list(GLINER_ART9_PROMPTS.values())
        predictions = self._model.predict_entities(text, prompts, threshold=self.threshold)
        detections: list[Detection] = []
        for prediction in predictions:
            label = prediction.get("label", "")
            entity_type = _PROMPT_TO_TYPE.get(label)
            if entity_type is None:
                continue
            start = int(prediction.get("start", 0))
            end = int(prediction.get("end", 0))
            if start >= end:
                continue
            detections.append(
                Detection(
                    start=start,
                    end=end,
                    text=text[start:end],
                    entity_type=entity_type,
                    confidence=float(prediction.get("score", 0.0)),
                    source=DetectionSource.ML_ARTICLE9,
                    rule="gliner_article9",
                    precedence=40,
                    rationale_code="external_article9_gliner",
                    requires_review=True,
                )
            )
        return detections
