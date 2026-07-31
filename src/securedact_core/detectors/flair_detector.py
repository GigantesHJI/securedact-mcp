from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..models import Detection, DetectionSource, EntityType

DEFAULT_TAG_MAP: dict[str, EntityType] = {
    "PER": EntityType.PERSON,
    "PERSON": EntityType.PERSON,
    "ORG": EntityType.ORGANIZATION,
    "ORGANIZATION": EntityType.ORGANIZATION,
    "LOC": EntityType.LOCATION,
    "GPE": EntityType.LOCATION,
    "ADDRESS": EntityType.ADDRESS,
    "DATE": EntityType.DATE,
    "MEDICAL": EntityType.MEDICAL,
    "DISEASE": EntityType.MEDICAL,
}


class FlairDetector:
    """Thread-safe Flair adapter. The heavyweight tagger is loaded only once."""

    name = "flair"
    contextual = True

    def __init__(
        self,
        model_path: str | Path,
        *,
        tag_map: dict[str, EntityType] | None = None,
        model_fingerprint: str | None = None,
        on_loading: Callable[[], None] | None = None,
        on_ready: Callable[[], None] | None = None,
        on_failure: Callable[[], None] | None = None,
    ) -> None:
        self.model_path = str(model_path)
        self.tag_map = tag_map or DEFAULT_TAG_MAP
        self.model_fingerprint = model_fingerprint
        self._tagger: Any | None = None
        self._sentence_type: Any | None = None
        self._lock = threading.Lock()
        self._failed = False
        self._on_loading = on_loading
        self._on_ready = on_ready
        self._on_failure = on_failure

    @property
    def loaded(self) -> bool:
        return self._tagger is not None

    @property
    def ready(self) -> bool:
        return self.loaded and not self._failed

    @property
    def safe_state(self) -> str:
        if self.ready:
            return "ready"
        return "failed" if self._failed else "discovered"

    def load(self) -> None:
        if self.loaded:
            return
        with self._lock:
            if self.loaded:
                return
            if self._failed:
                raise RuntimeError("Flair privacy detector is unavailable")
            if self._on_loading:
                self._on_loading()
            try:
                from flair.data import Sentence  # type: ignore[import-not-found]
                from flair.models.sequence_tagger_model import (  # type: ignore[import-not-found]
                    SequenceTagger,
                )

                self._tagger = SequenceTagger.load(self.model_path)
                self._sentence_type = Sentence
            except Exception as exc:
                self._failed = True
                if self._on_failure:
                    self._on_failure()
                raise RuntimeError("Flair privacy detector failed to load") from exc
            if self._on_ready:
                self._on_ready()

    def detect(self, text: str) -> list[Detection]:
        self.load()
        assert self._tagger is not None and self._sentence_type is not None
        sentence = self._sentence_type(text)
        with self._lock:
            self._tagger.predict(sentence)

        detections: list[Detection] = []
        for span in sentence.get_spans("ner"):
            label = span.get_label("ner")
            entity_type = self.tag_map.get(label.value.upper())
            if entity_type is None:
                continue
            start = int(span.start_position)
            end = int(span.end_position)
            detections.append(
                Detection(
                    start=start,
                    end=end,
                    text=text[start:end],
                    entity_type=entity_type,
                    confidence=float(label.score),
                    source=DetectionSource.FLAIR,
                    rule=f"flair:{label.value}",
                )
            )
        return detections
