from __future__ import annotations

import threading
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any

from ..models import Detection, DetectionSource, EntityType
from ..normalization import NormalizedText, normalize_for_detection

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

    @property
    def failure_code(self) -> str | None:
        return "contextual_model_load_failed" if self._failed else None

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
                # Flair/Transformers can emit banners while importing/loading.
                # MCP reserves stdout exclusively for protocol frames, and raw
                # dependency exceptions must not reach stderr diagnostics.
                with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                    from flair.data import Sentence
                    from flair.models.sequence_tagger_model import (
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
        normalized = normalize_for_detection(text)
        if normalized.text == text:
            return self._detect_view(text)
        return [
            self._map_to_original(normalized, detection)
            for detection in self._detect_view(normalized.text)
        ]

    def _detect_view(self, text: str) -> list[Detection]:
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

    @staticmethod
    def _map_to_original(view: NormalizedText, detection: Detection) -> Detection:
        start, end = view.original_span(detection.start, detection.end)
        return Detection(
            **detection.model_dump(exclude={"id", "start", "end", "text"}),
            start=start,
            end=end,
            text=view.original[start:end],
        )
