from __future__ import annotations

import re
import threading
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any

from ..models import Detection, DetectionSource, EntityType
from ..normalization import (
    NormalizedText,
    normalize_for_detection,
    requires_detection_normalization,
)
from .contextual_detector import NAME_PATTERN

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
PUBLIC_ORGANIZATION_CONTEXT = re.compile(
    r"(?:public|publieke|openbare)\s+"
    r"(?:organization|organisation|organisatie|institution|instelling|company|bedrijf)\s+$",
    re.IGNORECASE,
)


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
        if not requires_detection_normalization(text):
            return self._detect_view(text)
        normalized = normalize_for_detection(text)
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
            if entity_type == EntityType.ORGANIZATION and PUBLIC_ORGANIZATION_CONTEXT.search(
                text[max(0, start - 64) : start]
            ):
                continue
            if entity_type == EntityType.PERSON:
                start, end = self._person_boundaries(text, start, end)
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
        return self._deduplicate(detections)

    @staticmethod
    def _person_boundaries(text: str, start: int, end: int) -> tuple[int, int]:
        window_start = max(0, start - 48)
        positions = {
            window_start + match.start()
            for match in re.finditer(r"\b", text[window_start : start + 1])
        }
        candidates = []
        for position in positions:
            match = NAME_PATTERN.match(text, position)
            if match and match.start() <= start < match.end() and end <= match.end():
                candidates.append(match)
        if not candidates:
            return start, end
        match = min(
            candidates,
            key=lambda item: (
                item.start() != start,
                item.end() - item.start(),
            ),
        )
        expanded_start = match.start()
        particle_prefix = re.search(
            r"(?i)(?<!\w)(?:(?:de|den|der|van|von|al|el)\s+){1,3}$",
            text[max(0, expanded_start - 32) : expanded_start],
        )
        if particle_prefix:
            expanded_start = max(0, expanded_start - 32) + particle_prefix.start()
        expanded_end = match.end()
        if match.group(0).casefold().endswith(("'s", "\u2019s")):
            expanded_end -= 2
        return expanded_start, expanded_end

    @staticmethod
    def _deduplicate(detections: list[Detection]) -> list[Detection]:
        output: dict[tuple[int, int, EntityType], Detection] = {}
        for detection in detections:
            key = (detection.start, detection.end, detection.entity_type)
            current = output.get(key)
            if current is None or detection.confidence > current.confidence:
                output[key] = detection
        return list(output.values())

    @staticmethod
    def _map_to_original(view: NormalizedText, detection: Detection) -> Detection:
        start, end = view.original_span(detection.start, detection.end)
        return Detection(
            **detection.model_dump(exclude={"id", "start", "end", "text"}),
            start=start,
            end=end,
            text=view.original[start:end],
        )
