from __future__ import annotations

import re
import threading
from collections.abc import Mapping

from ..models import Detection
from .base import Detector

WORD_PATTERN = re.compile(r"[A-Za-zÀ-ÖØ-öø-ÿ]+", re.UNICODE)
ENGLISH_MARKERS = frozenset(
    {
        "a",
        "and",
        "are",
        "at",
        "contact",
        "for",
        "from",
        "has",
        "is",
        "my",
        "of",
        "please",
        "send",
        "the",
        "their",
        "this",
        "to",
        "with",
    }
)
DUTCH_MARKERS = frozenset(
    {
        "aan",
        "de",
        "een",
        "en",
        "heeft",
        "het",
        "is",
        "met",
        "mijn",
        "naar",
        "neem",
        "op",
        "stuur",
        "van",
        "voor",
        "zijn",
    }
)


def detect_local_language(text: str) -> str | None:
    """Return en/nl only when simple local evidence is decisive."""
    words = [match.group(0).casefold() for match in WORD_PATTERN.finditer(text)]
    if not words:
        return None
    english = sum(word in ENGLISH_MARKERS for word in words)
    dutch = sum(word in DUTCH_MARKERS for word in words)
    if any(sequence in text.casefold() for sequence in ("ij", "sch", "oe")):
        dutch += 1
    if english >= 2 and english >= dutch + 1:
        return "en"
    if dutch >= 2 and dutch >= english + 1:
        return "nl"
    return None


class LanguageAwareFlairDetector:
    """Route to a verified local Flair model; uncertain text runs through every model."""

    name = "flair_language_router"
    contextual = True

    def __init__(self, detectors: Mapping[str, Detector]) -> None:
        if not detectors:
            raise ValueError("At least one contextual model is required")
        if not set(detectors).issubset({"en", "nl"}):
            raise ValueError("Unsupported contextual model language")
        self.detectors = dict(detectors)
        self._load_lock = threading.RLock()
        self._load_attempted = False
        self._load_succeeded = False
        self._failure_code: str | None = None

    @property
    def ready(self) -> bool:
        with self._load_lock:
            return self._load_succeeded and all(
                bool(getattr(detector, "ready", False)) for detector in self.detectors.values()
            )

    @property
    def failure_code(self) -> str | None:
        with self._load_lock:
            return self._failure_code

    @property
    def safe_state(self) -> str:
        if self.ready:
            return "ready"
        return "failed" if self.failure_code else "discovered"

    def load(self) -> None:
        with self._load_lock:
            if self._load_succeeded:
                return
            if self._load_attempted:
                raise RuntimeError("One or more contextual models failed to load")
            self._load_attempted = True

            failed = False
            for detector in self.detectors.values():
                loader = getattr(detector, "load", None)
                if loader is None:
                    failed = True
                    continue
                try:
                    loader()
                except Exception:
                    failed = True
                    continue
                if not bool(getattr(detector, "ready", False)):
                    failed = True

            if failed:
                self._failure_code = "contextual_model_load_failed"
                raise RuntimeError("One or more contextual models failed to load")
            self._load_succeeded = True

    def detect(self, text: str) -> list[Detection]:
        self.load()
        if len(self.detectors) == 1:
            selected = tuple(self.detectors.values())
        else:
            language = detect_local_language(text)
            selected = (
                (self.detectors[language],)
                if language in self.detectors
                else tuple(self.detectors.values())
            )
        findings: list[Detection] = []
        for detector in selected:
            findings.extend(detector.detect(text))
        return findings
