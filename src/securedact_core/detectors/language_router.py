from __future__ import annotations

import re
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

    @property
    def ready(self) -> bool:
        return all(bool(getattr(detector, "ready", False)) for detector in self.detectors.values())

    def load(self) -> None:
        for detector in self.detectors.values():
            loader = getattr(detector, "load", None)
            if loader is not None:
                loader()

    def detect(self, text: str) -> list[Detection]:
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
