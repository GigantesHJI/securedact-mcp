from __future__ import annotations

from securedact_core.detectors.language_router import (
    LanguageAwareFlairDetector,
    detect_local_language,
)


class RecordingDetector:
    contextual = True
    ready = True

    def __init__(self, name: str, calls: list[str]) -> None:
        self.name = name
        self.calls = calls
        self.loaded = False

    def load(self) -> None:
        self.loaded = True

    def detect(self, _text: str):
        self.calls.append(self.name)
        return []


def test_local_language_detection_is_conservative() -> None:
    assert detect_local_language("Please send the report to John with this note") == "en"
    assert detect_local_language("Stuur het rapport naar Jan en neem contact op") == "nl"
    assert detect_local_language("Acme 123") is None


def test_both_models_select_english_and_dutch_locally() -> None:
    calls: list[str] = []
    router = LanguageAwareFlairDetector(
        {
            "en": RecordingDetector("english", calls),
            "nl": RecordingDetector("dutch", calls),
        }
    )
    router.load()

    router.detect("Please send the report to John with this note")
    assert calls == ["english"]
    calls.clear()
    router.detect("Stuur het rapport naar Jan en neem contact op")
    assert calls == ["dutch"]


def test_uncertain_language_runs_every_enabled_contextual_model() -> None:
    calls: list[str] = []
    router = LanguageAwareFlairDetector(
        {
            "en": RecordingDetector("english", calls),
            "nl": RecordingDetector("dutch", calls),
        }
    )

    router.detect("Acme 123")

    assert calls == ["english", "dutch"]


def test_single_enabled_model_is_never_silently_skipped() -> None:
    calls: list[str] = []
    router = LanguageAwareFlairDetector({"en": RecordingDetector("english", calls)})

    router.detect("Stuur het rapport naar Jan")

    assert calls == ["english"]
