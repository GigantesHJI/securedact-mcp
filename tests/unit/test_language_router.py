from __future__ import annotations

from securedact_core.detectors.language_router import (
    LanguageAwareFlairDetector,
    detect_local_language,
)


class RecordingDetector:
    contextual = True

    def __init__(self, name: str, calls: list[str], *, fail_load: bool = False) -> None:
        self.name = name
        self.calls = calls
        self.ready = False
        self.load_calls = 0
        self.fail_load = fail_load

    def load(self) -> None:
        self.load_calls += 1
        if self.fail_load:
            raise RuntimeError("synthetic child load failure with a private path")
        self.ready = True

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

    assert router.ready

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

    assert router.ready
    assert calls == ["english", "dutch"]


def test_single_enabled_model_is_never_silently_skipped() -> None:
    calls: list[str] = []
    router = LanguageAwareFlairDetector({"en": RecordingDetector("english", calls)})

    router.detect("Stuur het rapport naar Jan")

    assert router.ready
    assert calls == ["english"]


def test_load_initializes_every_child_exactly_once() -> None:
    calls: list[str] = []
    english = RecordingDetector("english", calls)
    dutch = RecordingDetector("dutch", calls)
    router = LanguageAwareFlairDetector({"en": english, "nl": dutch})

    assert not router.ready
    router.load()
    router.load()
    router.detect("Acme 123")

    assert router.ready
    assert english.load_calls == 1
    assert dutch.load_calls == 1


def test_one_child_failure_loads_all_children_once_and_fails_closed() -> None:
    calls: list[str] = []
    english = RecordingDetector("english", calls, fail_load=True)
    dutch = RecordingDetector("dutch", calls)
    router = LanguageAwareFlairDetector({"en": english, "nl": dutch})

    try:
        router.load()
    except RuntimeError as exc:
        assert str(exc) == "One or more contextual models failed to load"
    else:  # pragma: no cover - explicit assertion message
        raise AssertionError("router load must fail closed")

    assert not router.ready
    assert english.load_calls == 1
    assert dutch.load_calls == 1
    assert router.failure_code == "contextual_model_load_failed"

    try:
        router.load()
    except RuntimeError:
        pass
    else:  # pragma: no cover - explicit assertion message
        raise AssertionError("failed router must remain unavailable")
    assert english.load_calls == 1
    assert dutch.load_calls == 1
