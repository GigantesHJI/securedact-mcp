import sys
from types import ModuleType

import pytest

from securedact_core.detectors.flair_detector import FlairDetector
from securedact_core.models import EntityType


class Label:
    value = "PER"
    score = 0.73


class Span:
    start_position = 6
    end_position = 16

    def get_label(self, _name: str) -> Label:
        return Label()


class FakeSentence:
    def __init__(self, text: str) -> None:
        self.text = text

    def get_spans(self, _name: str) -> list[Span]:
        return [Span()]


class FakeTagger:
    def predict(self, _sentence: FakeSentence) -> None:
        return None


def test_flair_adapter_maps_tags_confidence_and_character_offsets() -> None:
    detector = FlairDetector("unused")
    detector._tagger = FakeTagger()
    detector._sentence_type = FakeSentence
    text = "Hello Ada Lovelace"
    result = detector.detect(text)[0]
    assert result.entity_type == EntityType.PERSON
    assert result.confidence == 0.73
    assert result.text == "Ada Lovela"
    assert text[result.start : result.end] == result.text


def test_flair_adapter_normalizes_input_and_maps_back_to_source_offsets() -> None:
    class DynamicSpan:
        def __init__(self, start: int, end: int) -> None:
            self.start_position = start
            self.end_position = end

        def get_label(self, _name: str) -> Label:
            return Label()

    class DynamicSentence(FakeSentence):
        def get_spans(self, _name: str) -> list[DynamicSpan]:
            value = "Ada Lovelace"
            if value not in self.text:
                return []
            start = self.text.index(value)
            return [DynamicSpan(start, start + len(value))]

    detector = FlairDetector("unused")
    detector._tagger = FakeTagger()
    detector._sentence_type = DynamicSentence
    text = "Hello Ada%20Lovelace"

    result = detector.detect(text)[0]

    assert result.text == "Ada%20Lovelace"
    assert text[result.start : result.end] == result.text


def _install_fake_flair_modules(
    monkeypatch: pytest.MonkeyPatch,
    sequence_tagger: type,
) -> None:
    flair = ModuleType("flair")
    data = ModuleType("flair.data")
    models = ModuleType("flair.models")
    sequence_module = ModuleType("flair.models.sequence_tagger_model")
    data.Sentence = FakeSentence  # type: ignore[attr-defined]
    sequence_module.SequenceTagger = sequence_tagger  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "flair", flair)
    monkeypatch.setitem(sys.modules, "flair.data", data)
    monkeypatch.setitem(sys.modules, "flair.models", models)
    monkeypatch.setitem(sys.modules, "flair.models.sequence_tagger_model", sequence_module)


def test_flair_detector_load_is_idempotent_and_ready_after_success(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class FakeSequenceTagger:
        calls = 0

        @classmethod
        def load(cls, _path: str) -> FakeTagger:
            cls.calls += 1
            print("third-party model banner")
            print("third-party model diagnostic", file=sys.stderr)
            return FakeTagger()

    _install_fake_flair_modules(monkeypatch, FakeSequenceTagger)
    detector = FlairDetector("C:\\synthetic\\model.bin")

    detector.load()
    detector.load()

    assert detector.ready
    assert detector.failure_code is None
    assert FakeSequenceTagger.calls == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_flair_detector_load_failure_exposes_only_safe_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingSequenceTagger:
        @classmethod
        def load(cls, _path: str) -> FakeTagger:
            raise RuntimeError("private exception with C:\\secret\\model.bin")

    _install_fake_flair_modules(monkeypatch, FailingSequenceTagger)
    detector = FlairDetector("C:\\synthetic\\model.bin")

    with pytest.raises(RuntimeError, match="Flair privacy detector failed to load") as error:
        detector.load()

    assert not detector.ready
    assert detector.safe_state == "failed"
    assert detector.failure_code == "contextual_model_load_failed"
    assert "secret" not in str(error.value).casefold()
