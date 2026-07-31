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
