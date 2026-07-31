from securedact_core.merge import merge_detections
from securedact_core.models import Detection, DetectionSource, EntityType


def detection(start: int, end: int, source: DetectionSource, kind: EntityType) -> Detection:
    return Detection(
        start=start,
        end=end,
        text="x" * (end - start),
        entity_type=kind,
        confidence=0.9,
        source=source,
    )


def test_deterministic_detection_wins_over_longer_statistical_span() -> None:
    statistical = detection(0, 20, DetectionSource.FLAIR, EntityType.PERSON)
    deterministic = detection(5, 12, DetectionSource.REGEX, EntityType.EMAIL)
    assert merge_detections([statistical, deterministic]) == [deterministic]


def test_longer_span_wins_within_same_source() -> None:
    short = detection(4, 8, DetectionSource.FLAIR, EntityType.PERSON)
    long = detection(2, 12, DetectionSource.FLAIR, EntityType.ORGANIZATION)
    assert merge_detections([short, long]) == [long]


def test_merge_preserves_order_and_never_returns_overlaps() -> None:
    last = detection(20, 25, DetectionSource.REGEX, EntityType.IPV4)
    first = detection(1, 6, DetectionSource.REGEX, EntityType.EMAIL)
    assert merge_detections([last, first]) == [first, last]
