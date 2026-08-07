from itertools import permutations

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


def test_merge_is_order_independent_across_every_input_permutation() -> None:
    findings = [
        detection(0, 30, DetectionSource.FLAIR, EntityType.PERSON),
        detection(8, 24, DetectionSource.CREDENTIALS, EntityType.ACCESS_TOKEN),
        detection(35, 45, DetectionSource.REGEX, EntityType.EMAIL),
        detection(45, 50, DetectionSource.CONTEXTUAL, EntityType.ORGANIZATION),
    ]
    expected = merge_detections(findings)

    assert all(merge_detections(list(order)) == expected for order in permutations(findings))


def test_equal_rank_tie_breaks_lexically_and_adjacent_spans_survive() -> None:
    lexical_winner = detection(0, 5, DetectionSource.FLAIR, EntityType.ORGANIZATION)
    lexical_loser = detection(0, 5, DetectionSource.FLAIR, EntityType.PERSON)
    adjacent = detection(5, 10, DetectionSource.FLAIR, EntityType.PERSON)

    assert merge_detections([lexical_loser, adjacent, lexical_winner]) == [
        lexical_winner,
        adjacent,
    ]


def test_sensitive_url_scope_wins_over_decoded_nested_credentials() -> None:
    url = detection(0, 80, DetectionSource.REGEX, EntityType.SENSITIVE_URL_PARAMETER)
    token = detection(30, 55, DetectionSource.CREDENTIALS, EntityType.API_TOKEN)
    email = detection(58, 75, DetectionSource.REGEX, EntityType.EMAIL)

    assert merge_detections([email, token, url]) == [url]
