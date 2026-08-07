from __future__ import annotations

import pytest

from securedact_core import EntityType, RedactionRequest, SecuredactEngine, build_production_engine
from securedact_core.detectors import CredentialsDetector


@pytest.mark.parametrize(
    ("text", "entity_type"),
    [
        (
            "-----BEGIN PRIVATE KEY-----\nSYNTHETICONLY\n-----END PRIVATE KEY-----",
            EntityType.PRIVATE_KEY,
        ),
        ("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", EntityType.API_TOKEN),
        ("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP", EntityType.ACCESS_TOKEN),
        (
            "eyJsyntheticHeader.eyJsyntheticPayload.syntheticSignature123",
            EntityType.ACCESS_TOKEN,
        ),
        (
            "postgresql://synthetic_user:not-a-real-password@db.example.test/app",
            EntityType.UNKNOWN_SECRET,
        ),
        ("Authorization: Bearer syntheticBearerToken123456789", EntityType.ACCESS_TOKEN),
        ("sessionid=syntheticSessionCookie123456", EntityType.SESSION_TOKEN),
        ("OAUTH_CLIENT_SECRET=syntheticClientSecret123456", EntityType.API_TOKEN),
        ("DB_PASSWORD=synthetic-password-only", EntityType.PASSWORD),
    ],
)
def test_representative_synthetic_credentials_are_detected(
    text: str,
    entity_type: EntityType,
) -> None:
    assert entity_type in {item.entity_type for item in CredentialsDetector().detect(text)}


@pytest.mark.parametrize(
    "text",
    [
        "version=1.2.3",
        "hash=0123456789abcdef0123456789abcdef",
        "uuid=123e4567-e89b-12d3-a456-426614174000",
        "API documentation uses YOUR_API_KEY_HERE.",
        "Authorization is discussed without a token.",
    ],
)
def test_common_coding_near_misses_are_not_credentials(text: str) -> None:
    assert CredentialsDetector().detect(text) == []


def test_strict_external_ai_blocks_credentials() -> None:
    engine = SecuredactEngine(build_production_engine(require_contextual=False))
    result = engine.prepare(
        RedactionRequest(text="Authorization: Bearer syntheticBearerToken123456789")
    )

    assert result.status == "blocked"
    assert result.counts == {"access_token": 1}
    assert result.sanitized_text is None


@pytest.mark.parametrize(
    "value",
    [
        "ghp_ABCDEFGHIJ\u200bKLMNOPQRSTUVWXYZ123456",
        "ghp%5FABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
        "ghp&#95;ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
    ],
)
def test_normalized_credentials_map_back_to_the_full_source(value: str) -> None:
    text = f"token={value}"

    detection = next(
        item for item in CredentialsDetector().detect(text) if item.entity_type == EntityType.API_TOKEN
    )

    assert detection.text == value
    assert text[detection.start : detection.end] == value
