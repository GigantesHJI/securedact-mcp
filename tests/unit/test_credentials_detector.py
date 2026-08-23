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
        item
        for item in CredentialsDetector().detect(text)
        if item.entity_type == EntityType.API_TOKEN
    )

    assert detection.text == value
    assert text[detection.start : detection.end] == value


# --- FW-002: generic / unknown-secret detector ---------------------------------


@pytest.mark.parametrize(
    ("text", "label"),
    [
        ('secret = "X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12"', "bare secret assignment"),
        ('{"auth_token": "X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12"}', "JSON secret"),
        ("access_key: X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12", "YAML secret"),
        ("INTERNAL_API_SECRET=X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12", "dotenv secret"),
        ("INTERNAL_TOKEN=X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12", "dotenv token"),
        ('credential = "X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12"', "generic password"),
        ('"server_secret": "AbCd1234EfGh5678IjKl9012MnOp3456"', "quoted JSON secret"),
        ("signing_key = 'QwErTy1234AsDfGh5678ZxCvBn9012MpLk'", "single-quoted secret"),
    ],
)
def test_unknown_secret_context_detected(text: str, label: str) -> None:
    detections = CredentialsDetector().detect(text)
    secrets = [d for d in detections if d.entity_type == EntityType.UNKNOWN_SECRET]
    assert secrets, f"expected an unknown secret for: {label}"
    # Span precision: only the value, not the label, is flagged.
    for secret in secrets:
        assert text[secret.start : secret.end] == secret.text
        assert secret.text not in ("", label)


@pytest.mark.parametrize(
    "text",
    [
        'uuid = "550e8400-e29b-41d4-a716-446655440000"',
        'sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
        'commit = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
        'integrity = "sha512-'
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"',
        "API_KEY=your-api-key-here",
        "TOKEN=<token>",
        'request_id = "X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12"',
        "ssh-ed25519 AAAA3NzA1k2examplekeyexamplekeyexamplekeyexamplekeyexamplekey==",
        'example_secret = "changeme"',
        "DB_HOST=db.example.test",
        'trace_id = "9f8e7d6c5b4a39281706"',
    ],
)
def test_benign_high_entropy_not_flagged_as_unknown_secret(text: str) -> None:
    detections = CredentialsDetector().detect(text)
    assert EntityType.UNKNOWN_SECRET not in {d.entity_type for d in detections}


def test_placeholder_values_not_flagged() -> None:
    for value in (
        "your-api-key-here",
        "YOUR_TOKEN_HERE",
        "example-secret",
        "changeme",
        "replace-me",
        "xxxxxxxx",
    ):
        text = f'secret = "{value}"'
        detections = CredentialsDetector().detect(text)
        assert EntityType.UNKNOWN_SECRET not in {d.entity_type for d in detections}, value


def test_lockfile_style_entries_not_flagged() -> None:
    text = """
    "dependencies": {
      "left-pad": "1.3.0",
      "integrity": "sha512-abcdef0123456789abcdef0123456789abcdef0123456789=="
    },
    "resolved": "https://registry.example.test/left-pad/-/left-pad-1.3.0.tgz"
    """
    detections = CredentialsDetector().detect(text)
    assert EntityType.UNKNOWN_SECRET not in {d.entity_type for d in detections}


def test_mixed_content_only_secret_flagged() -> None:
    text = (
        "request_id = 9f8e7d6c5b4a39281706\n"
        "file_hash = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        'secret = "X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12"\n'
        "print('normal source code')\n"
    )
    detections = CredentialsDetector().detect(text)
    secrets = [d for d in detections if d.entity_type == EntityType.UNKNOWN_SECRET]
    assert len(secrets) == 1
    assert secrets[0].text == "X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12"
    assert "9f8e7d6c5b4a39281706" not in {d.text for d in detections}
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" not in {
        d.text for d in detections
    }


def test_unknown_secret_blocks_through_engine_pipeline() -> None:
    engine = SecuredactEngine(build_production_engine(require_contextual=False))
    result = engine.prepare(RedactionRequest(text='secret = "X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12"'))
    assert result.status == "blocked"
    assert result.counts.get("unknown_secret", 0) >= 1


def test_known_labelled_secret_not_downgraded() -> None:
    # Precise labelled-secret rules keep their entity type; FW-002 is a fallback.
    for text, entity_type in (
        ('api_token = "X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12"', EntityType.API_TOKEN),
        ('access_token = "X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12"', EntityType.API_TOKEN),
        ('client_secret = "X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12"', EntityType.API_TOKEN),
        ('password = "X9fs82kLwQ7pM3vR8cN2tZ5yabcDEF12"', EntityType.PASSWORD),
    ):
        detections = CredentialsDetector().detect(text)
        types = {d.entity_type for d in detections}
        assert entity_type in types, f"missing {entity_type} for {text}"
        assert EntityType.UNKNOWN_SECRET not in types, f"downgraded {text}"
