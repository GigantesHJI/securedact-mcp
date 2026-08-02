from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from securedact_core import build_production_engine
from securedact_core.detectors import RegexDetector
from securedact_core.models import Detection, DetectionSource, EntityType
from securedact_mcp.server import create_server

ADDRESSES = (
    "emma@example.com",
    "emma.devries@example.com",
    "emma+privacy@example.com",
    "first_last@sub.example.org",
    "user-name@example.co.uk",
    "A.B@example.net",
    "x@example.org",
    "a123@example.com",
    "privacy.team@example.org",
    "under_score@example.net",
    "plus+tag@example.com",
    "Mixed.Case@sub.example.com",
    "alpha-beta@example.org",
    "x_y.z+tag@example.net",
    "localpart1234567890@example.com",
    "department-notices@sub.example.com",
    "first.middle.last@example.org",
    "UPPER@EXAMPLE.COM",
    "bounded-local-part-abcdefghijklmnopqrstuvwxyz@example.net",
    "a_b-c+d.e@example.com",
)

POSITIVE_TEMPLATES = (
    "{address}",
    "({address})",
    "Mijn e-mailadres is {address}.",
    "Please contact {address}, thank you.",
)

POSITIVE_CASES = tuple(
    pytest.param(template.format(address=address), address, id=f"email-positive-{index:03d}")
    for index, (address, template) in enumerate(
        (
            item
            for address in ADDRESSES
            for item in ((address, template) for template in POSITIVE_TEMPLATES)
        ),
        start=1,
    )
)

MALFORMED_VALUES = (
    "emma@example",
    "@example.com",
    "emma@",
    "emma example.com",
    "emma..devries@example.com",
    ".emma@example.com",
    "emma.@example.com",
    "emma@example..com",
    "emma@-example.com",
    "emma@example-.com",
    "emma@@example.com",
    "em@ma@example.com",
    "emma@example_com",
    "emma@example.c",
    "emma@example.123",
    "emma@example.com/path",
    "emma@example.com?query=yes",
    "emma@example.com#fragment",
    "emma@example.com:443",
    "https://emma@example.com/path",
    "http://emma@example.org/",
    "ordinary@prose",
    "version-1.2.3@build",
    "social handle @emma",
    "[EMAIL_1]",
)

NEGATIVE_CASES = tuple(
    pytest.param(template.format(value=value), id=f"email-negative-{index:03d}")
    for index, (value, template) in enumerate(
        (
            item
            for value in MALFORMED_VALUES
            for item in ((value, template) for template in ("{value}", "Waarde: {value}."))
        ),
        start=1,
    )
)


def _emails(text: str) -> list[Detection]:
    return [item for item in RegexDetector().detect(text) if item.entity_type == EntityType.EMAIL]


@pytest.mark.parametrize(("text", "address"), POSITIVE_CASES)
def test_email_positive_corpus_matches_only_the_complete_address(text: str, address: str) -> None:
    findings = _emails(text)

    assert [(item.start, item.end, item.text) for item in findings] == [
        (text.index(address), text.index(address) + len(address), address)
    ]


@pytest.mark.parametrize("text", NEGATIVE_CASES)
def test_email_negative_corpus_does_not_return_partial_matches(text: str) -> None:
    assert _emails(text) == []


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('"emma@example.com"', "emma@example.com"),
        ("[emma@example.com]", "emma@example.com"),
        ("emma@example.com;", "emma@example.com"),
        ("emma@example.com,", "emma@example.com"),
        ("één emma@example.com einde", "emma@example.com"),
        ("email=emma@example.com", "emma@example.com"),
        ("contact:emma@example.com", "emma@example.com"),
    ],
)
def test_email_boundaries_exclude_surrounding_text(text: str, expected: str) -> None:
    assert [item.text for item in _emails(text)] == [expected]


def test_multiple_and_repeated_emails_keep_stable_offsets_and_placeholders() -> None:
    text = "emma@example.com\r\nfirst_last@sub.example.org\nemma@example.com"
    engine = build_production_engine(require_contextual=False)

    analysis = engine.analyze(text)
    result = engine.redact(text, analysis=analysis)
    emails = [item for item in analysis.entities if item.entity_type == EntityType.EMAIL]

    assert [item.text for item in emails] == [
        "emma@example.com",
        "first_last@sub.example.org",
        "emma@example.com",
    ]
    assert result.sanitized_text == "[EMAIL_1]\r\n[EMAIL_2]\n[EMAIL_1]"
    assert engine.restore(result.sanitized_text, result.mapping) == text
    residual = engine.scan_residual(text, result, analysis, "default")
    assert residual.safe_to_send
    assert residual.residual_findings == []


class _FlairPersonDetector:
    name = "synthetic_flair"
    contextual = True
    ready = True

    def load(self) -> None:
        return None

    def detect(self, text: str) -> list[Detection]:
        value = "Emma de Vries"
        start = text.index(value)
        return [
            Detection(
                start=start,
                end=start + len(value),
                text=value,
                entity_type=EntityType.PERSON,
                confidence=0.99,
                source=DetectionSource.FLAIR,
                rule="synthetic_flair:PER",
            )
        ]


def test_flair_person_and_deterministic_email_coexist_in_production_stack() -> None:
    text = "Bespreek Emma de Vries via emma@example.com."
    engine = build_production_engine([_FlairPersonDetector()], require_contextual=True)
    engine.startup()

    analysis = engine.analyze(text)
    result = engine.redact(text, analysis=analysis)
    by_type = {item.entity_type: item for item in analysis.entities}

    assert by_type[EntityType.PERSON].text == "Emma de Vries"
    assert by_type[EntityType.PERSON].source == DetectionSource.FLAIR
    assert by_type[EntityType.EMAIL].text == "emma@example.com"
    assert by_type[EntityType.EMAIL].source in {DetectionSource.LABEL, DetectionSource.REGEX}
    assert result.sanitized_text == "Bespreek [PERSON_1] via [EMAIL_1]."
    assert "Emma de Vries" not in result.sanitized_text
    assert "emma@example.com" not in result.sanitized_text


def test_url_userinfo_has_explicit_url_precedence_and_is_not_split_into_email() -> None:
    findings = RegexDetector().detect("https://emma@example.com/path")

    assert [item.entity_type for item in findings] == [EntityType.SENSITIVE_URL_PARAMETER]
    assert not any(item.entity_type == EntityType.EMAIL for item in findings)


@st.composite
def _valid_email_contexts(draw: st.DrawFn) -> tuple[str, str]:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-"
    segment = st.text(alphabet=alphabet, min_size=1, max_size=12)
    local = ".".join(draw(st.lists(segment, min_size=1, max_size=3)))
    domain = draw(st.sampled_from(("example.com", "example.org", "example.net", "sub.example.com")))
    address = f"{local}@{domain}"
    prefix, suffix = draw(
        st.sampled_from((("", ""), ("(", ")"), ("[", "]"), ('"', '"'), ("Contact: ", ".")))
    )
    return f"{prefix}{address}{suffix}", address


@given(_valid_email_contexts())
@settings(max_examples=80, deadline=500)
def test_generated_valid_email_is_fully_detected_redacted_and_locally_restorable(
    case: tuple[str, str],
) -> None:
    text, address = case
    engine = build_production_engine(require_contextual=False)

    findings = _emails(text)
    assert [(item.start, item.end, item.text) for item in findings] == [
        (text.index(address), text.index(address) + len(address), address)
    ]
    analysis = engine.analyze(text)
    redaction = engine.redact(text, analysis=analysis)
    assert address not in redaction.sanitized_text
    assert engine.scan_residual(text, redaction, analysis, "default").safe_to_send
    assert engine.restore(redaction.sanitized_text, redaction.mapping) == text
    assert engine.restore(redaction.sanitized_text, {"[EMAIL_999]": address}) != text


@given(
    st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-",
        min_size=2,
        max_size=24,
    )
)
@settings(max_examples=60, deadline=300)
def test_generated_consecutive_dot_mutation_never_yields_a_partial_email(local: str) -> None:
    split = max(1, len(local) // 2)
    malformed = f"{local[:split]}..{local[split:]}@example.com"
    assert _emails(malformed) == []


def test_positive_and_negative_corpora_meet_release_minimums() -> None:
    assert len(POSITIVE_CASES) >= 75
    assert len(NEGATIVE_CASES) >= 50


@pytest.mark.asyncio
async def test_exact_email_never_reaches_safe_copy_or_human_logs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    text = "Mijn naam is Emma de Vries en mijn e-mailadres is emma@example.com."
    monkeypatch.setenv("SECUREDACT_SAFE_COPY_DIR", str(tmp_path))
    mcp_server = create_server(build_production_engine(require_contextual=False))

    result = await mcp_server._tool_manager._tools["create_safe_copy"].run(
        {"content": text, "filename": "synthetic-safe-copy.txt", "policy": "default"}
    )

    assert result["status"] == "ok"
    output = (tmp_path / "synthetic-safe-copy.txt").read_text(encoding="utf-8")
    assert output == "Mijn naam is [PERSON_1] en mijn e-mailadres is [EMAIL_1]."
    assert "Emma de Vries" not in output
    assert "emma@example.com" not in output
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
