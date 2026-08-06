from __future__ import annotations

import pytest

from securedact_core import PrivacyEngine, build_production_engine
from securedact_core.models import Detection, DetectionSource, EntityType, PrivacyAction
from securedact_core.production import PRODUCTION_DETERMINISTIC_DETECTORS
from securedact_mcp.runtime_lifecycle import lifecycle_from_server
from securedact_mcp.server import create_server


class _StaticContextualDetector:
    name = "synthetic_contextual"
    contextual = True
    ready = True

    def __init__(self, findings: list[Detection]) -> None:
        self.findings = findings

    def load(self) -> None:
        return None

    def detect(self, _text: str) -> list[Detection]:
        return list(self.findings)


def _detection(
    text: str,
    value: str,
    entity_type: EntityType,
    *,
    source: DetectionSource = DetectionSource.FLAIR,
    start: int | None = None,
    end: int | None = None,
) -> Detection:
    resolved_start = text.index(value) if start is None else start
    resolved_end = resolved_start + len(value) if end is None else end
    return Detection(
        start=resolved_start,
        end=resolved_end,
        text=text[resolved_start:resolved_end],
        entity_type=entity_type,
        confidence=0.99,
        source=source,
        rule="synthetic_contextual",
    )


def test_production_factory_enforces_complete_deterministic_stack() -> None:
    engine = build_production_engine(require_contextual=False)

    assert {item.name for item in engine.detectors if not item.contextual}.issuperset(
        PRODUCTION_DETERMINISTIC_DETECTORS
    )
    assert engine.deterministic_detectors_ready()
    assert engine.full_ready()


@pytest.mark.asyncio
async def test_incomplete_production_stack_never_reports_ready() -> None:
    engine = PrivacyEngine(
        [],
        require_contextual=False,
        required_detector_names=PRODUCTION_DETERMINISTIC_DETECTORS,
    )
    mcp_server = create_server(engine)
    lifecycle = lifecycle_from_server(mcp_server)

    result = await mcp_server._tool_manager._tools["analyze_text"].run(
        {"text": "synthetic input", "policy": "default"}
    )

    assert not engine.full_ready()
    assert lifecycle.snapshot().deterministic_detectors_ready is False
    assert result["status"] == "blocked"
    assert result["reason_codes"] == ["privacy_detector_stack_incomplete"]


def test_exact_duplicate_contextual_email_does_not_duplicate_placeholder() -> None:
    text = "Contact emma@example.com."
    contextual = _StaticContextualDetector([_detection(text, "emma@example.com", EntityType.EMAIL)])
    engine = build_production_engine([contextual], require_contextual=True)
    engine.startup()

    analysis = engine.analyze(text)
    redaction = engine.redact(text, analysis=analysis)
    emails = [item for item in analysis.entities if item.entity_type == EntityType.EMAIL]

    assert len(emails) == 1
    assert emails[0].source in {DetectionSource.LABEL, DetectionSource.REGEX}
    assert redaction.sanitized_text == "Contact [EMAIL_1]."
    assert redaction.entity_counts == {"email": 1}


def test_broader_statistical_overlap_cannot_suppress_deterministic_email() -> None:
    text = "value emma@example.com suffix"
    email_start = text.index("emma@example.com")
    contextual = _StaticContextualDetector(
        [
            _detection(
                text,
                "emma@example.com",
                EntityType.PERSON,
                start=email_start - 2,
                end=email_start + len("emma@example.com") + 2,
            )
        ]
    )
    engine = build_production_engine([contextual], require_contextual=True)
    engine.startup()

    analysis = engine.analyze(text)

    assert [(item.entity_type, item.text) for item in analysis.entities] == [
        (EntityType.EMAIL, "emma@example.com")
    ]


def test_unicode_offsets_sorting_serialization_and_actions_remain_attached() -> None:
    text = "🙂 Mijn naam is Emma de Vries; e-mail: emma@example.com."
    person = _detection(text, "Emma de Vries", EntityType.PERSON)
    engine = build_production_engine(
        [_StaticContextualDetector([person])],
        require_contextual=True,
    )
    engine.startup()

    analysis = engine.analyze(text)
    payload = analysis.model_dump(mode="json")
    entities = analysis.entities

    assert [item.start for item in entities] == sorted(item.start for item in entities)
    assert all(text[item.start : item.end] == item.text for item in entities)
    assert [item["text"] for item in payload["entities"]] == [item.text for item in entities]
    assert next(item for item in entities if item.entity_type == EntityType.EMAIL).action == (
        PrivacyAction.REDACT
    )
    assert next(item for item in entities if item.entity_type == EntityType.PERSON).action == (
        PrivacyAction.REDACT
    )
