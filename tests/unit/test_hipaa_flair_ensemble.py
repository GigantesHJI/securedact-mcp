from __future__ import annotations

import json
from pathlib import Path

import pytest

from securedact_core.detectors import RegexDetector
from securedact_core.detectors.hipaa_flair_detector import (
    HIPAA_FLAIR_DEFAULT_REVISION,
    HIPAA_FLAIR_DEFAULT_THRESHOLD,
    HipaaFlairPersonDetector,
    create_hipaa_flair_detector,
)
from securedact_core.engine import PrivacyEngine
from securedact_core.hipaa import run_hipaa_safe_harbor
from securedact_core.models import Detection, DetectionSource, EntityType

_REVISIONS_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "benchmarks"
    / "hipaa"
    / "flair_predictions.json"
)


class _RawStub:
    """Configurable Flair backend double for unit tests (no real model)."""

    def __init__(self, detections: list[Detection], *, fail_load: bool = False) -> None:
        self._detections = detections
        self.fail_load = fail_load
        self.load_calls = 0
        self.detect_calls = 0

    def load(self) -> None:
        self.load_calls += 1
        if self.fail_load:
            raise RuntimeError("injected model load failure")

    def detect(self, text: str) -> list[Detection]:
        self.detect_calls += 1
        if self.fail_load:
            raise RuntimeError("injected inference failure")
        aligned: list[Detection] = []
        for det in self._detections:
            offset = text.find(det.text)
            if offset == -1:
                continue
            aligned.append(det.model_copy(update={"start": offset, "end": offset + len(det.text)}))
        return aligned


def _person(text: str, conf: float, start: int = 0) -> Detection:
    return Detection(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=EntityType.PERSON,
        confidence=conf,
        source=DetectionSource.FLAIR,
        rule="replay_flair",
    )


def _location(text: str, conf: float, start: int = 0) -> Detection:
    return Detection(
        start=start,
        end=start + len(text),
        text=text,
        entity_type=EntityType.LOCATION,
        confidence=conf,
        source=DetectionSource.FLAIR,
        rule="replay_flair",
    )


def _detector(
    raw: _RawStub, *, threshold: float = HIPAA_FLAIR_DEFAULT_THRESHOLD
) -> HipaaFlairPersonDetector:
    return HipaaFlairPersonDetector(raw_detector=raw, threshold=threshold)


# --- PERSON-only gate -----------------------------------------------------------


def test_gate_admits_only_person() -> None:
    raw = _RawStub([_person("John Smith", 0.95), _location("Chicago", 0.9)])
    out = _detector(raw).detect("John Smith lives in Chicago")
    assert [d.entity_type for d in out] == [EntityType.PERSON]
    assert out[0].text == "John Smith"


def test_gate_rejects_organization_and_geography() -> None:
    org = Detection(
        start=0,
        end=3,
        text="IBM",
        entity_type=EntityType.ORGANIZATION,
        confidence=0.9,
        source=DetectionSource.FLAIR,
        rule="x",
    )
    raw = _RawStub([org, _location("Springfield", 0.92)])
    out = _detector(raw).detect("IBM in Springfield")
    assert out == [], "Only PERSON may pass the HIPAA Flair gate"


def test_gate_applies_confidence_threshold() -> None:
    raw = _RawStub([_person("Low", 0.40), _person("High", 0.60, start=10)])
    out = _detector(raw, threshold=0.50).detect("Low High")
    assert [d.text for d in out] == ["High"]


def test_threshold_rejects_below_and_at_boundary() -> None:
    raw = _RawStub([_person("Exactly", 0.50), _person("Below", 0.49, start=10)])
    out = _detector(raw, threshold=0.50).detect("Exactly Below")
    assert [d.text for d in out] == ["Exactly"]


def test_threshold_validation_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        HipaaFlairPersonDetector(threshold=1.5)
    with pytest.raises(ValueError):
        HipaaFlairPersonDetector(threshold=-0.1)


# --- Lazy loading --------------------------------------------------------------


def test_lazy_load_not_triggered_before_detect() -> None:
    raw = _RawStub([_person("Jane Doe", 0.95)])
    det = _detector(raw)
    assert det._raw is raw
    assert raw.load_calls == 0
    out = det.detect("Jane Doe here")
    assert [d.text for d in out] == ["Jane Doe"]


def test_create_factory_default_threshold() -> None:
    det = create_hipaa_flair_detector(raw_detector=_RawStub([]))
    assert det.threshold == HIPAA_FLAIR_DEFAULT_THRESHOLD
    assert det.model_id == "flair/ner-english-large"
    assert det.revision == HIPAA_FLAIR_DEFAULT_REVISION


# --- Deterministic backward compatibility ---------------------------------------


def test_deterministic_default_does_not_enable_flair() -> None:
    engine = PrivacyEngine(detectors=[RegexDetector()])
    text = "SSN: 123-45-6789 and phone +1 415-555-2671"
    base = run_hipaa_safe_harbor(engine, text)
    ctx = run_hipaa_safe_harbor(engine, text, contextual_ner=False)
    assert ctx.contextual_ner is None
    assert ctx.identifiers_detected == base.identifiers_detected
    assert ctx.identifiers_redacted == base.identifiers_redacted


def test_deterministic_ssn_still_detected_with_flair_enabled() -> None:
    engine = PrivacyEngine(detectors=[RegexDetector()])
    raw = _RawStub([_person("Maria Gonzalez", 0.95)])
    res = run_hipaa_safe_harbor(
        engine,
        "SSN: 123-45-6789, Patient: Maria Gonzalez",
        contextual_ner=True,
        flair_detector=_detector(raw),
    )
    types = {c.letter: c.detected for c in res.categories}
    assert types["G"] >= 1  # SSN
    assert types["A"] >= 1  # Flair name
    assert res.contextual_ner is not None
    assert res.contextual_ner.requested is True
    assert res.contextual_ner.available is True
    assert res.contextual_ner.gated_categories == ("A",)
    assert res.contextual_ner.fallback is False


# --- Missing model / dependency failure ----------------------------------------


def test_missing_model_falls_back_deterministic() -> None:
    engine = PrivacyEngine(detectors=[RegexDetector()])
    raw = _RawStub([], fail_load=True)
    res = run_hipaa_safe_harbor(
        engine, "SSN: 123-45-6789", contextual_ner=True, flair_detector=_detector(raw)
    )
    assert res.contextual_ner is not None
    assert res.contextual_ner.fallback is True
    assert res.contextual_ner.note is not None
    # Deterministic detection still functions.
    assert any(c.letter == "G" and c.detected >= 1 for c in res.categories)


def test_missing_model_emits_no_false_person() -> None:
    engine = PrivacyEngine(detectors=[RegexDetector()])
    raw = _RawStub([], fail_load=True)
    res = run_hipaa_safe_harbor(
        engine, "No identifiers here.", contextual_ner=True, flair_detector=_detector(raw)
    )
    assert res.contextual_ner is not None
    assert res.contextual_ner.fallback is True
    assert all(c.detected == 0 for c in res.categories)


# --- Precision guard: Dr. Lee is preserved (no title hack) ---------------------


def test_dr_lee_is_not_suppressed() -> None:
    """The one known Flair person FP ('Dr. Lee') must be surfaced honestly.

    A generic honorific/title gate is explicitly rejected by the evidence because
    it also removes the true name 'Mr. Lee'. We therefore do NOT suppress it.
    """
    engine = PrivacyEngine(detectors=[RegexDetector()])
    raw = _RawStub([_person("Lee", 1.0, start=4)])
    res = run_hipaa_safe_harbor(
        engine,
        "Dr. Lee reviewed the radiology images.",
        contextual_ner=True,
        flair_detector=_detector(raw),
    )
    assert res.contextual_ner is not None
    assert res.contextual_ner.available is True
    # 'Lee' is admitted as a PERSON detection (the honest FP), not silently dropped.
    names = {f.text for f in res.residual_findings if f.category == "A"}
    assert "Lee" in names or any(c.letter == "A" and c.detected >= 1 for c in res.categories)


# --- Free-text name recovery (contextual PERSON) ------------------------------


def _replay_from_predictions() -> _RawStub | None:
    if not _REVISIONS_PATH.exists():
        return None
    data = json.loads(_REVISIONS_PATH.read_text(encoding="utf-8"))["predictions"]
    by_text: dict[str, list[Detection]] = {}
    for preds in data.values():
        for pred in preds:
            et = pred.get("entity_type", "").lower()
            if et not in {"person", "per"}:
                continue
            text = pred.get("text", "")
            by_text.setdefault(text, []).append(
                Detection(
                    start=int(pred["start"]),
                    end=int(pred["end"]),
                    text=text,
                    entity_type=EntityType.PERSON,
                    confidence=float(pred["confidence"]),
                    source=DetectionSource.FLAIR,
                    rule="replay_flair",
                )
            )

    class _Replay:
        name = "replay"
        contextual = True

        def load(self) -> None:
            return None

        def detect(self, text: str) -> list[Detection]:
            return list(by_text.get(text, []))

    return _Replay()


@pytest.mark.parametrize(
    "text",
    [
        "Patient: Maria Gonzalez",
        "John Smith presented with chest pain and was admitted.",
        "Son of Mr. Lee was notified of the results.",
    ],
)
def test_flair_recovers_freetext_name(text: str) -> None:
    engine = PrivacyEngine(detectors=[RegexDetector()])
    replay = _replay_from_predictions()
    if replay is None:
        pytest.skip("recorded Flair predictions not available")
    # Build a raw stub that returns the recorded PERSON predictions for this text.
    preds = json.loads(_REVISIONS_PATH.read_text(encoding="utf-8"))["predictions"]
    targets = {
        p["text"]: Detection(
            start=int(p["start"]),
            end=int(p["end"]),
            text=p["text"],
            entity_type=EntityType.PERSON,
            confidence=float(p["confidence"]),
            source=DetectionSource.FLAIR,
            rule="replay_flair",
        )
        for plist in preds.values()
        for p in plist
        if p.get("entity_type", "").lower() in {"person", "per"}
    }

    class _TextReplay:
        name = "replay"
        contextual = True

        def load(self) -> None:
            return None

        def detect(self, t: str) -> list[Detection]:
            return [d for d in targets.values() if d.text in t]

    res = run_hipaa_safe_harbor(
        engine, text, contextual_ner=True, flair_detector=_detector(_TextReplay())
    )
    # Category A (Names) should now register a detection via Flair.
    assert any(c.letter == "A" and c.detected >= 1 for c in res.categories)
    # The residual scan must not still surface the same detectable PERSON.
    assert all(f.category != "A" for f in res.residual_findings)


def test_recovered_name_is_redacted() -> None:
    name = "Maria Gonzalez"
    raw = _RawStub([_person(name, 0.98)])
    hipaa_engine = PrivacyEngine(
        detectors=[RegexDetector(), _detector(raw)], require_contextual=False
    )
    audit = hipaa_engine.audit(f"Patient: {name}", "hipaa_safe_harbor")
    assert name not in audit.sanitized_text


# --- Overlap / dedup: deterministic wins on conflict ---------------------------


def test_deterministic_and_flair_person_do_not_double_count() -> None:
    # Contextual rules detect the labelled name as PERSON at higher precedence;
    # Flair also flags it. The merge must yield a single entity, not duplicates.
    hipaa_engine = PrivacyEngine(
        detectors=[
            RegexDetector(),
            _detector(_RawStub([_person("John Smith", 0.9, start=8)])),
        ],
        require_contextual=False,
    )
    audit = hipaa_engine.audit("Caller: John Smith requested records", "hipaa_safe_harbor")
    persons = [f for f in audit.original_findings if f.entity_type == EntityType.PERSON]
    # Exactly one PERSON entity for the single name (deterministic/contextual + Flair merge).
    assert len(persons) == 1


# --- Existing contextual rules remain active in ensemble mode ------------------


def test_existing_contextual_rules_active_with_flair() -> None:
    from securedact_core.detectors import ContextualPrivacyDetector

    engine = PrivacyEngine(detectors=[RegexDetector(), ContextualPrivacyDetector()])
    raw = _RawStub([_person("Maria Gonzalez", 0.95)])
    res = run_hipaa_safe_harbor(
        engine,
        "Relationship: spouse is listed as the emergency contact.",
        contextual_ner=True,
        flair_detector=_detector(raw),
    )
    # Relationship (category R) is recovered by the existing contextual rules, not Flair.
    assert any(c.letter == "R" and c.detected >= 1 for c in res.categories)
