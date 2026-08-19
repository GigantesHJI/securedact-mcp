from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from securedact_core import (
    PrepareStatus,
    RedactionRequest,
    ResponseMode,
    RestorationRequest,
    SecuredactConfigurationError,
    SecuredactEngine,
    build_production_engine,
)
from securedact_core.detectors import RegexDetector


def _engine(*, debug_enabled: bool = False) -> SecuredactEngine:
    return SecuredactEngine(
        build_production_engine(require_contextual=False),
        debug_enabled=debug_enabled,
    )


def test_minimal_prepare_is_approved_and_recursively_leak_free() -> None:
    canary = "alex.canary@example.test"
    result = _engine().prepare(RedactionRequest(text=f"Contact {canary}"))
    payload = result.model_dump(mode="json", exclude_none=True)

    assert payload == {
        "schema_version": "1",
        "status": "ok",
        "outcome": "pseudonymized",
        "policy": "strict_external_ai",
        "policy_version": 1,
        "policy_digest": result.policy_digest,
        "counts": {"email": 1},
        "action_counts": {"pseudonymize": 1},
        "sanitized_text": "Contact [EMAIL_1]",
        "reason_codes": ["automatic_pseudonymization"],
    }
    assert canary not in json.dumps(payload, sort_keys=True)
    assert "mapping" not in json.dumps(payload, sort_keys=True)


def test_blocked_and_review_results_never_contain_approved_output() -> None:
    blocked = _engine().prepare(
        RedactionRequest(text="Authorization: Bearer syntheticTokenValue123456")
    )
    review = _engine().prepare(RedactionRequest(text="Emma is Muslim.", policy="default"))

    assert blocked.status == PrepareStatus.BLOCKED
    assert blocked.reason_codes == ["policy_blocked"]
    assert blocked.sanitized_text is None
    assert review.status == PrepareStatus.REVIEW_REQUIRED
    assert review.sanitized_text is None


def test_review_mode_contains_offsets_but_not_raw_values() -> None:
    canary = "alex.review@example.test"
    result = _engine().prepare(
        RedactionRequest(
            text=f"Contact {canary}",
            response_mode=ResponseMode.REVIEW,
        )
    )
    payload = result.model_dump(mode="json", exclude_none=True)

    assert payload["status"] == "ok"
    assert payload["findings"][0]["entity_type"] == "email"
    assert canary not in json.dumps(payload, sort_keys=True)


def test_debug_requires_process_configuration_not_request_alone() -> None:
    canary = "alex.debug@example.test"
    request = RedactionRequest(text=canary, response_mode=ResponseMode.DEBUG)

    disabled = _engine().prepare(request)
    enabled = _engine(debug_enabled=True).prepare(request)

    assert disabled.status == PrepareStatus.BLOCKED
    assert disabled.reason_codes == ["debug_mode_disabled"]
    assert enabled.status == PrepareStatus.OK
    assert enabled.debug_details is not None
    assert canary not in json.dumps(enabled.debug_details)
    assert enabled.debug_details[0]["decision"] == "pseudonymize"


def test_restore_capable_uses_opaque_single_use_session() -> None:
    canary = "alex.restore@example.test"
    engine = _engine()
    prepared = engine.prepare(
        RedactionRequest(text=canary, response_mode=ResponseMode.RESTORE_CAPABLE)
    )

    assert prepared.restoration_session is not None
    assert canary not in prepared.model_dump_json()
    restored = engine.restore(
        RestorationRequest(
            text=prepared.sanitized_text or "",
            restoration_session=prepared.restoration_session,
        )
    )
    replay = engine.restore(
        RestorationRequest(
            text="[EMAIL_1]",
            restoration_session=prepared.restoration_session,
        )
    )

    assert restored.status == PrepareStatus.OK
    assert restored.restored_text == canary
    assert replay.status == PrepareStatus.BLOCKED
    assert replay.reason_codes == ["restoration_session_consumed"]


def test_public_request_schema_is_strict_and_stable() -> None:
    with pytest.raises(ValidationError):
        RedactionRequest.model_validate({"text": "safe", "unknown": True})
    with pytest.raises(ValidationError):
        RedactionRequest(text="safe", response_mode="unsafe")  # type: ignore[arg-type]

    missing = _engine().prepare(RedactionRequest(text="safe", policy="missing"))
    assert missing.status == PrepareStatus.BLOCKED
    assert missing.reason_codes == ["policy_not_found"]


def test_public_api_supports_detector_dependency_injection() -> None:
    engine = SecuredactEngine.with_detectors([RegexDetector()])
    result = engine.prepare(RedactionRequest(text="alex.injected@example.test"))
    assert result.status == PrepareStatus.OK

    with pytest.raises(SecuredactConfigurationError):
        SecuredactEngine.with_detectors([])
