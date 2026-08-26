# SPDX-License-Identifier: Apache-2.0
"""Privacy-safe result reduction and validation (AGENT-011 / CP-500-D).

This module is the single choke point that turns local :class:`ScanResult`
objects (which never leave the machine) into the closed-vocabulary, content-free
summary the control plane accepts. It enforces the safe-result contract
(§21/§22/§23/§24): only allowlisted fields, only allowlisted category labels,
closed enums, bounded counts, and the fail-closed rule for ``failed`` results.
Any attempt to smuggle content-bearing fields or unknown categories is rejected.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from securedact_core.connectors.scan import (
    ScanErrorCode,
    ScanResult,
    ScanSeverity,
    ScanStatus,
)

MAX_RESULT_PAYLOAD_BYTES = 8192

# Closed vocabulary of control-plane-safe category labels (mirrors the web
# SAFE_CATEGORY_LABELS so the agent can never introduce a new category).
SAFE_CATEGORY_LABELS = frozenset(
    {
        "address",
        "email",
        "iban",
        "credit_card",
        "person",
        "phone",
        "relationship",
        "organization",
        "bsn",
        "kvk",
        "date",
        "location",
        "other",
        "ip",
        "ner",
        "secret",
        "special_category",
    }
)

# Allowlisted safe error codes (§21).
SAFE_ERROR_CODES = frozenset(
    {
        "connector_unavailable",
        "resource_not_found",
        "auth_required",
        "policy_invalid",
        "engine_unavailable_local",
        "temporary_network_error",
        "agent_execution_error",
        "unsupported_target",
        "cancelled",
        "lease_invalid",
        "result_invalid",
        "internal_error",
    }
)

SEVERITY_LEVELS = frozenset({"none", "low", "medium", "high"})
POLICY_DECISIONS = frozenset({"allow", "review", "redact", "block"})
SUPPORTED_ACTIONS = frozenset({"none", "review", "redact", "block"})

# Content-bearing field names that must never appear in a result payload (§22).
_DENIED_RESULT_FIELDS = frozenset(
    {
        "text",
        "content",
        "raw_text",
        "matches",
        "samples",
        "snippets",
        "name",
        "email",
        "phone",
        "iban",
        "iban_value",
        "raw_findings",
        "document",
    }
)

_ALLOWED_RESULT_FIELDS = frozenset(
    {
        "status",
        "severity",
        "categories",
        "counts",
        "review_required",
        "policy_decision",
        "supported_action",
        "warnings",
        "safe_error_code",
        "resources_scanned",
        "duration_ms",
        "policy_version_id",
        "policy_digest",
    }
)

# Entity type (upper-cased) -> safe category label. Keys are the canonical
# securedact_core.models.EntityType values so the reducer maps exactly what the
# engine emits. Anything not listed falls back to "other" (a closed label).
_ENTITY_LABEL: dict[str, str] = {
    "PERSON": "person",
    "ORGANIZATION": "organization",
    "ORGANISATION": "organization",
    "LOCATION": "location",
    "ADDRESS": "address",
    "STREET_ADDRESS": "address",
    "HOUSE_NUMBER": "address",
    "COUNTRY": "address",
    "POSTCODE": "address",
    "US_ZIP": "address",
    "DATE": "date",
    "DATE_OF_BIRTH": "date",
    "AGE": "date",
    "TIME": "date",
    "APPOINTMENT": "date",
    "EMAIL": "email",
    "PHONE": "phone",
    "FAX": "phone",
    "BSN": "bsn",
    "IBAN": "iban",
    "CREDIT_CARD_NUMBER": "credit_card",
    "CREDIT_CARD": "credit_card",
    "RELATIONSHIP": "relationship",
    "UNKNOWN_SECRET": "secret",
    "CREDENTIALS": "secret",
    "SESSION_TOKEN": "secret",
    "API_TOKEN": "secret",
    "ACCESS_TOKEN": "secret",
    "PASSWORD": "secret",
    "PRIVATE_KEY": "secret",
    "RACIAL_OR_ETHNIC_ORIGIN": "special_category",
    "POLITICAL_OPINION": "special_category",
    "RELIGIOUS_OR_PHILOSOPHICAL_BELIEF": "special_category",
    "TRADE_UNION_MEMBERSHIP": "special_category",
    "GENETIC_DATA": "special_category",
    "BIOMETRIC_DATA": "special_category",
    "HEALTH_DATA": "special_category",
    "SEX_LIFE": "special_category",
    "SEXUAL_ORIENTATION": "special_category",
    "SPECIAL_CATEGORY_CONTEXT": "special_category",
}

_SPECIAL_OR_SECRET_LABELS = frozenset({"secret", "special_category"})

_SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
_DECISION_RANK = {"allow": 1, "redact": 2, "review": 3, "block": 4}
_ACTION_RANK = {"none": 1, "review": 2, "redact": 3, "block": 4}


def label_for_entity(entity_type: str) -> str:
    """Map a core entity type to a control-plane-safe category label."""

    return _ENTITY_LABEL.get(entity_type.upper(), "other")


def _severity_label(sev: ScanSeverity) -> str:
    return {
        ScanSeverity.NONE: "none",
        ScanSeverity.LOW: "low",
        ScanSeverity.MEDIUM: "medium",
        ScanSeverity.HIGH: "high",
    }[sev]


@dataclass(slots=True)
class ExecutionResult:
    """A reduced, privacy-safe job outcome ready for the control plane."""

    status: str  # "succeeded" | "failed"
    severity: str
    categories: list[str]
    counts: dict[str, int]
    review_required: bool
    policy_decision: str
    supported_action: str
    safe_error_code: str | None
    resources_scanned: int
    duration_ms: int
    policy_version_id: str | None
    policy_digest: str | None


def _map_scan_error(error: ScanErrorCode | None) -> str:
    if error is None:
        return "agent_execution_error"
    return {
        ScanErrorCode.UNSUPPORTED_FORMAT: "unsupported_target",
        ScanErrorCode.RETRIEVAL_FAILED: "resource_not_found",
        ScanErrorCode.UNAUTHORIZED: "auth_required",
        ScanErrorCode.ENGINE_UNAVAILABLE: "engine_unavailable_local",
        ScanErrorCode.TIMEOUT: "temporary_network_error",
        ScanErrorCode.RATE_LIMITED: "temporary_network_error",
    }.get(error, "agent_execution_error")


def _per_file_decision(status: ScanStatus, result: ScanResult) -> tuple[str, str]:
    if status == ScanStatus.BLOCKED:
        return "block", "block"
    if status == ScanStatus.REVIEW_REQUIRED:
        return "review", "review"
    if result.supported_action == "redact":
        return "redact", "redact"
    return "allow", "none"


def reduce_scan_results(
    results: list[ScanResult],
    *,
    policy_version_id: str | None,
    policy_digest: str | None,
    resources_scanned: int,
    duration_ms: int,
    safe_error_code: str | None = None,
) -> ExecutionResult:
    """Reduce local scan results into a single privacy-safe job outcome."""

    aggregated_counts: dict[str, int] = {}
    categories: set[str] = set()
    severity_rank = 0
    decision_rank = 1  # allow
    action_rank = 1  # none
    review_required = False
    warnings: list[str] = []
    failed = False
    error_code = safe_error_code

    for result in results:
        if result.status == ScanStatus.ERROR:
            # Per-file errors are reported as safe warnings; they do not fail the
            # whole job (only a job-level execution exception does that).
            if error_code is None:
                error_code = _map_scan_error(result.error.code if result.error else None)
            if result.error is not None and len(warnings) < 20:
                code = _map_scan_error(result.error.code)
                if code in SAFE_ERROR_CODES and code not in warnings:
                    warnings.append(code)
            continue

        for entity_type, count in (result.counts or {}).items():
            label = label_for_entity(entity_type)
            categories.add(label)
            aggregated_counts[label] = aggregated_counts.get(label, 0) + int(count)

        sev_label = _severity_label(result.severity)
        severity_rank = max(severity_rank, _SEVERITY_RANK[sev_label])
        # Escalate severity to high when a secret/special-category label is present.
        if categories & _SPECIAL_OR_SECRET_LABELS:
            severity_rank = max(severity_rank, _SEVERITY_RANK["high"])

        decision, action = _per_file_decision(result.status, result)
        decision_rank = max(decision_rank, _DECISION_RANK[decision])
        action_rank = max(action_rank, _ACTION_RANK[action])
        if result.requires_review:
            review_required = True

    if aggregated_counts:
        severity_rank = max(severity_rank, _SEVERITY_RANK["medium"])

    if failed and error_code is None:
        error_code = "agent_execution_error"

    if categories & _SPECIAL_OR_SECRET_LABELS:
        review_required = True

    decision = "allow"
    for name, rank in _DECISION_RANK.items():
        if rank == decision_rank:
            decision = name
    action = "none"
    for name, rank in _ACTION_RANK.items():
        if rank == action_rank:
            action = name

    if decision in {"review", "block"}:
        review_required = True

    if failed:
        # Fail-closed: a failed job can never be reported as safe.
        return ExecutionResult(
            status="failed",
            severity="none",
            categories=[],
            counts={},
            review_required=True,
            policy_decision="review",
            supported_action="none",
            safe_error_code=error_code or "agent_execution_error",
            resources_scanned=resources_scanned,
            duration_ms=duration_ms,
            policy_version_id=policy_version_id,
            policy_digest=policy_digest,
        )

    return ExecutionResult(
        status="succeeded",
        severity=severity_label_from_rank(severity_rank),
        categories=sorted(categories),
        counts={k: aggregated_counts[k] for k in sorted(aggregated_counts)},
        review_required=review_required,
        policy_decision=decision,
        supported_action=action,
        safe_error_code=None,
        resources_scanned=resources_scanned,
        duration_ms=duration_ms,
        policy_version_id=policy_version_id,
        policy_digest=policy_digest,
    )


def severity_label_from_rank(rank: int) -> str:
    for name, value in _SEVERITY_RANK.items():
        if value == rank:
            return name
    return "none"


def build_safe_result_dict(
    result: ExecutionResult, *, warnings: list[str] | None = None
) -> dict[str, Any]:
    """Serialize an :class:`ExecutionResult` into the allowed result envelope."""

    return {
        "status": result.status,
        "severity": result.severity,
        "categories": result.categories,
        "counts": result.counts,
        "review_required": result.review_required,
        "policy_decision": result.policy_decision,
        "supported_action": result.supported_action,
        "warnings": sorted(set(warnings or [])),
        "safe_error_code": result.safe_error_code,
        "resources_scanned": result.resources_scanned,
        "duration_ms": result.duration_ms,
        "policy_version_id": result.policy_version_id,
        "policy_digest": result.policy_digest,
    }


def validate_safe_result(result: dict[str, Any]) -> dict[str, Any]:
    """Enforce the safe-result contract; raise ``ValueError`` on any violation."""

    if not isinstance(result, dict):
        raise ValueError("result must be an object")
    if len(json.dumps(result).encode("utf-8")) > MAX_RESULT_PAYLOAD_BYTES:
        raise ValueError("result payload too large")

    for key in result:
        if key in _DENIED_RESULT_FIELDS or key not in _ALLOWED_RESULT_FIELDS:
            raise ValueError(f"disallowed result field: {key}")

    status = result.get("status")
    if status not in {"succeeded", "failed"}:
        raise ValueError("status must be succeeded|failed")

    severity = result.get("severity")
    if severity is not None and severity not in SEVERITY_LEVELS:
        raise ValueError("invalid severity")

    categories = result.get("categories") or []
    if not isinstance(categories, list):
        raise ValueError("categories must be a list")
    for c in categories:
        if c not in SAFE_CATEGORY_LABELS:
            raise ValueError(f"unknown category: {c}")

    counts = result.get("counts") or {}
    if not isinstance(counts, dict):
        raise ValueError("counts must be an object")
    for k, v in counts.items():
        if k not in SAFE_CATEGORY_LABELS:
            raise ValueError(f"unknown count category: {k}")
        if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > 1_000_000:
            raise ValueError("count out of range")

    policy_decision = result.get("policy_decision")
    if policy_decision is not None and policy_decision not in POLICY_DECISIONS:
        raise ValueError("invalid policy_decision")
    supported_action = result.get("supported_action")
    if supported_action is not None and supported_action not in SUPPORTED_ACTIONS:
        raise ValueError("invalid supported_action")

    warnings = result.get("warnings") or []
    if not isinstance(warnings, list) or len(warnings) > 20:
        raise ValueError("too many warnings")
    for w in warnings:
        if w not in SAFE_ERROR_CODES:
            raise ValueError(f"unknown warning: {w}")

    safe_error_code = result.get("safe_error_code")
    if safe_error_code is not None and safe_error_code not in SAFE_ERROR_CODES:
        raise ValueError("invalid safe_error_code")

    resources_scanned = result.get("resources_scanned", 0)
    if (
        isinstance(resources_scanned, bool)
        or not isinstance(resources_scanned, int)
        or resources_scanned < 0
        or resources_scanned > 10_000_000
    ):
        raise ValueError("resources_scanned out of range")

    duration_ms = result.get("duration_ms")
    if duration_ms is not None and (
        isinstance(duration_ms, bool)
        or not isinstance(duration_ms, int)
        or duration_ms < 0
        or duration_ms > 24 * 60 * 60 * 1000
    ):
        raise ValueError("duration_ms out of range")

    if status == "failed":
        if not result.get("review_required"):
            raise ValueError("failed result requires review_required=true")
        if result.get("policy_decision") != "review":
            raise ValueError("failed result requires policy_decision=review")
        if result.get("supported_action") != "none":
            raise ValueError("failed result requires supported_action=none")
        if not result.get("safe_error_code"):
            raise ValueError("failed result requires safe_error_code")

    return result
