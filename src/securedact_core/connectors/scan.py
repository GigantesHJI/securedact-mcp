# SPDX-License-Identifier: Apache-2.0
"""Connector scan request/result contracts (ARCH-003).

These models translate a connector operation into the canonical SecuRedact
result shape. They are intentionally privacy-safe: a ``ScanResult`` never
contains raw detected sensitive values or token material. Findings are
aggregated summaries (category, count, decision) suitable for a dashboard or
SPFx panel.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .contracts import ConnectorResource, ScanContext


class ScanStatus(StrEnum):
    """Outcome of a connector scan."""

    COMPLETED = "completed"
    REVIEW_REQUIRED = "review_required"
    BLOCKED = "blocked"
    ERROR = "error"


class ScanSeverity(StrEnum):
    """Risk severity derived from the scan result."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ScanErrorCode(StrEnum):
    """Structured error codes for a failed scan.

    These avoid leaking raw upstream error text to clients and never carry
    token/exception internals.
    """

    UNSUPPORTED_FORMAT = "unsupported_format"
    CONTENT_TOO_LARGE = "content_too_large"
    EXTRACTION_FAILED = "extraction_failed"
    RETRIEVAL_FAILED = "retrieval_failed"
    ENGINE_UNAVAILABLE = "engine_unavailable"
    TENANT_MISMATCH = "tenant_mismatch"
    UNAUTHORIZED = "unauthorized"
    INVALID_RESOURCE = "invalid_resource"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    UNEXPECTED = "unexpected"


class ScanError(BaseModel):
    """A structured, safe error describing a failed scan."""

    model_config = ConfigDict(extra="forbid")

    code: ScanErrorCode
    message: str = Field(max_length=512)
    retryable: bool = False


class ScanFinding(BaseModel):
    """An aggregated, privacy-safe finding summary.

    Contains no raw detected value. ``category`` is the entity/category type
    (e.g. ``email_address``, ``credit_card``) and ``count`` is how many were
    detected. ``decision`` is the action taken by policy.
    """

    model_config = ConfigDict(extra="forbid")

    category: str = Field(max_length=128)
    count: int = Field(ge=0)
    decision: str = Field(max_length=32)
    is_secret: bool = False


class ScanRequest(BaseModel):
    """A connector scan request handed to the SecuRedact service boundary."""

    model_config = ConfigDict(extra="forbid")

    resource: ConnectorResource
    context: ScanContext = Field(default_factory=ScanContext)
    requested_capabilities: set[str] = Field(default_factory=set)


class ScanResult(BaseModel):
    """The canonical, privacy-safe result of a connector scan."""

    model_config = ConfigDict(extra="forbid")

    status: ScanStatus
    severity: ScanSeverity = ScanSeverity.NONE
    resource_id: str = Field(max_length=512)
    platform: str = Field(max_length=64)
    org_id: str = Field(max_length=128)
    tenant_id: str = Field(max_length=128)
    integration_id: str | None = Field(default=None, max_length=128)
    categories: list[str] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    findings: list[ScanFinding] = Field(default_factory=list)
    policy_decision: str | None = Field(default=None, max_length=32)
    supported_action: Literal["none", "review", "redact", "quarantine"] = "none"
    redaction_available: bool = False
    requires_review: bool = False
    warnings: list[str] = Field(default_factory=list)
    error: ScanError | None = Field(default=None)
    scan_metadata: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str | None = Field(default=None, max_length=128)
