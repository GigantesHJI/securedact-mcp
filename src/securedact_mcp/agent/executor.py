# SPDX-License-Identifier: Apache-2.0
"""Job execution: pull a claimed job, scan locally, reduce to a safe result (AGENT-012).

The executor never sees or emits raw document content. It hands opaque target
references to a :class:`ScanProvider` (which performs the read-only local scan),
aggregates the privacy-safe :class:`ScanResult` objects, and reduces them to a
single :class:`ExecutionResult`. Lease expiry is checked before any work begins
so an expired claim is never acted on.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from securedact_core.api import SecuredactEngine
from securedact_core.connectors.contracts import ScanContext
from securedact_core.connectors.scan import ScanResult

from .errors import JobExecutionError, LeaseError
from .policy import ResolvedPolicy
from .reducer import ExecutionResult, reduce_scan_results

# Target type vocabulary (mirrors ScanTargetType on the control plane).
TARGET_INTEGRATION = "integration"
TARGET_DRIVE = "drive"
TARGET_FOLDER = "folder"
TARGET_SITE = "site"
TARGET_RESOURCE = "resource"
TARGET_RESOURCE_COLLECTION = "resource_collection"

_LEASE_EXPIRY_SKEW_SECONDS = 30


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """An opaque scan target derived from a claim (no raw content)."""

    platform: str
    integration_id: str | None
    target_type: str
    target_ref: str


@dataclass(frozen=True, slots=True)
class JobClaim:
    """A parsed, validated job claim including the one-time lease secret."""

    job_id: str
    schedule_id: str | None
    organization_id: str
    platform: str
    integration_id: str | None
    target_type: str
    target_ref: str
    attempt: int
    max_attempts: int
    lease_id: str
    lease_secret: str
    lease_generation: int
    lease_expires_at: str
    policy: dict[str, Any]

    @classmethod
    def from_claim(cls, claim: dict[str, Any]) -> JobClaim:
        if not isinstance(claim, dict):
            raise LeaseError("claim must be an object")
        lease_secret = claim.get("lease_secret")
        if not lease_secret or not isinstance(lease_secret, str):
            raise LeaseError("claim is missing the one-time lease secret")
        return cls(
            job_id=str(claim.get("job_id", "")),
            schedule_id=claim.get("schedule_id"),
            organization_id=str(claim.get("organization_id", "")),
            platform=str(claim.get("platform", "")),
            integration_id=claim.get("integration_id"),
            target_type=str(claim.get("target_type", "")),
            target_ref=str(claim.get("target_ref", "")),
            attempt=int(claim.get("attempt", 1)),
            max_attempts=int(claim.get("max_attempts", 1)),
            lease_id=str(claim.get("lease_id", "")),
            lease_secret=lease_secret,
            lease_generation=int(claim.get("lease_generation", 1)),
            lease_expires_at=str(claim.get("lease_expires_at", "")),
            policy=claim.get("policy") or {},
        )

    @property
    def target(self) -> ScanTarget:
        return ScanTarget(
            platform=self.platform,
            integration_id=self.integration_id,
            target_type=self.target_type,
            target_ref=self.target_ref,
        )

    def is_expired(
        self, *, clock: Callable[[], float] | None = None, skew: int = _LEASE_EXPIRY_SKEW_SECONDS
    ) -> bool:
        if not self.lease_expires_at:
            return True
        try:
            # The control plane emits UTC timestamps; parse them as UTC so lease
            # expiry is not shifted by the local timezone (which would falsely
            # mark claims expired on non-UTC machines).
            expiry = (
                datetime.strptime(self.lease_expires_at, "%Y-%m-%dT%H:%M:%SZ")
                .replace(tzinfo=UTC)
                .timestamp()
            )
        except (ValueError, OverflowError):
            return True
        now = (clock or time.time)()
        return now > (expiry - skew)


@runtime_checkable
class ScanProvider(Protocol):
    """Performs a read-only local scan for an opaque target and returns results."""

    def scan(
        self,
        target: ScanTarget,
        context: ScanContext,
        engine: SecuredactEngine,
        *,
        heartbeat: Callable[[], None] | None = None,
    ) -> list[ScanResult]: ...


def execute_job(
    claim: JobClaim,
    engine: SecuredactEngine,
    provider: ScanProvider,
    policy: ResolvedPolicy,
    *,
    heartbeat: Callable[[], None] | None = None,
    clock: Callable[[], float] | None = None,
) -> ExecutionResult:
    """Execute a claimed job locally and reduce it to a safe result.

    Raises :class:`LeaseError` if the lease has already expired (no work is done).
    Any provider/engine failure is captured as a fail-closed ``failed`` result.
    """

    if claim.is_expired(clock=clock):
        raise LeaseError("job lease expired before execution could start")

    context = ScanContext(policy=policy.policy.name)
    started = (clock or time.time)()
    if heartbeat is not None:
        heartbeat()

    try:
        results = list(provider.scan(claim.target, context, engine, heartbeat=heartbeat))
    except LeaseError:
        raise
    except Exception as exc:
        raise JobExecutionError(f"local job execution failed: {exc}") from exc

    finished = (clock or time.time)()
    duration_ms = max(0, int((finished - started) * 1000))
    # A single-file scan yields one result per resource; a folder/drive scan
    # yields one aggregate result whose safe ``scan_metadata`` carries the real
    # ``files_scanned`` count. Prefer that aggregate count so the control plane
    # sees how many Drive items were actually inspected, falling back to the
    # number of result objects otherwise.
    resources_scanned = 0
    for result in results:
        meta = getattr(result, "scan_metadata", None) or {}
        files_scanned = meta.get("files_scanned")
        resources_scanned += (
            int(files_scanned) if isinstance(files_scanned, int) and files_scanned > 0 else 1
        )

    return reduce_scan_results(
        results,
        policy_version_id=policy.policy_version_id,
        policy_digest=policy.content_digest,
        resources_scanned=resources_scanned,
        duration_ms=duration_ms,
    )
