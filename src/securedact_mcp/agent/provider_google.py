# SPDX-License-Identifier: Apache-2.0
"""Google Workspace scan provider (AGENT-015).

Bridges a claimed ``google_workspace`` job to the existing, read-only Google
Drive connector. The provider performs only local, read-only scanning: it uses
the customer's locally-stored OAuth token (never the control plane) and returns
privacy-safe :class:`ScanResult` objects. Microsoft 365 is intentionally not
provided here (no local Graph transport exists yet).
"""

from __future__ import annotations

from typing import Callable

from securedact_core.api import SecuredactEngine
from securedact_core.connectors.contracts import ScanContext
from securedact_core.connectors.scan import (
    ScanResult,
    ScanSeverity,
    ScanStatus,
)

from .errors import JobExecutionError
from .executor import (
    ScanProvider,
    ScanTarget,
    TARGET_DRIVE,
    TARGET_FOLDER,
    TARGET_INTEGRATION,
    TARGET_RESOURCE,
    TARGET_RESOURCE_COLLECTION,
    TARGET_SITE,
)


def _summary_to_result(summary: object) -> ScanResult:
    """Reduce a bulk :class:`DriveScanSummary` to one aggregate, safe ScanResult.

    Bulk folder/drive scans report only aggregate file counts (no per-file
    category breakdown from the browser), so the result carries resource counts
    for review routing rather than category detail. This is privacy-safe and
    correct for control-plane routing; per-file category detail is fully reported
    for single-file (RESOURCE) scans.
    """

    files_with_findings = int(getattr(summary, "files_with_findings", 0) or 0)
    files_failed = int(getattr(summary, "files_failed", 0) or 0)
    files_scanned = int(getattr(summary, "files_scanned", 0) or 0)
    severity = (
        ScanSeverity.MEDIUM if files_with_findings > 0 or files_failed > 0 else ScanSeverity.NONE
    )
    return ScanResult(
        status=ScanStatus.COMPLETED,
        severity=severity,
        resource_id=str(getattr(summary, "root_id", "") or "drive"),
        platform="google_workspace",
        org_id="google",
        tenant_id="",
        integration_id=None,
        categories=[],
        counts={},
        findings=[],
        policy_decision=None,
        supported_action="none",
        redaction_available=False,
        requires_review=files_with_findings > 0 or files_failed > 0,
        warnings=[],
        error=None,
        scan_metadata={
            "files_scanned": files_scanned,
            "files_with_findings": files_with_findings,
            "files_failed": files_failed,
            "files_unsupported": int(getattr(summary, "files_unsupported", 0) or 0),
        },
        correlation_id=None,
    )


class GoogleScanProvider:
    """Read-only Google Drive scan provider for the managed agent."""

    def scan(
        self,
        target: ScanTarget,
        context: ScanContext,
        engine: SecuredactEngine,
        *,
        heartbeat: Callable[[], None] | None = None,
    ) -> list[ScanResult]:
        try:
            from ..connectors.google.client import GoogleConfigError, build_client
        except Exception as exc:  # noqa: BLE001
            raise JobExecutionError(f"google provider unavailable: {exc}") from exc

        try:
            from ..connectors.google.config import load_google_config

            config = load_google_config()
        except GoogleConfigError as exc:
            raise JobExecutionError(f"google connector not configured: {exc}") from exc

        client = build_client(config, engine)
        if heartbeat is not None:
            heartbeat()

        target_type = target.target_type
        if target_type in (TARGET_RESOURCE, TARGET_RESOURCE_COLLECTION) and target.target_ref:
            result = client.scan_file(
                target.target_ref, context, integration_id=target.integration_id
            )
            return [result]
        if target_type in (TARGET_FOLDER, TARGET_SITE) and target.target_ref:
            summary = client.scan_folder(
                target.target_ref, context, integration_id=target.integration_id
            )
            return [_summary_to_result(summary)]
        # DRIVE / INTEGRATION -> scan the whole My Drive / bound integration.
        summary = client.scan_drive(context, integration_id=target.integration_id)
        return [_summary_to_result(summary)]
