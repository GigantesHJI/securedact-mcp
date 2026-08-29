# SPDX-License-Identifier: Apache-2.0
"""Google Workspace scan provider (AGENT-015).

Bridges a claimed ``google_workspace`` job to the existing, read-only Google
Drive connector. The provider performs only local, read-only scanning: it uses
the customer's locally-stored OAuth token (never the control plane) and returns
privacy-safe :class:`ScanResult` objects. Microsoft 365 is intentionally not
provided here (no local Graph transport exists yet).
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from typing import Protocol, cast

from securedact_core.api import SecuredactEngine
from securedact_core.connectors.contracts import ScanContext
from securedact_core.connectors.scan import (
    ScanResult,
    ScanSeverity,
    ScanStatus,
)

from .config import AgentFiles
from .connectors import ConnectorBindingStore
from .errors import JobExecutionError
from .executor import (
    TARGET_DRIVE,
    TARGET_FOLDER,
    TARGET_INTEGRATION,
    TARGET_RESOURCE,
    TARGET_RESOURCE_COLLECTION,
    TARGET_SITE,
    ScanTarget,
)


class _GoogleConnectorClient(Protocol):
    """Narrow structural boundary for the optional Google connector client."""

    def scan_file(
        self, file_id: str, context: ScanContext, *, integration_id: str | None = None
    ) -> ScanResult: ...
    def scan_folder(
        self,
        folder_id: str,
        context: ScanContext,
        *,
        integration_id: str | None = None,
        heartbeat: Callable[[], None] | None = None,
    ) -> object: ...
    def scan_drive(
        self,
        context: ScanContext,
        *,
        integration_id: str | None = None,
        heartbeat: Callable[[], None] | None = None,
    ) -> object: ...


class _GoogleClientModule(Protocol):
    """Narrow structural boundary for the optional Google connector client module."""

    GoogleConfigError: type[Exception]

    def build_client(self, config: object, engine: SecuredactEngine) -> _GoogleConnectorClient: ...


class _GoogleConfigModule(Protocol):
    """Narrow structural boundary for the optional Google connector config module."""

    def load_google_config(self, *, require_enabled: bool = ..., profile: str = ...) -> object: ...


def _summary_to_result(summary: object) -> ScanResult:
    """Reduce a bulk :class:`DriveScanSummary` to one aggregate, safe ScanResult.

    Bulk folder/drive scans report aggregate file counts and per-category finding
    counts (never the values) so the control plane can route review and show which
    kinds of PII were detected. Per-file category detail is fully reported for
    single-file (RESOURCE) scans.
    """

    files_with_findings = int(getattr(summary, "files_with_findings", 0) or 0)
    files_failed = int(getattr(summary, "files_failed", 0) or 0)
    files_scanned = int(getattr(summary, "files_scanned", 0) or 0)
    files_clean = int(getattr(summary, "files_clean", 0) or 0)
    files_unsupported = int(getattr(summary, "files_unsupported", 0) or 0)
    findings_total = int(getattr(summary, "findings_total", 0) or 0)
    category_counts = dict(getattr(summary, "category_counts", {}) or {})
    severity = (
        ScanSeverity.MEDIUM
        if files_with_findings > 0 or files_failed > 0 or category_counts
        else ScanSeverity.NONE
    )
    return ScanResult(
        status=ScanStatus.COMPLETED,
        severity=severity,
        resource_id=str(getattr(summary, "root_id", "") or "drive"),
        platform="google_workspace",
        org_id="google",
        tenant_id="",
        integration_id=None,
        categories=sorted(category_counts.keys()),
        counts=dict(sorted(category_counts.items())),
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
            "files_unsupported": files_unsupported,
            "files_clean": files_clean,
            "findings_total": findings_total,
        },
        correlation_id=None,
    )


class GoogleScanProvider:
    """Read-only Google Drive scan provider for the managed agent.

    The provider performs only local, read-only scanning. It never receives
    OAuth material from the control plane: given the claimed ``integration_id``
    it resolves the local :class:`ConnectorBinding`, validates the platform, and
    loads the Google configuration/OAuth token for THAT binding's
    ``local_profile``. Missing bindings, platform mismatches, and unloadable
    profiles all fail closed (a safe ``JobExecutionError`` that the runner turns
    into a privacy-safe failed result).
    """

    def __init__(
        self,
        *,
        files: AgentFiles | None = None,
        binding_store: ConnectorBindingStore | None = None,
    ) -> None:
        self._files = files
        self._binding_store = binding_store or ConnectorBindingStore(files)

    def _resolve_local_profile(self, target: ScanTarget) -> str:
        """Map a claimed ``integration_id`` to its exact local profile (fail closed)."""

        integration_id = target.integration_id
        if not integration_id:
            raise JobExecutionError(
                "google_workspace scan requires an integration_id; the control "
                "plane must never supply OAuth material"
            )
        binding = self._binding_store.get(integration_id)
        if binding is None:
            raise JobExecutionError(
                f"no local connector binding for integration_id {integration_id!r} "
                "(the control plane must never supply OAuth material)"
            )
        if binding.platform != "google_workspace":
            raise JobExecutionError(
                f"connector binding platform {binding.platform!r} for "
                f"integration_id {integration_id!r} does not match the claimed "
                "google_workspace job"
            )
        # Never fall back to an unrelated/default profile when a binding is
        # required; only the binding's own local_profile is used.
        return binding.local_profile or "default"

    def scan(
        self,
        target: ScanTarget,
        context: ScanContext,
        engine: SecuredactEngine,
        *,
        heartbeat: Callable[[], None] | None = None,
    ) -> list[ScanResult]:
        try:
            client_module = cast(
                _GoogleClientModule,
                importlib.import_module("securedact_mcp.connectors.google.client"),
            )
            config_module = cast(
                _GoogleConfigModule,
                importlib.import_module("securedact_mcp.connectors.google.config"),
            )
        except ModuleNotFoundError as exc:
            raise JobExecutionError(f"google provider unavailable: {exc}") from exc

        # Resolve the managed-agent integration binding to the exact local
        # profile, then load THAT profile's configuration/OAuth material. This
        # keeps the control plane out of credential handling entirely.
        local_profile = self._resolve_local_profile(target)

        try:
            config = config_module.load_google_config(profile=local_profile)
        except client_module.GoogleConfigError as exc:
            raise JobExecutionError(
                f"google connector not configured for profile {local_profile!r}: {exc}"
            ) from exc

        client = client_module.build_client(config, engine)
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
                target.target_ref,
                context,
                integration_id=target.integration_id,
                heartbeat=heartbeat,
            )
            return [_summary_to_result(summary)]
        if target_type in (TARGET_DRIVE, TARGET_INTEGRATION):
            # DRIVE / INTEGRATION -> scan the whole My Drive / bound integration.
            summary = client.scan_drive(
                context, integration_id=target.integration_id, heartbeat=heartbeat
            )
            return [_summary_to_result(summary)]
        # Any other target type is unknown: the agent must never guess or broaden
        # the operation. Fail closed as a safe execution error.
        raise JobExecutionError(
            f"unsupported google_workspace target_type {target_type!r}; "
            "the control plane must only issue known target types"
        )
