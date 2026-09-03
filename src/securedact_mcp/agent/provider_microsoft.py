# SPDX-License-Identifier: Apache-2.0
"""Microsoft 365 scan provider (M365-102).

Bridges a claimed ``microsoft365`` job to the existing, read-only Microsoft
Graph connector. The provider performs only local, read-only scanning: it uses
the customer's locally-stored OAuth token (never the control plane) and returns
privacy-safe :class:`ScanResult` objects. Google Workspace is intentionally not
provided here (separate provider).
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from securedact_core.api import SecuredactEngine
from securedact_core.app_paths import SecuredactPaths
from securedact_core.connectors.contracts import ScanContext
from securedact_core.connectors.fingerprint import (
    EncryptedFingerprintKeyStore,
    FingerprintConfig,
    compute_resource_fingerprint,
)
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


class _MicrosoftConnectorClient(Protocol):
    """Narrow structural boundary for the optional Microsoft connector client."""

    def scan_file(
        self, drive_id: str, item_id: str, context: ScanContext, *, integration_id: str | None = None
    ) -> ScanResult: ...
    def scan_folder(
        self,
        drive_id: str,
        folder_id: str,
        context: ScanContext,
        *,
        integration_id: str | None = None,
        heartbeat: Callable[[], None] | None = None,
        site_id: str | None = None,
    ) -> object: ...
    def scan_drive(
        self,
        drive_id: str,
        context: ScanContext,
        *,
        integration_id: str | None = None,
        heartbeat: Callable[[], None] | None = None,
        site_id: str | None = None,
    ) -> object: ...


class _MicrosoftClientModule(Protocol):
    """Narrow structural boundary for the optional Microsoft connector client module."""

    MicrosoftConfigError: type[Exception]

    def build_client(self, config: object, engine: SecuredactEngine, fingerprint_config: FingerprintConfig | None = None) -> _MicrosoftConnectorClient: ...


class _MicrosoftConfigModule(Protocol):
    """Narrow structural boundary for the optional Microsoft connector config module."""

    def load_microsoft_config(self, *, require_enabled: bool = ..., profile: str = ...) -> object: ...


class _MicrosoftTargetRegistryModule(Protocol):
    """Narrow structural boundary for the optional Microsoft target registry."""

    LocalTargetRecord: type
    TargetRegistryError: type[Exception]
    TargetRegistryStore: type

    def __getattr__(self, name: str) -> object: ...


def _compute_aggregate_fingerprint(
    fingerprint_config: FingerprintConfig | None,
    drive_id: str | None,
    site_id: str | None,
) -> str:
    """Compute a privacy-safe fingerprint for an aggregate scan target."""
    if fingerprint_config is None:
        # Fallback: use a generic identifier
        return "aggregate"
    if drive_id:
        return compute_resource_fingerprint(fingerprint_config, "drive", drive_id)
    if site_id:
        return compute_resource_fingerprint(fingerprint_config, "site", site_id)
    return "aggregate"


def _summary_to_result(summary: object, fingerprint_config: FingerprintConfig | None = None) -> ScanResult:
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
    # Use privacy-safe fingerprint for aggregate scans
    drive_id = getattr(summary, "drive_id", None)
    site_id = getattr(summary, "site_id", None)
    resource_id = _compute_aggregate_fingerprint(fingerprint_config, drive_id, site_id)
    source = str(getattr(summary, "source", "") or "microsoft365")
    return ScanResult(
        status=ScanStatus.COMPLETED,
        severity=severity,
        resource_id=resource_id,
        platform="microsoft365",
        org_id="microsoft",
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
            "source_type": source,
            # Include fingerprints for longitudinal tracking, not raw IDs
            "drive_fingerprint": compute_resource_fingerprint(fingerprint_config, "drive", drive_id) if fingerprint_config and drive_id else None,
            "site_fingerprint": compute_resource_fingerprint(fingerprint_config, "site", site_id) if fingerprint_config and site_id else None,
        },
        correlation_id=None,
    )


@dataclass(frozen=True, slots=True)
class ResolvedMicrosoftTarget:
    """The result of resolving an opaque ``target_ref`` against the local registry.

    Carries only what the provider needs to invoke :class:`MicrosoftGraphBrowser`.
    Raw Graph ids are present here because the agent is the one calling Graph
    locally; they never appear in the job/result payloads.
    """

    drive_id: str
    folder_id: str | None
    site_id: str | None
    drive_fingerprint: str | None
    folder_fingerprint: str | None
    site_fingerprint: str | None
    kind: str


class MicrosoftScanProvider:
    """Read-only Microsoft 365 scan provider for the managed agent.

    The provider performs only local, read-only scanning. It never receives
    OAuth material from the control plane: given the claimed ``integration_id``
    it resolves the local :class:`ConnectorBinding`, validates the platform, and
    loads the Microsoft configuration/OAuth token for THAT binding's
    ``local_profile``. Missing bindings, platform mismatches, and unloadable
    profiles all fail closed (a safe :class:`JobExecutionError` that the runner
    turns into a privacy-safe failed result).

    ``target_type``/``target_ref`` resolution rules:

    * ``folder``/``site``: ``target_ref`` is an **opaque** ``target_id``
      resolved through the local :class:`TargetRegistryStore`. The agent
      fails closed if the registry is missing, corrupt, or the target is
      not bound to the claimed ``integration_id``. Raw ``driveId:folderId``
      composite strings are rejected to prevent raw Graph ids from crossing
      the control-plane privacy boundary.
    * ``drive``: an opaque ``target_id`` for a SharePoint drive (kind
      ``sharepoint_drive``); OneDrive is reached via ``integration`` /
      ``drive_id="me"`` and does not require a registered target.
    * ``integration``: empty ``target_ref`` scans the entire bound
      integration (the customer's My Drive / OneDrive root via
      ``drive_id="me"``). This remains the canonical whole-OneDrive scan.
    * ``resource``: ``target_ref`` is an opaque ``target_id`` resolved to a
      specific drive item (kind ``one_drive_folder`` / ``sharepoint_folder``
      is NOT used for ``resource``; the registry entry must have a
      folder_id).

    Privacy-safe resource fingerprints are computed using an HMAC key derived
    from the agent's machine-local fingerprint key store, scoped to the
    provider (microsoft365) and tenant.
    """

    def __init__(
        self,
        *,
        files: AgentFiles | None = None,
        binding_store: ConnectorBindingStore | None = None,
        target_registry_factory: Callable[[Path], object] | None = None,
    ) -> None:
        self._files = files
        self._binding_store = binding_store or ConnectorBindingStore(files)
        self._fingerprint_store = EncryptedFingerprintKeyStore(AgentFiles.resolve().root)
        self._target_registry_factory = target_registry_factory or (
            lambda data_dir: _load_target_registry(data_dir)
        )

    def _resolve_local_profile(self, target: ScanTarget) -> str:
        """Map a claimed ``integration_id`` to its exact local profile (fail closed)."""

        integration_id = target.integration_id
        if not integration_id:
            raise JobExecutionError(
                "microsoft365 scan requires an integration_id; the control "
                "plane must never supply OAuth material"
            )
        binding = self._binding_store.get(integration_id)
        if binding is None:
            raise JobExecutionError(
                f"no local connector binding for integration_id {integration_id!r} "
                "(the control plane must never supply OAuth material)"
            )
        if binding.platform != "microsoft365":
            raise JobExecutionError(
                f"connector binding platform {binding.platform!r} for "
                f"integration_id {integration_id!r} does not match the claimed "
                "microsoft365 job"
            )
        # Never fall back to an unrelated/default profile when a binding is
        # required; only the binding's own local_profile is used.
        return binding.local_profile or "default"

    def _create_fingerprint_config(self, integration_id: str) -> FingerprintConfig:
        """Create a fingerprint config scoped to the Microsoft 365 provider and tenant."""
        # Use integration_id as tenant scope for fingerprinting
        return self._fingerprint_store.create_config("microsoft365", integration_id)

    def _resolve_opaque_target(
        self,
        target: ScanTarget,
    ) -> ResolvedMicrosoftTarget:
        """Resolve an opaque ``target_id`` against the local target registry.

        Fails closed if the target is missing, the integration does not match,
        or the registry is corrupt.
        """

        try:
            registry_module = cast(
                _MicrosoftTargetRegistryModule,
                importlib.import_module(
                    "securedact_mcp.connectors.microsoft.target_registry"
                ),
            )
        except ModuleNotFoundError as exc:
            raise JobExecutionError(
                f"microsoft target registry unavailable: {exc}"
            ) from exc

        if not target.target_ref:
            raise JobExecutionError(
                "microsoft365 folder/drive/site scans require an opaque "
                "target_ref (mtgt_...); register a target locally with "
                "'securedact-mcp microsoft targets add'"
            )

        integration_id = target.integration_id
        if not integration_id:
            raise JobExecutionError(
                "microsoft365 scans require an integration_id to resolve the "
                "opaque target_ref"
            )

        store = self._target_registry_factory(SecuredactPaths.resolve().root)
        try:
            record = store.get(target.target_ref, integration_id=integration_id)
        except registry_module.TargetRegistryError as exc:
            raise JobExecutionError(
                f"microsoft365 target registry rejected target_ref "
                f"{target.target_ref!r}: {exc}"
            ) from exc

        if target.target_type in (TARGET_FOLDER, TARGET_SITE):
            if record.folder_id is None:
                raise JobExecutionError(
                    f"target {target.target_ref!r} is not a folder "
                    f"(kind={record.kind!r}); cannot use it for a folder scan"
                )
        if target.target_type == TARGET_DRIVE:
            if record.folder_id is not None:
                # A drive target must be a drive (no folder_id).
                raise JobExecutionError(
                    f"target {target.target_ref!r} is a folder "
                    f"(kind={record.kind!r}); use target_type='folder' "
                    "instead of 'drive'"
                )

        return ResolvedMicrosoftTarget(
            drive_id=record.drive_id,
            folder_id=record.folder_id,
            site_id=record.site_id,
            drive_fingerprint=record.drive_fingerprint,
            folder_fingerprint=record.folder_fingerprint,
            site_fingerprint=record.site_fingerprint,
            kind=record.kind,
        )

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
                _MicrosoftClientModule,
                importlib.import_module("securedact_mcp.connectors.microsoft.client"),
            )
            config_module = cast(
                _MicrosoftConfigModule,
                importlib.import_module("securedact_mcp.connectors.microsoft.config"),
            )
        except ModuleNotFoundError as exc:
            raise JobExecutionError(f"microsoft provider unavailable: {exc}") from exc

        # Resolve the managed-agent integration binding to the exact local
        # profile, then load THAT profile's configuration/OAuth material. This
        # keeps the control plane out of credential handling entirely.
        local_profile = self._resolve_local_profile(target)

        try:
            config = config_module.load_microsoft_config(profile=local_profile)
        except client_module.MicrosoftConfigError as exc:
            raise JobExecutionError(
                f"microsoft connector not configured for profile {local_profile!r}: {exc}"
            ) from exc

        # Create fingerprint config for privacy-safe resource identity
        fingerprint_config = self._create_fingerprint_config(target.integration_id)

        client = client_module.build_client(config, engine, fingerprint_config=fingerprint_config)
        if heartbeat is not None:
            heartbeat()

        target_type = target.target_type

        # ---------------------------------------------------------------------------
        # FOLDER / SITE: resolve opaque target_ref -> raw Graph ids locally, then scan.
        # Raw "driveId:folderId" / "siteId:driveId:folderId" strings are explicitly
        # rejected here so the control plane cannot reintroduce the privacy boundary
        # violation that motivated this design.
        # ---------------------------------------------------------------------------
        if target_type in (TARGET_FOLDER, TARGET_SITE):
            if _looks_like_raw_composite(target.target_ref):
                raise JobExecutionError(
                    "microsoft365 folder/site target_ref must be an opaque "
                    "mtgt_... token registered locally; raw driveId:folderId "
                    "strings are not accepted to keep Graph identifiers out "
                    "of the control-plane privacy boundary"
                )
            resolved = self._resolve_opaque_target(target)
            summary = client.scan_folder(
                resolved.drive_id,
                resolved.folder_id or "",
                context,
                integration_id=target.integration_id,
                heartbeat=heartbeat,
                site_id=resolved.site_id,
            )
            return [_summary_to_result(summary, fingerprint_config)]

        # ---------------------------------------------------------------------------
        # DRIVE: resolve opaque target_ref -> a SharePoint drive. OneDrive (the
        # user's "My Drive") is reached via `integration` + empty target_ref
        # rather than via a registered drive target, so customers do not need
        # to enumerate OneDrive to scan it.
        # ---------------------------------------------------------------------------
        if target_type == TARGET_DRIVE:
            if _looks_like_raw_composite(target.target_ref):
                raise JobExecutionError(
                    "microsoft365 drive target_ref must be an opaque "
                    "mtgt_... token registered locally; raw driveId strings "
                    "are not accepted to keep Graph identifiers out of the "
                    "control-plane privacy boundary"
                )
            resolved = self._resolve_opaque_target(target)
            summary = client.scan_drive(
                resolved.drive_id,
                context,
                integration_id=target.integration_id,
                heartbeat=heartbeat,
                site_id=resolved.site_id,
            )
            return [_summary_to_result(summary, fingerprint_config)]

        # ---------------------------------------------------------------------------
        # INTEGRATION: canonical whole-OneDrive scan. Empty target_ref -> drive_id="me".
        # This remains the documented, single-call path to scan the user's full
        # OneDrive without registering any target.
        # ---------------------------------------------------------------------------
        if target_type == TARGET_INTEGRATION:
            if target.target_ref:
                raise JobExecutionError(
                    "microsoft365 integration target_ref must be empty; the "
                    "agent resolves the user's OneDrive (drive_id='me') "
                    "locally. For specific drives or folders, register an "
                    "opaque target locally and use target_type='drive' or "
                    "'folder'."
                )
            summary = client.scan_drive(
                "me",
                context,
                integration_id=target.integration_id,
                heartbeat=heartbeat,
                site_id=None,
            )
            return [_summary_to_result(summary, fingerprint_config)]

        # ---------------------------------------------------------------------------
        # RESOURCE / RESOURCE_COLLECTION: single-file scan. The opaque target_ref
        # must resolve to a record whose folder_id identifies the drive item to
        # scan. (The "folder_id" field doubles as the item id for ``resource``
        # records registered via the future ``targets add --item-id`` path; for
        # backwards compatibility with the new design, this provider only
        # supports the folder flow today.)
        # ---------------------------------------------------------------------------
        if target_type in (TARGET_RESOURCE, TARGET_RESOURCE_COLLECTION):
            if _looks_like_raw_composite(target.target_ref):
                raise JobExecutionError(
                    "microsoft365 resource target_ref must be an opaque "
                    "mtgt_... token registered locally; raw driveId:itemId "
                    "strings are not accepted"
                )
            resolved = self._resolve_opaque_target(target)
            item_id = resolved.folder_id
            if not item_id:
                raise JobExecutionError(
                    "microsoft365 resource target must point at a drive item; "
                    "register an item via 'microsoft targets add --item-id'"
                )
            result = client.scan_file(
                resolved.drive_id,
                item_id,
                context,
                integration_id=target.integration_id,
            )
            return [result]

        # Any other target type is unknown: the agent must never guess or broaden
        # the operation. Fail closed as a safe execution error.
        raise JobExecutionError(
            f"unsupported microsoft365 target_type {target_type!r}; "
            "the control plane must only issue known target types"
        )


def _looks_like_raw_composite(target_ref: str) -> bool:
    """Heuristic: does ``target_ref`` look like a raw driveId:folderId string?

    Used to reject legacy raw composite strings explicitly so the privacy
    boundary cannot be re-introduced by an out-of-date control plane.
    """

    if not target_ref:
        return False
    if target_ref.startswith("mtgt_"):
        return False
    # A raw composite contains a colon and does NOT start with the opaque
    # prefix. The opaque prefix is the only legal form for folder / drive /
    # resource scans now.
    return ":" in target_ref


def _load_target_registry(data_dir: Path) -> object:
    """Default factory for the target registry, resolved against the machine root."""

    from securedact_mcp.connectors.microsoft.target_registry import TargetRegistryStore

    return TargetRegistryStore(data_dir)