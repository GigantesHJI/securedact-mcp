# SPDX-License-Identifier: Apache-2.0
"""High-level Microsoft connector client (control plane, M365-102).

Wires configuration, credential storage, OAuth, the concrete transport, the
core :class:`MicrosoftGraphBrowser`, and the :class:`ConnectorScanner` into a
single facade used by the CLI and managed agent. Keeps the MCP server and
existing integrations untouched; Microsoft is an additive, opt-in capability.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from securedact_core.connectors import ConnectorScanner
from securedact_core.connectors.contracts import (
    ConnectorCapability,
    ConnectorIdentity,
    ScanContext,
)
from securedact_core.connectors.fingerprint import FingerprintConfig
from securedact_core.connectors.microsoft import (
    DriveScanSummary,
    MicrosoftApiError,
    MicrosoftDrive,
    MicrosoftGraphBrowser,
    MicrosoftGraphItem,
    MicrosoftSite,
    default_connector_scopes,
    has_write_scope,
)
from securedact_core.connectors.scan import ScanResult

from .auth import require_valid_credentials
from .config import MicrosoftConfigError, MicrosoftConnectorConfig


def _assert_readonly(config: MicrosoftConnectorConfig) -> None:
    if has_write_scope(config.scopes):
        raise MicrosoftConfigError("Microsoft connector is configured with a write scope")


class MicrosoftConnectorClient:
    """End-user facade for the read-only Microsoft 365 connector."""

    def __init__(
        self,
        config: MicrosoftConnectorConfig,
        engine: Any,
        *,
        transport: Any = None,
        user_id: str | None = None,
        tenant_id: str | None = None,
        fingerprint_config: FingerprintConfig | None = None,
    ) -> None:
        _assert_readonly(config)
        self._config = config
        self._engine = engine
        self._browser: MicrosoftGraphBrowser | None = None
        self._transport = transport
        self._user_id_override = user_id
        self._tenant_id_override = tenant_id
        self._fingerprint_config = fingerprint_config

    def _ensure_browser(self) -> MicrosoftGraphBrowser:
        if self._browser is not None:
            return self._browser
        _assert_readonly(self._config)
        # A transport may be injected (e.g. by tests or a recorded-replay smoke
        # run). When it is, the live OAuth credential lookup is bypassed and the
        # injected transport's verified identity is used. The default production
        # path still resolves real local credentials and the real HTTP transport.
        if self._transport is None:
            from .transport import MicrosoftGraphTransport

            credentials = require_valid_credentials(self._config)
            transport = MicrosoftGraphTransport(credentials)
        else:
            transport = self._transport
        user_id = self._user_id_override or transport.user_id
        tenant_id = self._tenant_id_override or transport.tenant_id
        identity = ConnectorIdentity(
            org_id="microsoft",
            integration_id="microsoft365",
            tenant_id=tenant_id,
            platform="microsoft365",
            user_id=user_id,
        )
        self._transport = transport
        self._browser = MicrosoftGraphBrowser(identity, transport, fingerprint_config=self._fingerprint_config)
        return self._browser

    def capabilities(self) -> frozenset[ConnectorCapability]:
        return self._ensure_browser().capabilities()

    def list_drives(self) -> list[MicrosoftDrive]:
        return self._ensure_browser().list_drives()

    def get_drive(self, drive_id: str) -> MicrosoftDrive:
        return self._ensure_browser().get_drive(drive_id)

    def list_sites(self) -> list[MicrosoftSite]:
        return self._ensure_browser().list_sites()

    def get_site(self, site_id: str) -> MicrosoftSite:
        return self._ensure_browser().get_site(site_id)

    def get_site_drive(self, site_id: str) -> MicrosoftDrive:
        return self._ensure_browser().get_site_drive(site_id)

    def list_children(
        self, drive_id: str, folder_id: str | None = None
    ) -> list[MicrosoftGraphItem]:
        return self._ensure_browser().list_children(drive_id, folder_id=folder_id)

    def scan_file(
        self,
        drive_id: str,
        item_id: str,
        context: ScanContext | None = None,
        *,
        integration_id: str | None = None,
        user_id: str | None = None,
    ) -> ScanResult:
        scanner = ConnectorScanner(self._engine)
        return self._ensure_browser().select_and_scan(
            drive_id, item_id, scanner, context, integration_id=integration_id, user_id=user_id
        )

    def scan_folder(
        self,
        drive_id: str,
        folder_id: str,
        context: ScanContext | None = None,
        *,
        integration_id: str | None = None,
        user_id: str | None = None,
        site_id: str | None = None,
        max_files: int = 0,
        heartbeat: Callable[[], None] | None = None,
    ) -> DriveScanSummary:
        scanner = ConnectorScanner(self._engine)
        # Set the current site ID on the browser for metadata
        browser = self._ensure_browser()
        browser._current_site_id = site_id
        return browser.scan_folder(
            drive_id,
            folder_id,
            scanner,
            context,
            integration_id=integration_id,
            user_id=user_id,
            site_id=site_id,
            max_files=max_files,
            heartbeat=heartbeat,
        )

    def scan_drive(
        self,
        drive_id: str,
        context: ScanContext | None = None,
        *,
        integration_id: str | None = None,
        user_id: str | None = None,
        site_id: str | None = None,
        max_files: int = 0,
        heartbeat: Callable[[], None] | None = None,
    ) -> DriveScanSummary:
        scanner = ConnectorScanner(self._engine)
        browser = self._ensure_browser()
        browser._current_site_id = site_id
        return browser.scan_drive(
            drive_id,
            scanner,
            context,
            integration_id=integration_id,
            user_id=user_id,
            site_id=site_id,
            max_files=max_files,
            heartbeat=heartbeat,
        )


def build_client(
    config: MicrosoftConnectorConfig,
    engine: Any,
    *,
    transport: Any = None,
    user_id: str | None = None,
    tenant_id: str | None = None,
    fingerprint_config: FingerprintConfig | None = None,
) -> MicrosoftConnectorClient:
    return MicrosoftConnectorClient(config, engine, transport=transport, user_id=user_id, tenant_id=tenant_id, fingerprint_config=fingerprint_config)


__all__ = [
    "MicrosoftApiError",
    "MicrosoftConfigError",
    "MicrosoftConnectorClient",
    "MicrosoftConnectorConfig",
    "build_client",
    "default_connector_scopes",
]