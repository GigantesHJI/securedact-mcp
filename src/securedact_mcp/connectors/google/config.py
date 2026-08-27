# SPDX-License-Identifier: Apache-2.0
"""Google connector configuration loader (control plane, GWS-110).

Pure, dependency-free configuration resolution for the Google connector. It
follows the existing SecuRedact convention of reading optional, non-secret
environment overrides and failing closed when required values are missing or
malformed. No Google SDK, no token material, and no network access here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from securedact_core.app_paths import SecuredactPaths
from securedact_core.connectors.google import default_connector_scopes, has_write_scope

from .storage import GoogleCredentialStore


@dataclass(frozen=True, slots=True)
class GoogleConnectorConfig:
    """Resolved Google connector configuration (application/client only)."""

    enabled: bool
    client_id: str | None
    client_secret: str | None
    redirect_uri: str
    scopes: list[str]
    token_path: Path
    key_path: Path

    def require_credentials(self) -> tuple[str, str]:
        """Return ``(client_id, client_secret)`` or raise (fail closed)."""

        if not self.client_id or not self.client_secret:
            raise GoogleConfigError(
                "Google OAuth client id/secret are not configured. Set "
                "SECUREDACT_GOOGLE_CLIENT_ID and SECUREDACT_GOOGLE_CLIENT_SECRET."
            )
        return self.client_id, self.client_secret

    def credential_store(self) -> GoogleCredentialStore:
        return GoogleCredentialStore(self.token_path, self.key_path)


class GoogleConfigError(ValueError):
    """Raised when Google configuration is missing or malformed."""


def _resolve_token_paths() -> tuple[Path, Path]:
    paths = SecuredactPaths.resolve()
    base = paths.root / "google"
    base.mkdir(parents=True, exist_ok=True)
    return base / "token.json.enc", base / "token.key"


def load_google_config(*, require_enabled: bool = False) -> GoogleConnectorConfig:
    """Resolve the Google connector configuration from the environment.

    Google is an additive capability: it is disabled unless explicitly enabled,
    so existing users (and CI) are unaffected. When ``require_enabled`` is true
    and Google is disabled, this raises :class:`GoogleConfigError`.
    """

    enabled = os.getenv("SECUREDACT_GOOGLE_ENABLED", "0") == "1"
    if require_enabled and not enabled:
        raise GoogleConfigError("Google connector is not enabled. Set SECUREDACT_GOOGLE_ENABLED=1.")

    client_id = os.getenv("SECUREDACT_GOOGLE_CLIENT_ID") or None
    client_secret = os.getenv("SECUREDACT_GOOGLE_CLIENT_SECRET") or None

    redirect_uri = os.getenv("SECUREDACT_GOOGLE_REDIRECT_URI", "http://localhost:8080/")

    scopes_override = os.getenv("SECUREDACT_GOOGLE_SCOPES")
    if scopes_override:
        scopes = [scope.strip() for scope in scopes_override.split() if scope.strip()]
        if has_write_scope(scopes):
            raise GoogleConfigError(
                "Configured Google scopes include a write/expanded Drive scope. "
                "The GWS-110 connector is read-only and must not request it."
            )
    else:
        scopes = default_connector_scopes()

    token_path_override = os.getenv("SECUREDACT_GOOGLE_TOKEN_PATH")
    if token_path_override:
        token_path = Path(token_path_override).expanduser()
        key_path = token_path.with_suffix(token_path.suffix + ".key")
    else:
        token_path, key_path = _resolve_token_paths()

    return GoogleConnectorConfig(
        enabled=enabled,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        scopes=scopes,
        token_path=token_path,
        key_path=key_path,
    )
