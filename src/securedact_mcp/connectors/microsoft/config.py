# SPDX-License-Identifier: Apache-2.0
"""Microsoft connector configuration loader (control plane, M365-102).

Pure, dependency-free configuration resolution for the Microsoft connector. It
follows the existing SecuRedact convention of reading optional, non-secret
environment overrides and failing closed when required values are missing or
malformed. No Microsoft SDK, no token material, and no network access here.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from securedact_core.app_paths import SecuredactPaths
from securedact_core.connectors.microsoft import default_connector_scopes, has_write_scope

from .client_config_store import MicrosoftClientConfigStore
from .managed import (
    MANAGED_MICROSOFT_CLIENT_ID_ENV,
    get_managed_microsoft_config,
    is_managed_microsoft_available,
    resolve_managed_microsoft_client_id,
)
from .storage import MicrosoftCredentialStore


@dataclass(frozen=True, slots=True)
class MicrosoftConnectorConfig:
    """Resolved Microsoft connector configuration (application/client only)."""

    enabled: bool
    client_id: str | None
    client_secret: str | None
    tenant_id: str
    redirect_uri: str
    scopes: list[str]
    token_path: Path
    key_path: Path
    # True when the resolved configuration uses the SecuRedact-managed (owned)
    # Microsoft Entra application. This flag lets the token exchange send it
    # without treating it as customer-supplied BYO material.
    managed: bool = False

    def require_credentials(self) -> tuple[str, str]:
        """Return ``(client_id, client_secret)`` or raise (fail closed).

        A missing client *secret* is tolerated for public clients. A missing
        client *id* is always a hard failure.
        """

        if not self.client_id:
            raise MicrosoftConfigError(
                "Microsoft Entra client id is not configured. Set "
                "MICROSOFT_ENTRA_CLIENT_ID, or configure the SecuRedact-managed "
                "app via MICROSOFT_ENTRA_MANAGED_CLIENT_ID, or run setup with "
                "--microsoft-byo to use your own Entra OAuth app."
            )
        return self.client_id, self.client_secret or ""

    def credential_store(self) -> MicrosoftCredentialStore:
        return MicrosoftCredentialStore(self.token_path, self.key_path)


class MicrosoftConfigError(ValueError):
    """Raised when Microsoft configuration is missing or malformed."""


def _safe_profile_name(profile: str) -> str:
    """Sanitize a local profile name into a path-safe component (fail closed)."""

    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", profile)
    if not cleaned or cleaned in (".", ".."):
        raise MicrosoftConfigError(f"invalid microsoft profile name: {profile!r}")
    return cleaned


def _resolve_token_paths(
    profile: str = "default", data_dir: str | Path | None = None
) -> tuple[Path, Path]:
    # An explicit ``data_dir`` pins the token vault to a specific machine root
    # (e.g. ``C:\\ProgramData\\Securedact``) without relying on the ambient
    # ``SECUREDACT_APP_DATA_DIR`` environment. This is what lets the managed-agent
    # setup authorize Microsoft *locally on the machine* and keep the OAuth token in
    # the same protected data dir the scheduled task reads from.
    if data_dir is not None:
        paths_root = Path(data_dir).expanduser().resolve()
    else:
        paths_root = SecuredactPaths.resolve().root
    base = paths_root / "microsoft"
    # Per-profile OAuth tokens are isolated under a ``profiles/`` subdirectory so
    # a managed-agent binding selects exactly one local token. The implicit
    # ``default`` profile keeps the historic on-disk location used by the
    # direct/local CLI and unmanaged usage, preserving backwards compatibility.
    if profile and profile != "default":
        base = base / "profiles" / _safe_profile_name(profile)
    base.mkdir(parents=True, exist_ok=True)
    return base / "token.json.enc", base / "token.key"


def load_microsoft_config(
    *, require_enabled: bool = False, profile: str = "default", data_dir: str | Path | None = None
) -> MicrosoftConnectorConfig:
    """Resolve the Microsoft connector configuration from the environment.

    Microsoft is an additive capability: it is disabled unless explicitly enabled,
    so existing users (and CI) are unaffected. When ``require_enabled`` is true
    and Microsoft is disabled, this raises :class:`MicrosoftConfigError`.

    ``profile`` selects the local OAuth token/credential store (per the
    managed-agent :class:`ConnectorBinding`). The implicit ``default`` profile
    preserves the historic direct/local CLI behavior; any other profile isolates
    its token under ``microsoft/profiles/<profile>/``. The control plane never
    supplies OAuth material or the profile -- it is resolved locally.
    """

    if not isinstance(profile, str) or not profile:
        raise MicrosoftConfigError("microsoft profile must be a non-empty string")

    enabled = os.getenv("SECUREDACT_MICROSOFT_ENABLED", "0") == "1"
    if require_enabled and not enabled:
        raise MicrosoftConfigError("Microsoft connector is not enabled. Set SECUREDACT_MICROSOFT_ENABLED=1.")

    client_id = os.getenv("MICROSOFT_ENTRA_CLIENT_ID") or None
    client_secret = os.getenv("MICROSOFT_ENTRA_CLIENT_SECRET") or None
    tenant_id_env = os.getenv("MICROSOFT_ENTRA_TENANT_ID")
    tenant_id = tenant_id_env or "common"

    # Fall back to the encrypted, machine-local client config store. The operator
    # supplies the client id/secret at setup time and they are persisted encrypted
    # under the machine data root (never as a machine env var). The SYSTEM-run
    # scheduled task loads them from here after the setup session closes and after
    # reboot. The environment always wins when present (local interactive sessions).
    if client_id is None or client_secret is None or tenant_id_env is None:
        store_dir = data_dir or SecuredactPaths.resolve().root
        try:
            stored = MicrosoftClientConfigStore(store_dir).load_full()
            stored_cid, stored_secret, stored_tid = stored
        except Exception:
            stored_cid = stored_secret = stored_tid = None
        client_id = client_id or stored_cid
        client_secret = client_secret or stored_secret
        if tenant_id_env is None:
            tenant_id = stored_tid or tenant_id

    # Final fallback: the SecuRedact-managed (owned) Microsoft Entra public-client application.
    is_managed = False
    if client_id is None:
        if is_managed_microsoft_available():
            is_managed = True
            managed_config = get_managed_microsoft_config()
            client_id = managed_config.client_id
            # No client_secret for public-client / PKCE flow
            client_secret = None
        # else: remains None, will fail later in require_credentials()

    redirect_uri = os.getenv(
        "SECUREDACT_M365_REDIRECT_URI",
        "http://localhost",
    )

    scopes_override = os.getenv("SECUREDACT_MICROSOFT_SCOPES")
    if scopes_override:
        scopes = [scope.strip() for scope in scopes_override.split() if scope.strip()]
        if has_write_scope(scopes):
            raise MicrosoftConfigError(
                "Configured Microsoft scopes include a write/expanded Graph scope. "
                "The M365-102 connector is read-only and must not request it."
            )
    else:
        scopes = default_connector_scopes()

    token_path_override = os.getenv("SECUREDACT_MICROSOFT_TOKEN_PATH")
    if token_path_override:
        token_path = Path(token_path_override).expanduser()
        key_path = token_path.with_suffix(token_path.suffix + ".key")
    else:
        token_path, key_path = _resolve_token_paths(profile, data_dir=data_dir)

    return MicrosoftConnectorConfig(
        enabled=enabled,
        client_id=client_id,
        client_secret=client_secret,
        tenant_id=tenant_id,
        redirect_uri=redirect_uri,
        scopes=scopes,
        token_path=token_path,
        key_path=key_path,
        managed=is_managed,
    )


def save_microsoft_client_config(
    data_dir: str | Path | None, client_id: str | None, client_secret: str | None
) -> None:
    """Persist the Microsoft Entra client (app) config encrypted under the machine root.

    This is the supported replacement for publishing ``MICROSOFT_ENTRA_CLIENT_SECRET``
    at machine scope: the secret stays machine-local, encrypted at rest, and is loaded
    by the SYSTEM-run scheduled task after reboot -- never placed in argv, env, logs,
    or the control plane.
    """

    MicrosoftClientConfigStore(data_dir or SecuredactPaths.resolve().root).save(
        client_id, client_secret
    )


def load_microsoft_client_config(
    data_dir: str | Path | None,
) -> tuple[str | None, str | None]:
    """Return the decrypted ``(client_id, client_secret)`` from the machine-local store."""

    return MicrosoftClientConfigStore(data_dir or SecuredactPaths.resolve().root).load()