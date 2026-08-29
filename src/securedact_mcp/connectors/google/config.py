# SPDX-License-Identifier: Apache-2.0
"""Google connector configuration loader (control plane, GWS-110).

Pure, dependency-free configuration resolution for the Google connector. It
follows the existing SecuRedact convention of reading optional, non-secret
environment overrides and failing closed when required values are missing or
malformed. No Google SDK, no token material, and no network access here.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from securedact_core.app_paths import SecuredactPaths
from securedact_core.connectors.google import default_connector_scopes, has_write_scope

from .storage import GoogleClientConfigStore, GoogleCredentialStore


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


def _safe_profile_name(profile: str) -> str:
    """Sanitize a local profile name into a path-safe component (fail closed)."""

    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", profile)
    if not cleaned or cleaned in (".", ".."):
        raise GoogleConfigError(f"invalid google profile name: {profile!r}")
    return cleaned


def _resolve_token_paths(
    profile: str = "default", data_dir: str | Path | None = None
) -> tuple[Path, Path]:
    # An explicit ``data_dir`` pins the token vault to a specific machine root
    # (e.g. ``C:\\ProgramData\\Securedact``) without relying on the ambient
    # ``SECUREDACT_APP_DATA_DIR`` environment. This is what lets the managed-agent
    # setup authorize Google *locally on the machine* and keep the OAuth token in
    # the same protected data dir the scheduled task reads from.
    if data_dir is not None:
        paths_root = Path(data_dir).expanduser().resolve()
    else:
        paths_root = SecuredactPaths.resolve().root
    base = paths_root / "google"
    # Per-profile OAuth tokens are isolated under a ``profiles/`` subdirectory so
    # a managed-agent binding selects exactly one local token. The implicit
    # ``default`` profile keeps the historic on-disk location used by the
    # direct/local CLI and unmanaged usage, preserving backwards compatibility.
    if profile and profile != "default":
        base = base / "profiles" / _safe_profile_name(profile)
    base.mkdir(parents=True, exist_ok=True)
    return base / "token.json.enc", base / "token.key"


def load_google_config(
    *, require_enabled: bool = False, profile: str = "default", data_dir: str | Path | None = None
) -> GoogleConnectorConfig:
    """Resolve the Google connector configuration from the environment.

    Google is an additive capability: it is disabled unless explicitly enabled,
    so existing users (and CI) are unaffected. When ``require_enabled`` is true
    and Google is disabled, this raises :class:`GoogleConfigError`.

    ``profile`` selects the local OAuth token/credential store (per the
    managed-agent :class:`ConnectorBinding`). The implicit ``default`` profile
    preserves the historic direct/local CLI behavior; any other profile isolates
    its token under ``google/profiles/<profile>/``. The control plane never
    supplies OAuth material or the profile -- it is resolved locally.
    """

    if not isinstance(profile, str) or not profile:
        raise GoogleConfigError("google profile must be a non-empty string")

    enabled = os.getenv("SECUREDACT_GOOGLE_ENABLED", "0") == "1"
    if require_enabled and not enabled:
        raise GoogleConfigError("Google connector is not enabled. Set SECUREDACT_GOOGLE_ENABLED=1.")

    client_id = os.getenv("SECUREDACT_GOOGLE_CLIENT_ID") or None
    client_secret = os.getenv("SECUREDACT_GOOGLE_CLIENT_SECRET") or None

    # Fall back to the encrypted, machine-local client config store. The operator
    # supplies the client id/secret at setup time and they are persisted encrypted
    # under the machine data root (never as a machine env var). The SYSTEM-run
    # scheduled task loads them from here after the setup session closes and after
    # reboot. The environment always wins when present (local interactive sessions).
    if client_id is None or client_secret is None:
        store_dir = data_dir or SecuredactPaths.resolve().root
        try:
            store_id, store_secret = GoogleClientConfigStore(store_dir).load()
        except Exception:
            store_id = store_secret = None
        client_id = client_id or store_id
        client_secret = client_secret or store_secret

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
        # Explicit override always wins (preserves direct/local CLI behavior and
        # lets operators point at a specific token file regardless of profile).
        token_path = Path(token_path_override).expanduser()
        key_path = token_path.with_suffix(token_path.suffix + ".key")
    else:
        token_path, key_path = _resolve_token_paths(profile, data_dir=data_dir)

    return GoogleConnectorConfig(
        enabled=enabled,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        scopes=scopes,
        token_path=token_path,
        key_path=key_path,
    )


def save_google_client_config(
    data_dir: str | Path | None, client_id: str | None, client_secret: str | None
) -> None:
    """Persist the Google OAuth client (app) config encrypted under the machine root.

    This is the supported replacement for publishing ``SECUREDACT_GOOGLE_CLIENT_SECRET``
    at machine scope: the secret stays machine-local, encrypted at rest, and is loaded
    by the SYSTEM-run scheduled task after reboot -- never placed in argv, env, logs,
    or the control plane.
    """

    GoogleClientConfigStore(data_dir or SecuredactPaths.resolve().root).save(
        client_id, client_secret
    )


def load_google_client_config(
    data_dir: str | Path | None,
) -> tuple[str | None, str | None]:
    """Return the decrypted ``(client_id, client_secret)`` from the machine-local store."""

    return GoogleClientConfigStore(data_dir or SecuredactPaths.resolve().root).load()
