# SPDX-License-Identifier: Apache-2.0
"""Encrypted local token storage for the Google connector (GWS-110).

Tokens are encrypted at rest with Fernet. The key is kept in a separate file
next to the token (same pattern as the existing :class:`EncryptedLocalVault`):
the key is never embedded in the token file and never logged. All methods fail
safe -- a missing/corrupt token is reported as ``None`` so the caller can
re-authenticate rather than leaking or crashing.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import cast

from cryptography.fernet import Fernet, InvalidToken


def _load_or_create_key(key_path: Path) -> bytes:
    """Return the Fernet key for ``key_path``, creating it (0600) if absent."""

    key_path = Path(key_path)
    if not key_path.exists():
        key = Fernet.generate_key()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(key)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
    return key_path.read_bytes()


class GoogleCredentialStore:
    """Stores the OAuth token JSON encrypted on disk."""

    def __init__(self, token_path: Path, key_path: Path) -> None:
        self.token_path = Path(token_path)
        self.key_path = Path(key_path)

    def _key(self) -> bytes:
        return _load_or_create_key(self.key_path)

    def save_token(self, token: dict[str, object]) -> None:
        """Encrypt and persist a token dict (e.g. from ``Credentials.to_json``)."""

        cipher = Fernet(self._key())
        payload = json.dumps(token, separators=(",", ":")).encode("utf-8")
        self.token_path.parent.mkdir(parents=True, exist_ok=True)
        self.token_path.write_bytes(cipher.encrypt(payload))
        try:
            os.chmod(self.token_path, 0o600)
        except OSError:
            pass

    def load_token(self) -> dict[str, object] | None:
        """Return the decrypted token dict, or ``None`` if absent/corrupt."""

        if not self.token_path.exists():
            return None
        try:
            cipher = Fernet(self._key())
            raw = cipher.decrypt(self.token_path.read_bytes())
            return cast("dict[str, object]", json.loads(raw))
        except (InvalidToken, json.JSONDecodeError, ValueError):
            return None

    def delete_token(self) -> None:
        self.token_path.unlink(missing_ok=True)


class GoogleClientConfigStore:
    """Encrypted, machine-local store for the Google OAuth client (app) config.

    Holds the non-token client credentials (``client_id`` and ``client_secret``)
    that an operator supplies during setup. They are encrypted at rest with
    Fernet under the SecuRedact machine data root so the SYSTEM-run scheduled
    task can load them after the setup PowerShell session closes and after a
    reboot -- without ever placing the secret in a machine-wide environment
    variable, argv, logs, or the control plane.

    The OAuth access/refresh tokens remain in :class:`GoogleCredentialStore`; this
    store is for the client (application) secret only.
    """

    def __init__(self, data_dir: Path | str) -> None:
        base = Path(data_dir) / "google"
        self._token_path = base / "client_config.json.enc"
        self._key_path = base / "client_config.key"

    def _key(self) -> bytes:
        return _load_or_create_key(self._key_path)

    def save(self, client_id: str | None, client_secret: str | None) -> None:
        """Encrypt and persist the client (app) config to the machine data root."""

        cipher = Fernet(self._key())
        payload = json.dumps(
            {"client_id": client_id, "client_secret": client_secret},
            separators=(",", ":"),
        ).encode("utf-8")
        self._token_path.parent.mkdir(parents=True, exist_ok=True)
        self._token_path.write_bytes(cipher.encrypt(payload))
        try:
            os.chmod(self._token_path, 0o600)
        except OSError:
            pass

    def load(self) -> tuple[str | None, str | None]:
        """Return the decrypted ``(client_id, client_secret)`` or ``(None, None)``."""

        if not self._token_path.exists():
            return None, None
        try:
            cipher = Fernet(self._key())
            raw = cipher.decrypt(self._token_path.read_bytes())
            data = json.loads(raw)
        except (InvalidToken, json.JSONDecodeError, ValueError):
            return None, None
        return data.get("client_id"), data.get("client_secret")
