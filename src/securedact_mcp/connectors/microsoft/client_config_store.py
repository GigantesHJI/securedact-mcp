# SPDX-License-Identifier: Apache-2.0
"""Encrypted, machine-local store for the Microsoft Entra client (app) config.

Holds the non-token client credentials (``client_id``, ``client_secret``, and
``tenant_id``) that an operator supplies during setup. They are encrypted at
rest with Fernet under the SecuRedact machine data root so the SYSTEM-run
scheduled task can load them after the setup PowerShell session closes and
after a reboot — without ever placing the secret in a machine-wide
environment variable, argv, logs, or the control plane.

The OAuth access/refresh tokens remain in :class:`MicrosoftCredentialStore`;
this store is for the client (application) configuration only.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

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


class MicrosoftClientConfigStore:
    """Encrypted, machine-local store for the Microsoft Entra client (app) config."""

    def __init__(self, data_dir: Path | str) -> None:
        base = Path(data_dir) / "microsoft"
        self._token_path = base / "client_config.json.enc"
        self._key_path = base / "client_config.key"

    def _key(self) -> bytes:
        return _load_or_create_key(self._key_path)

    def save(
        self,
        client_id: str | None,
        client_secret: str | None,
        *,
        tenant_id: str | None = None,
    ) -> None:
        """Encrypt and persist the client (app) config to the machine data root.

        ``tenant_id`` is optional and only persisted when supplied. When omitted
        on a subsequent save, the previously stored tenant id is preserved.
        """

        # Round-trip the existing payload so we can preserve a tenant_id that
        # was previously stored without overwriting it with ``None``.
        _existing_cid, _existing_secret, existing_tid = self.load_full()
        payload = {
            "client_id": client_id,
            "client_secret": client_secret,
            "tenant_id": tenant_id if tenant_id is not None else existing_tid,
        }
        cipher = Fernet(self._key())
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self._token_path.parent.mkdir(parents=True, exist_ok=True)
        self._token_path.write_bytes(cipher.encrypt(body))
        try:
            os.chmod(self._token_path, 0o600)
        except OSError:
            pass

    def load(self) -> tuple[str | None, str | None]:
        """Return the decrypted ``(client_id, client_secret)`` or ``(None, None)``."""

        cid, secret, _tid = self.load_full()
        return cid, secret

    def load_full(self) -> tuple[str | None, str | None, str | None]:
        """Return the decrypted ``(client_id, client_secret, tenant_id)`` triple.

        Missing or corrupt storage returns ``(None, None, None)`` so the caller
        can fail closed.
        """

        if not self._token_path.exists():
            return None, None, None
        try:
            cipher = Fernet(self._key())
            raw = cipher.decrypt(self._token_path.read_bytes())
            data = json.loads(raw)
        except (InvalidToken, json.JSONDecodeError, ValueError):
            return None, None, None
        return (
            data.get("client_id"),
            data.get("client_secret"),
            data.get("tenant_id"),
        )
