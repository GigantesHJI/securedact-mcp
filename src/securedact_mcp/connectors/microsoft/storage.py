# SPDX-License-Identifier: Apache-2.0
"""Encrypted local token storage for the Microsoft connector (M365-102).

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


class MicrosoftCredentialStore:
    """Stores the OAuth token JSON encrypted on disk."""

    def __init__(self, token_path: Path, key_path: Path) -> None:
        self.token_path = Path(token_path)
        self.key_path = Path(key_path)

    def _key(self) -> bytes:
        return _load_or_create_key(self.key_path)

    def save_token(self, token: dict[str, object]) -> None:
        """Encrypt and persist a token dict (e.g. from MSAL token cache)."""

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
