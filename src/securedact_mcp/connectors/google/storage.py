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


class GoogleCredentialStore:
    """Stores the OAuth token JSON encrypted on disk."""

    def __init__(self, token_path: Path, key_path: Path) -> None:
        self.token_path = Path(token_path)
        self.key_path = Path(key_path)

    def _key(self) -> bytes:
        if not self.key_path.exists():
            key = Fernet.generate_key()
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            self.key_path.write_bytes(key)
            try:
                os.chmod(self.key_path, 0o600)
            except OSError:
                pass
        return self.key_path.read_bytes()

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
