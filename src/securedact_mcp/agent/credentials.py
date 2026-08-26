# SPDX-License-Identifier: Apache-2.0
"""Secure local storage for the issued agent credential (AGENT-004).

The control plane returns the raw ``sra_<id>_<secret>`` credential exactly once,
at registration or rotation. It is never logged, never sent back to the control
plane in any body, and is persisted only in OS-protected storage:

* ``keyring`` (when available and selected) stores it in the platform credential
  manager; or
* an encrypted SQLite vault (Fernet) keyed by a per-machine key file under the
  agent directory, as a fallback.

The credential is always sent as ``Authorization: Bearer <raw credential>``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import InvalidToken

from securedact_core.storage import EncryptedLocalVault

from .errors import AgentCredentialError

_CREDENTIAL_SERVICE_NAME = "securedact-agent"
_DEFAULT_BACKEND = "file"


@dataclass(frozen=True, slots=True)
class AgentCredential:
    """An issued agent credential (the raw ``sra_..._<secret>`` string)."""

    raw: str

    @property
    def authorization_header(self) -> str:
        """Return the ``Authorization`` header value for this credential."""

        return f"Bearer {self.raw}"

    @property
    def credential_id(self) -> str:
        """Return the public lookup id portion (``sra_<id>``), never the secret."""

        parts = self.raw.split("_")
        if len(parts) >= 3 and parts[0] == "sra":
            return parts[1]
        return ""


class AgentCredentialStore:
    """Persists and rotates the agent credential in OS-protected storage."""

    def __init__(self, agent_id: str, *, root: Path, backend: str | None = None) -> None:
        self._agent_id = agent_id
        self._root = Path(root)
        self._backend = backend or os.getenv(
            "SECUREDACT_AGENT_CREDENTIAL_BACKEND", _DEFAULT_BACKEND
        )
        self._key_path = self._root / "credential.key"
        self._vault_path = self._root / "credentials.db"

    def get(self) -> AgentCredential | None:
        raw = self._read_raw()
        if not raw:
            return None
        return AgentCredential(raw=raw)

    def save(self, raw: str) -> AgentCredential:
        if not raw or not raw.startswith("sra_"):
            raise AgentCredentialError("refusing to store a malformed credential")
        self._write_raw(raw)
        return AgentCredential(raw=raw)

    def delete(self) -> None:
        self._delete_raw()

    def rotate(self, new_raw: str) -> AgentCredential:
        """Atomically replace the stored credential; call only after server accepts."""

        return self.save(new_raw)

    # --- backends -------------------------------------------------------------

    def _read_raw(self) -> str | None:
        if self._backend == "keyring":
            return self._read_keyring()
        return self._read_vault()

    def _write_raw(self, raw: str) -> None:
        if self._backend == "keyring":
            self._write_keyring(raw)
            return
        self._write_vault(raw)

    def _delete_raw(self) -> None:
        if self._backend == "keyring":
            self._delete_keyring()
            return
        self._root.mkdir(parents=True, exist_ok=True)
        try:
            vault = EncryptedLocalVault(self._vault_path, self._key())
            vault.delete_mapping(self._agent_id)
        except (InvalidToken, ValueError):
            pass

    def _key(self) -> bytes:
        if self._key_path.exists():
            return self._key_path.read_bytes()
        self._root.mkdir(parents=True, exist_ok=True)
        key = EncryptedLocalVault.generate_key()
        self._key_path.write_bytes(key)
        _restrict(self._key_path)
        return key

    def _vault(self) -> EncryptedLocalVault:
        return EncryptedLocalVault(self._vault_path, self._key())

    def _read_vault(self) -> str | None:
        try:
            vault = self._vault()
        except (InvalidToken, ValueError):
            return None
        mapping = vault.load_mapping(self._agent_id)
        if mapping is None:
            return None
        return mapping.get("credential")

    def _write_vault(self, raw: str) -> None:
        self._vault().save_mapping(self._agent_id, {"credential": raw})

    def _read_keyring(self) -> str | None:
        try:
            import keyring
        except Exception:
            return None
        try:
            return keyring.get_password(_CREDENTIAL_SERVICE_NAME, self._agent_id)
        except Exception:
            return None

    def _write_keyring(self, raw: str) -> None:
        import keyring

        keyring.set_password(_CREDENTIAL_SERVICE_NAME, self._agent_id, raw)

    def _delete_keyring(self) -> None:
        try:
            import keyring
        except Exception:
            return
        try:
            keyring.delete_password(_CREDENTIAL_SERVICE_NAME, self._agent_id)
        except Exception:  # noqa: S110  # best-effort keyring cleanup; a failed delete does not affect rotation
            pass


def _restrict(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
