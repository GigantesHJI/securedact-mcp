from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


class EncryptedLocalVault:
    """Optional encrypted mapping storage; the encryption key is never stored in SQLite."""

    def __init__(self, database_path: str | Path, key: bytes) -> None:
        self.path = Path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._cipher = Fernet(key)
        self._initialize()

    @staticmethod
    def generate_key() -> bytes:
        return Fernet.generate_key()

    def save_mapping(self, mapping_id: str, mapping: dict[str, str]) -> None:
        payload = json.dumps(mapping, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        encrypted = self._cipher.encrypt(payload)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO mappings (id, ciphertext, created_at) VALUES (?, ?, ?)",
                (mapping_id, encrypted, datetime.now(UTC).isoformat()),
            )

    def load_mapping(self, mapping_id: str) -> dict[str, str] | None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT ciphertext FROM mappings WHERE id = ?", (mapping_id,)
            ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(self._cipher.decrypt(row[0]))
        except (InvalidToken, json.JSONDecodeError) as exc:
            raise ValueError("Stored privacy mapping could not be decrypted") from exc
        if not isinstance(value, dict) or not all(
            isinstance(key, str) and isinstance(item, str) for key, item in value.items()
        ):
            raise ValueError("Stored privacy mapping is invalid")
        return value

    def delete_mapping(self, mapping_id: str) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute("DELETE FROM mappings WHERE id = ?", (mapping_id,))

    def _initialize(self) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS mappings (
                    id TEXT PRIMARY KEY,
                    ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
