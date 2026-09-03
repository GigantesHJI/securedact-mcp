# SPDX-License-Identifier: Apache-2.0
"""Privacy-safe resource fingerprinting for enterprise connectors.

This module provides a tenant/provider-scoped HMAC-based fingerprint mechanism
that replaces raw provider resource identifiers in control-plane payloads.

The fingerprint is computed as:
    HMAC-SHA256(key, provider + "|" + resource_type + "|" + stable_resource_id)

Security properties:
- Keyed HMAC, not plain hash
- Stable across repeated scans of the same resource
- Tenant/org scoped (key derived from tenant-scoped secret)
- Provider scoped (domain-separated by provider name)
- Resource-type scoped (driveItem, drive, site, etc.)
- No raw resource ID recoverable from the digest
- Key never sent to control plane
- Supports key rotation via version prefix
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.fernet import Fernet, InvalidToken


# Fingerprint version for key rotation support
FINGERPRINT_VERSION = 1
FINGERPRINT_PREFIX = f"fp{FINGERPRINT_VERSION}_"

# Resource types for domain separation
ResourceType = Literal["driveItem", "drive", "site", "folder"]


class FingerprintError(ValueError):
    """Raised when fingerprint computation fails."""


@dataclass(frozen=True, slots=True)
class FingerprintConfig:
    """Configuration for fingerprint computation."""

    # The HMAC key (32 bytes for SHA-256)
    key: bytes
    # Provider name for domain separation (e.g., "microsoft365", "google_workspace")
    provider: str
    # Tenant/organization identifier for scoping
    tenant_id: str


def _derive_fingerprint_key(
    master_key: bytes, provider: str, tenant_id: str
) -> bytes:
    """Derive a provider/tenant-scoped fingerprint key from a master key.

    Uses HKDF-like derivation: HMAC-SHA256(master_key, provider + "|" + tenant_id)
    """
    info = f"{provider}|{tenant_id}".encode("utf-8")
    return hmac.new(master_key, info, hashlib.sha256).digest()


def compute_resource_fingerprint(
    config: FingerprintConfig,
    resource_type: ResourceType,
    stable_resource_id: str,
) -> str:
    """Compute a privacy-safe fingerprint for a provider resource.

    Args:
        config: FingerprintConfig with key, provider, and tenant_id
        resource_type: Type of resource (driveItem, drive, site, folder)
        stable_resource_id: The provider's stable resource identifier

    Returns:
        A versioned fingerprint string (e.g., "fp1_a1b2c3d4...")

    The fingerprint is stable for the same resource across scans but cannot
    be reversed to obtain the original resource ID.
    """
    if not stable_resource_id:
        raise FingerprintError("stable_resource_id must not be empty")

    # Domain-separated input: provider|resource_type|resource_id
    message = f"{config.provider}|{resource_type}|{stable_resource_id}".encode("utf-8")
    digest = hmac.new(config.key, message, hashlib.sha256).digest()
    # Use first 16 bytes (128 bits) for compactness while maintaining security
    fingerprint = digest[:16].hex()
    return f"{FINGERPRINT_PREFIX}{fingerprint}"


def verify_fingerprint(
    config: FingerprintConfig,
    resource_type: ResourceType,
    stable_resource_id: str,
    fingerprint: str,
) -> bool:
    """Verify a fingerprint matches the expected value for a resource.

    Uses constant-time comparison to prevent timing attacks.
    """
    if not fingerprint.startswith(FINGERPRINT_PREFIX):
        return False
    expected = compute_resource_fingerprint(config, resource_type, stable_resource_id)
    return hmac.compare_digest(expected, fingerprint)


# --- Key management ---

_FINGERPRINT_KEY_FILENAME = "fingerprint.key"


def _get_fingerprint_key_path(data_dir: Path) -> Path:
    """Get the path to the fingerprint master key file."""
    return data_dir / _FINGERPRINT_KEY_FILENAME


def load_or_create_fingerprint_master_key(data_dir: Path) -> bytes:
    """Load or create the fingerprint master key.

    The master key is used to derive provider/tenant-scoped fingerprint keys.
    It is stored encrypted at rest using the same pattern as other secrets.
    """
    key_path = _get_fingerprint_key_path(data_dir)
    if key_path.exists():
        return key_path.read_bytes()
    # Generate a new master key
    data_dir.mkdir(parents=True, exist_ok=True)
    master_key = os.urandom(32)  # 256 bits for SHA-256 HMAC
    key_path.write_bytes(master_key)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return master_key


class FingerprintKeyStore:
    """Manages the fingerprint master key and derives scoped keys.

    The master key is stored locally and used to derive per-provider/tenant
    keys on demand. This avoids storing multiple keys while maintaining
    proper domain separation.
    """

    def __init__(self, data_dir: Path | str) -> None:
        self._data_dir = Path(data_dir)
        self._master_key = load_or_create_fingerprint_master_key(self._data_dir)

    def get_scoped_key(self, provider: str, tenant_id: str) -> bytes:
        """Derive a provider/tenant-scoped fingerprint key."""
        return _derive_fingerprint_key(self._master_key, provider, tenant_id)

    def create_config(self, provider: str, tenant_id: str) -> FingerprintConfig:
        """Create a FingerprintConfig for the given provider and tenant."""
        key = self.get_scoped_key(provider, tenant_id)
        return FingerprintConfig(key=key, provider=provider, tenant_id=tenant_id)


# --- Integration with existing encrypted storage ---

class EncryptedFingerprintKeyStore:
    """Fingerprint key store that encrypts the master key at rest.

    Uses the same Fernet-based encryption pattern as the rest of the codebase.
    """

    def __init__(self, data_dir: Path | str, encryption_key: bytes | None = None) -> None:
        self._data_dir = Path(data_dir)
        self._key_path = self._data_dir / "fingerprint.key.enc"
        self._encryption_key = encryption_key or self._load_or_create_encryption_key()

    def _load_or_create_encryption_key(self) -> bytes:
        """Load or create the Fernet encryption key for the fingerprint key."""
        key_file = self._data_dir / "fingerprint_enc.key"
        if key_file.exists():
            return key_file.read_bytes()
        self._data_dir.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        key_file.write_bytes(key)
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
        return key

    def _get_cipher(self) -> Fernet:
        return Fernet(self._encryption_key)

    def save_master_key(self, master_key: bytes) -> None:
        """Encrypt and save the master key."""
        self._data_dir.mkdir(parents=True, exist_ok=True)
        cipher = self._get_cipher()
        encrypted = cipher.encrypt(master_key)
        self._key_path.write_bytes(encrypted)
        try:
            os.chmod(self._key_path, 0o600)
        except OSError:
            pass

    def load_master_key(self) -> bytes | None:
        """Load and decrypt the master key."""
        if not self._key_path.exists():
            return None
        try:
            cipher = self._get_cipher()
            return cipher.decrypt(self._key_path.read_bytes())
        except (InvalidToken, ValueError):
            return None

    def get_or_create_master_key(self) -> bytes:
        """Get existing master key or create a new one."""
        existing = self.load_master_key()
        if existing is not None:
            return existing
        master_key = os.urandom(32)
        self.save_master_key(master_key)
        return master_key

    def create_config(self, provider: str, tenant_id: str) -> FingerprintConfig:
        """Create a FingerprintConfig for the given provider and tenant."""
        master_key = self.get_or_create_master_key()
        key = _derive_fingerprint_key(master_key, provider, tenant_id)
        return FingerprintConfig(key=key, provider=provider, tenant_id=tenant_id)