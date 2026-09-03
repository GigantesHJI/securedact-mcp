# SPDX-License-Identifier: Apache-2.0
"""Tests for privacy-safe resource fingerprinting (M365-102)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from securedact_core.connectors.fingerprint import (
    EncryptedFingerprintKeyStore,
    FingerprintConfig,
    ResourceType,
    _derive_fingerprint_key,
    compute_resource_fingerprint,
    verify_fingerprint,
)


class TestFingerprintBasics:
    """Basic fingerprint computation and verification tests."""

    def test_same_resource_same_fingerprint(self):
        """Same resource with same config produces same fingerprint."""
        config = FingerprintConfig(
            key=b"a" * 32,
            provider="microsoft365",
            tenant_id="tenant-1",
        )
        fp1 = compute_resource_fingerprint(config, "driveItem", "item-123")
        fp2 = compute_resource_fingerprint(config, "driveItem", "item-123")
        assert fp1 == fp2
        assert fp1.startswith("fp1_")

    def test_different_resource_different_fingerprint(self):
        """Different resources produce different fingerprints."""
        config = FingerprintConfig(
            key=b"a" * 32,
            provider="microsoft365",
            tenant_id="tenant-1",
        )
        fp1 = compute_resource_fingerprint(config, "driveItem", "item-123")
        fp2 = compute_resource_fingerprint(config, "driveItem", "item-456")
        assert fp1 != fp2

    def test_different_resource_type_different_fingerprint(self):
        """Different resource types produce different fingerprints."""
        config = FingerprintConfig(
            key=b"a" * 32,
            provider="microsoft365",
            tenant_id="tenant-1",
        )
        fp1 = compute_resource_fingerprint(config, "driveItem", "item-123")
        fp2 = compute_resource_fingerprint(config, "drive", "item-123")
        assert fp1 != fp2

    def test_different_tenant_different_fingerprint(self):
        """Different tenants produce different fingerprints for same resource.

        This works because different tenants get different derived keys.
        """
        # Use key derivation to get different keys for different tenants
        master_key = b"master" * 4
        key1 = _derive_fingerprint_key(master_key, "microsoft365", "tenant-1")
        key2 = _derive_fingerprint_key(master_key, "microsoft365", "tenant-2")
        config1 = FingerprintConfig(
            key=key1,
            provider="microsoft365",
            tenant_id="tenant-1",
        )
        config2 = FingerprintConfig(
            key=key2,
            provider="microsoft365",
            tenant_id="tenant-2",
        )
        fp1 = compute_resource_fingerprint(config1, "driveItem", "item-123")
        fp2 = compute_resource_fingerprint(config2, "driveItem", "item-123")
        assert fp1 != fp2

    def test_different_provider_different_fingerprint(self):
        """Different providers produce different fingerprints."""
        config1 = FingerprintConfig(
            key=b"a" * 32,
            provider="microsoft365",
            tenant_id="tenant-1",
        )
        config2 = FingerprintConfig(
            key=b"a" * 32,
            provider="google_workspace",
            tenant_id="tenant-1",
        )
        fp1 = compute_resource_fingerprint(config1, "driveItem", "item-123")
        fp2 = compute_resource_fingerprint(config2, "driveItem", "item-123")
        assert fp1 != fp2

    def test_different_key_different_fingerprint(self):
        """Different HMAC keys produce different fingerprints."""
        config1 = FingerprintConfig(
            key=b"a" * 32,
            provider="microsoft365",
            tenant_id="tenant-1",
        )
        config2 = FingerprintConfig(
            key=b"b" * 32,
            provider="microsoft365",
            tenant_id="tenant-1",
        )
        fp1 = compute_resource_fingerprint(config1, "driveItem", "item-123")
        fp2 = compute_resource_fingerprint(config2, "driveItem", "item-123")
        assert fp1 != fp2

    def test_verify_fingerprint(self):
        """Fingerprint verification works correctly."""
        config = FingerprintConfig(
            key=b"a" * 32,
            provider="microsoft365",
            tenant_id="tenant-1",
        )
        fp = compute_resource_fingerprint(config, "driveItem", "item-123")
        assert verify_fingerprint(config, "driveItem", "item-123", fp) is True
        assert verify_fingerprint(config, "driveItem", "item-456", fp) is False
        assert verify_fingerprint(config, "drive", "item-123", fp) is False


class TestKeyDerivation:
    """Key derivation tests."""

    def test_derive_fingerprint_key_deterministic(self):
        """Key derivation is deterministic."""
        key1 = _derive_fingerprint_key(b"master" * 4, "microsoft365", "tenant-1")
        key2 = _derive_fingerprint_key(b"master" * 4, "microsoft365", "tenant-1")
        assert key1 == key2
        assert len(key1) == 32

    def test_derive_fingerprint_key_different_inputs(self):
        """Different inputs produce different derived keys."""
        key1 = _derive_fingerprint_key(b"master" * 4, "microsoft365", "tenant-1")
        key2 = _derive_fingerprint_key(b"master" * 4, "microsoft365", "tenant-2")
        key3 = _derive_fingerprint_key(b"master" * 4, "google_workspace", "tenant-1")
        assert key1 != key2
        assert key1 != key3


class TestEncryptedFingerprintKeyStore:
    """Tests for the encrypted fingerprint key store."""

    def test_get_or_create_master_key(self):
        """Master key is created and retrieved correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            store = EncryptedFingerprintKeyStore(data_dir)
            key1 = store.get_or_create_master_key()
            key2 = store.get_or_create_master_key()
            assert key1 == key2
            assert len(key1) == 32

    def test_create_config(self):
        """FingerprintConfig is created with derived key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            store = EncryptedFingerprintKeyStore(data_dir)
            config = store.create_config("microsoft365", "tenant-1")
            assert isinstance(config, FingerprintConfig)
            assert config.provider == "microsoft365"
            assert config.tenant_id == "tenant-1"
            assert len(config.key) == 32

    def test_same_config_same_key(self):
        """Multiple configs for same provider/tenant use same key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            store = EncryptedFingerprintKeyStore(data_dir)
            config1 = store.create_config("microsoft365", "tenant-1")
            config2 = store.create_config("microsoft365", "tenant-1")
            assert config1.key == config2.key

    def test_different_tenant_different_key(self):
        """Different tenants get different keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            store = EncryptedFingerprintKeyStore(data_dir)
            config1 = store.create_config("microsoft365", "tenant-1")
            config2 = store.create_config("microsoft365", "tenant-2")
            assert config1.key != config2.key

    def test_persistence_across_instances(self):
        """Master key persists across store instances."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            store1 = EncryptedFingerprintKeyStore(data_dir)
            key1 = store1.get_or_create_master_key()
            store2 = EncryptedFingerprintKeyStore(data_dir)
            key2 = store2.get_or_create_master_key()
            assert key1 == key2


class TestFingerprintInScanResults:
    """Tests verifying fingerprints appear correctly in scan results."""

    def test_fingerprint_format(self):
        """Fingerprint has correct versioned format."""
        config = FingerprintConfig(
            key=b"a" * 32,
            provider="microsoft365",
            tenant_id="tenant-1",
        )
        fp = compute_resource_fingerprint(config, "driveItem", "item-123")
        assert fp.startswith("fp1_")
        # 16 bytes = 32 hex chars
        assert len(fp) == len("fp1_") + 32

    def test_raw_id_not_in_fingerprint(self):
        """Raw resource ID cannot be recovered from fingerprint."""
        config = FingerprintConfig(
            key=b"a" * 32,
            provider="microsoft365",
            tenant_id="tenant-1",
        )
        raw_id = "01D4FA2B3C4D5E6F!123"
        fp = compute_resource_fingerprint(config, "driveItem", raw_id)
        assert raw_id not in fp
        assert "01D4FA2B3C4D5E6F" not in fp
        assert "123" not in fp  # Not trivially extractable

    def test_fingerprint_stable_across_calls(self):
        """Fingerprint is stable across multiple computations."""
        config = FingerprintConfig(
            key=b"a" * 32,
            provider="microsoft365",
            tenant_id="tenant-1",
        )
        fingerprints = [compute_resource_fingerprint(config, "driveItem", "item-123") for _ in range(100)]
        assert len(set(fingerprints)) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])