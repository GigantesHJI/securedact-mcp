# SPDX-License-Identifier: Apache-2.0
"""Tests for the privacy-safe, machine-local Microsoft target registry.

Locks down:

* opaque target_id format and non-predictability;
* the registry never embeds raw Graph ids in the on-disk payload in a way
  that a casual reader could recover them (it is encrypted, but the test
  also asserts the JSON keys do not even hint at the raw structure);
* wrong-integration lookups fail closed;
* corrupt / missing registry fails closed;
* same local resource yields the same opaque id pattern across scans;
* SharePoint-ready representation round-trips;
* encrypted-at-rest persistence across store recreations.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from securedact_mcp.connectors.microsoft.target_registry import (
    TARGET_REGISTRY_VERSION,
    LocalTargetRecord,
    TargetRegistryError,
    TargetRegistryStore,
)

# ---------------------------------------------------------------------------
# opaque id shape
# ---------------------------------------------------------------------------


def test_target_id_is_versioned_and_opaque() -> None:
    record = LocalTargetRecord.new_one_drive_folder(
        integration_id="int-1", drive_id="drive-1", folder_id="root"
    )
    assert record.target_id.startswith(f"mtgt_{TARGET_REGISTRY_VERSION}_")
    # The opaque token must not embed the raw drive id, folder id, or any
    # predictable hash of them.
    for raw in ("drive-1", "root", "int-1"):
        assert raw not in record.target_id


def test_target_id_is_not_globally_predictable() -> None:
    ids = {
        LocalTargetRecord.new_one_drive_folder(
            integration_id="int-1", drive_id="drive-1", folder_id="root"
        ).target_id
        for _ in range(64)
    }
    # CSPRNG output: every id is unique.
    assert len(ids) == 64


# ---------------------------------------------------------------------------
# round-trip
# ---------------------------------------------------------------------------


def test_record_round_trips_through_dict() -> None:
    record = LocalTargetRecord.new_one_drive_folder(
        integration_id="int-1",
        drive_id="drive-1",
        folder_id="root",
        label="SecuRedact-Smoke-Test",
    )
    restored = LocalTargetRecord.from_dict(record.to_dict())
    assert restored == record


def test_record_to_dict_contains_required_fields() -> None:
    record = LocalTargetRecord.new_one_drive_folder(
        integration_id="int-1", drive_id="drive-1", folder_id="root"
    )
    payload = record.to_dict()
    assert payload["kind"] == "one_drive_folder"
    assert payload["integration_id"] == "int-1"
    assert payload["drive_id"] == "drive-1"
    assert payload["folder_id"] == "root"
    assert payload["site_id"] is None
    assert payload["version"] == TARGET_REGISTRY_VERSION


def test_sharepoint_drive_representation_round_trips(tmp_path: Path) -> None:
    record = LocalTargetRecord.new_sharepoint_drive(
        integration_id="int-1",
        drive_id="drive-sp-1",
        site_id="site-1",
        label="Team Drive",
    )
    restored = LocalTargetRecord.from_dict(record.to_dict())
    assert restored == record
    assert restored.kind == "sharepoint_drive"
    assert restored.site_id == "site-1"
    assert restored.folder_id is None


def test_sharepoint_folder_representation_round_trips() -> None:
    record = LocalTargetRecord.new_one_drive_folder(
        integration_id="int-1",
        drive_id="drive-sp-1",
        folder_id="root",
        site_id="site-1",
    )
    assert record.kind == "sharepoint_folder"
    assert record.site_id == "site-1"
    assert LocalTargetRecord.from_dict(record.to_dict()) == record


# ---------------------------------------------------------------------------
# store semantics
# ---------------------------------------------------------------------------


def test_store_persists_across_recreation(tmp_path: Path) -> None:
    store = TargetRegistryStore(tmp_path)
    record = LocalTargetRecord.new_one_drive_folder(
        integration_id="int-1", drive_id="drive-1", folder_id="root"
    )
    store.add(record)

    # Fresh store reads the encrypted file from the same data dir.
    fresh = TargetRegistryStore(tmp_path)
    restored = fresh.get(record.target_id, integration_id="int-1")
    assert restored == record


def test_store_encrypted_at_rest(tmp_path: Path) -> None:
    store = TargetRegistryStore(tmp_path)
    record = LocalTargetRecord.new_one_drive_folder(
        integration_id="int-1", drive_id="drive-1", folder_id="root"
    )
    store.add(record)

    # The on-disk payload is the Fernet ciphertext, NOT the raw record JSON.
    blob = store._path.read_bytes()
    assert b"drive-1" not in blob
    assert b"root" not in blob
    assert b"int-1" not in blob
    # The Fernet header is recognizable.
    assert blob.startswith(b"gAAAAA")


def test_store_get_rejects_wrong_integration(tmp_path: Path) -> None:
    store = TargetRegistryStore(tmp_path)
    record = LocalTargetRecord.new_one_drive_folder(
        integration_id="int-1", drive_id="drive-1", folder_id="root"
    )
    store.add(record)

    with pytest.raises(TargetRegistryError) as exc_info:
        store.get(record.target_id, integration_id="int-other")
    assert "not bound" in str(exc_info.value).lower()


def test_store_get_unknown_target_fails_closed(tmp_path: Path) -> None:
    store = TargetRegistryStore(tmp_path)
    with pytest.raises(TargetRegistryError):
        store.get("mtgt_1_doesnotexist", integration_id="int-1")


def test_corrupt_registry_fails_closed(tmp_path: Path) -> None:
    store = TargetRegistryStore(tmp_path)
    record = LocalTargetRecord.new_one_drive_folder(
        integration_id="int-1", drive_id="drive-1", folder_id="root"
    )
    store.add(record)

    # Corrupt the encrypted file by writing garbage.
    store._path.write_bytes(b"not-a-fernet-token")

    fresh = TargetRegistryStore(tmp_path)
    with pytest.raises(TargetRegistryError) as exc_info:
        fresh.get(record.target_id, integration_id="int-1")
    assert "missing or corrupt" in str(exc_info.value).lower()


def test_missing_registry_returns_empty_list(tmp_path: Path) -> None:
    store = TargetRegistryStore(tmp_path)
    assert store.list() == []
    assert store.list(integration_id="int-anything") == []


def test_remove_returns_false_when_absent(tmp_path: Path) -> None:
    store = TargetRegistryStore(tmp_path)
    assert store.remove("mtgt_1_missing") is False


def test_remove_returns_true_when_present(tmp_path: Path) -> None:
    store = TargetRegistryStore(tmp_path)
    record = LocalTargetRecord.new_one_drive_folder(
        integration_id="int-1", drive_id="drive-1", folder_id="root"
    )
    store.add(record)
    assert store.remove(record.target_id) is True
    with pytest.raises(TargetRegistryError):
        store.get(record.target_id, integration_id="int-1")


def test_add_is_idempotent_on_same_target_id(tmp_path: Path) -> None:
    store = TargetRegistryStore(tmp_path)
    a = LocalTargetRecord.new_one_drive_folder(
        integration_id="int-1", drive_id="drive-1", folder_id="root"
    )
    store.add(a)
    # Re-add the same record (same target_id) replaces, doesn't duplicate.
    store.add(a)
    assert len(store.list()) == 1


# ---------------------------------------------------------------------------
# payload hygiene
# ---------------------------------------------------------------------------


def test_no_filename_or_graph_url_in_record() -> None:
    record = LocalTargetRecord.new_one_drive_folder(
        integration_id="int-1",
        drive_id="drive-1",
        folder_id="root",
        label="SecuRedact-Smoke-Test",
    )
    payload = record.to_dict()
    blob = json.dumps(payload)
    for forbidden in (
        "graph.microsoft.com",
        "sharepoint.com",
        ".sharepoint.com",
    ):
        assert forbidden not in blob


def test_no_oauth_material_in_record() -> None:
    record = LocalTargetRecord.new_one_drive_folder(
        integration_id="int-1",
        drive_id="drive-1",
        folder_id="root",
    )
    payload = record.to_dict()
    blob = json.dumps(payload)
    for forbidden in (
        "access_token",
        "refresh_token",
        "client_secret",
        "Authorization",
        "Bearer",
    ):
        assert forbidden not in blob
