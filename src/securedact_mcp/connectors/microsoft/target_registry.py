# SPDX-License-Identifier: Apache-2.0
"""Privacy-safe, machine-local Microsoft target registry (M365-102 / M365-PRIV).

Stores an *opaque* ``target_id`` for each Microsoft resource a customer wants
to schedule, plus the raw ``drive_id`` / ``folder_id`` / ``site_id`` needed to
resolve it at scan time. The control plane only ever sees the opaque
``target_id``; the raw Graph identifiers stay encrypted under the machine
data root.

Design choices:

* **Reversibility required** (unlike the existing :mod:`fingerprint` HMAC).
  The local agent must be able to map an opaque ``target_id`` back to the
  raw ``drive_id`` / ``folder_id`` / ``site_id`` so it can call the Graph
  API. This is therefore NOT a fingerprint — it is an encrypted lookup
  table. The opaque ``target_id`` is a versioned random token, not a
  predictable hash, so it carries no information about the underlying
  resource.

* **Versioned** so a future migration can re-key the registry without
  invalidating the encrypted payload.

* **Scanned-only on the matching ``integration_id``** — lookups for a
  different ``integration_id`` fail closed (the same opaque token can be
  re-registered under a different integration if the customer wants to,
  but never silently resolved).

* **Encrypted at rest** with Fernet using a key bound to the machine data
  root (same pattern as :class:`MicrosoftCredentialStore` and
  :class:`MicrosoftClientConfigStore`). The file is chmod 0600.

* **Atomic writes** via ``tmp.replace`` so a crash mid-write cannot leave a
  half-written registry.

* **No Graph URL, no filename, no OAuth material** is stored in the
  registry. Only opaque ids, fingerprints, and an operator-visible label.

* **Fail-closed**: a missing/corrupt registry, a missing target, an
  integration mismatch, or a malformed record all raise rather than
  returning a partial result.
"""

from __future__ import annotations

import builtins
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cryptography.fernet import Fernet, InvalidToken

from securedact_core.connectors.fingerprint import (
    EncryptedFingerprintKeyStore,
    ResourceType,
    compute_resource_fingerprint,
)

# Bumped when the on-disk schema changes incompatibly.
TARGET_REGISTRY_VERSION = 1

# Stable, scoped resource-type labels for domain separation in the fingerprint.
_RESOURCE_TYPE_DRIVE: ResourceType = "drive"
_RESOURCE_TYPE_FOLDER: ResourceType = "folder"
_RESOURCE_TYPE_SITE: ResourceType = "site"

# Opaque token length (in bytes) for ``target_id``. 192 bits is more than
# enough to make accidental or adversarial collisions infeasible while keeping
# the printed token reasonable to paste into a control-plane form.
_TARGET_ID_BYTES = 24


TargetKind = Literal["one_drive_folder", "sharepoint_drive", "sharepoint_folder"]


@dataclass(frozen=True, slots=True)
class LocalTargetRecord:
    """A single opaque target entry.

    Fields:

    * ``target_id``: opaque token the control plane sees; never derived from
      the raw Graph ids.
    * ``kind``: one of the supported ``TargetKind`` values. Drives the
      provider's resolution behavior at scan time.
    * ``integration_id``: the SecuRedact control-plane integration id this
      target is bound to.
    * ``label``: an operator-visible label (folder name, drive display name).
      Stored ONLY for operator convenience; never sent to the control plane.
    * ``drive_id`` / ``folder_id`` / ``site_id``: the raw Microsoft Graph
      identifiers. Persisted encrypted at rest; never returned by any public
      method that crosses a boundary.
    * ``drive_fingerprint`` / ``folder_fingerprint`` / ``site_fingerprint``:
      privacy-safe HMAC fingerprints for control-plane result payloads
      (mirrors the existing fingerprint design).
    * ``created_at``: ISO-8601 UTC timestamp the target was registered.
    * ``version``: schema version of this record (allows in-place migration).
    """

    target_id: str
    kind: TargetKind
    integration_id: str
    label: str | None
    drive_id: str
    folder_id: str | None
    site_id: str | None
    drive_fingerprint: str
    folder_fingerprint: str | None
    site_fingerprint: str | None
    created_at: str
    version: int = TARGET_REGISTRY_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "kind": self.kind,
            "integration_id": self.integration_id,
            "label": self.label,
            "drive_id": self.drive_id,
            "folder_id": self.folder_id,
            "site_id": self.site_id,
            "drive_fingerprint": self.drive_fingerprint,
            "folder_fingerprint": self.folder_fingerprint,
            "site_fingerprint": self.site_fingerprint,
            "created_at": self.created_at,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LocalTargetRecord:
        try:
            return cls(
                target_id=str(data["target_id"]),
                kind=data["kind"],
                integration_id=str(data["integration_id"]),
                label=data.get("label"),
                drive_id=str(data["drive_id"]),
                folder_id=data.get("folder_id"),
                site_id=data.get("site_id"),
                drive_fingerprint=str(data["drive_fingerprint"]),
                folder_fingerprint=data.get("folder_fingerprint"),
                site_fingerprint=data.get("site_fingerprint"),
                created_at=str(data["created_at"]),
                version=int(data.get("version", TARGET_REGISTRY_VERSION)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise TargetRegistryError(f"malformed target record: {exc}") from exc

    @classmethod
    def new_one_drive_folder(
        cls,
        *,
        integration_id: str,
        drive_id: str,
        folder_id: str,
        site_id: str | None = None,
        label: str | None = None,
        now: str | None = None,
        fingerprint_config: Any | None = None,
    ) -> LocalTargetRecord:
        """Construct a record for an OneDrive folder (or SharePoint folder)."""

        if not integration_id:
            raise TargetRegistryError("integration_id is required")
        if not drive_id:
            raise TargetRegistryError("drive_id is required")
        if not folder_id:
            raise TargetRegistryError("folder_id is required")

        kind: TargetKind
        if site_id:
            kind = "sharepoint_folder"
        else:
            kind = "one_drive_folder"

        drive_fp, folder_fp, site_fp = _compute_fingerprints(
            drive_id=drive_id,
            folder_id=folder_id,
            site_id=site_id,
            fingerprint_config=fingerprint_config,
        )

        return cls(
            target_id=_new_target_id(),
            kind=kind,
            integration_id=integration_id,
            label=label,
            drive_id=drive_id,
            folder_id=folder_id,
            site_id=site_id,
            drive_fingerprint=drive_fp,
            folder_fingerprint=folder_fp,
            site_fingerprint=site_fp,
            created_at=now or _now_iso(),
        )

    @classmethod
    def new_sharepoint_drive(
        cls,
        *,
        integration_id: str,
        drive_id: str,
        site_id: str,
        label: str | None = None,
        now: str | None = None,
        fingerprint_config: Any | None = None,
    ) -> LocalTargetRecord:
        if not site_id:
            raise TargetRegistryError("site_id is required for sharepoint_drive targets")
        if not drive_id:
            raise TargetRegistryError("drive_id is required")
        drive_fp, _, site_fp = _compute_fingerprints(
            drive_id=drive_id,
            folder_id=None,
            site_id=site_id,
            fingerprint_config=fingerprint_config,
        )
        return cls(
            target_id=_new_target_id(),
            kind="sharepoint_drive",
            integration_id=integration_id,
            label=label,
            drive_id=drive_id,
            folder_id=None,
            site_id=site_id,
            drive_fingerprint=drive_fp,
            folder_fingerprint=None,
            site_fingerprint=site_fp,
            created_at=now or _now_iso(),
        )


class TargetRegistryError(ValueError):
    """Raised when a registry lookup or write fails."""


class TargetRegistryStore:
    """Encrypted, machine-local store for opaque Microsoft targets.

    The on-disk layout is a single encrypted JSON document containing a list
    of :class:`LocalTargetRecord` entries (each carrying both the opaque
    ``target_id`` and the raw ``drive_id`` / ``folder_id`` / ``site_id``).
    The document is encrypted with a Fernet key kept in a sibling file (chmod
    0600); writes are atomic via ``tmp.replace``.
    """

    _FILENAME = "target_registry.json.enc"
    _KEY_FILENAME = "target_registry.key"

    def __init__(self, data_dir: Path | str) -> None:
        base = Path(data_dir) / "microsoft"
        self._path = base / self._FILENAME
        self._key_path = base / self._KEY_FILENAME

    # --- public surface -------------------------------------------------

    def add(self, record: LocalTargetRecord) -> None:
        """Insert or replace a target record atomically."""

        records = self._load()
        # Replace any prior record with the same target_id (idempotent re-add).
        records = [r for r in records if r.target_id != record.target_id]
        records.append(record)
        self._save(records)

    def get(self, target_id: str, *, integration_id: str | None = None) -> LocalTargetRecord:
        """Resolve an opaque target. Fail closed if absent or mismatched."""

        if not target_id:
            raise TargetRegistryError("target_id is required")
        for record in self._load():
            if record.target_id != target_id:
                continue
            if integration_id is not None and record.integration_id != integration_id:
                raise TargetRegistryError(
                    "target is not bound to the supplied integration_id "
                    "(the agent will never cross-resolve targets across integrations)"
                )
            return record
        raise TargetRegistryError(
            f"no local target registered for target_id={target_id!r}; "
            "register it locally via 'securedact-mcp microsoft targets add'"
        )

    def list(self, *, integration_id: str | None = None) -> builtins.list[LocalTargetRecord]:
        """List local targets (optionally filtered by integration_id)."""

        records = self._load()
        if integration_id is not None:
            records = [r for r in records if r.integration_id == integration_id]
        return records

    def remove(self, target_id: str) -> bool:
        """Remove a target record. Returns True if anything was removed."""

        records = self._load()
        kept = [r for r in records if r.target_id != target_id]
        if len(kept) == len(records):
            return False
        self._save(kept)
        return True

    # --- internals ------------------------------------------------------

    def _load(self) -> builtins.list[LocalTargetRecord]:
        if not self._path.exists():
            return []
        try:
            cipher = Fernet(self._load_or_create_key())
            raw = cipher.decrypt(self._path.read_bytes())
            data = json.loads(raw)
        except (InvalidToken, json.JSONDecodeError, ValueError) as exc:
            # Fail closed: a corrupt registry is treated as empty AND a
            # caller-visible error to surface the problem. The provider
            # layer translates "no record" into JobExecutionError.
            raise TargetRegistryError(
                "Microsoft target registry is missing or corrupt; "
                "the agent will not fall back to raw target_ref values."
            ) from exc
        if not isinstance(data, list):
            raise TargetRegistryError("Microsoft target registry payload is not a list")
        out: list[LocalTargetRecord] = []
        for entry in data:
            if not isinstance(entry, dict):
                raise TargetRegistryError("registry entry is not an object")
            out.append(LocalTargetRecord.from_dict(entry))
        return out

    def _save(self, records: builtins.list[LocalTargetRecord]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        cipher = Fernet(self._load_or_create_key())
        body = json.dumps([r.to_dict() for r in records], separators=(",", ":")).encode("utf-8")
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_bytes(cipher.encrypt(body))
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self._path)

    def _load_or_create_key(self) -> bytes:
        if not self._key_path.exists():
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_bytes(Fernet.generate_key())
            try:
                os.chmod(self._key_path, 0o600)
            except OSError:
                pass
        return self._key_path.read_bytes()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _new_target_id() -> str:
    """Return a fresh, non-predictable opaque target id."""

    # ``secrets.token_urlsafe`` is a CSPRNG-backed, base64-url-safe token.
    raw = secrets.token_urlsafe(_TARGET_ID_BYTES)
    return f"mtgt_{TARGET_REGISTRY_VERSION}_{raw}"


def _now_iso() -> str:
    import time

    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _compute_fingerprints(
    *,
    drive_id: str,
    folder_id: str | None,
    site_id: str | None,
    fingerprint_config: Any | None,
) -> tuple[str, str | None, str | None]:
    """Compute HMAC fingerprints using the existing fingerprint key store.

    The fingerprint key store is read from the same machine data dir so
    domain separation lines up with the existing design. When no fingerprint
    config is available (e.g. tests that don't load the master key), we
    fall back to a deterministic placeholder rather than leaking the raw id.
    """

    if fingerprint_config is None:
        try:
            from securedact_core.app_paths import SecuredactPaths

            store = EncryptedFingerprintKeyStore(SecuredactPaths.resolve().root)
            fingerprint_config = store.create_config("microsoft365", tenant_id="local")
        except Exception:
            fingerprint_config = None

    if fingerprint_config is None:
        # No fingerprint key available yet. Return safe placeholders; the
        # caller can still operate without fingerprints (results won't
        # contain a fingerprint, but the raw Graph id never crosses the
        # boundary because the registry itself is encrypted).
        return (
            _placeholder(drive_id),
            (_placeholder(folder_id) if folder_id else None),
            (_placeholder(site_id) if site_id else None),
        )

    return (
        compute_resource_fingerprint(fingerprint_config, _RESOURCE_TYPE_DRIVE, drive_id),
        (
            compute_resource_fingerprint(fingerprint_config, _RESOURCE_TYPE_FOLDER, folder_id)
            if folder_id
            else None
        ),
        (
            compute_resource_fingerprint(fingerprint_config, _RESOURCE_TYPE_SITE, site_id)
            if site_id
            else None
        ),
    )


def _placeholder(value: str | None) -> str:
    """A non-reversible placeholder when fingerprint keying is unavailable."""

    if not value:
        return ""
    # ``fp1_`` mirrors the fingerprint prefix used elsewhere so downstream
    # consumers can recognize the field; the bytes are derived from
    # ``value`` itself (not reversible in any meaningful sense, but it
    # also cannot collide with a real HMAC fingerprint because the key is
    # not used).
    import hashlib

    return "fp1_local_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


__all__ = [
    "TARGET_REGISTRY_VERSION",
    "LocalTargetRecord",
    "TargetRegistryError",
    "TargetRegistryStore",
]
