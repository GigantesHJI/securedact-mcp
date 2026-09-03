# SPDX-License-Identifier: Apache-2.0
"""Privacy-boundary regression tests for the Microsoft managed-agent path.

These tests simulate the exact first live smoke test:

    1. ``microsoft setup`` (configuration only, encrypted at rest)
    2. ``microsoft status`` (no secrets in output)
    3. ``agent connector bind microsoft365``
    4. local target discovery + registration (opaque target_id only)
    5. job with ``target_type="folder"``, ``target_ref=mtgt_...``
    6. provider resolves via local registry
    7. scan exactly the three synthetic files

The tests assert that no raw driveId, folderId, siteId, driveItemId, Graph
URL, OAuth token, filename or PII crosses the managed-agent boundary in the
new documented workflow. The control plane only sees:

* the opaque ``mtgt_...`` target_ref,
* bounded aggregate result metadata,
* the registered integration_id.

All Graph I/O uses the injected mock transport (no live network).
"""

from __future__ import annotations

import io
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

import securedact_mcp.connectors.microsoft.cli_commands as microsoft_cli
import securedact_mcp.connectors.microsoft.client as microsoft_client_mod
import securedact_mcp.connectors.microsoft.config as microsoft_config_mod
from securedact_core import SecuredactEngine
from securedact_core.app_paths import SecuredactPaths
from securedact_core.connectors.fingerprint import EncryptedFingerprintKeyStore, FingerprintConfig
from securedact_core.policies import STRICT_EXTERNAL_AI_POLICY
from securedact_core.production import build_production_engine
from securedact_mcp.agent.agent_runner import _submit_result
from securedact_mcp.agent.client import ControlPlaneClient
from securedact_mcp.agent.connectors import ConnectorBinding, ConnectorBindingStore
from securedact_mcp.agent.executor import JobClaim, ScanTarget, execute_job
from securedact_mcp.agent.policy import ResolvedPolicy
from securedact_mcp.agent.provider_microsoft import MicrosoftScanProvider
from securedact_mcp.connectors.microsoft.config import MicrosoftConnectorConfig
from securedact_mcp.connectors.microsoft.target_registry import (
    LocalTargetRecord,
    TargetRegistryStore,
)
from tests.unit.agent_helpers import FakeTransport, fake_claim
from tests.unit.microsoft_transport_fake import FakeMicrosoftTransport

SYNTHETIC_FILES = {
    "clean.txt": b"Nothing sensitive here.\n",
    "customer-test.txt": b"Customer contact: customer@example.test\n",
    "medical-test.txt": b"Patient: test@example.test\n",
}


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def data_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    base = Path(tempfile.mkdtemp(prefix="ms_priv_", dir=tmp_path))
    monkeypatch.setattr(SecuredactPaths, "resolve", lambda: _FakePaths(base))
    return base


@pytest.fixture
def fingerprint_store(monkeypatch: pytest.MonkeyPatch, data_dir: Path) -> EncryptedFingerprintKeyStore:
    store = EncryptedFingerprintKeyStore(data_dir)

    cfg = FingerprintConfig(
        key=b"test-key-for-testing-" + b"x" * 12,
        provider="microsoft365",
        tenant_id="int-1",
    )

    # Capture the ORIGINAL create_config so we can call it from the patched
    # version without recursing through the monkeypatch.
    _original_create_config = EncryptedFingerprintKeyStore.create_config

    def fake_create(self, provider: str, tenant_id: str):
        if provider == "microsoft365" and tenant_id == "int-1":
            return cfg
        return _original_create_config(self, provider, tenant_id)

    import securedact_mcp.agent.provider_microsoft as provider_microsoft

    monkeypatch.setattr(provider_microsoft, "EncryptedFingerprintKeyStore", lambda *a, **k: store)
    monkeypatch.setattr(EncryptedFingerprintKeyStore, "create_config", fake_create)
    return store


@pytest.fixture
def microsoft_config(monkeypatch: pytest.MonkeyPatch, data_dir: Path) -> MicrosoftConnectorConfig:
    config = MicrosoftConnectorConfig(
        enabled=True,
        client_id="test-client-id",
        client_secret="test-client-secret",  # noqa: S106  # test fixture, not a real secret
        tenant_id="test-tenant",
        redirect_uri="http://localhost:8080/",
        scopes=["User.Read", "Files.Read", "Sites.Read.All", "offline_access"],
        token_path=data_dir / "microsoft" / "token.json.enc",
        key_path=data_dir / "microsoft" / "token.key",
        managed=False,
    )
    monkeypatch.setattr(
        microsoft_config_mod, "load_microsoft_config", lambda **kw: config
    )
    return config


@pytest.fixture
def fake_credentials(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    creds = {
        "access_token": "fake-access-token",
        "refresh_token": "fake-refresh-token",
        "token_type": "Bearer",
        "expires_in": 3600,
    }
    import securedact_mcp.connectors.microsoft.auth as microsoft_auth

    monkeypatch.setattr(microsoft_auth, "require_valid_credentials", lambda c: creds)
    monkeypatch.setattr(microsoft_client_mod, "require_valid_credentials", lambda c: creds)
    return creds


@pytest.fixture
def binding_store(monkeypatch: pytest.MonkeyPatch) -> ConnectorBindingStore:
    store = _FakeBindingStore(
        {
            "int-1": ConnectorBinding(
                integration_id="int-1", platform="microsoft365", local_profile="default"
            )
        }
    )
    import securedact_mcp.agent.provider_microsoft as provider_microsoft

    monkeypatch.setattr(provider_microsoft, "ConnectorBindingStore", lambda *a, **k: store)
    return store


class _FakePaths:
    def __init__(self, root: Path) -> None:
        self.root = root


class _FakeBindingStore:
    def __init__(self, bindings: dict[str, ConnectorBinding]) -> None:
        self._bindings = bindings

    def get(self, integration_id: str) -> ConnectorBinding | None:
        return self._bindings.get(integration_id)

    def list(self) -> list[ConnectorBinding]:
        return list(self._bindings.values())


def _engine() -> SecuredactEngine:
    return SecuredactEngine(build_production_engine(require_contextual=False))


def _policy() -> ResolvedPolicy:
    return ResolvedPolicy(
        policy=STRICT_EXTERNAL_AI_POLICY,
        policy_version_id="pv-priv-1",
        content_digest="d" * 64,
    )


def _patch_client(monkeypatch: pytest.MonkeyPatch, transport: FakeMicrosoftTransport) -> None:
    captured = transport

    def fake_build(
        config,
        eng,
        *,
        transport=None,
        user_id=None,
        tenant_id=None,
        fingerprint_config=None,
    ):
        # Ignore the kwarg the provider passes (or omits) and always use the
        # closure-captured fake transport. The provider never passes ``transport``
        # in production; it relies on the connector client's ``_ensure_browser``
        # to load credentials. For a mocked scan we want the fake transport
        # regardless.
        return microsoft_client_mod.MicrosoftConnectorClient(
            config,
            eng,
            transport=captured,
            user_id=user_id or "user-123",
            tenant_id=tenant_id or "tenant-456",
            fingerprint_config=fingerprint_config,
        )

    monkeypatch.setattr(microsoft_client_mod, "build_client", fake_build)


def _smoke_test_transport() -> FakeMicrosoftTransport:
    """Build a transport that hosts the smoke-test folder and its 3 files."""

    transport = FakeMicrosoftTransport()
    transport.add_drive(id="drive-1", name="My Drive", driveType="personal")
    transport.add_item(
        "drive-1",
        id="smoke",
        name="SecuRedact-Smoke-Test",
        folder={},
        parentReference={"id": "root", "driveId": "drive-1"},
        size=0,
    )
    for filename, content in SYNTHETIC_FILES.items():
        transport.add_item(
            "drive-1",
            id=filename.replace(".", "_"),
            name=filename,
            file={"mimeType": "text/plain"},
            parentReference={"id": "smoke", "driveId": "drive-1"},
            size=len(content),
        )
        transport.set_content(
            "drive-1", filename.replace(".", "_"), content
        )
    return transport


# ---------------------------------------------------------------------------
# Phase 2: setup CLI does not leak secrets
# ---------------------------------------------------------------------------


def test_setup_does_not_echo_client_secret(
    monkeypatch: pytest.MonkeyPatch,
    data_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``microsoft setup --no-secret`` must never print the secret back."""

    out = io.StringIO()
    rc = microsoft_cli.cmd_setup(
        client_id="PUBLIC_CLIENT_ID",
        no_secret=True,
        input_fn=lambda _prompt: "",
        secret_input_fn=lambda _prompt: "should-not-be-echoed",
        output=out,
    )
    assert rc == 0

    captured = out.getvalue() + capsys.readouterr().out
    for forbidden in (
        "should-not-be-echoed",
        "PUBLIC_CLIENT_ID",  # we accept the id being shown; nothing else.
        # If anyone ever changes the cmd to print the secret back, this catches it.
    ):
        # client_id is allowed to be referenced indirectly via "stored"; the
        # secret must never appear.
        if forbidden == "PUBLIC_CLIENT_ID":
            continue
        assert forbidden not in captured


def test_setup_persists_encrypted_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, data_dir: Path) -> None:
    """``microsoft setup`` writes the client id encrypted (not plaintext)."""

    out = io.StringIO()
    rc = microsoft_cli.cmd_setup(
        client_id="MY_PUBLIC_CLIENT_ID",
        no_secret=True,
        tenant_id="my-tenant",
        input_fn=lambda _prompt: "",
        secret_input_fn=lambda _prompt: "",
        output=out,
    )
    assert rc == 0

    enc_path = data_dir / "microsoft" / "client_config.json.enc"
    assert enc_path.exists()
    blob = enc_path.read_bytes()
    assert b"MY_PUBLIC_CLIENT_ID" not in blob  # Fernet ciphertext, not plaintext.
    assert blob.startswith(b"gAAAAA")


# ---------------------------------------------------------------------------
# Phase 4: targets CLI never prints raw Graph ids
# ---------------------------------------------------------------------------


def test_targets_add_returns_opaque_target_id_only(
    monkeypatch: pytest.MonkeyPatch,
    data_dir: Path,
    microsoft_config: MicrosoftConnectorConfig,
    fake_credentials: dict[str, Any],
) -> None:
    """``microsoft targets add`` echoes only ``target_id`` (not raw driveId)."""

    transport = _smoke_test_transport()
    _patch_client(monkeypatch, transport)

    out = io.StringIO()
    rc = microsoft_cli.cmd_targets_add(
        drive_id="drive-1",
        folder_id="smoke",
        folder_name="SecuRedact-Smoke-Test",
        integration_id="int-1",
        label="SecuRedact-Smoke-Test",
        output=out,
    )
    assert rc == 0
    payload = json.loads(out.getvalue())

    assert "target_id" in payload
    assert payload["target_id"].startswith("mtgt_1_")
    for forbidden in (
        "drive-1",
        "smoke",
        "drive_id",
        "folder_id",
        "site_id",
    ):
        assert forbidden not in payload, f"target CLI leaks {forbidden!r}"
    assert "drive_fingerprint" in payload
    assert "folder_fingerprint" in payload


# ---------------------------------------------------------------------------
# Phase 5: full smoke-test scenario with privacy assertions
# ---------------------------------------------------------------------------


def test_full_smoke_test_no_raw_identifiers_cross_boundary(
    monkeypatch: pytest.MonkeyPatch,
    data_dir: Path,
    fingerprint_store: EncryptedFingerprintKeyStore,
    binding_store: ConnectorBindingStore,
    microsoft_config: MicrosoftConnectorConfig,
    fake_credentials: dict[str, Any],
) -> None:
    """End-to-end privacy contract for the documented customer workflow."""

    transport = _smoke_test_transport()
    _patch_client(monkeypatch, transport)

    # 1+2+3 happen by the fixtures; bind locally.
    binding = binding_store.get("int-1")
    assert binding is not None and binding.platform == "microsoft365"

    # 4+5: register the folder locally and obtain an opaque target_id.
    record = LocalTargetRecord.new_one_drive_folder(
        integration_id="int-1",
        drive_id="drive-1",
        folder_id="smoke",
        label="SecuRedact-Smoke-Test",
    )
    TargetRegistryStore(data_dir).add(record)
    opaque_target_ref = record.target_id
    assert opaque_target_ref.startswith("mtgt_1_")
    # ``target_ref`` MUST NOT contain a raw driveId or folderId.
    for raw in ("drive-1", "smoke"):
        assert raw not in opaque_target_ref

    # 6: a control-plane job with only the opaque target_ref.
    claim = JobClaim.from_claim(
        fake_claim(
            job_id="job-smoke",
            platform="microsoft365",
            target_type="folder",
            target_ref=opaque_target_ref,
        )
    )

    provider = MicrosoftScanProvider()
    exe = execute_job(claim, _engine(), provider, _policy())
    assert exe.status == "succeeded"

    # 7: the scan must touch exactly the three synthetic files.
    assert exe.resources_scanned == 3

    # 8: result metadata must carry the fingerprints, not the raw ids.
    from securedact_mcp.agent.reducer import build_safe_result_dict

    safe = build_safe_result_dict(exe)
    blob = json.dumps(safe, sort_keys=True)

    for forbidden in (
        # raw Graph ids must never appear in the safe result
        "drive-1",
        '"smoke"',
        "drive_id",
        "folder_id",
        "site_id",
        # content / PII
        "customer@example.test",
        "test@example.test",
        "Nothing sensitive here.",
        # OAuth tokens
        "fake-access-token",
        "fake-refresh-token",
        # Graph URLs
        "graph.microsoft.com",
        "sharepoint.com",
        # Filenames
        "clean.txt",
        "customer-test.txt",
        "medical-test.txt",
    ):
        assert forbidden not in blob, f"safe result leaks {forbidden!r}"

    # 9: submission to the (fake) control plane must not carry raw ids either.
    cp = FakeTransport()
    client = ControlPlaneClient(
        "https://cp.example.test",
        credential_provider=lambda: type("C", (), {"authorization_header": "Bearer sra_test"})(),
        transport=cp,
    )
    _submit_result(client, claim, exe)
    outbound = "\n".join(
        json.dumps(body) if isinstance(body, dict) else str(body) for _, _, body in cp.requests
    )
    for forbidden in (
        "drive-1",
        '"smoke"',
        "drive_id",
        "folder_id",
        "site_id",
        "customer@example.test",
        "test@example.test",
        "fake-access-token",
        "fake-refresh-token",
        "graph.microsoft.com",
        "clean.txt",
        "customer-test.txt",
        "medical-test.txt",
    ):
        assert forbidden not in outbound, f"control plane receives {forbidden!r}"


def test_raw_drive_id_folder_id_target_ref_rejected_by_provider(
    monkeypatch: pytest.MonkeyPatch,
    data_dir: Path,
    fingerprint_store: EncryptedFingerprintKeyStore,
    binding_store: ConnectorBindingStore,
    microsoft_config: MicrosoftConnectorConfig,
    fake_credentials: dict[str, Any],
) -> None:
    """The privacy boundary: a raw composite target_ref MUST be rejected."""

    transport = _smoke_test_transport()
    _patch_client(monkeypatch, transport)
    provider = MicrosoftScanProvider()

    from securedact_core.connectors.contracts import ScanContext
    from securedact_mcp.agent.errors import JobExecutionError

    with pytest.raises(JobExecutionError) as exc_info:
        provider.scan(
            ScanTarget(
                platform="microsoft365",
                integration_id="int-1",
                target_type="folder",
                target_ref="drive-1:smoke",  # raw composite -- MUST be rejected.
            ),
            ScanContext(),
            _engine(),
        )
    assert "mtgt_" in str(exc_info.value)


def test_integration_target_with_empty_ref_still_works(
    monkeypatch: pytest.MonkeyPatch,
    data_dir: Path,
    fingerprint_store: EncryptedFingerprintKeyStore,
    binding_store: ConnectorBindingStore,
    microsoft_config: MicrosoftConnectorConfig,
    fake_credentials: dict[str, Any],
) -> None:
    """The canonical whole-OneDrive scan (``integration`` + empty ``target_ref``) remains valid."""

    transport = FakeMicrosoftTransport()
    transport.add_drive(id="me", name="My Drive", driveType="personal")
    transport.add_item("me", id="root", name="Root", folder={}, parentReference={}, size=0)
    transport.add_item(
        "me",
        id="file-1",
        name="notes.txt",
        file={"mimeType": "text/plain"},
        parentReference={"id": "root", "driveId": "me"},
        size=100,
    )
    transport.set_content("me", "file-1", b"contact: ops@example.test")
    _patch_client(monkeypatch, transport)

    claim = JobClaim.from_claim(
        fake_claim(
            job_id="job-int",
            platform="microsoft365",
            target_type="integration",
            target_ref="",
        )
    )
    provider = MicrosoftScanProvider()
    exe = execute_job(claim, _engine(), provider, _policy())
    assert exe.status == "succeeded"
    assert exe.resources_scanned == 1


def test_unknown_target_ref_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    data_dir: Path,
    fingerprint_store: EncryptedFingerprintKeyStore,
    binding_store: ConnectorBindingStore,
    microsoft_config: MicrosoftConnectorConfig,
    fake_credentials: dict[str, Any],
) -> None:
    """An opaque target that was never registered must fail closed."""

    from securedact_core.connectors.contracts import ScanContext
    from securedact_mcp.agent.errors import JobExecutionError

    provider = MicrosoftScanProvider()
    with pytest.raises(JobExecutionError) as exc_info:
        provider.scan(
            ScanTarget(
                platform="microsoft365",
                integration_id="int-1",
                target_type="folder",
                target_ref="mtgt_1_doesnotexist",
            ),
            ScanContext(),
            _engine(),
        )
    assert "no local target registered" in str(exc_info.value).lower()


def test_wrong_integration_cannot_resolve_target(
    monkeypatch: pytest.MonkeyPatch,
    data_dir: Path,
    fingerprint_store: EncryptedFingerprintKeyStore,
    microsoft_config: MicrosoftConnectorConfig,
    fake_credentials: dict[str, Any],
) -> None:
    """A target registered for ``int-A`` MUST NOT be resolvable by ``int-B``."""

    # Register a binding for int-B so the provider reaches the registry check.
    store = _FakeBindingStore(
        {
            "int-A": ConnectorBinding(integration_id="int-A", platform="microsoft365"),
            "int-B": ConnectorBinding(integration_id="int-B", platform="microsoft365"),
        }
    )
    import securedact_mcp.agent.provider_microsoft as provider_microsoft

    monkeypatch.setattr(provider_microsoft, "ConnectorBindingStore", lambda *a, **k: store)

    record = LocalTargetRecord.new_one_drive_folder(
        integration_id="int-A",
        drive_id="drive-1",
        folder_id="root",
    )
    TargetRegistryStore(data_dir).add(record)

    from securedact_core.connectors.contracts import ScanContext
    from securedact_mcp.agent.errors import JobExecutionError

    provider = MicrosoftScanProvider()
    with pytest.raises(JobExecutionError) as exc_info:
        provider.scan(
            ScanTarget(
                platform="microsoft365",
                integration_id="int-B",
                target_type="folder",
                target_ref=record.target_id,
            ),
            ScanContext(),
            _engine(),
        )
    assert "not bound" in str(exc_info.value).lower()