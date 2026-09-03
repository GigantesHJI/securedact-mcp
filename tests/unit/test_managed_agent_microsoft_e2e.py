# SPDX-License-Identifier: Apache-2.0
"""End-to-end managed-agent Microsoft 365 scan flow (M365-102).

Proves the FIRST REAL production-style managed local scan:

    control-plane claim (microsoft365)
        -> MicrosoftScanProvider
        -> local Microsoft Graph retrieval (FAKE transport, no network/SDK)
        -> securedact_core detection (real deterministic engine)
        -> privacy-safe reducer
        -> ONLY bounded summary metadata submitted to the (fake) control plane

No Microsoft SDK, no live account, and no real control plane are used. The tests
assert the synthetic source document's PII and any OAuth token material never
leave the machine: they are absent from the safe result, the job heartbeat, and
every recorded control-plane request body.
"""

from __future__ import annotations

import importlib
import json
import os
import tempfile
import types
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

import securedact_mcp.agent.provider_microsoft as provider_microsoft
import securedact_mcp.connectors.microsoft.client as microsoft_client_mod
import securedact_mcp.connectors.microsoft.config as microsoft_config_mod
import securedact_mcp.connectors.microsoft.auth as microsoft_auth
from securedact_core import SecuredactEngine
from securedact_core.connectors.fingerprint import EncryptedFingerprintKeyStore, FingerprintConfig
from securedact_core.connectors.microsoft import (
    CANONICAL_GRAPH_BASE,
    MicrosoftApiError,
)
from securedact_mcp.connectors.microsoft.config import MicrosoftConnectorConfig
from securedact_core.policies import STRICT_EXTERNAL_AI_POLICY
from securedact_core.production import build_production_engine
from securedact_mcp.agent.agent_runner import _failed_result, _submit_result
from securedact_mcp.agent.client import ControlPlaneClient
from securedact_mcp.agent.connectors import ConnectorBinding
from securedact_mcp.agent.executor import JobClaim, ScanTarget, execute_job
from securedact_mcp.agent.policy import ResolvedPolicy
from securedact_mcp.agent.reducer import (
    assert_no_forbidden_substrings,
    build_safe_result_dict,
    validate_safe_result,
)
from securedact_mcp.connectors.microsoft.client import MicrosoftConnectorClient
from tests.unit.agent_helpers import FakeTransport, fake_claim
from tests.unit.microsoft_transport_fake import FakeMicrosoftTransport

FOLDER_MIME = "folder"


class _FakeBindingStore:
    """In-memory ConnectorBindingStore returning a fixed binding for int-1."""

    def __init__(self, bindings: dict[str, ConnectorBinding]) -> None:
        self._bindings = bindings

    def get(self, integration_id: str) -> ConnectorBinding | None:
        return self._bindings.get(integration_id)

    def list(self) -> list[ConnectorBinding]:
        return list(self._bindings.values())


class _FakePaths:
    """Stand-in for :class:`securedact_core.app_paths.SecuredactPaths` for tests."""

    def __init__(self, root: Path) -> None:
        self.root = root


@dataclass
class _TargetRegistryHandle:
    """Helper returned by the ``microsoft_target_registry`` fixture."""

    store: object
    register: Callable[..., str]


@pytest.fixture(autouse=True)
def microsoft_default_binding(monkeypatch):
    """Every managed-agent Microsoft scan now requires a local binding lookup.

    Provide the integration_id used by the shared ``fake_claim`` helper so the
    existing end-to-end scans resolve to the ``default`` local profile.
    """

    store = _FakeBindingStore(
        {
            "int-1": ConnectorBinding(
                integration_id="int-1",
                platform="microsoft365",
                local_profile="default",
            )
        }
    )
    monkeypatch.setattr(provider_microsoft, "ConnectorBindingStore", lambda *a, **k: store)
    return store


@pytest.fixture
def microsoft_target_registry(monkeypatch):
    """Yield a per-test encrypted Microsoft target registry rooted in a temp dir.

    The fixture monkey-patches :data:`SecuredactPaths.resolve` so the provider
    reads from the temp registry, and exposes a small helper to register a
    target. Tests then use the returned ``target_id`` (an opaque ``mtgt_...``
    token) in the claim's ``target_ref``.
    """

    from securedact_core import app_paths as core_app_paths

    temp_dir = Path(tempfile.mkdtemp(prefix="ms_target_registry_"))
    temp_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(core_app_paths.SecuredactPaths, "resolve", lambda: _FakePaths(temp_dir))

    from securedact_mcp.connectors.microsoft.target_registry import (
        LocalTargetRecord,
        TargetRegistryStore,
    )

    store = TargetRegistryStore(temp_dir)

    def register(
        *,
        drive_id: str = "drive-1",
        folder_id: str = "root",
        site_id: str | None = None,
        integration_id: str = "int-1",
        label: str | None = None,
    ) -> str:
        record = LocalTargetRecord.new_one_drive_folder(
            integration_id=integration_id,
            drive_id=drive_id,
            folder_id=folder_id,
            site_id=site_id,
            label=label,
        )
        store.add(record)
        return record.target_id

    return _TargetRegistryHandle(store=store, register=register)


@pytest.fixture(autouse=True)
def microsoft_test_config(monkeypatch):
    """Provide a test Microsoft config with temp token paths."""
    # Use a unique temp dir per test to avoid conflicts
    temp_dir = Path(tempfile.mkdtemp(prefix="microsoft_test_"))
    temp_dir.mkdir(parents=True, exist_ok=True)
    
    # Create a minimal config for testing
    config = MicrosoftConnectorConfig(
        enabled=True,
        client_id="test-client-id",
        client_secret="test-client-secret",
        tenant_id="test-tenant",
        redirect_uri="http://localhost:8080/",
        scopes=["User.Read", "Files.Read", "Sites.Read.All", "offline_access"],
        token_path=temp_dir / "token.json.enc",
        key_path=temp_dir / "token.key",
        managed=False,
    )
    
    def fake_load_config(*, require_enabled: bool = False, profile: str = "default", data_dir: str | Path | None = None):
        return config
    
    monkeypatch.setattr(microsoft_config_mod, "load_microsoft_config", fake_load_config)
    return config


@pytest.fixture(autouse=True)
def microsoft_fingerprint_store(monkeypatch):
    """Mock the fingerprint store to use a temp directory."""
    # Use a unique temp dir per test
    temp_dir = Path(tempfile.mkdtemp(prefix="fingerprint_test_"))
    temp_dir.mkdir(parents=True, exist_ok=True)
    
    # Create a test fingerprint store with the temp dir
    test_store = EncryptedFingerprintKeyStore(temp_dir)
    
    # Create a deterministic fingerprint config for testing
    test_config = FingerprintConfig(
        key=b"test-key-for-testing-" + b"x" * 12,  # 32 bytes
        provider="microsoft365",
        tenant_id="int-1",
    )
    
    def fake_create_config(self, provider: str, tenant_id: str):
        if provider == "microsoft365" and tenant_id == "int-1":
            return test_config
        return EncryptedFingerprintKeyStore.create_config(self, provider, tenant_id)
    
    # Patch at module level
    monkeypatch.setattr(provider_microsoft, "EncryptedFingerprintKeyStore", lambda *a, **k: test_store)
    monkeypatch.setattr(EncryptedFingerprintKeyStore, "create_config", fake_create_config)
    return test_store


@pytest.fixture(autouse=True)
def microsoft_credentials(monkeypatch):
    """Mock require_valid_credentials to return fake credentials."""
    fake_credentials = {
        "access_token": "fake-access-token",
        "refresh_token": "fake-refresh-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "User.Read Files.Read Sites.Read.All offline_access",
    }
    monkeypatch.setattr(microsoft_auth, "require_valid_credentials", lambda config: fake_credentials)
    # Also patch in the client module where it's imported
    monkeypatch.setattr(microsoft_client_mod, "require_valid_credentials", lambda config: fake_credentials)
    return fake_credentials


# The synthetic source document full of obvious fake PII. None of these strings
# may ever reach the control plane.
SYNTHETIC_DOC = (
    "Contact Jane Example at jane@example.com or call +31612345678. "
    "IBAN NL91ABNA0417164300 belongs to Jane Example."
)


def _engine() -> SecuredactEngine:
    return SecuredactEngine(build_production_engine(require_contextual=False))


def _resolved_policy() -> ResolvedPolicy:
    return ResolvedPolicy(
        policy=STRICT_EXTERNAL_AI_POLICY,
        policy_version_id="pv-e2e-1",
        content_digest="d" * 64,
    )


@pytest.fixture
def engine():
    return _engine()


def _patch_microsoft_client(monkeypatch, transport):
    """Route MicrosoftScanProvider's client construction at our fake transport."""

    captured = transport

    def fake_build(config, eng, *, transport=None, user_id=None, tenant_id=None, fingerprint_config=None):
        return MicrosoftConnectorClient(config, eng, transport=captured, user_id="user-123", tenant_id="tenant-456", fingerprint_config=fingerprint_config)

    monkeypatch.setattr(microsoft_client_mod, "build_client", fake_build)
    return transport


# --- 1. Single-file end-to-end ------------------------------------------------


def test_single_file_microsoft_scan_submits_only_safe_metadata(monkeypatch, engine, microsoft_target_registry):
    transport = FakeMicrosoftTransport()
    transport.add_drive(id="drive-1", name="My Drive", driveType="personal")
    transport.add_item("drive-1", id="file-1", name="Report", file={"mimeType": "text/plain"}, parentReference={"id": "root", "driveId": "drive-1"}, size=200)
    transport.set_content("drive-1", "file-1", SYNTHETIC_DOC.encode("utf-8"))
    _patch_microsoft_client(monkeypatch, transport)

    target_id = microsoft_target_registry.register(drive_id="drive-1", folder_id="file-1")
    claim = JobClaim.from_claim(
        fake_claim(
            job_id="job-single",
            platform="microsoft365",
            target_type="resource",
            target_ref=target_id,
        )
    )
    provider = provider_microsoft.MicrosoftScanProvider()
    exe = execute_job(claim, engine, provider, _resolved_policy())

    assert exe.status == "succeeded"
    # Real category breakdown is surfaced (never the values).
    assert exe.categories == ["email", "iban", "phone"]
    assert exe.counts == {"email": 1, "iban": 1, "phone": 1}
    assert exe.severity == "medium"

    result_dict = build_safe_result_dict(exe)
    assert validate_safe_result(result_dict)["status"] == "succeeded"
    blob = json.dumps(result_dict, sort_keys=True)
    for forbidden in (
        "Jane Example",
        "jane@example.com",
        "NL91ABNA0417164300",
        "+31612345678",
        "text",
        "content",
        "access_token",
        "refresh_token",
    ):
        assert forbidden not in blob


# --- 2. Folder / aggregate end-to-end ----------------------------------------


def test_folder_microsoft_scan_aggregates_categories_and_resources(monkeypatch, engine, microsoft_target_registry):
    transport = FakeMicrosoftTransport()
    transport.add_drive(id="drive-1", name="My Drive", driveType="personal")
    transport.add_item("drive-1", id="root", name="Root", folder={}, parentReference={}, size=0)
    transport.add_item("drive-1", id="file-1", name="a.txt", file={"mimeType": "text/plain"}, parentReference={"id": "root", "driveId": "drive-1"}, size=200)
    transport.add_item("drive-1", id="file-2", name="b.pdf", file={"mimeType": "application/pdf"}, parentReference={"id": "root", "driveId": "drive-1"}, size=200)
    transport.add_item("drive-1", id="clean", name="clean.txt", file={"mimeType": "text/plain"}, parentReference={"id": "root", "driveId": "drive-1"}, size=50)
    transport.add_item("drive-1", id="pii", name="pii.txt", file={"mimeType": "text/plain"}, parentReference={"id": "root", "driveId": "drive-1"}, size=200)
    transport.set_content("drive-1", "file-1", b"mail jane@example.com")
    transport.set_content("drive-1", "clean", b"nothing to see")
    transport.set_content("drive-1", "pii", b"IBAN NL91ABNA0417164300 phone +31612345678")
    _patch_microsoft_client(monkeypatch, transport)

    target_id = microsoft_target_registry.register(drive_id="drive-1", folder_id="root")
    claim = JobClaim.from_claim(
        fake_claim(job_id="job-folder", platform="microsoft365", target_type="folder", target_ref=target_id)
    )
    provider = provider_microsoft.MicrosoftScanProvider()
    exe = execute_job(claim, engine, provider, _resolved_policy())

    assert exe.status == "succeeded"
    assert exe.resources_scanned == 3
    assert exe.counts.get("email") == 1
    assert exe.counts.get("iban") == 1
    assert exe.counts.get("phone") == 1
    assert exe.review_required is True

    result_dict = build_safe_result_dict(exe)
    assert validate_safe_result(result_dict)["status"] == "succeeded"
    blob = json.dumps(result_dict, sort_keys=True)
    assert "jane@example.com" not in blob
    assert "NL91ABNA0417164300" not in blob


# --- 2b. Lease heartbeat during local scan -----------------------------------


def test_folder_scan_keeps_lease_alive_via_heartbeat(monkeypatch, engine, microsoft_target_registry):
    transport = FakeMicrosoftTransport()
    transport.add_drive(id="drive-1", name="My Drive", driveType="personal")
    transport.add_item("drive-1", id="root", name="Root", folder={}, parentReference={}, size=0)
    for i in range(30):
        fid = f"f{i}"
        transport.add_item("drive-1", id=fid, name=f"{fid}.txt", file={"mimeType": "text/plain"}, parentReference={"id": "root", "driveId": "drive-1"}, size=50)
        transport.set_content("drive-1", fid, b"nothing to see")
    _patch_microsoft_client(monkeypatch, transport)

    provider = provider_microsoft.MicrosoftScanProvider()
    calls: list[int] = []

    from securedact_core.connectors.contracts import ScanContext

    target_id = microsoft_target_registry.register(drive_id="drive-1", folder_id="root")
    target = ScanTarget(
        platform="microsoft365",
        integration_id="int-1",
        target_type="folder",
        target_ref=target_id,
    )
    provider.scan(target, ScanContext(), engine, heartbeat=lambda: calls.append(1))

    assert len(calls) >= 2


# --- 3. Control-plane submission privacy (PII exfiltration regression) -------


def test_pii_never_reaches_control_plane(monkeypatch, engine, microsoft_target_registry):
    transport = FakeMicrosoftTransport()
    transport.add_drive(id="drive-1", name="My Drive", driveType="personal")
    transport.add_item("drive-1", id="file-1", name="Report", file={"mimeType": "text/plain"}, parentReference={"id": "root", "driveId": "drive-1"}, size=200)
    transport.set_content("drive-1", "file-1", SYNTHETIC_DOC.encode("utf-8"))
    _patch_microsoft_client(monkeypatch, transport)

    target_id = microsoft_target_registry.register(drive_id="drive-1", folder_id="file-1")
    claim = JobClaim.from_claim(
        fake_claim(job_id="job-pii", platform="microsoft365", target_type="resource", target_ref=target_id)
    )
    provider = provider_microsoft.MicrosoftScanProvider()
    exe = execute_job(claim, engine, provider, _resolved_policy())

    cp = FakeTransport()
    client = ControlPlaneClient(
        "https://cp.example.test",
        credential_provider=lambda: types.SimpleNamespace(authorization_header="Bearer sra_test"),
        transport=cp,
    )
    _submit_result(client, claim, exe)

    outbound = "\n".join(
        json.dumps(body) if isinstance(body, dict) else str(body) for _, _, body in cp.requests
    )
    for forbidden in (
        "Jane Example",
        "jane@example.com",
        "NL91ABNA0417164300",
        "+31612345678",
    ):
        assert forbidden not in outbound
    submitted = cp.last_request()[2]
    assert submitted["result"]["status"] == "succeeded"
    assert "jane@example.com" not in json.dumps(submitted, sort_keys=True)


# --- 4. OAuth token exfiltration regression ----------------------------------


def test_oauth_tokens_never_leak(monkeypatch, engine, microsoft_target_registry):
    transport = FakeMicrosoftTransport(user_id="ya29.fake-access-token")
    transport.add_drive(id="drive-1", name="My Drive", driveType="personal")
    transport.add_item("drive-1", id="file-1", name="Report", file={"mimeType": "text/plain"}, parentReference={"id": "root", "driveId": "drive-1"}, size=200)
    transport.set_content("drive-1", "file-1", SYNTHETIC_DOC.encode("utf-8"))
    _patch_microsoft_client(monkeypatch, transport)

    target_id = microsoft_target_registry.register(drive_id="drive-1", folder_id="file-1")
    claim = JobClaim.from_claim(
        fake_claim(job_id="job-token", platform="microsoft365", target_type="resource", target_ref=target_id)
    )
    provider = provider_microsoft.MicrosoftScanProvider()
    exe = execute_job(claim, engine, provider, _resolved_policy())

    assert_no_forbidden_substrings(build_safe_result_dict(exe))

    cp = FakeTransport()
    client = ControlPlaneClient(
        "https://cp.example.test",
        credential_provider=lambda: types.SimpleNamespace(authorization_header="Bearer sra_test"),
        transport=cp,
    )
    _submit_result(client, claim, exe)
    outbound = "\n".join(
        json.dumps(body) if isinstance(body, dict) else str(body) for _, _, body in cp.requests
    )
    assert "ya29." not in outbound
    assert "1//" not in outbound


# --- 5. Optional connector missing -> safe connector_unavailable -------------


def test_missing_microsoft_connector_fails_closed(monkeypatch, engine, microsoft_target_registry):
    real_import = importlib.import_module

    def fake_import(name, *args, **kwargs):
        if name.startswith("securedact_mcp.connectors.microsoft"):
            raise ModuleNotFoundError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(provider_microsoft.importlib, "import_module", fake_import)
    provider = provider_microsoft.MicrosoftScanProvider()
    from securedact_core.connectors.contracts import ScanContext

    target_id = microsoft_target_registry.register(drive_id="drive-1", folder_id="file-1")

    with pytest.raises(Exception) as exc_info:
        provider.scan(
            ScanTarget(
                platform="microsoft365",
                integration_id="int-1",
                target_type="resource",
                target_ref=target_id,
            ),
            ScanContext(),
            engine,
        )
    from securedact_mcp.agent.errors import JobExecutionError

    assert type(exc_info.value) is JobExecutionError
    assert "ModuleNotFoundError" not in str(exc_info.value)


# --- 6. Capability advertisement ---------------------------------------------


def test_capability_advertises_microsoft_not_only_google():
    from securedact_mcp.agent.capabilities import AgentCapabilities

    caps = AgentCapabilities.default()
    assert "google_drive" in caps.capabilities
    assert "google_workspace" in caps.supported_platforms
    # Microsoft is now advertised
    assert "microsoft365" in caps.supported_platforms
    assert "microsoft_graph" in caps.capabilities


# --- 7. Optional-connector failure maps to safe connector_unavailable --------


def test_provider_unavailable_maps_to_connector_unavailable(engine):
    from securedact_mcp.agent.errors import JobExecutionError
    from tests.unit.agent_helpers import FakeScanProvider

    claim = JobClaim.from_claim(fake_claim(platform="microsoft365"))
    provider = FakeScanProvider(
        [],
        error=JobExecutionError(
            "microsoft provider unavailable: ModuleNotFoundError "
            "No module named 'securedact_mcp.connectors.microsoft.client'"
        ),
    )
    with pytest.raises(JobExecutionError) as exc_info:
        execute_job(claim, engine, provider, _resolved_policy())
    assert "unavailable" in str(exc_info.value).lower()
    failed = _failed_result(_resolved_policy(), "connector_unavailable")
    assert (
        validate_safe_result(build_safe_result_dict(failed))["safe_error_code"]
        == "connector_unavailable"
    )


# --- 8. SharePoint site/drive scan -------------------------------------------


def test_sharepoint_site_scan(monkeypatch, engine, microsoft_target_registry):
    transport = FakeMicrosoftTransport()
    transport.add_drive(id="drive-sp-1", name="Documents", driveType="documentLibrary")
    transport.add_site(id="site-1", displayName="Team Site", webUrl="https://contoso.sharepoint.com/sites/team")
    transport.add_item("drive-sp-1", id="root", name="Root", folder={}, parentReference={}, size=0)
    transport.add_item("drive-sp-1", id="file-1", name="report.txt", file={"mimeType": "text/plain"}, parentReference={"id": "root", "driveId": "drive-sp-1"}, size=200)
    transport.set_content("drive-sp-1", "file-1", b"Contact john@contoso.com")
    _patch_microsoft_client(monkeypatch, transport)

    target_id = microsoft_target_registry.register(
        drive_id="drive-sp-1", folder_id="root", site_id="site-1"
    )
    claim = JobClaim.from_claim(
        fake_claim(job_id="job-sp", platform="microsoft365", target_type="folder", target_ref=target_id)
    )
    provider = provider_microsoft.MicrosoftScanProvider()
    exe = execute_job(claim, engine, provider, _resolved_policy())

    assert exe.status == "succeeded"
    assert exe.resources_scanned == 1
    assert exe.counts.get("email") == 1


# --- 9. Drive scan (whole drive) ---------------------------------------------


def test_drive_scan(monkeypatch, engine, microsoft_target_registry):
    """A whole-drive scan must use a registered opaque drive target."""

    transport = FakeMicrosoftTransport()
    transport.add_drive(id="drive-1", name="My Drive", driveType="personal")
    transport.add_item("drive-1", id="root", name="Root", folder={}, parentReference={}, size=0)
    transport.add_item("drive-1", id="file-1", name="notes.txt", file={"mimeType": "text/plain"}, parentReference={"id": "root", "driveId": "drive-1"}, size=100)
    transport.set_content("drive-1", "file-1", b"test@example.com")
    _patch_microsoft_client(monkeypatch, transport)

    # Register a "sharepoint_drive" so the provider's drive scan path resolves
    # through the opaque target registry (no raw driveId crossing the boundary).
    from securedact_mcp.connectors.microsoft.target_registry import LocalTargetRecord

    record = LocalTargetRecord.new_sharepoint_drive(
        integration_id="int-1", drive_id="drive-1", site_id="synthetic-site"
    )
    microsoft_target_registry.store.add(record)
    claim = JobClaim.from_claim(
        fake_claim(job_id="job-drive", platform="microsoft365", target_type="drive", target_ref=record.target_id)
    )
    provider = provider_microsoft.MicrosoftScanProvider()
    exe = execute_job(claim, engine, provider, _resolved_policy())

    assert exe.status == "succeeded"
    assert exe.resources_scanned == 1
    assert exe.counts.get("email") == 1


# --- 10. Integration target scan ---------------------------------------------


def test_integration_target_scan(monkeypatch, engine):
    transport = FakeMicrosoftTransport()
    # Add a "me" drive which is the default for integration target
    transport.add_drive(id="me", name="My Drive", driveType="personal")
    transport.add_item("me", id="root", name="Root", folder={}, parentReference={}, size=0)
    transport.add_item("me", id="file-1", name="notes.txt", file={"mimeType": "text/plain"}, parentReference={"id": "root", "driveId": "me"}, size=100)
    transport.set_content("me", "file-1", b"test@example.com")
    _patch_microsoft_client(monkeypatch, transport)

    claim = JobClaim.from_claim(
        fake_claim(job_id="job-int", platform="microsoft365", target_type="integration", target_ref="")
    )
    provider = provider_microsoft.MicrosoftScanProvider()
    exe = execute_job(claim, engine, provider, _resolved_policy())

    assert exe.status == "succeeded"
    assert exe.resources_scanned == 1
    assert exe.counts.get("email") == 1


# --- 11. Unsupported target type fails closed --------------------------------


def test_unsupported_target_type_fails_closed(monkeypatch, engine):
    transport = FakeMicrosoftTransport()
    transport.add_drive(id="drive-1", name="My Drive", driveType="personal")
    _patch_microsoft_client(monkeypatch, transport)

    claim = JobClaim.from_claim(
        fake_claim(job_id="job-bad", platform="microsoft365", target_type="unknown_type", target_ref="drive-1")
    )
    provider = provider_microsoft.MicrosoftScanProvider()

    from securedact_mcp.agent.errors import JobExecutionError
    with pytest.raises(JobExecutionError) as exc_info:
        execute_job(claim, engine, provider, _resolved_policy())
    assert "unsupported microsoft365 target_type" in str(exc_info.value)