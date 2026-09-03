# SPDX-License-Identifier: Apache-2.0
"""Regression test: Microsoft config / credentials / targets are visible to a
separately-instantiated service-style runtime.

This locks down the contract documented in :mod:`docs.managed-agent.md`:

* All Microsoft-scoped stores (``MicrosoftClientConfigStore``,
  ``MicrosoftCredentialStore``, ``TargetRegistryStore``) and the agent's
  ``ConnectorBindingStore`` MUST resolve their on-disk location through
  :class:`securedact_core.app_paths.SecuredactPaths` so that the
  ``SECUREDACT_APP_DATA_DIR`` environment variable (which the Windows service
  install publishes at machine scope via ``setx /M``) routes every store to
  the same ``C:\\ProgramData\\Securedact`` root.
* A second runtime instantiated "as the service" (without the interactive
  user's ``LOCALAPPDATA``) MUST be able to read every store written by the
  operator's interactive ``securedact-mcp microsoft ...`` commands.

The test simulates the machine-wide env publication by writing the same value
to both ``os.environ`` and (on Windows) a sentinel file under the test root.
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
from securedact_core.production import build_production_engine
from securedact_mcp.agent.config import AgentFiles
from securedact_mcp.agent.connectors import (
    SUPPORTED_BINDING_PLATFORMS,
    ConnectorBinding,
    ConnectorBindingStore,
)
from securedact_mcp.agent.executor import JobClaim, execute_job
from securedact_mcp.agent.policy import ResolvedPolicy
from securedact_mcp.agent.provider_microsoft import MicrosoftScanProvider
from securedact_mcp.connectors.microsoft.client import MicrosoftConnectorClient
from securedact_mcp.connectors.microsoft.client_config_store import (
    MicrosoftClientConfigStore,
)
from securedact_mcp.connectors.microsoft.config import MicrosoftConnectorConfig
from securedact_mcp.connectors.microsoft.storage import MicrosoftCredentialStore
from securedact_mcp.connectors.microsoft.target_registry import (
    LocalTargetRecord,
    TargetRegistryStore,
)
from tests.unit.agent_helpers import fake_claim
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
def machine_data_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Simulate the Windows service install publishing the machine-wide root.

    Sets ``SECUREDACT_APP_DATA_DIR`` to a temp dir and patches
    :class:`SecuredactPaths` so the interactive "operator" and the "service"
    runtime both resolve to the same root.
    """

    base = Path(tempfile.mkdtemp(prefix="ms_machine_root_", dir=tmp_path))
    base.mkdir(parents=True, exist_ok=True)

    # 1) Set the env var (what `setx /M SECUREDACT_APP_DATA_DIR <path>` does).
    monkeypatch.setenv("SECUREDACT_APP_DATA_DIR", str(base))

    # 2) Sanity-check: SecuredactPaths.resolve() must honor it on every platform.
    resolved = SecuredactPaths.resolve().root
    assert resolved == base.resolve(), (
        f"SecuredactPaths.resolve().root must honor SECUREDACT_APP_DATA_DIR; "
        f"expected {base.resolve()}, got {resolved}"
    )

    return base


@pytest.fixture
def microsoft_config_for_machine(
    monkeypatch: pytest.MonkeyPatch, machine_data_dir: Path
) -> MicrosoftConnectorConfig:
    """Patch ``load_microsoft_config`` to return a config rooted in the machine dir.

    This mirrors what the service runtime would do: the config loader reads
    the client secret from the encrypted local store, and the token vault
    path is derived from the same ``SecuredactPaths`` root.
    """

    token_path = machine_data_dir / "microsoft" / "token.json.enc"
    key_path = machine_data_dir / "microsoft" / "token.key"
    token_path.parent.mkdir(parents=True, exist_ok=True)

    config = MicrosoftConnectorConfig(
        enabled=True,
        client_id="test-client-id",
        client_secret="test-client-secret",  # noqa: S106  # test fixture
        tenant_id="test-tenant",
        redirect_uri="http://localhost:8080/",
        scopes=["User.Read", "Files.Read", "Sites.Read.All", "offline_access"],
        token_path=token_path,
        key_path=key_path,
        managed=False,
    )

    monkeypatch.setattr(microsoft_config_mod, "load_microsoft_config", lambda **kw: config)
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
def fingerprint_store(
    monkeypatch: pytest.MonkeyPatch, machine_data_dir: Path
) -> EncryptedFingerprintKeyStore:
    store = EncryptedFingerprintKeyStore(machine_data_dir)
    cfg = FingerprintConfig(
        key=b"test-key-for-testing-" + b"x" * 12,
        provider="microsoft365",
        tenant_id="int-1",
    )
    _original = EncryptedFingerprintKeyStore.create_config

    def fake_create(self, provider: str, tenant_id: str):
        if provider == "microsoft365" and tenant_id == "int-1":
            return cfg
        return _original(self, provider, tenant_id)

    import securedact_mcp.agent.provider_microsoft as provider_microsoft

    monkeypatch.setattr(provider_microsoft, "EncryptedFingerprintKeyStore", lambda *a, **k: store)
    monkeypatch.setattr(EncryptedFingerprintKeyStore, "create_config", fake_create)
    return store


@pytest.fixture
def binding_store() -> ConnectorBindingStore:
    """A real, on-disk binding store rooted in the machine data dir.

    The agent CLI writes bindings here via the real ``ConnectorBindingStore``;
    the service runtime reads them from the same file. Uses the production
    ``AgentFiles.resolve()`` path (which yields ``<root>/agent/``) so the
    fixture matches the agent's actual on-disk layout.
    """

    files = AgentFiles.resolve()
    store = ConnectorBindingStore(files=files)
    return store


# ---------------------------------------------------------------------------
# the test
# ---------------------------------------------------------------------------


def test_service_runtime_sees_interactively_written_microsoft_state(
    monkeypatch: pytest.MonkeyPatch,
    machine_data_dir: Path,
    microsoft_config_for_machine: MicrosoftConnectorConfig,
    fake_credentials: dict[str, Any],
    fingerprint_store: EncryptedFingerprintKeyStore,
    binding_store: ConnectorBindingStore,
) -> None:
    """The end-to-end cross-runtime privacy + service-visibility contract.

    Simulates:

    1. the operator runs ``securedact-mcp microsoft setup`` interactively;
    2. the operator runs ``securedact-mcp microsoft auth``;
    3. the operator runs ``securedact-mcp microsoft targets add``;
    4. the operator runs ``securedact-mcp agent connector bind microsoft365``;
    5. a fresh "service" runtime (with the same machine-wide env) reads every
       store from the same on-disk location and successfully scans the
       synthetic folder via the opaque target.
    """

    # ------------------------------------------------------------------
    # 1) operator: microsoft setup (encrypted local config)
    # ------------------------------------------------------------------
    out = io.StringIO()
    rc = microsoft_cli.cmd_setup(
        client_id="OPERATOR_CLIENT_ID",
        client_secret="OPERATOR_CLIENT_SECRET",  # noqa: S106  # test fixture
        tenant_id="operator-tenant",
        no_secret=False,
        input_fn=lambda _p: "",
        secret_input_fn=lambda _p: "OPERATOR_CLIENT_SECRET",
        output=out,
    )
    assert rc == 0
    client_config_path = machine_data_dir / "microsoft" / "client_config.json.enc"
    assert client_config_path.exists(), "microsoft setup must write to the machine-wide data root"

    # The encrypted file must not contain the secret in cleartext.
    blob = client_config_path.read_bytes()
    assert b"OPERATOR_CLIENT_SECRET" not in blob
    assert blob.startswith(b"gAAAAA")

    # ------------------------------------------------------------------
    # 2) operator: microsoft auth (writes the encrypted token vault)
    # ------------------------------------------------------------------
    MicrosoftCredentialStore(
        microsoft_config_for_machine.token_path,
        microsoft_config_for_machine.key_path,
    ).save_token(dict(fake_credentials))
    assert microsoft_config_for_machine.token_path.exists()

    # ------------------------------------------------------------------
    # 3) operator: microsoft targets add (encrypted target registry)
    # ------------------------------------------------------------------
    TargetRegistryStore(machine_data_dir).add(
        LocalTargetRecord.new_one_drive_folder(
            integration_id="int-1",
            drive_id="drive-1",
            folder_id="smoke",
            label="SecuRedact-Smoke-Test",
        )
    )
    registry_path = machine_data_dir / "microsoft" / "target_registry.json.enc"
    assert registry_path.exists()
    # The registry file must be encrypted, not plaintext.
    registry_blob = registry_path.read_bytes()
    assert b"drive-1" not in registry_blob
    assert b"smoke" not in registry_blob
    assert b"int-1" not in registry_blob

    # ------------------------------------------------------------------
    # 4) operator: agent connector bind microsoft365
    # ------------------------------------------------------------------
    # The agent CLI writes via ConnectorBindingStore (rooted in
    # SecuredactPaths.resolve().root, which is the machine data dir).
    binding_store.bind(
        ConnectorBinding(integration_id="int-1", platform="microsoft365", local_profile="default")
    )
    bindings_path = machine_data_dir / "agent" / "connector-bindings.json"
    assert bindings_path.exists()
    bindings_blob = bindings_path.read_text(encoding="utf-8")
    parsed = json.loads(bindings_blob)
    assert "int-1" in parsed
    assert parsed["int-1"]["platform"] == "microsoft365"
    # No OAuth material in the binding file.
    for forbidden in ("OPERATOR_CLIENT_SECRET", "fake-access-token"):
        assert forbidden not in bindings_blob

    # ------------------------------------------------------------------
    # 5) "service" runtime: a fresh MicrosoftScanProvider, no shared state
    # ------------------------------------------------------------------
    # Simulate the service: no in-process caches, all state read from disk.
    # We construct the provider WITHOUT a binding_store argument so it
    # resolves the store from AgentFiles.resolve() -> SecuredactPaths.

    real_AgentFiles = AgentFiles
    files_svc = real_AgentFiles.resolve()
    assert files_svc.root.parent == machine_data_dir.resolve(), (
        f"agent files root must live under the machine data dir; got {files_svc.root}"
    )

    # Build a fresh fake transport for the service to use.
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
        iid = filename.replace(".", "_")
        transport.add_item(
            "drive-1",
            id=iid,
            name=filename,
            file={"mimeType": "text/plain"},
            parentReference={"id": "smoke", "driveId": "drive-1"},
            size=len(content),
        )
        transport.set_content("drive-1", iid, content)

    captured = transport

    def fake_build(
        config, eng, *, transport=None, user_id=None, tenant_id=None, fingerprint_config=None
    ):
        return MicrosoftConnectorClient(
            config,
            eng,
            transport=captured,
            user_id=user_id or "user-123",
            tenant_id=tenant_id or "tenant-456",
            fingerprint_config=fingerprint_config,
        )

    monkeypatch.setattr(microsoft_client_mod, "build_client", fake_build)

    # The provider must read the binding, the client config, the token, and
    # the target registry from the machine-wide data dir, with no in-process
    # state from the "operator" session.
    provider = MicrosoftScanProvider()

    # Sanity: provider resolves the binding from the same store.
    binding = provider._binding_store.get("int-1")
    assert binding is not None
    assert binding.platform == "microsoft365"

    # The opaque target_ref we registered earlier.
    registry = TargetRegistryStore(machine_data_dir)
    [record] = registry.list(integration_id="int-1")
    assert record.target_id.startswith("mtgt_1_")
    assert record.drive_id == "drive-1"
    assert record.folder_id == "smoke"

    # ------------------------------------------------------------------
    # 6) execute the mocked scan as the "service" would
    # ------------------------------------------------------------------
    claim = JobClaim.from_claim(
        fake_claim(
            job_id="job-smoke-service",
            platform="microsoft365",
            target_type="folder",
            target_ref=record.target_id,
        )
    )
    engine = SecuredactEngine(build_production_engine(require_contextual=False))
    from securedact_core.policies import STRICT_EXTERNAL_AI_POLICY

    policy = ResolvedPolicy(
        policy=STRICT_EXTERNAL_AI_POLICY,
        policy_version_id="pv-svc-1",
        content_digest="d" * 64,
    )
    exe = execute_job(claim, engine, provider, policy)
    assert exe.status == "succeeded"
    # The service-runtime scan must touch all 3 synthetic files.
    assert exe.resources_scanned == 3


# ---------------------------------------------------------------------------
# additional root-resolution invariants
# ---------------------------------------------------------------------------


def test_all_microsoft_stores_share_machine_data_root(
    machine_data_dir: Path,
) -> None:
    """Every Microsoft-scoped store must resolve under the same data root."""

    assert SecuredactPaths.resolve().root == machine_data_dir.resolve()

    # Agent binding store
    agent_files = AgentFiles.resolve()
    assert agent_files.root.is_relative_to(machine_data_dir)

    # Microsoft client config
    cfg_store = MicrosoftClientConfigStore(machine_data_dir)
    assert cfg_store._token_path.is_relative_to(machine_data_dir)

    # Microsoft credential (token) store via the config loader's resolver
    from securedact_mcp.connectors.microsoft.config import _resolve_token_paths

    token_path, key_path = _resolve_token_paths("default")
    assert token_path.is_relative_to(machine_data_dir)
    assert key_path.is_relative_to(machine_data_dir)

    # Microsoft target registry
    tr_store = TargetRegistryStore(machine_data_dir)
    assert tr_store._path.is_relative_to(machine_data_dir)
    assert tr_store._key_path.is_relative_to(machine_data_dir)


def test_supported_binding_platforms_contains_microsoft() -> None:
    """The CLI choices list is the source of truth for binding platforms."""

    assert "google_workspace" in SUPPORTED_BINDING_PLATFORMS
    assert "microsoft365" in SUPPORTED_BINDING_PLATFORMS
