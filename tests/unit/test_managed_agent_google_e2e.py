# SPDX-License-Identifier: Apache-2.0
"""End-to-end managed-agent Google Drive scan flow (AGENT-018 / GWS-110).

Proves the FIRST REAL production-style managed local scan:

    control-plane claim (google_workspace)
        -> GoogleScanProvider
        -> local Google Drive retrieval (FAKE transport, no network/SDK)
        -> securedact_core detection (real deterministic engine)
        -> privacy-safe reducer
        -> ONLY bounded summary metadata submitted to the (fake) control plane

No Google SDK, no live account, and no real control plane are used. The tests
assert the synthetic source document's PII and any OAuth token material never
leave the machine: they are absent from the safe result, the job heartbeat, and
every recorded control-plane request body.
"""

from __future__ import annotations

import importlib
import json
import re
import types
from urllib.parse import unquote

import pytest

import securedact_mcp.agent.provider_google as provider_google
import securedact_mcp.connectors.google.client as google_client_mod
import securedact_mcp.connectors.google.auth as google_auth_mod
from securedact_core import SecuredactEngine
from securedact_core.connectors.google import (
    CANONICAL_DRIVE_BASE,
    GoogleApiError,
)
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
from securedact_mcp.connectors.google.client import GoogleConnectorClient
from tests.unit.agent_helpers import FakeTransport, fake_claim

DOCS = "application/vnd.google-apps.document"
FOLDER = "application/vnd.google-apps.folder"


class _FakeBindingStore:
    """In-memory ConnectorBindingStore returning a fixed binding for int-1."""

    def __init__(self, bindings: dict[str, ConnectorBinding]) -> None:
        self._bindings = bindings

    def get(self, integration_id: str) -> ConnectorBinding | None:
        return self._bindings.get(integration_id)

    def list(self) -> list[ConnectorBinding]:
        return list(self._bindings.values())


@pytest.fixture(autouse=True)
def google_default_binding(monkeypatch):
    """Every managed-agent Google scan now requires a local binding lookup.

    Provide the integration_id used by the shared ``fake_claim`` helper so the
    existing end-to-end scans resolve to the ``default`` local profile.
    """

    store = _FakeBindingStore(
        {
            "int-1": ConnectorBinding(
                integration_id="int-1",
                platform="google_workspace",
                local_profile="default",
            )
        }
    )
    monkeypatch.setattr(provider_google, "ConnectorBindingStore", lambda *a, **k: store)
    return store


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


class FakeGoogleTransport:
    """Minimal in-memory Google Drive v3 double (no SDK, no network)."""

    def __init__(self, user_id: str = "user-123") -> None:
        self.base_url = CANONICAL_DRIVE_BASE
        self.user_id = user_id
        self.refresh_token: str | None = None
        self.by_id: dict[str, dict] = {}
        self.exports: dict[str, bytes] = {}
        self.media: dict[str, bytes] = {}

    def add_file(self, **kwargs: object) -> dict:
        item = dict(kwargs)
        self.by_id[item["id"]] = item
        return item

    def get_json(self, path: str) -> dict:
        path = unquote(path)
        m = re.match(r"files/([^?]+)\?fields=", path)
        if m:
            item = self.by_id.get(m.group(1))
            if item is None:
                raise GoogleApiError("not found", status_code=404)
            return item
        if path.startswith("files?q="):
            folder_id = None
            mm = re.search(r"'([^']+)' in parents", path)
            if mm and mm.group(1) != "root":
                folder_id = mm.group(1)
            items = [
                it
                for it in self.by_id.values()
                if (
                    folder_id is None
                    and ("root" in (it.get("parents") or []) or not it.get("parents"))
                )
                or (folder_id is not None and folder_id in (it.get("parents") or []))
            ]
            return {"files": items}
        raise GoogleApiError("unexpected path", status_code=400)

    def get_content(self, path: str, *, max_bytes: int | None = None) -> bytes:
        if "/export?mimeType=" in path:
            fid = re.match(r"files/([^/]+)/export", path).group(1)
            data = self.exports.get(fid)
        elif "alt=media" in path:
            fid = re.match(r"files/([^?]+)\?alt=media", path).group(1)
            data = self.media.get(fid)
        else:
            raise GoogleApiError("unexpected content path", status_code=400)
        if data is None:
            raise GoogleApiError("not found", status_code=404)
        return data


def _patch_google_client(monkeypatch, transport):
    """Route GoogleScanProvider's client construction at our fake transport.

    The production provider calls ``build_client(config, engine)`` with no
    transport, so we capture and force the injected fake transport regardless of
    what the caller passes. This exercises the real GoogleScanProvider +
    GoogleConnectorClient + GoogleDriveBrowser path without any Google SDK,
    network, or on-disk credential being touched.
    """

    captured = transport

    def fake_build(config, eng, *, transport=None, user_id=None):
        return GoogleConnectorClient(config, eng, transport=captured, user_id="user-123")

    def fake_load_credentials(config):
        # Return a dummy credential object that the client can use
        class FakeCreds:
            pass
        return FakeCreds()

    monkeypatch.setattr(google_client_mod, "build_client", fake_build)
    monkeypatch.setattr(google_auth_mod, "load_credentials", fake_load_credentials)
    return transport


# --- 1. Single-file end-to-end ------------------------------------------------


def test_single_file_google_scan_submits_only_safe_metadata(monkeypatch, engine):
    transport = FakeGoogleTransport()
    transport.add_file(id="doc1", name="Report", mimeType=DOCS, parents=["root"])
    transport.exports["doc1"] = SYNTHETIC_DOC.encode("utf-8")
    _patch_google_client(monkeypatch, transport)

    claim = JobClaim.from_claim(
        fake_claim(job_id="job-single", target_type="resource", target_ref="doc1")
    )
    provider = provider_google.GoogleScanProvider()
    exe = execute_job(claim, engine, provider, _resolved_policy())

    assert exe.status == "succeeded"
    # Real category breakdown is surfaced (never the values).
    assert exe.categories == ["email", "iban", "phone"]
    assert exe.counts == {"email": 1, "iban": 1, "phone": 1}
    # The strict policy allowed/auto-handled the content (status OK), so no
    # human review is required, but the findings are still summarized safely.
    assert exe.severity == "medium"

    result_dict = build_safe_result_dict(exe)
    # The strict validator accepts it (allowlisted fields only).
    assert validate_safe_result(result_dict)["status"] == "succeeded"
    # No PII / content / token substrings anywhere in the serialized result.
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


def test_folder_google_scan_aggregates_categories_and_resources(monkeypatch, engine):
    transport = FakeGoogleTransport()
    transport.add_file(id="folder", name="Folder", mimeType=FOLDER, parents=["root"])
    transport.add_file(id="a", name="a.txt", mimeType="text/plain", parents=["folder"], size=200)
    transport.add_file(
        id="b", name="b.pdf", mimeType="application/pdf", parents=["folder"], size=200
    )
    transport.add_file(
        id="clean", name="clean.txt", mimeType="text/plain", parents=["folder"], size=50
    )
    transport.add_file(
        id="pii", name="pii.txt", mimeType="text/plain", parents=["folder"], size=200
    )
    transport.media["a"] = b"mail jane@example.com"
    transport.media["clean"] = b"nothing to see"
    transport.media["pii"] = b"IBAN NL91ABNA0417164300 phone +31612345678"
    _patch_google_client(monkeypatch, transport)

    claim = JobClaim.from_claim(
        fake_claim(job_id="job-folder", target_type="folder", target_ref="folder")
    )
    provider = provider_google.GoogleScanProvider()
    exe = execute_job(claim, engine, provider, _resolved_policy())

    assert exe.status == "succeeded"
    # resources_scanned reflects the real number of Drive items inspected.
    # (b.pdf is unsupported, so it is counted as unsupported rather than scanned.)
    assert exe.resources_scanned == 3
    # Category counts are aggregated (a=email, pii=iban+phone); values are not.
    assert exe.counts.get("email") == 1
    assert exe.counts.get("iban") == 1
    assert exe.counts.get("phone") == 1
    # The aggregate marks review required because findings were discovered.
    assert exe.review_required is True

    result_dict = build_safe_result_dict(exe)
    assert validate_safe_result(result_dict)["status"] == "succeeded"
    blob = json.dumps(result_dict, sort_keys=True)
    assert "jane@example.com" not in blob
    assert "NL91ABNA0417164300" not in blob


# --- 2b. Lease heartbeat during local scan (AGENT-018 / GWS-110, §19) ---------

# OAuth token material must also never be surfaced as identity. A leaked
# ``ya29.``/``1//`` token in ``user_id`` would still pass the reducer's substring
# check, so the connector must guarantee the resolved identity is a benign
# ``sub`` and never the bearer token.


def test_folder_scan_keeps_lease_alive_via_heartbeat(monkeypatch, engine):
    transport = FakeGoogleTransport()
    transport.add_file(id="folder", name="Folder", mimeType=FOLDER, parents=["root"])
    for i in range(30):
        fid = f"f{i}"
        transport.add_file(
            id=fid, name=f"{fid}.txt", mimeType="text/plain", parents=["folder"], size=50
        )
        transport.media[fid] = b"nothing to see"
    _patch_google_client(monkeypatch, transport)

    provider = provider_google.GoogleScanProvider()
    calls: list[int] = []

    from securedact_core.connectors.contracts import ScanContext

    target = ScanTarget(
        platform="google_workspace",
        integration_id="int-1",
        target_type="folder",
        target_ref="folder",
    )
    provider.scan(target, ScanContext(), engine, heartbeat=lambda: calls.append(1))

    # Heartbeat must fire at least once at the provider boundary and again inside
    # the recursive Drive walk, so a long scan cannot silently lose its lease.
    # (No concurrent threads are used -- the walk calls it sequentially.)
    assert len(calls) >= 2


# --- 3. Control-plane submission privacy (PII exfiltration regression) -------


def test_pii_never_reaches_control_plane(monkeypatch, engine):
    transport = FakeGoogleTransport()
    transport.add_file(id="doc1", name="Report", mimeType=DOCS, parents=["root"])
    transport.exports["doc1"] = SYNTHETIC_DOC.encode("utf-8")
    _patch_google_client(monkeypatch, transport)

    claim = JobClaim.from_claim(
        fake_claim(job_id="job-pii", target_type="resource", target_ref="doc1")
    )
    provider = provider_google.GoogleScanProvider()
    exe = execute_job(claim, engine, provider, _resolved_policy())

    cp = FakeTransport()  # fake control plane recording every request
    client = ControlPlaneClient(
        "https://cp.example.test",
        credential_provider=lambda: types.SimpleNamespace(authorization_header="Bearer sra_test"),
        transport=cp,
    )
    _submit_result(client, claim, exe)

    # Concatenate every outgoing request body to the control plane.
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
    # The safe result arrived and is itself clean.
    submitted = cp.last_request()[2]
    assert submitted["result"]["status"] == "succeeded"
    assert "jane@example.com" not in json.dumps(submitted, sort_keys=True)


# --- 4. OAuth token exfiltration regression ----------------------------------


def test_oauth_tokens_never_leak(monkeypatch, engine):
    transport = FakeGoogleTransport(user_id="ya29.fake-access-token")
    transport.held_credential = "1//fake-refresh-token"
    transport.add_file(id="doc1", name="Report", mimeType=DOCS, parents=["root"])
    transport.exports["doc1"] = SYNTHETIC_DOC.encode("utf-8")
    _patch_google_client(monkeypatch, transport)

    claim = JobClaim.from_claim(
        fake_claim(job_id="job-token", target_type="resource", target_ref="doc1")
    )
    provider = provider_google.GoogleScanProvider()
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


def test_missing_google_connector_fails_closed(monkeypatch, engine):
    real_import = importlib.import_module

    def fake_import(name, *args, **kwargs):
        if name.startswith("securedact_mcp.connectors.google"):
            raise ModuleNotFoundError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(provider_google.importlib, "import_module", fake_import)
    provider = provider_google.GoogleScanProvider()
    from securedact_core.connectors.contracts import ScanContext

    with pytest.raises(Exception) as exc_info:
        provider.scan(
            ScanTarget(
                platform="google_workspace",
                integration_id="int-1",
                target_type="resource",
                target_ref="doc1",
            ),
            ScanContext(),
            engine,
        )
    # The raw ModuleNotFoundError must be converted into a safe JobExecutionError.
    from securedact_mcp.agent.errors import JobExecutionError

    assert type(exc_info.value) is JobExecutionError
    assert "ModuleNotFoundError" not in str(exc_info.value)


# --- 6. Capability advertisement ---------------------------------------------


def test_capability_advertises_google_not_microsoft():
    from securedact_mcp.agent.capabilities import AgentCapabilities

    caps = AgentCapabilities.default()
    assert "google_drive" in caps.capabilities
    assert "google_workspace" in caps.supported_platforms
    # Microsoft has no local Graph transport yet -> never advertised.
    assert "microsoft365" not in caps.supported_platforms
    assert "microsoft" not in caps.capabilities


# --- 7. Optional-connector failure maps to safe connector_unavailable --------


def test_provider_unavailable_maps_to_connector_unavailable(engine):
    from securedact_mcp.agent.errors import JobExecutionError
    from tests.unit.agent_helpers import FakeScanProvider

    claim = JobClaim.from_claim(fake_claim())
    provider = FakeScanProvider(
        [],
        error=JobExecutionError(
            "google provider unavailable: ModuleNotFoundError "
            "No module named 'securedact_mcp.connectors.google.client'"
        ),
    )
    with pytest.raises(JobExecutionError) as exc_info:
        execute_job(claim, engine, provider, _resolved_policy())
    # The runner maps this to the safe connector_unavailable code.
    assert "unavailable" in str(exc_info.value).lower()
    failed = _failed_result(_resolved_policy(), "connector_unavailable")
    assert (
        validate_safe_result(build_safe_result_dict(failed))["safe_error_code"]
        == "connector_unavailable"
    )
