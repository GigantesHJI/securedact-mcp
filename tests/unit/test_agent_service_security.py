# SPDX-License-Identifier: Apache-2.0
"""Security regression tests for the managed-agent Windows service (AGENT-SEC).

These run on every platform. Windows-specific SCM/ACL operations are exercised
with injected providers/mocks so CI (non-Windows) can still prove the security
policy. The policy functions in :mod:`securedact_mcp.agent.service_security` are
pure and testable without pywin32.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from securedact_mcp.agent import service, service_security
from securedact_mcp.agent.agent_runner import build_provider
from securedact_mcp.agent.executor import JobClaim, ScanTarget
from securedact_mcp.agent.provider_google import GoogleScanProvider
from securedact_mcp.agent.safe_log import scrub

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def ace(sid: str, *rights: str, atype: str = "allow") -> tuple[str, str, set[str]]:
    """Build a single ACL entry for injection into a fake acl_provider."""

    return (sid, atype, set(rights))


def safe_provider(path: Path) -> list[tuple[str, str, set[str]]]:
    """Simulate a correctly hardened path: only SYSTEM + Admins can write."""

    return [
        ace("S-1-5-18", "write", "modify", "owner", "dac"),
        ace("S-1-5-32-544", "write", "modify", "owner", "dac"),
        ace("S-1-5-32-545", "read"),  # Users: read only
    ]


def user_writable_provider(path: Path) -> list[tuple[str, str, set[str]]]:
    """Simulate a user-writable venv (pipx / uv tool): the installing user can write."""

    return [
        ace("S-1-5-18", "write", "modify", "owner", "dac"),
        ace("S-1-5-32-544", "write"),
        ace("S-1-5-21-1000", "write", "modify", "owner", "dac"),  # normal user owns it
    ]


# ---------------------------------------------------------------------------
# Section 1/9: code-path integrity gate (fail closed)
# ---------------------------------------------------------------------------


def test_validate_install_security_passes_for_hardened_paths(tmp_path):
    issues = service_security.validate_install_security(
        tmp_path / "data", acl_provider=safe_provider, paths=[tmp_path / "code"]
    )
    assert issues == []


def test_validate_install_security_blocks_user_writable_code(tmp_path):
    issues = service_security.validate_install_security(
        tmp_path / "data",
        acl_provider=user_writable_provider,
        paths=[tmp_path / "venv" / "Lib" / "site-packages" / "securedact_mcp"],
    )
    assert any(i.startswith("writable_code_path:") for i in issues)
    assert "S-1-5-21-1000" in ";".join(issues)


def test_validate_install_security_fails_closed_when_acl_unverifiable(tmp_path, monkeypatch):
    # When no ACL provider is available we cannot prove the code paths are safe,
    # so the install must be refused regardless of the current platform.
    monkeypatch.setattr(service_security, "_default_acl_provider", lambda: None)
    issues = service_security.validate_install_security(tmp_path / "data", paths=[tmp_path / "x"])
    assert any(i.startswith("acl_provider_unavailable:") for i in issues)


def test_validate_install_security_deny_overrides_allow(tmp_path):
    # A DENY for the untrusted writer must clear it from the effective writers.
    def provider(p: Path) -> list[tuple[str, str, set[str]]]:
        return [
            ace("S-1-5-18", "write"),
            ace("S-1-5-21-1000", "write"),
            ace("S-1-5-21-1000", "write", atype="deny"),
        ]

    issues = service_security.validate_install_security(
        tmp_path / "data", acl_provider=provider, paths=[tmp_path / "code"]
    )
    assert issues == []


def test_validate_install_security_blocks_world_writable_data_dir(tmp_path):
    def provider(p: Path) -> list[tuple[str, str, set[str]]]:
        return [ace("S-1-1-0", "write")]  # Everyone can write

    issues = service_security.validate_install_security(
        tmp_path / "data", acl_provider=provider, paths=[tmp_path / "code"]
    )
    assert any(i.startswith("writable_data_dir:") for i in issues)


# ---------------------------------------------------------------------------
# Section 3b: vSA SID canonicalization (AGENT-SEC vSA normalization bug)
# ---------------------------------------------------------------------------
#
# The hardened data dir legitimately grants the virtual service account
# ``NT SERVICE\SecuredactAgent`` Full control. On real Windows that identity may
# surface in a DACL either as its friendly name OR as its raw SID
# (``S-1-5-80-...``); the validator must treat both as the one trusted service
# identity, resolved by name via LookupAccountName — NOT by trusting an
# ``S-1-5-80-*`` prefix generically.

VSA_FRIENDLY = r"NT SERVICE\SecuredactAgent"
VSA_SID = "S-1-5-80-620614963-1222874592-19579718-3907403416-2176592688"
INSTALLING_USER_SID = "S-1-5-21-1000"


def _patch_vsa_lookup(monkeypatch) -> None:
    """Canonicalize the vSA friendly name to its exact SID; fail closed otherwise."""

    def fake_lookup(name: str) -> str | None:
        if name == VSA_FRIENDLY:
            return VSA_SID
        return None

    monkeypatch.setattr(service_security, "_lookup_sid", fake_lookup)


def test_vsa_trusted_when_represented_by_friendly_name(tmp_path, monkeypatch):
    _patch_vsa_lookup(monkeypatch)
    aces = [ace(VSA_FRIENDLY, "write", "modify", "owner", "dac")]
    assert not service_security.untrusted_writers(aces, service_account=VSA_FRIENDLY)


def test_vsa_trusted_when_represented_by_raw_sid(tmp_path, monkeypatch):
    _patch_vsa_lookup(monkeypatch)
    aces = [ace(VSA_SID, "write", "modify", "owner", "dac")]
    assert not service_security.untrusted_writers(aces, service_account=VSA_FRIENDLY)
    # The same ACE must also clear the data-dir gate end to end.
    untrusted = service_security.untrusted_writers(aces, service_account=VSA_FRIENDLY)
    assert untrusted == set()


def test_unrelated_vsa_sid_remains_untrusted(tmp_path, monkeypatch):
    _patch_vsa_lookup(monkeypatch)
    unrelated = "S-1-5-80-111111111-222222222-333333333-444444444-555555555"
    aces = [ace(unrelated, "write", "modify", "owner", "dac")]
    untrusted = service_security.untrusted_writers(aces, service_account=VSA_FRIENDLY)
    assert unrelated in untrusted


def test_real_programdata_acl_passes_with_vsa(tmp_path, monkeypatch):
    _patch_vsa_lookup(monkeypatch)
    aces = [
        ace(VSA_SID, "write", "modify", "owner", "dac"),  # vSA: full on its own store
        ace("S-1-5-32-544", "write", "modify", "owner", "dac"),  # Administrators
        ace("S-1-5-18", "write", "modify", "owner", "dac"),  # SYSTEM
        ace(INSTALLING_USER_SID, "read"),  # installing user: RX only
    ]

    def provider(p: Path) -> list[tuple[str, str, set[str]]]:
        return aces

    issues = service_security.validate_install_security(
        tmp_path / "data", acl_provider=provider, paths=[], service_account=VSA_FRIENDLY
    )
    assert issues == []


def test_world_writable_still_fails_with_vsa_trusted(tmp_path, monkeypatch):
    _patch_vsa_lookup(monkeypatch)
    aces = [
        ace(VSA_SID, "write", "modify", "owner", "dac"),
        ace("S-1-5-32-544", "write"),
        ace("S-1-5-18", "write"),
        ace("S-1-1-0", "write"),  # Everyone: still a hard fail
    ]

    def provider(p: Path) -> list[tuple[str, str, set[str]]]:
        return aces

    issues = service_security.validate_install_security(
        tmp_path / "data", acl_provider=provider, paths=[], service_account=VSA_FRIENDLY
    )
    assert any(i.startswith("writable_data_dir:") for i in issues)


def test_installing_user_full_still_fails(tmp_path, monkeypatch):
    _patch_vsa_lookup(monkeypatch)
    aces = [
        ace(VSA_SID, "write", "modify", "owner", "dac"),
        ace("S-1-5-32-544", "write"),
        ace("S-1-5-18", "write"),
        ace(INSTALLING_USER_SID, "write", "modify", "owner", "dac"),  # user must stay RX
    ]

    def provider(p: Path) -> list[tuple[str, str, set[str]]]:
        return aces

    issues = service_security.validate_install_security(
        tmp_path / "data", acl_provider=provider, paths=[], service_account=VSA_FRIENDLY
    )
    assert any(i.startswith("writable_data_dir:") for i in issues)


def test_unresolvable_sid_mapping_fails_closed(tmp_path, monkeypatch):
    # No principal (including a malformed/unknown name) may be silently trusted
    # when it cannot be resolved to a canonical SID.
    monkeypatch.setattr(service_security, "_lookup_sid", lambda name: None)
    aces = [ace(r"UNRESOLVABLE\GhostPrincipal", "write", "modify", "owner", "dac")]
    untrusted = service_security.untrusted_writers(aces, service_account=VSA_FRIENDLY)
    assert r"UNRESOLVABLE\GhostPrincipal" in untrusted


def test_system_and_administrators_trusted_by_canonical_sid(tmp_path, monkeypatch):
    _patch_vsa_lookup(monkeypatch)
    aces = [
        ace("S-1-5-18", "write", "modify", "owner", "dac"),
        ace("S-1-5-32-544", "write", "modify", "owner", "dac"),
    ]
    # Without naming the service account the gate is strict (SYSTEM/Admin only).
    assert service_security.untrusted_writers(aces) == set()


# ---------------------------------------------------------------------------
# Section 3c: two-phase lifecycle reconciliation (AGENT-SEC vSA / SCM ordering)
# ---------------------------------------------------------------------------
#
# Phase 1 (pre-SCM) must NOT require the vSA SID to resolve. The SCM service
# does not exist yet, so ``LookupAccountName`` returns ERROR_NONE_MAPPED (1332)
# and must not be called as a prerequisite. Phase 1 deterministically resets the
# data dir to the bootstrap ACL (SYSTEM/Admins F + installer RX, no vSA) — which
# also strips any stale vSA ACE left by a prior, since-removed install. Phase 3
# (post-SCM, after the account transition) resolves the *exact* vSA SID and trusts
# it. No S-1-5-80-* prefix is trusted generically.

BOOTSTRAP_ACES = [
    ace("S-1-5-18", "write", "modify", "owner", "dac"),  # SYSTEM
    ace("S-1-5-32-544", "write", "modify", "owner", "dac"),  # Administrators
    ace(INSTALLING_USER_SID, "read"),  # installing user: RX only
]


def _bootstrap_provider(p: Path) -> list[tuple[str, str, set[str]]]:
    return list(BOOTSTRAP_ACES)


def test_phase1_valid_without_vsa_resolution(tmp_path, monkeypatch):
    # Simulate no SCM service: the vSA name is unresolvable.
    monkeypatch.setattr(service_security, "_lookup_sid", lambda name: None)
    issues = service_security.validate_install_security(
        tmp_path / "data", acl_provider=_bootstrap_provider, paths=[tmp_path / "code"]
    )
    assert issues == []


def test_phase1_does_not_attempt_vsa_lookup(tmp_path, monkeypatch):
    calls: list[str] = []

    def spy(name: str) -> str | None:
        calls.append(name)
        return None

    monkeypatch.setattr(service_security, "_lookup_sid", spy)
    # Strict gate (no service_account) must validate without any name resolution.
    assert service_security.untrusted_writers(BOOTSTRAP_ACES) == set()
    service_security.validate_install_security(
        tmp_path / "data", acl_provider=_bootstrap_provider, paths=[]
    )
    # The vSA account is never resolved during Phase 1.
    assert calls == []


def test_vsa_sid_resolves_after_scm_creation(tmp_path, monkeypatch):
    # Post-SCM: the account now exists, so LookupAccountName yields the exact SID.
    _patch_vsa_lookup(monkeypatch)
    sids = service_security.trusted_write_sids(service_account=VSA_FRIENDLY)
    assert sids == {"S-1-5-18", "S-1-5-32-544", VSA_SID}


def test_virtual_service_account_sid_is_deterministic_and_exact():
    # The vSA SID is a pure function of the service name — no LookupAccountName,
    # so it is stable pre- and post-SCM and immune to resolver quirks.
    sid = service_security._virtual_service_account_sid(VSA_FRIENDLY)
    assert sid is not None and sid.startswith("S-1-5-80-")
    assert sid == service_security._virtual_service_account_sid(VSA_FRIENDLY)
    # The "NT SERVICE\" prefix is the same identity; the leaf name is hashed.
    assert sid == service_security._virtual_service_account_sid("SecuredactAgent")
    # We trust the EXACT SID, never a prefix: an arbitrary S-1-5-80-* is distinct.
    assert sid != "S-1-5-80-111111111-222222222-333333333-444444444-555555555"


def test_vsa_trusted_without_lookupaccountname(tmp_path, monkeypatch):
    # Hardening reality: LookupAccountName for a vSA can be flaky/unavailable even
    # post-SCM on some hosts, returning None. The gate must still trust the vSA by
    # its deterministically computed SID (the one Windows assigned to the on-disk
    # ACE), not by a name lookup.
    monkeypatch.setattr(service_security, "_lookup_sid", lambda name: None)
    vsa_sid = service_security._virtual_service_account_sid(VSA_FRIENDLY)
    aces = [ace(vsa_sid, "write", "modify", "owner", "dac")]
    assert not service_security.untrusted_writers(aces, service_account=VSA_FRIENDLY)
    # The exact same SID must also be present in the trusted set.
    assert vsa_sid in service_security.trusted_write_sids(service_account=VSA_FRIENDLY)


def test_diagnostic_includes_phase_and_untrusted_sid(tmp_path, monkeypatch):
    _patch_vsa_lookup(monkeypatch)
    aces = [ace("S-1-1-0", "write")]  # Everyone -> must fail closed

    def provider(p: Path) -> list[tuple[str, str, set[str]]]:
        return aces

    issues = service_security.validate_install_security(
        tmp_path / "data",
        acl_provider=provider,
        paths=[],
        phase="phase3_final_integrity",
    )
    assert any(i.startswith("writable_data_dir:") for i in issues)
    issue = next(i for i in issues if i.startswith("writable_data_dir:"))
    # The diagnostic pinpoints the phase and the offending writer SID (not a secret).
    assert "phase=phase3_final_integrity" in issue
    assert "untrusted=S-1-1-0" in issue


@pytest.mark.skipif(sys.platform != "win32", reason="real-Windows ACL enumeration")
def test_real_windows_vsa_data_dir_trusted_with_actual_provider(tmp_path):
    """End-to-end on real Windows: the actual ACL provider + the vSA's on-disk SID.

    Uses ``enumerate_aces_windows`` (the production provider) against a real temp
    directory whose DACL was set with the deterministic vSA SID, SYSTEM/Admins F,
    and the installing user RX. Proves the gate trusts the vSA by its resolved SID
    and that an unrelated S-1-5-80-* service SID is still rejected.
    """

    import win32security

    from securedact_mcp.agent import service_security as s

    vsa = s._virtual_service_account_sid("NT SERVICE\\SecuredactAgent")
    assert vsa is not None and vsa.startswith("S-1-5-80-")
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    system_sid = win32security.ConvertStringSidToSid("S-1-5-18")
    admin_sid = win32security.ConvertStringSidToSid("S-1-5-32-544")
    vsa_sid = win32security.ConvertStringSidToSid(vsa)
    unrelated = win32security.ConvertStringSidToSid(
        "S-1-5-80-111111111-222222222-333333333-444444444-555555555"
    )

    def _set_dacl(sids_with_mask):
        dacl = win32security.ACL()
        for sid, mask in sids_with_mask:
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, mask, sid)
        sd = win32security.GetFileSecurity(str(data_dir), win32security.DACL_SECURITY_INFORMATION)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(str(data_dir), win32security.DACL_SECURITY_INFORMATION, sd)

    # Trusted layout: SYSTEM/Admins F, installing user RX, vSA F (its own store).
    _set_dacl(
        [
            (system_sid, 0x1F01FF),
            (admin_sid, 0x1F01FF),
            (win32security.ConvertStringSidToSid("S-1-5-21-1000"), 0x1200A9),
            (vsa_sid, 0x1F01FF),
        ]
    )

    # The actual provider enumerates the on-disk raw SID; it must match the
    # deterministic identity we trust.
    enumerated = {sid for sid, _, _ in s.enumerate_aces_windows(data_dir)}
    assert vsa in enumerated

    issues = s.validate_install_security(
        data_dir,
        acl_provider=s.enumerate_aces_windows,
        service_account="NT SERVICE\\SecuredactAgent",
        phase="phase3_final_integrity",
    )
    assert not any(i.startswith("writable_data_dir:") for i in issues), issues

    # If LookupAccountName happens to resolve the vSA, it must equal the SID the
    # provider enumerates (the user's verification requirement).
    looked = s._lookup_sid("NT SERVICE\\SecuredactAgent")
    if looked is not None:
        assert looked == vsa

    # An unrelated service SID with Full control must still be flagged.
    _set_dacl(
        [
            (system_sid, 0x1F01FF),
            (admin_sid, 0x1F01FF),
            (vsa_sid, 0x1F01FF),
            (unrelated, 0x1F01FF),
        ]
    )
    issues2 = s.validate_install_security(
        data_dir,
        acl_provider=s.enumerate_aces_windows,
        service_account="NT SERVICE\\SecuredactAgent",
        phase="phase3_final_integrity",
    )
    assert any(i.startswith("writable_data_dir:") for i in issues2), issues2


# ---------------------------------------------------------------------------
# Section 2: least-privilege identity
# ---------------------------------------------------------------------------


def test_recommended_service_account_is_virtual(monkeypatch):
    monkeypatch.delenv("SECUREDACT_AGENT_SERVICE_ACCOUNT", raising=False)
    assert service_security.recommended_service_account() == r"NT SERVICE\SecuredactAgent"


def test_service_account_principals_grant_user_read_only():
    principals = service_security.build_service_account_principals(
        "C:\\ProgramData\\Securedact",
        service_account=r"NT SERVICE\SecuredactAgent",
        installing_user="alice",
    )
    joined = " ".join(principals)
    # Installing user must be RX (read/execute), never F (full/write).
    assert "alice:(OI)(CI)RX" in joined
    assert "alice:(OI)(CI)F" not in joined
    # SYSTEM + Admins + service account get full.
    assert "*S-1-5-18:(OI)(CI)F" in joined
    # Built-in Administrators MUST be referenced by canonical SID (locale-independent),
    # never by the English localized account name (which triggers icacls 1332 / 1352).
    assert r"*S-1-5-32-544:(OI)(CI)F" in joined
    assert "Administrators:" not in joined
    assert r"NT SERVICE\SecuredactAgent:(OI)(CI)F" in joined


def test_service_account_principals_omit_system_for_localsystem():
    principals = service_security.build_service_account_principals(
        "C:\\ProgramData\\Securedact",
        service_account="LocalSystem",
        installing_user="alice",
    )
    joined = " ".join(principals)
    # LocalSystem is already covered by the S-1-5-18 grant; must not be re-added.
    assert r"LocalSystem:(OI)(CI)F" not in joined


# ---------------------------------------------------------------------------
# Section 3/9: ProgramData ACL hardening must fail closed
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Section 4: import/DLL hijacking mitigation
# ---------------------------------------------------------------------------


def test_service_env_disables_user_site_and_has_no_secret():
    env = service.build_service_env(Path("C:/ProgramData/Securedact"))
    assert env["PYTHONNOUSERSITE"] == "1"
    blob = " ".join(f"{k}={v}" for k, v in env.items())
    for forbidden in ("sra_", "srr_", "sl_", "Bearer ", "token", "ya29."):
        assert forbidden not in blob


# ---------------------------------------------------------------------------
# Section 6: control-plane job cannot invoke arbitrary capability
# ---------------------------------------------------------------------------


def test_build_provider_rejects_unknown_platform():
    assert build_provider("google_workspace") is not None
    assert build_provider("linux") is None
    assert build_provider("cmd.exe") is None
    assert build_provider("") is None


def test_job_claim_ignores_arbitrary_execution_fields():
    # A malicious claim carrying shell/exec/url/path/env must be inert: the
    # executor only reads a fixed allowlist of fields.
    malicious = {
        "job_id": "j1",
        "lease_secret": "sl_abc",
        "platform": "google_workspace",
        "target_type": "folder",
        "target_ref": "root",
        "policy": {},
        "command": "calc.exe",
        "exec": "powershell -e ...",
        "shell": True,
        "url": "https://evil.example",
        "path": "C:\\Windows\\System32",
        "env": {"SECUREDACT_AGENT_CREDENTIAL": "sra_x_y"},
        "import": "os",
    }
    claim = JobClaim.from_claim(malicious)
    # None of the attacker-controlled keys surface as usable attributes.
    for bad in ("command", "exec", "shell", "url", "import"):
        assert not hasattr(claim, bad)
    # The real, schema-bound fields are the only ones the loop can act on.
    assert claim.platform == "google_workspace"
    assert claim.target_ref == "root"


def test_google_provider_fails_closed_on_unknown_target_type(monkeypatch):
    import securedact_mcp.agent.provider_google as pg

    # Stub the optional Google connector modules so the provider can load them.
    fake_client = SimpleNamespace(
        GoogleConfigError=Exception, build_client=lambda *a, **k: object()
    )
    fake_config = SimpleNamespace(load_google_config=lambda *a, **k: object())
    monkeypatch.setattr(
        pg.importlib,
        "import_module",
        lambda name: fake_client if name.endswith(".client") else fake_config,
    )
    provider = GoogleScanProvider(files=None)
    # Stub the binding store so the local-profile resolution succeeds.
    provider._binding_store = SimpleNamespace(  # type: ignore[assignment]
        get=lambda integration_id: SimpleNamespace(
            platform="google_workspace", local_profile="default"
        )
    )
    target = ScanTarget(
        platform="google_workspace",
        integration_id="i1",
        target_type="arbitrary_exec",
        target_ref="x",
    )
    with pytest.raises(Exception, match=r"unsupported|target_type"):
        provider.scan(target, context=None, engine=None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Section 10: secret / log scrubbing
# ---------------------------------------------------------------------------


def test_safe_log_scrubs_all_secret_families():
    sample = (
        "cred sra_abc_def leak srr_ghi_jkl lease sl_mno "
        "Authorization: Bearer topsecret ya29.ya29token "
        "refresh_token=rt_xyz entitlement=eyJ.x.y"
    )
    out = scrub(sample)
    for leak in (
        "sra_abc_def",
        "srr_ghi_jkl",
        "sl_mno",
        "topsecret",
        "ya29.ya29token",
        "rt_xyz",
    ):
        assert leak not in out


# ---------------------------------------------------------------------------
# Section 11: service command line carries no secret
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Dev-baseline flag safety (migrated from the orphaned legacy SCM test suite)
# ---------------------------------------------------------------------------
#
# ``SECUREDACT_AGENT_SERVICE_DEV_BASELINE`` is a DEV-ONLY escape hatch that
# bypasses the custom hardening and runs under the simplest viable identity. It
# must be impossible to flip on by accident (only the literal ``"1"`` enables
# it); otherwise a misconfigured host could silently ship an unhardened runtime.


@pytest.mark.parametrize(
    "val",
    ["", "0", "false", "FALSE", "true", "yes", "on", "y", "2", "10", "one", " 1", "1 "],
)
def test_dev_baseline_not_enabled_for_other_values(monkeypatch, val):
    monkeypatch.setenv(service_security.DEV_BASELINE_ENV, val)
    assert service_security.is_dev_baseline_enabled() is False


def test_dev_baseline_disabled_when_unset(monkeypatch):
    monkeypatch.delenv(service_security.DEV_BASELINE_ENV, raising=False)
    assert service_security.is_dev_baseline_enabled() is False


def test_dev_baseline_enabled_only_for_literal_1(monkeypatch):
    monkeypatch.setenv(service_security.DEV_BASELINE_ENV, "1")
    assert service_security.is_dev_baseline_enabled() is True


# ---------------------------------------------------------------------------
# Section 11: foreground mode unaffected
# ---------------------------------------------------------------------------


def test_foreground_run_loop_still_resolves_and_stops(monkeypatch, tmp_path):
    from securedact_mcp.agent import agent_runner
    from securedact_mcp.agent.config import AgentFiles
    from tests.unit.test_agent_runner import _runner_transport

    transport = _runner_transport({"n": 0}, [])
    files = AgentFiles.resolve(root=tmp_path / "agent")
    agent_runner.register_agent(
        "srr_tok", control_plane_url="https://cp.example.com", files=files, transport=transport
    )
    monkeypatch.setattr(agent_runner, "run_agent_loop", lambda *a, **k: 0)
    rc = service.run_service_loop(stop=lambda: True, idle_sleep=0, data_dir=tmp_path)
    assert rc == 0
