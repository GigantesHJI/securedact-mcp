# SPDX-License-Identifier: Apache-2.0
"""ACL locale-independence regression tests for managed-agent provisioning.

These prove the Windows ACL provisioning path never depends on the *localized*
English built-in account names ("Administrators", "SYSTEM"). On a non-English
Windows host the friendly name ``Administrators`` is not resolvable by
``LookupAccountName`` / icacls, which yields ERROR_NONE_MAPPED (exit 1332) and
aborts the managed-agent install before registration.

The fix is to reference the built-in principals by their canonical, stable SIDs
with icacls' ``*SID`` syntax:

* LocalSystem:        *S-1-5-18
* Builtin Admins:     *S-1-5-32-544

These tests run on every platform; the Windows name-resolution failure is
simulated so CI (non-Windows) can still prove the regression stays fixed.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from securedact_mcp.agent import deploy, service_security

# SID strings that must be used instead of localized friendly names.
SID_LOCALSYSTEM = "S-1-5-18"
SID_ADMINISTRATORS = "S-1-5-32-544"

# The localized English names that must NEVER reach an icacls argument.
_FORBIDDEN_FRIENDLY = ("Administrators", "SYSTEM")


def _is_icacls(args: list[str]) -> bool:
    return bool(args) and "icacls" in str(args[0]).lower()


def _granted_principals(cmd: list[str]) -> list[str]:
    """Return the principal tokens (left of ':' in a grant) from an icacls cmd."""

    out: list[str] = []
    for tok in cmd:
        tok = str(tok)
        if any(sep in tok for sep in (":(OI)", ":F", ":RX", ":M")):
            out.append(tok.split(":", 1)[0])
    return out


class _NonEnglishIcaclsRunner:
    """Mimics real-Windows icacls on a host where friendly names are unresolvable.

    Real icacls treats a grant principal that is a localized account name as a
    name to look up via LookupAccountName. On a non-English host that lookup fails
    with ERROR_NONE_MAPPED and icacls exits 1332. We reproduce that exactly so any
    regression that re-introduces a friendly-name principal fails closed here.
    """

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.failed_stderr: list[str] = []

    def __call__(self, cmd: list[str], _inp: object) -> object:
        self.calls.append(list(cmd))
        if _is_icacls(cmd):
            for principal in _granted_principals(cmd):
                bare = principal[1:] if principal.startswith("*") else principal
                if bare in _FORBIDDEN_FRIENDLY:
                    self.failed_stderr.append(
                        f"{bare}: No mapping between account names and security IDs was done."
                    )
                    return SimpleNamespace(
                        returncode=1332,
                        stderr=self.failed_stderr[-1],
                    )
        return SimpleNamespace(returncode=0, stderr="")


# ---------------------------------------------------------------------------
# 1. Administrators uses the canonical SID, not the English localized name
# ---------------------------------------------------------------------------


def test_build_principals_administrators_uses_canonical_sid():
    principals = service_security.build_service_account_principals(
        "C:\\ProgramData\\Securedact",
        service_account=r"NT SERVICE\SecuredactAgent",
        installing_user="alice",
    )
    joined = " ".join(principals)
    assert r"*S-1-5-32-544:(OI)(CI)F" in joined
    assert "Administrators" not in joined
    assert r"*S-1-5-18:(OI)(CI)F" in joined


# ---------------------------------------------------------------------------
# 2. SYSTEM uses the canonical SID (S-1-5-18)
# ---------------------------------------------------------------------------


def test_build_principals_system_uses_canonical_sid():
    principals = service_security.build_service_account_principals(
        "C:\\ProgramData\\Securedact",
        service_account="LocalSystem",
        installing_user="alice",
    )
    joined = " ".join(principals)
    assert r"*S-1-5-18:(OI)(CI)F" in joined
    assert "SYSTEM:" not in joined


# ---------------------------------------------------------------------------
# 3. Generated icacls commands need no localized name lookup (non-English host)
# ---------------------------------------------------------------------------


def test_runtime_icacls_commands_are_locale_independent(tmp_path: Path):
    runtime = tmp_path / "runtime"
    runner = _NonEnglishIcaclsRunner()
    deploy._harden_runtime_dir(
        runtime,
        command_runner=runner,
        service_account=r"NT SERVICE\SecuredactAgent",
        installing_user="alice",
    )
    assert runner.calls, "icacls was not invoked"
    for cmd in runner.calls:
        for principal in _granted_principals(cmd):
            bare = principal[1:] if principal.startswith("*") else principal
            assert bare not in _FORBIDDEN_FRIENDLY


# ---------------------------------------------------------------------------
# 4. A simulated non-English Windows host cannot trigger 1332 from naming
# ---------------------------------------------------------------------------


def test_non_english_host_runtime_never_triggers_1332(tmp_path: Path):
    runtime = tmp_path / "runtime"
    runner = _NonEnglishIcaclsRunner()
    # Would raise AgentError(icacls=1332) if any friendly name slipped in.
    deploy._harden_runtime_dir(
        runtime,
        command_runner=runner,
        service_account=r"NT SERVICE\SecuredactAgent",
        installing_user="alice",
    )
    assert runner.failed_stderr == []


def test_non_english_host_parent_acl_never_triggers_1332(tmp_path: Path, monkeypatch):
    # Wire a fake data dir so the parent is the expected Securedact data dir.
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    runtime = data_dir / "runtime"
    runtime.mkdir()
    monkeypatch.setattr(service_security, "_lookup_sid", lambda name: None)
    runner = _NonEnglishIcaclsRunner()
    deploy._harden_runtime_parent(
        runtime,
        command_runner=runner,
        installing_user="alice",
        data_dir=data_dir,
    )
    assert runner.calls, "parent icacls was not invoked"
    for cmd in runner.calls:
        for principal in _granted_principals(cmd):
            bare = principal[1:] if principal.startswith("*") else principal
            assert bare not in _FORBIDDEN_FRIENDLY
    assert runner.failed_stderr == []


# ---------------------------------------------------------------------------
# 5. Existing ACL invariants remain unchanged
# ---------------------------------------------------------------------------


def test_acl_invariants_preserved(monkeypatch):
    monkeypatch.setattr(service_security, "_lookup_sid", lambda name: None)
    principals = service_security.build_service_account_principals(
        "C:\\ProgramData\\Securedact",
        service_account=r"NT SERVICE\SecuredactAgent",
        installing_user="alice",
    )
    joined = " ".join(principals)
    # SYSTEM/Admins still full control.
    assert r"*S-1-5-18:(OI)(CI)F" in joined
    assert r"*S-1-5-32-544:(OI)(CI)F" in joined
    # Installing user is read+execute only, never full.
    assert "alice:(OI)(CI)RX" in joined
    assert "alice:(OI)(CI)F" not in joined
    # No Users / Everyone writer.
    assert "Users" not in joined
    assert "Everyone" not in joined
    # vSA retains full on its own store.
    assert r"NT SERVICE\SecuredactAgent:(OI)(CI)F" in joined


def test_fail_closed_preserved_when_icacls_fails(tmp_path: Path):
    from securedact_mcp.agent.errors import AgentError

    def _boom(cmd, _inp):
        if _is_icacls(cmd):
            return SimpleNamespace(returncode=1332, stderr="boom")
        return SimpleNamespace(returncode=0, stderr="")

    with pytest.raises(AgentError):
        deploy._harden_runtime_dir(
            tmp_path / "runtime",
            command_runner=_boom,
            service_account=r"NT SERVICE\SecuredactAgent",
            installing_user="alice",
        )
