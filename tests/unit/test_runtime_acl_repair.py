# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the real-Windows empty-DACL runtime defect.

Root cause (reproduced on real Windows): a single
``icacls <tree> /inheritance:r /T /grant:r ...(OI)(CI)...`` leaves existing *leaf
files* (e.g. ``Scripts\\python.exe``) with an EMPTY, deny-all DACL, because
Windows drops an ACE that carries the container-inherit (``CI``) / object-inherit
(``OI``) flags on a non-container object. This broke ``CreateProcess`` (WinError
5) and failed closed on launch. The same inheritance semantics also meant the
parent data dir kept inherited (too-permissive) ``Users`` rights when its
hardening was skipped.

These tests model real icacls inheritance semantics with a faithful simulator and
prove that:

* a runtime tree containing a child executable with an EMPTY / non-inheriting DACL
  is fully repaired (every directory AND file ends up executable by SYSTEM/
  Administrators and read-only by the installing user);
* the second / final hardening pass adds the vSA as RX *recursively* on the runtime
  without ever granting it F on the runtime;
* ``verify_runtime_tree_acl`` fails closed when a file is left with an empty DACL
  or the parent data dir still carries inherited ``Users`` write rights.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

import pytest

from securedact_mcp.agent import deploy, service_security
from securedact_mcp.agent.deploy import RunInput, RunResult
from securedact_mcp.agent.errors import AgentError

VSA = r"NT SERVICE\SecuredactAgent"
# The exact vSA SID a real ``LookupAccountName`` returns once the SCM service
# exists (modeled here so the simulator matches production ``enumerate_aces_windows``
# output, which yields raw SIDs, not friendly names).
VSA_SID = "S-1-5-80-620614963-1222874592-19579718-3907403416-2176592688"

# Map the principal names icacls emits to the SIDs the real ACL provider returns,
# so the simulator can feed the production ``untrusted_writers`` / ``_trusted_has_rx``
# policy functions unchanged.
_SID_NORM = {
    "*S-1-5-18": "S-1-5-18",
    "*S-1-5-32-544": "S-1-5-32-544",
    VSA: VSA_SID,
}


def _patch_vsa_lookup(monkeypatch) -> None:
    """Resolve the vSA friendly name to its exact SID ( post-SCM ), fail closed else."""

    def fake_lookup(name: str) -> str | None:
        if name == VSA:
            return VSA_SID
        return None

    monkeypatch.setattr(service_security, "_lookup_sid", fake_lookup)


def _rights_from(spec: str) -> set[str]:
    """Map an icacls rights string to the high-level rights set the policy uses."""

    base = re.sub(r"\([^)]*\)", "", spec)
    if base == "F":
        # F == GENERIC_ALL; mirrors service_security._mask_to_rights.
        return service_security._mask_to_rights(0x10000000)
    # RX (read + execute) is not mapped to any high-level right by the policy, so
    # an RX-only principal is neither a "writer" nor (by itself) a "read+execute"
    # grant for SYSTEM/Admins -- exactly the real behavior we rely on.
    return set()


class WindowsAclSimulator:
    """Faithful model of icacls/Windows DACL semantics for leaf vs container.

    Tracks a DACL per path. Applying an ACE that carries ``(OI)``/``(CI)`` to a
    *leaf file* drops the ACE (real Windows behavior); applying it to a container
    keeps it (and it would propagate to future children). ``/inheritance:r``
    removes inherited ACEs; ``/grant:r`` replaces, ``/grant`` appends/merges.
    """

    def __init__(self, paths: list[Path], files: set[Path]) -> None:
        self.paths = paths
        self.files = files
        self.dacls: dict[Path, dict[str, str]] = {p: {} for p in paths}

    @classmethod
    def discover(cls, root: Path) -> WindowsAclSimulator:
        paths: list[Path] = [root]
        files: set[Path] = set()
        for child in sorted(root.rglob("*")):
            paths.append(child)
            if child.is_file():
                files.add(child)
        return cls(paths, files)

    def _targets(self, target: Path, recursive: bool) -> list[Path]:
        if not recursive:
            return [target]
        out = []
        for p in self.paths:
            if p == target or target in p.parents:
                out.append(p)
        return out

    def apply(self, cmd: list[str]) -> None:
        args = [str(a) for a in cmd]
        if not (args and "icacls" in args[0].lower()):
            return
        target = Path(args[1])
        remove_inheritance = "/inheritance:r" in args
        recursive = "/T" in args
        principals: list[tuple[str, str]] = []
        for i, a in enumerate(args):
            if a in ("/grant:r", "/grant"):
                mode = "replace" if a == "/grant:r" else "add"
                j = i + 1
                while j < len(args) and not args[j].startswith("/"):
                    principals.append((mode, args[j]))
                    j += 1
                break
        if remove_inheritance:
            # Inherited ACEs are modeled as already-materialized explicit ACEs on
            # Windows; the only observable effect here is the explicit grants below.
            pass
        for t in self._targets(target, recursive):
            is_file = t in self.files
            for _mode, princ in principals:
                name, _, rights = princ.partition(":")
                base = re.sub(r"\([^)]*\)", "", rights)
                has_inherit = "(" in rights and ("OI" in rights or "CI" in rights)
                if is_file and has_inherit:
                    # Real Windows drops (OI)(CI) ACEs on leaf files -> no usable ACE.
                    continue
                self.dacls.setdefault(t, {})[name] = base

    def provider(self, path: Path) -> list[tuple[str, str, set[str]]]:
        dacl = self.dacls.get(Path(path), {})
        aces: list[tuple[str, str, set[str]]] = []
        for name, rights in dacl.items():
            sid = _SID_NORM.get(name, name)
            aces.append((sid, "allow", _rights_from(rights)))
        return aces


class SimulatingRunner:
    """Command runner that drives ``icacls`` commands through the simulator."""

    def __init__(self, sim: WindowsAclSimulator) -> None:
        self.sim = sim
        self.calls: list[tuple[list[str], RunInput]] = []

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        args = list(arguments)
        self.calls.append((args, run_input))
        if args and "icacls" in str(args[0]).lower():
            self.sim.apply(args)
        return RunResult(returncode=0, stdout="", stderr="")


def _build_runtime_tree(root: Path) -> None:
    (root / "Scripts").mkdir(parents=True)
    (root / "Scripts" / "python.exe").write_bytes(b"MZ")
    (root / "python312.dll").write_bytes(b"DLL")
    (root / "Lib" / "site-packages" / "securedact_mcp").mkdir(parents=True)
    (root / "Lib" / "site-packages" / "securedact_mcp" / "__init__.py").write_bytes(b"")
    (root / "Lib" / "site-packages" / "win32").mkdir(parents=True)
    (root / "Lib" / "site-packages" / "win32" / "pythonservice.exe").write_bytes(b"MZ")


def _icacls_calls(runner: SimulatingRunner) -> list[list[str]]:
    return [args for args, _ in runner.calls if "icacls" in str(args[0]).lower()]


def _seed_data_dir(sim: WindowsAclSimulator, data_dir: Path, *, with_vsa: bool = False) -> None:
    """Model the (correctly hardened) data dir so post-hardening verify passes."""

    data_dir.mkdir(parents=True, exist_ok=True)
    sim.paths.append(data_dir)
    dacl = {"*S-1-5-18": "F", "*S-1-5-32-544": "F", "alice": "RX"}
    if with_vsa:
        dacl[VSA] = "F"
    sim.dacls[data_dir] = dacl


# ---------------------------------------------------------------------------
# 1. Two-pass hardening repairs a runtime tree that contains an empty-DACL child
# ---------------------------------------------------------------------------


def test_two_pass_repairs_empty_dacl_child_executable(tmp_path: Path) -> None:
    runtime = tmp_path / "data" / "runtime"
    _build_runtime_tree(runtime)
    # Model the reported defect: the existing child executable has an EMPTY (deny-all)
    # DACL / non-inheriting ACEs before hardening.
    sim = WindowsAclSimulator.discover(runtime)
    sim.dacls[runtime / "Scripts" / "python.exe"] = {}
    runner = SimulatingRunner(sim)

    deploy._harden_runtime_dir(runtime, command_runner=runner, installing_user="alice")

    calls = _icacls_calls(runner)
    assert len(calls) == 2, calls
    pass1, pass2 = calls
    # Pass 1: replace + remove inheritance, recursive, container-propagation ACEs.
    assert "/inheritance:r" in pass1 and "/T" in pass1 and "/grant:r" in pass1
    assert any("alice:(OI)(CI)RX" in a for a in pass1)
    # Pass 2: append flag-less ACEs so leaf files become executable (no /inheritance:r).
    assert "/grant" in pass2 and "/inheritance:r" not in pass2 and "/T" in pass2
    assert any("alice:RX" in a for a in pass2)

    # Every leaf file now has usable ACEs (NOT an empty DACL).
    python = runtime / "Scripts" / "python.exe"
    assert sim.dacls[python] == {"*S-1-5-18": "F", "*S-1-5-32-544": "F", "alice": "RX"}, sim.dacls[
        python
    ]
    dll = runtime / "python312.dll"
    assert sim.dacls[dll].get("*S-1-5-18") == "F"
    svc = runtime / "Lib" / "site-packages" / "win32" / "pythonservice.exe"
    assert sim.dacls[svc].get("*S-1-5-18") == "F"
    # Directories keep the (OI)(CI) propagation ACE (effective F) plus the leaf ACE.
    assert sim.dacls[runtime].get("*S-1-5-18") == "F"

    # The fail-closed post-hardening verification passes on the REAL effective ACLs.
    _seed_data_dir(sim, tmp_path / "data")
    deploy.verify_runtime_tree_acl(runtime, acl_provider=sim.provider, data_dir=tmp_path / "data")


def test_two_pass_repairs_full_tree_including_package_files(tmp_path: Path) -> None:
    runtime = tmp_path / "data" / "runtime"
    _build_runtime_tree(runtime)
    sim = WindowsAclSimulator.discover(runtime)
    # Every file starts with a non-inheriting/empty DACL (worst case).
    for f in sim.files:
        sim.dacls[f] = {}
    runner = SimulatingRunner(sim)

    deploy._harden_runtime_dir(runtime, command_runner=runner, installing_user="alice")

    # All critical code paths enumerated by the production validator are repaired.
    for path in deploy._runtime_code_paths(runtime):
        dacl = sim.dacls.get(path, {})
        assert dacl.get("*S-1-5-18") == "F", f"{path} not SYSTEM-executable: {dacl}"
        assert dacl.get("*S-1-5-32-544") == "F", f"{path} not Admin-executable: {dacl}"
        # Installing user is read-only, never Full, on the runtime tree.
        assert dacl.get("alice") == "RX", f"{path} user ACE wrong: {dacl}"


# ---------------------------------------------------------------------------
# 2. Final (vSA) pass adds RX recursively, never F, on the runtime tree
# ---------------------------------------------------------------------------


def test_final_pass_adds_vsa_rx_recursively_not_f(tmp_path: Path, monkeypatch) -> None:
    # Post-SCM: the vSA name now resolves to its exact SID, so the data dir's
    # vSA:(F) ACE is trusted by SID during verification (not by a name fallback).
    _patch_vsa_lookup(monkeypatch)
    runtime = tmp_path / "data" / "runtime"
    _build_runtime_tree(runtime)
    sim = WindowsAclSimulator.discover(runtime)
    runner = SimulatingRunner(sim)

    deploy._harden_runtime_dir(
        runtime,
        command_runner=runner,
        service_account=VSA,
        installing_user="alice",
        include_service=True,
    )

    calls = _icacls_calls(runner)
    # vSA appears in BOTH passes (container propagation + leaf files).
    assert all(any(f"{VSA}:(OI)(CI)RX" in a or f"{VSA}:RX" in a for a in c) for c in calls)
    # vSA is NEVER granted F anywhere on the runtime tree.
    assert not any(f"{VSA}:(OI)(CI)F" in a or f"{VSA}:F" in a for c in calls for a in c)

    python = runtime / "Scripts" / "python.exe"
    assert sim.dacls[python].get(VSA) == "RX", sim.dacls[python]
    # No vSA:F on any runtime object.
    for path, dacl in sim.dacls.items():
        assert dacl.get(VSA) != "F", f"{path} wrongly grants vSA F: {dacl}"

    _seed_data_dir(sim, tmp_path / "data", with_vsa=True)
    deploy.verify_runtime_tree_acl(
        runtime,
        acl_provider=sim.provider,
        data_dir=tmp_path / "data",
        service_account=VSA,
    )


# ---------------------------------------------------------------------------
# 3. verify_runtime_tree_acl fails closed on the two observed real-host defects
# ---------------------------------------------------------------------------


def test_verify_fails_closed_on_empty_dacl_file(tmp_path: Path) -> None:
    runtime = tmp_path / "data" / "runtime"
    _build_runtime_tree(runtime)
    sim = WindowsAclSimulator.discover(runtime)
    # Harden correctly first...
    deploy._harden_runtime_dir(
        runtime, command_runner=SimulatingRunner(sim), installing_user="alice"
    )
    # ...then regress one file to an empty DACL (the primary defect).
    sim.dacls[runtime / "Scripts" / "python.exe"] = {}
    with pytest.raises(AgentError):
        deploy.verify_runtime_tree_acl(
            runtime, acl_provider=sim.provider, data_dir=tmp_path / "data"
        )


def test_verify_fails_closed_on_permissive_parent_users_write(tmp_path: Path) -> None:
    runtime = tmp_path / "data" / "runtime"
    _build_runtime_tree(runtime)
    sim = WindowsAclSimulator.discover(runtime)
    deploy._harden_runtime_dir(
        runtime, command_runner=SimulatingRunner(sim), installing_user="alice"
    )
    # Parent data dir still carries inherited Users write/create (the second defect).
    parent = tmp_path / "data"
    parent.mkdir(parents=True, exist_ok=True)
    sim.paths.append(parent)
    sim.dacls[parent] = {"S-1-5-18": "F", "*S-1-5-32-544": "F", "alice": "RX", "S-1-5-32-545": "F"}
    with pytest.raises(AgentError):
        deploy.verify_runtime_tree_acl(runtime, acl_provider=sim.provider, data_dir=parent)


# ---------------------------------------------------------------------------
# 4. Old single-pass command sequence would NOT repair the tree (regression guard)
# ---------------------------------------------------------------------------


class SinglePassRunner:
    """Models the OLD buggy implementation: only the first (container) pass runs."""

    def __init__(self, sim: WindowsAclSimulator) -> None:
        self.sim = sim
        self._applied = False

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        args = list(arguments)
        if args and "icacls" in str(args[0]).lower():
            # Honor only the first icacls command (the OLD single pass); the second
            # (leaf-file) pass simply did not exist, so leaf files kept an empty DACL.
            if not self._applied:
                self.sim.apply(args)
                self._applied = True
        return RunResult(returncode=0, stdout="", stderr="")


def test_old_single_pass_leaves_child_file_empty_and_verify_rejects(tmp_path: Path) -> None:
    runtime = tmp_path / "data" / "runtime"
    _build_runtime_tree(runtime)
    sim = WindowsAclSimulator.discover(runtime)
    deploy._harden_runtime_dir(
        runtime, command_runner=SinglePassRunner(sim), installing_user="alice"
    )
    python = runtime / "Scripts" / "python.exe"
    # The leaf file is left with an EMPTY DACL (the real defect).
    assert sim.dacls[python] == {}, sim.dacls[python]
    # Fail-closed verification therefore rejects the runtime before any token use.
    with pytest.raises(AgentError):
        deploy.verify_runtime_tree_acl(
            runtime, acl_provider=sim.provider, data_dir=tmp_path / "data"
        )
