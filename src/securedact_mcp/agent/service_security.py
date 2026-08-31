# SPDX-License-Identifier: Apache-2.0
"""Install-time and runtime security gatekeeping for the managed-agent service.

These helpers implement the Windows managed-agent security release gate:

* **Code-path integrity (Section 1).** The service runs as a high-privilege
  identity (LocalSystem or a virtual service account). Any executable, the
  Python interpreter, the ``securedact_mcp`` package, its ``site-packages``, and
  the pywin32 module directory that LocalSystem will *load* must NOT be writable
  by a non-admin / non-SYSTEM principal. If it is, a normal interactive user can
  drop a module and get code execution as the service identity. We therefore
  fail closed at install time when such a writable path is detected.
* **Least-privilege identity (Section 2).** The default recommended identity is a
  per-service virtual service account ``NT SERVICE\\SecuredactAgent`` — isolated,
  password-less, and granted only the rights it needs. LocalSystem is supported
  only as an explicit fallback.
* **ProgramData ACL (Section 3).** The machine-wide data dir ACL is computed and
  applied by :mod:`securedact_legacy.service_windows`; the helpers here define
  the *trusted* writer set used to validate that hardening actually succeeded.

The platform-specific ACL enumeration is isolated behind
:func:`enumerate_aces_windows` and is only imported on Windows. The pure policy
functions (:func:`effective_writers`, :func:`validate_install_security`) are
fully testable on any platform by injecting an ``acl_provider``.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

# Well-known SIDs that are always trusted to hold write access on code/data
# paths a privileged service loads or owns. Anything else with write is treated
# as an escalation risk. These are pinned by *canonical SID* (never by a prefix
# pattern) so an arbitrary ``S-1-5-80-*`` virtual-service-account SID is NOT
# trusted by default.
_WELL_KNOWN_TRUSTED_SIDS = frozenset(
    {
        "S-1-5-18",  # LocalSystem
        "S-1-5-32-544",  # Administrators
    }
)

# Rights (high-level) that confer the ability to modify/replace a file or its
# security descriptor. A principal holding any of these on a code path can plant
# code that the service will execute.
_WRITE_RIGHTS = frozenset({"write", "modify", "owner", "dac"})

# Windows ACCESS_MASK bit constants (stable across versions; hard-coded so the
# pure logic stays importable and testable without pywin32).
_FILE_WRITE_BITS = 0x0002 | 0x0004 | 0x0010 | 0x0100  # data/append/ea/attributes
_STD_DELETE = 0x10000
_STD_WRITE_DAC = 0x40000
_STD_WRITE_OWNER = 0x80000
_GENERIC_WRITE = 0x40000000
_GENERIC_ALL = 0x10000000

# Default least-privilege identity. A virtual service account is auto-created by
# Windows from the service name (``SecuredactAgent``), needs no password, and is
# isolated from other services and from interactive users.
DEFAULT_VIRTUAL_SERVICE_ACCOUNT = r"NT SERVICE\SecuredactAgent"

# SIDs/names that, when used as the service account, are already covered by the
# SYSTEM principal grant and must not be re-added as a named ACE.
_SYSTEM_EQUIVALENTS = frozenset({"LocalSystem", "local system", r"NT AUTHORITY\System", "system"})

# ---------------------------------------------------------------------------
# DEV-ONLY baseline mode (explicit opt-in; NEVER production secure)
# ---------------------------------------------------------------------------

DEV_BASELINE_ENV = "SECUREDACT_AGENT_SERVICE_DEV_BASELINE"


def is_dev_baseline_enabled() -> bool:
    """Return True ONLY when ``SECUREDACT_AGENT_SERVICE_DEV_BASELINE == '1'``.

    This is an explicitly opt-in, DEV-ONLY escape hatch that temporarily bypasses
    the custom Windows service hardening (ProgramData DACL replacement, runtime
    tree ACL hardening, the code-path integrity gate, vSA ACL/SID validation, and
    pre-start ACL assertions) so the *basic* service lifecycle can be proven
    first. It is NEVER enabled by default and is NOT activated by any other value
    ('0', 'true', 'yes', 'on', 'false', '', etc.), so it cannot be turned on by
    accident or by unrelated environment configuration.

    Application/protocol security is always preserved regardless of this flag:
    the one-time registration token, agent credential, and OAuth token are never
    placed in argv/env/logs; no arbitrary job command is executed; Google content
    stays local; the result allowlist / privacy reducer stays active; and TLS /
    control-plane authentication remain required.
    """

    return os.environ.get(DEV_BASELINE_ENV, "") == "1"


# Shared warning string emitted when the DEV-ONLY baseline service path is used.
# It is defined here (not in the dormant ``service_windows`` reference backend) so
# the active Task Scheduler backend and the reference backend reuse one constant
# without the wheel having to ship ``service_windows``.
DEV_BASELINE_WARNING = (
    "DEV-ONLY BASELINE MODE: custom Windows hardening (ProgramData DACL, "
    "runtime-tree ACL, code-path integrity gate, vSA ACL/SID validation, and "
    "pre-start ACL assertions) was BYPASSED. This is NOT production secure and "
    "must never be used outside local debugging."
)


def recommended_service_account() -> str:
    """Return the least-privilege service identity to install under.

    Defaults to a virtual service account. ``SECUREDACT_AGENT_SERVICE_ACCOUNT``
    can force an explicit account (e.g. ``LocalSystem``) for environments that
    cannot use a vSA, but this should be the exception and documented.
    """

    forced = os.environ.get("SECUREDACT_AGENT_SERVICE_ACCOUNT")
    if forced:
        return forced
    return DEFAULT_VIRTUAL_SERVICE_ACCOUNT


def _mask_to_rights(mask: int) -> set[str]:
    """Map a Windows ACCESS_MASK to high-level right names (pure, testable)."""

    rights: set[str] = set()
    if mask & _FILE_WRITE_BITS:
        rights.add("write")
    if mask & _STD_WRITE_DAC:
        rights.add("dac")
    if mask & _STD_WRITE_OWNER:
        rights.add("owner")
    if mask & _STD_DELETE:
        rights.add("delete")
    if mask & _GENERIC_WRITE:
        rights.add("write")
    if mask & _GENERIC_ALL:
        rights.update({"write", "modify", "owner", "dac", "delete"})
    return rights


def _lookup_sid(name: str) -> str | None:
    """Resolve an account name to its canonical SID string via Windows APIs.

    This is the ONLY sanctioned way to learn a service identity's SID: we call
    ``LookupAccountName`` (or equivalent) so that ``NT SERVICE\\SecuredactAgent``
    and its raw ``S-1-5-80-...`` twin collapse to the *exact same* SID. We never
    trust a SID *prefix* (e.g. "any S-1-5-80-*") — only the concrete resolved
    identity is added to the trusted set.

    Returns ``None`` when not on Windows or when the name cannot be resolved.
    Callers must NOT interpret ``None`` as a reason to *trust* anything: an
    unresolvable service account is simply omitted from the trusted set, which
    is the safe direction (its ACE will not yet be present in that state, e.g.
    before SCM registration).
    """

    if sys.platform != "win32":
        return None
    import win32security

    try:
        sid, _, _ = win32security.LookupAccountName(None, name)
        return str(win32security.ConvertSidToStringSid(sid))
    except Exception:
        return None


def _virtual_service_account_sid(account: str) -> str | None:
    """Deterministically compute a virtual-service-account SID from its name.

    Virtual service accounts (``NT SERVICE\\<name>``) have a SID of the form
    ``S-1-5-80-<sha1(name)>``: the five subauthorities are the little-endian
    32-bit words of the SHA-1 hash of the *service name* (the ``<name>`` portion,
    UTF-16LE). Windows assigns exactly this SID to the on-disk ACE, so computing it
    directly:

    * removes any dependency on ``LookupAccountName`` succeeding (which is
      unavailable before SCM registration and can be flaky on some hosts); and
    * guarantees the trusted SID equals the one the real ACL provider enumerates,
      regardless of how the principal is represented (raw SID or friendly name).

    This is the *exact* identity, never an ``S-1-5-80-*`` prefix — an unrelated
    service SID will not match. Returns ``None`` for inputs that are not a
    service-style name.
    """

    import hashlib

    name = account
    if name.upper().startswith("NT SERVICE\\"):
        name = name[len("NT SERVICE\\") :]
    # Windows derives the vSA SID from the UPPERCASED service name (UTF-16LE), so
    # we hash the uppercased leaf name to match the SID it assigns to the ACE.
    name = name.upper()
    if not name:
        return None
    try:
        digest = hashlib.sha1(name.encode("utf-16-le"), usedforsecurity=False).digest()
    except Exception:
        return None
    if len(digest) < 20:
        return None
    subs = [int.from_bytes(digest[i : i + 4], "little") for i in range(0, 20, 4)]
    return "S-1-5-80-" + "-".join(str(s) for s in subs)


def _is_sid_string(token: str) -> bool:
    """True when ``token`` is already a canonical SID string (``S-1-...``)."""

    return token.startswith("S-1-")


def _canonical_sid(token: str) -> str | None:
    """Map a principal token (SID string or account name) to its canonical SID.

    A token that is already a canonical SID string is returned unchanged. An
    account name is resolved via Windows APIs. Returns ``None`` for an
    unresolvable name (callers fail closed / do not trust it).
    """

    if _is_sid_string(token):
        return token
    return _lookup_sid(token)


def _canonicalize_or_keep(token: str) -> str:
    """Canonicalize ``token``, but never drop it to ``None``.

    Used when normalizing ACE principals: if a token cannot be resolved we keep
    the original string so it still appears in the effective-writer set (and,
    because it will not be in the trusted set, is flagged as untrusted — i.e.
    we fail closed rather than silently ignore an unparseable principal).
    """

    canonical = _canonical_sid(token)
    return canonical if canonical is not None else token


def trusted_write_sids(
    *,
    service_account: str | None = None,
    extra_trusted: Iterable[str] | None = None,
) -> frozenset[str]:
    """Canonical SIDs trusted to hold write on service code/data paths.

    Always includes LocalSystem and Administrators (canonical SIDs). The
    configured service identity (default ``NT SERVICE\\SecuredactAgent``) is
    resolved to its *exact* SID via :func:`_lookup_sid` and trusted as well, so
    the vSA's legitimately-granted Full control on its own data store is not
    false-flagged. Because we resolve by name, a friendly-name ACE and its raw
    SID twin compare equal, and an *unrelated* ``S-1-5-80-*`` service SID (which
    does not match the resolved identity) remains untrusted.

    If ``service_account`` cannot be resolved (non-Windows host, or SCM-not-yet
    created) it is omitted — the safe direction, since its ACE is absent in that
    state.
    """

    sids: set[str] = set(_WELL_KNOWN_TRUSTED_SIDS)
    account = service_account or recommended_service_account()
    if account and account not in _SYSTEM_EQUIVALENTS:
        # Trust the configured service identity by its *exact* SID. We resolve it
        # two independent ways and trust the union:
        #   * via LookupAccountName (Windows API, post-SCM), and
        #   * deterministically from the service name (the algorithm Windows uses
        #     to assign the on-disk SID), which works even pre-SCM and is immune
        #     to LookupAccountName quirks. The leaf name is tried as-is and
        #     uppercased; only the concrete SID(s) derived from the configured
        #     account are trusted — never an S-1-5-80-* prefix.
        resolved = _canonical_sid(account)
        if resolved is not None:
            sids.add(resolved)
        for candidate in (
            _virtual_service_account_sid(account),
            _virtual_service_account_sid(account.upper()),
        ):
            if candidate is not None:
                sids.add(candidate)
    if extra_trusted:
        for token in extra_trusted:
            resolved = _canonical_sid(token)
            if resolved is not None:
                sids.add(resolved)
    return frozenset(sids)


def effective_writers(
    aces: Iterable[tuple[str, str, set[str]]],
    *,
    sid_normalizer: Callable[[str], str] = _canonicalize_or_keep,
) -> set[str]:
    """Return canonical SIDs that effectively hold write rights on a path.

    ``aces`` is a sequence of ``(principal, "allow"|"deny", {rights})`` where
    ``principal`` is a SID string or account name. Each principal is normalized
    to its canonical SID before comparison (see :func:`_canonicalize_or_keep`),
    so ``NT SERVICE\\SecuredactAgent`` and ``S-1-5-80-...`` are treated as one
    identity. A DENY ACE overrides a matching ALLOW ACE for the same principal
    (Windows semantics), preserved across normalization.
    """

    allowed: dict[str, bool] = {}
    denied: dict[str, bool] = {}
    for sid, atype, rights in aces:
        key = sid_normalizer(sid)
        has_write = bool(_WRITE_RIGHTS & rights)
        if not has_write:
            continue
        if atype == "deny":
            denied[key] = True
        else:
            allowed[key] = True
    return {sid for sid in allowed if not denied.get(sid)}


def untrusted_writers(
    aces: Iterable[tuple[str, str, set[str]]],
    *,
    trusted_sids: Iterable[str] | None = None,
    service_account: str | None = None,
) -> set[str]:
    """Canonical SIDs with effective write that are NOT in the trusted set.

    Default (neither argument supplied): trust ONLY the well-known SYSTEM and
    Administrators SIDs — the strict code-path gate (a service identity must
    never be trusted on code paths it loads unless explicitly named). Pass
    ``service_account`` to additionally trust that identity's *exact* resolved
    SID (e.g. the vSA on its own data store), without special-casing any SID
    string or trusting a SID prefix. ``trusted_sids`` overrides both.
    """

    if trusted_sids is None:
        if service_account is None:
            trusted_sids = _WELL_KNOWN_TRUSTED_SIDS
        else:
            trusted_sids = trusted_write_sids(service_account=service_account)
    return effective_writers(aces) - set(trusted_sids)


def enumerate_aces_windows(path: Path) -> list[tuple[str, str, set[str]]]:
    """Enumerate the DACL of ``path`` into ``(sid, allow/deny, rights)`` tuples.

    Raises on any unreadable/unexpected ACL so callers fail closed. Windows only.
    """

    import win32security

    sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    if dacl is None:
        # No DACL means "everyone full control" — treat as untrusted.
        raise PermissionError("path has no DACL (effectively world-writable)")
    aces: list[tuple[str, str, set[str]]] = []
    deny_types = (
        win32security.ACCESS_DENIED_ACE_TYPE,
        win32security.ACCESS_DENIED_OBJECT_ACE_TYPE,
    )
    for i in range(dacl.GetAceCount()):
        try:
            ace = dacl.GetAce(i)
        except Exception as exc:  # any unreadable ACE fails closed
            raise PermissionError(f"unreadable ACE at index {i}: {exc}") from exc
        # pywin32 returns ((ace_type, ace_flags), mask, sid) for non-object ACEs.
        header, mask, sid = ace[0], int(ace[1]), ace[2]
        ace_type = header[0]
        atype = "deny" if ace_type in deny_types else "allow"
        rights = _mask_to_rights(mask)
        try:
            sid_str = win32security.ConvertSidToStringSid(sid)
        except Exception:
            sid_str = "*unknown*"
        aces.append((sid_str, atype, rights))
    return aces


def _default_acl_provider() -> Callable[[Path], list[tuple[str, str, set[str]]]] | None:
    if sys.platform == "win32":
        return enumerate_aces_windows
    return None


def candidate_code_paths() -> list[Path]:
    """Exact on-disk paths LocalSystem will load when the service runs.

    Includes the Python interpreter, its directory, the ``securedact_mcp``
    package, every ``site-packages`` root, and the pywin32 module directory
    (home of ``pythonservice.exe``). Windows only (imports pywin32 lazily).
    """

    import site

    import win32service

    import securedact_mcp

    raw: list[Path] = [
        Path(sys.executable),
        Path(sys.executable).parent,
        Path(securedact_mcp.__file__).parent,
        Path(win32service.__file__).parent,
    ]
    for sp in getattr(site, "getsitepackages", lambda: [])() or []:
        raw.append(Path(sp))

    resolved: list[Path] = []
    seen: set[Path] = set()
    for p in raw:
        try:
            rp = p.resolve()
        except OSError:
            rp = p
        if rp not in seen:
            seen.add(rp)
            resolved.append(rp)
    return resolved


def validate_install_security(
    data_dir: Path | str,
    *,
    acl_provider: Callable[[Path], list[tuple[str, str, set[str]]]] | None = None,
    paths: Iterable[Path] | None = None,
    service_account: str | None = None,
    phase: str = "install",
) -> list[str]:
    """Return blocking issue strings for an unsafe service install.

    The install must be aborted when the returned list is non-empty. In
    particular it fails closed when:

    * no real ACL provider is available (non-Windows / ACLs unreadable) and we
      therefore cannot *prove* the code paths are safe; or
    * any executable/package/site-packages/pywin32 path is writable by a
      principal other than SYSTEM/Administrators (the pipx/uv user-writable
      venv privilege-escalation class); or
    * the data dir is writable by anyone other than SYSTEM/Administrators or the
      configured service identity (e.g. the vSA on its own store). ``service_account``
      names that exact identity so it is trusted by its resolved SID — not by a
      SID prefix — and unrelated service SIDs are still rejected.

    Every emitted issue carries ``;phase=<phase>`` and, for writable-path issues,
    ``;untrusted=<sid,...>`` (the offending writer SIDs, which are not secrets)
    so future failures pinpoint whether they came from the strict Phase-1 gate
    (``phase1_code_path_integrity``) or the service-aware Phase-3 gate
    (``phase3_final_integrity``).
    """

    issues: list[str] = []
    provider = acl_provider or _default_acl_provider()
    if provider is None:
        issues.append(
            "acl_provider_unavailable:cannot_verify_code_path_integrity;"
            f"install only from an admin-owned, non-user-writable Python environment;phase={phase}"
        )
        return issues

    target_dir = Path(data_dir)
    for path in paths if paths is not None else candidate_code_paths():
        try:
            aces = provider(path)
        except Exception as exc:  # unreadable ACL fails closed
            issues.append(f"unreadable_acl:{path}:{exc};phase={phase}")
            continue
        writers = untrusted_writers(aces, service_account=service_account)
        if writers:
            issues.append(
                "writable_code_path:"
                + str(path)
                + ":"
                + ",".join(sorted(writers))
                + f";phase={phase};untrusted="
                + ",".join(sorted(writers))
            )

    # The data dir itself must not be world-writable either.
    try:
        data_aces = provider(target_dir)
    except Exception as exc:
        issues.append(f"unreadable_acl:{target_dir}:{exc};phase={phase}")
    else:
        writers = untrusted_writers(data_aces, service_account=service_account)
        if writers:
            issues.append(
                "writable_data_dir:"
                + str(target_dir)
                + f";phase={phase};untrusted="
                + ",".join(sorted(writers))
            )
    return issues


def safe_deployment_hint() -> str:
    """Human-readable guidance for operators hitting the code-path gate."""

    return (
        "Install into an admin-owned, non-user-writable Python environment "
        "(e.g. a virtualenv under C:\\ProgramData\\Securedact\\venv or "
        "C:\\Program Files\\Securedact, owned by SYSTEM/Administrators). Do NOT "
        "use 'pipx install' or 'uv tool install', which place the interpreter and "
        "site-packages under the installing user's profile and are writable by "
        "that user — running them as a service would be a local privilege "
        "escalation."
    )


def build_service_account_principals(
    data_dir: Path | str,
    *,
    service_account: str,
    installing_user: str,
) -> list[str]:
    """Return icacls ``/grant:r`` principal strings for the hardened data dir.

    * SYSTEM + Administrators: full control.
    * The service account (vSA or LocalSystem): full control on its own store.
    * The installing user: READ ONLY — enough for local diagnostics, but NOT
      enough to replace the credential vault, Fernet key, OAuth vault, or
      bindings (which would enable impersonation / escalation).
    """

    principals = [
        r"*S-1-5-18:(OI)(CI)F",
        r"*S-1-5-32-544:(OI)(CI)F",
    ]
    if service_account and service_account not in _SYSTEM_EQUIVALENTS:
        principals.append(f"{service_account}:(OI)(CI)F")
    # Installing user gets read+execute, never write, on the whole subtree.
    principals.append(f"{installing_user}:(OI)(CI)RX")
    return principals
