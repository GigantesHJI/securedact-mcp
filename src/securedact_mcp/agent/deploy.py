# SPDX-License-Identifier: Apache-2.0
"""Secure machine-owned runtime provisioning for the managed Windows agent.

This module implements the *secure* deployment path that replaces the unsafe
``pipx install`` / ``uv tool install`` service execution model (AGENT-DEPLOY).

Problem statement
-----------------
A Windows Service running under a privileged identity (virtual service account or
LocalSystem) must never load Python/package code from a path writable by an
ordinary, non-admin user. ``pipx`` and ``uv tool`` place the interpreter and
``site-packages`` under the installing user's profile, which that user can write —
so running them as a service is a local privilege-escalation. The install-time
security gate in :mod:`securedact_mcp.agent.service_security` already refuses
such installs (fail-closed).

Chosen model (Approach A — dedicated machine-owned Python environment)
---------------------------------------------------------------------
When the customer opts into the Managed Agent during ``securedact-mcp setup``,
we provision a **separate, admin/SYSTEM-owned Python virtual environment** under
``C:\\ProgramData\\Securedact\\runtime`` and install the *exact same* pinned
``securedact-mcp`` package (plus its dependencies, including ``pywin32``) into it.
Everything the service loads at runtime lives under that machine path, which is
writable only by Administrators/SYSTEM, readable/executable by the service
account (``NT SERVICE\\SecuredactAgent``), and never writable by ordinary users.

Why this is safer than pipx/uv-tool service execution
----------------------------------------------------
* The service ``ImagePath`` ends up pointing at
  ``C:\\ProgramData\\Securedact\\runtime\\Scripts\\pythonservice.exe`` (the
  pywin32 host installed inside the machine runtime), not a user profile.
* Ordinary users cannot replace the interpreter, the package, or
  ``site-packages`` (so they cannot plant code that runs as the service identity).
* The service data dir (``C:\\ProgramData\\Securedact``) is ACL-hardened
   separately (see :mod:`securedact_mcp.agent.service_security` for the trusted-writer invariants used by the active backend); the *code* lives
  in the sibling ``runtime`` dir with its own read-only-to-users ACL.

The configuration state (``agent.json``, credential vault, OAuth vault, bindings)
stays in the data dir, so re-provisioning / upgrading the *runtime* never touches
state — upgrade preserves registration, credentials, bindings, and OAuth tokens.

All privileged operations require elevation and are fail-closed. Windows-specific
primitive operations (subprocess execution, ACL enumeration, elevation) are kept
behind injectable boundaries so the policy is fully testable on any platform.
"""

from __future__ import annotations

import ctypes
import importlib.metadata
import json
import logging
import os
import re
import shutil  # noqa: F401 - kept so tests can monkeypatch deploy.shutil.which
import subprocess
import sys
import zipfile
from collections.abc import Callable, Mapping, Sequence
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from ..connectors.google import managed as google_managed
from . import google_setup, service, service_security
from .config import AgentFiles
from .errors import AgentError
from .safe_log import scrub

_LOGGER = logging.getLogger(__name__)

# A version pin must be a non-empty string of PEP 440-ish characters. This
# rejects shell metacharacters, whitespace, and URL/remote indicators so an
# untrusted value can never become an arbitrary install target.
_VERSION_PIN_RE = re.compile(r"^\d+(\.\d+)*([a-zA-Z0-9.\-+!~]*)$")
_REMOTE_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")

# ---------------------------------------------------------------------------
# Location constants (the concrete secure deployment path)
# ---------------------------------------------------------------------------

RUNTIME_DIRNAME = "runtime"
DEFAULT_DATA_DIR_ENV = "SECUREDACT_APP_DATA_DIR"

# The managed-agent provisioning installs only the connector extras the customer
# actually selected, never every optional extra. When Google Workspace support is
# enabled the machine runtime must carry the Google OAuth dependencies the scan
# provider imports; the released pin below installs exactly that extra for the
# running version.
GOOGLE_CONNECTOR_PLATFORM = "google_workspace"
GOOGLE_EXTRA = "google"

# Concrete Google runtime imports the provider actually relies on. The post-install
# probe fails closed if any of these cannot be imported from the machine runtime.
GOOGLE_RUNTIME_IMPORTS = (
    "google.auth",
    "google.oauth2.credentials",
    "google_auth_oauthlib.flow",
    "requests",
)

# The exact one-liner an operator can run by hand to verify the machine runtime
# (kept in sync with GOOGLE_RUNTIME_IMPORTS so the documented command and the
# automated probe can never drift apart).
GOOGLE_RUNTIME_OK_MARKER = "GOOGLE RUNTIME OK"
GOOGLE_RUNTIME_IMPORT_CHECK = (
    "import google_auth_oauthlib, google.auth, google.oauth2.credentials, requests; "
    f"print({GOOGLE_RUNTIME_OK_MARKER!r})"
)

# Capability probe for the *installed* runtime distribution. A stale machine runtime
# can import ``securedact_mcp.agent.runtime_bootstrap`` while having no
# ``google-auth`` subcommand at all (observed: an older 0.4.2 whose bootstrap only
# offered install/stop/start/status/uninstall). Routing authorization into such a
# runtime would fail with ``invalid choice: 'google-auth'``, so provisioning and
# readiness assert the capability explicitly. A build without ``supports`` raises in
# the child process -> non-zero exit -> capability missing (fail closed).
GOOGLE_AUTH_CAPABILITIES = ("google-auth", "google-auth-loopback", "google-auth-verify")
GOOGLE_AUTH_CAPABILITY_CHECK = (
    "from securedact_mcp.agent.runtime_bootstrap import supports; "
    "raise SystemExit(0 if supports("
    + ", ".join(repr(cap) for cap in GOOGLE_AUTH_CAPABILITIES)
    + ") else 1)"
)


def default_runtime_path() -> Path:
    """Return the secure machine-owned runtime root (ProgramData/Securedact/runtime)."""

    program_data = os.getenv("ProgramData") or r"C:\ProgramData"
    return Path(program_data) / "Securedact" / RUNTIME_DIRNAME


def resolve_runtime_python(runtime_path: Path) -> Path:
    """Return the python interpreter that lives *inside* the machine runtime."""

    runtime_path = Path(runtime_path)
    if sys.platform == "win32":
        return runtime_path / "Scripts" / "python.exe"
    return runtime_path / "bin" / "python"


def _runtime_root_for_python(runtime_python: Path) -> Path:
    """Return the runtime root owning ``runtime_python`` (inverse of resolve_runtime_python)."""

    # ``<root>/Scripts/python.exe`` (win32) or ``<root>/bin/python`` (posix).
    return Path(runtime_python).parent.parent


def resolve_machine_runtime_python(runtime_path: Path | str | None) -> Path | None:
    """Return the *existing* machine-runtime interpreter for ``runtime_path``.

    Single source of truth for "which interpreter does the managed agent's Google
    work run in". ``None`` means there is no machine runtime interpreter at
    ``runtime_path`` (dev / non-Windows / not provisioned yet).

    This exists because the Google readiness probe and the Google authorization
    step MUST agree on the interpreter. When they disagreed, setup printed the
    contradictory pair "Google dependencies: available" (probed
    ``C:\\ProgramData\\Securedact\\runtime\\Scripts\\python.exe``) together with
    ``No module named 'google_auth_oauthlib'`` (raised in the setup CLI's own
    interpreter). Both paths now resolve through this one function, so they can
    never diverge again. It deliberately does NOT invent a default: the caller
    passes the runtime it actually provisioned.
    """

    if runtime_path is None:
        return None
    candidate = resolve_runtime_python(Path(runtime_path))
    return candidate if candidate.exists() else None


# ---------------------------------------------------------------------------
# Command execution abstraction (injectable for tests)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RunInput:
    stdin: str | None = None
    env: Mapping[str, str] | None = None
    timeout: int = 300


@dataclass(slots=True)
class RunResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


CommandRunner = Callable[[Sequence[str], RunInput], RunResult]


def _default_runner(arguments: Sequence[str], run_input: RunInput) -> RunResult:
    """Real subprocess runner used at runtime (Windows service provisioning)."""

    # The interpreter / venv paths are resolved locally and never come from
    # untrusted input, so this is a controlled execution boundary.
    completed = subprocess.run(  # noqa: S603 - executable path is resolved internally
        list(arguments),
        input=run_input.stdin,
        capture_output=True,
        text=True,
        timeout=run_input.timeout,
        check=False,
        env=dict(os.environ, **(run_input.env or {})),
    )
    return RunResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


# ---------------------------------------------------------------------------
# Elevation (Windows only; mockable for tests)
# ---------------------------------------------------------------------------


def is_elevated() -> bool:
    """Return True only when the current process holds admin rights (Windows)."""

    if sys.platform != "win32":
        return False
    try:  # pragma: no cover - platform specific
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # pragma: no cover - defensive
        return False


# Internal marker (never a secret) that tells a re-launched child it is the
# already-elevated continuation of a managed-agent setup, so it resumes the
# onboarding exactly once instead of re-prompting for elevation. It is inherited
# by the runas child via the parent environment and is also carried on argv.
AGENT_ELEVATED_ENV = "SECUREDACT_AGENT_ELEVATED"


def build_elevation_argv(
    *,
    google: str | None = None,
    google_integration_id: str | None = None,
    google_byo: bool = False,
) -> list[str]:
    """Return the exact argv params for the elevated managed-agent re-launch.

    The file executed is always ``sys.executable`` (the RC venv interpreter that
    is currently running ``securedact_mcp.cli``) and the params always use the
    ``-m securedact_mcp.cli`` module form. This guarantees the elevated
    continuation runs the SAME RC code, independent of PATH and of any globally
    installed ``securedact-mcp`` (e.g. ``C:\\Program Files\\Python312\\Scripts\\
    securedact-mcp.exe``). The ``--agent`` flag selects only the managed-agent
    module; ``--agent-elevated`` is the internal resume marker (carries no
    secret). No registration token or credential is ever placed here.

    An explicit Google Workspace selection is forwarded so the elevated
    continuation -- which is the process that actually performs the machine-local
    Google onboarding -- cannot lose it across the UAC boundary. Only non-secret
    values are forwarded: the ``yes``/``no`` choice and the validated dashboard
    integration id (never a token, credential, or OAuth client secret).
    """

    argv = ["-m", "securedact_mcp.cli", "setup", "--agent", "--agent-elevated"]
    if google in {"yes", "no"}:
        argv += ["--google", google]
    validated = google_setup.normalize_integration_id(google_integration_id)
    if validated:
        argv += ["--google-integration-id", validated]
    if google_byo:
        argv += ["--google-byo"]
    return argv


def resolve_elevation_target(
    *,
    google: str | None = None,
    google_integration_id: str | None = None,
    google_byo: bool = False,
) -> tuple[str, list[str]]:
    """Return ``(interpreter, params)`` for the elevated re-launch.

    The interpreter is the currently-running RC venv python and the params use the
    ``-m securedact_mcp.cli`` module form, so the elevated process can never
    resolve a different (global) install. Exposed separately so tests can prove
    the exact RC interpreter/code is used during elevation.
    """

    return (
        sys.executable,
        build_elevation_argv(
            google=google,
            google_integration_id=google_integration_id,
            google_byo=google_byo,
        ),
    )


def self_elevate(
    argv: Sequence[str] | None = None, *, runas_fn: Callable[[Sequence[str]], int] | None = None
) -> int:
    """Re-launch the current RC interpreter elevated via the Windows UAC ``runas`` verb.

    Returns the exit code of the elevated process when ``runas_fn`` is injected
    (tests); in production it uses ``ShellExecuteEx`` with ``runas``. A non-zero
    return means elevation was declined/failed, which the caller must treat as a
    safe stop (it must NOT raise ``_ElevationHandoff`` in that case). A return of
    0 indicates the elevated child ran (the current process should then exit).
    """

    if argv is None:
        argv = build_elevation_argv()
    else:
        argv = list(argv)
    # ``run_managed_agent_module`` passes the full ``[interpreter, *params]`` argv.
    # Normalise to params-only here: the platform call always uses the currently
    # running RC interpreter (``sys.executable``) as the launch target, independent
    # of PATH / any globally installed ``securedact-mcp``.
    if argv and Path(argv[0]) == Path(sys.executable):
        argv = argv[1:]
    if runas_fn is not None:
        return runas_fn(list(argv))
    if sys.platform != "win32":  # pragma: no cover - platform specific
        return 2
    return _shell_execute_runas(list(argv))  # pragma: no cover - platform specific


def _shell_execute_runas(
    argv: list[str], cwd: str | None = None
) -> int:  # pragma: no cover - platform specific
    """Use ShellExecuteEx with the ``runas`` verb to request elevation.

    The elevated child is launched with the current working directory preserved
    (``cwd`` defaults to ``os.getcwd()``), so the RC checkout / launch context is
    retained across the UAC boundary. ``ctypes`` is referenced via the module
    attribute so it can be mocked in tests on non-Windows platforms.
    """

    exe = sys.executable
    params = subprocess.list2cmdline(argv)
    work_dir = cwd or os.getcwd()

    class SHELLEXECUTEINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", wintypes.ULONG),
            ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", wintypes.LPCWSTR),
            ("hKeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD),
            ("hIconOrMonitor", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]

    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    info = SHELLEXECUTEINFO()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = SEE_MASK_NOCLOSEPROCESS
    info.hwnd = 0
    info.lpVerb = "runas"
    info.lpFile = exe
    info.lpParameters = params
    info.lpDirectory = work_dir
    info.nShow = 1

    _LOGGER.debug(
        "elevation handoff: exe=%s args=%d cwd=%s verb=runas",
        os.path.basename(exe),
        len(argv),
        work_dir,
    )

    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
        # Sanitized diagnostics only: executable basename, argument *count*
        # (shape), cwd, and the Windows error code. Never argv values, env, or
        # any secret material.
        last_error = ctypes.windll.kernel32.GetLastError()
        _LOGGER.error(
            "elevation handoff failed: exe=%s args=%d cwd=%s code=%s",
            os.path.basename(exe),
            len(argv),
            work_dir,
            last_error,
        )
        return 2
    if info.hProcess:
        ctypes.windll.kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
        exit_code = wintypes.DWORD()
        ctypes.windll.kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code))
        ctypes.windll.kernel32.CloseHandle(info.hProcess)
        _LOGGER.debug(
            "elevation handoff child exited: exe=%s args=%d cwd=%s exit=%s",
            os.path.basename(exe),
            len(argv),
            work_dir,
            int(exit_code.value),
        )
        return int(exit_code.value)
    return 0


# ---------------------------------------------------------------------------
# Runtime path security validation (reuses the existing code-path gate)
# ---------------------------------------------------------------------------


def _runtime_code_paths(runtime_path: Path) -> list[Path]:
    """Compute the on-disk code paths the service will load from the runtime."""

    runtime_path = Path(runtime_path)
    if sys.platform == "win32":
        python = runtime_path / "Scripts" / "python.exe"
        scripts = runtime_path / "Scripts"
    else:
        python = runtime_path / "bin" / "python"
        scripts = runtime_path / "bin"
    site = runtime_path / "Lib" / "site-packages"
    candidates = [
        python,
        scripts,
        site,
        site / "securedact_mcp",
        site / "securedact_core",
        site / "win32",
        site / "pywin32_system32",
    ]
    return [p for p in candidates if p.exists()]


def validate_runtime_security(
    runtime_path: Path | str,
    *,
    acl_provider: Callable[[Path], list[tuple[str, str, set[str]]]] | None = None,
    paths: Sequence[Path] | None = None,
) -> list[str]:
    """Return blocking issue strings for an unsafe machine runtime.

    Reuses :func:`securedact_mcp.agent.service_security.untrusted_writers` so the
    exact same policy that rejects user-writable pipx/uv venvs also validates the
    machine runtime. A runtime whose interpreter/package/site-packages/pywin32
    paths are writable by any non-SYSTEM/non-Admin principal is rejected.
    """

    provider = acl_provider or service_security._default_acl_provider()
    if provider is None:
        return [
            "acl_provider_unavailable:cannot_verify_runtime_integrity;"
            "provision only from an admin-owned, non-user-writable location"
        ]
    target = Path(runtime_path)
    issues: list[str] = []
    for path in paths if paths is not None else _runtime_code_paths(target):
        try:
            aces = provider(path)
        except Exception as exc:  # unreadable ACL fails closed
            issues.append(f"unreadable_acl:{path}:{exc}")
            continue
        if service_security.untrusted_writers(aces):
            issues.append("writable_code_path:" + str(path))
    return issues


def _resolve_securedact_version() -> str:
    """Return the version of the securedact-mcp code *currently executing*.

    The machine runtime MUST install exactly the same version that is running
    this setup wizard, so the service loads code identical to what was
    validated. The authoritative source is the in-process
    ``securedact_mcp.__version__`` (the code literally executing). Installed
    distribution metadata is only a cross-check / fallback when the canonical
    module constant is unavailable.

    Fails closed: if no version can be determined we raise rather than fall
    back to a hardcoded default (e.g. ``0.1.0``) or ``"latest"``.
    """

    from .. import __version__ as module_version

    installed: str | None = None
    try:
        installed = importlib.metadata.version("securedact-mcp")
    except importlib.metadata.PackageNotFoundError:
        installed = None

    if module_version:
        # The installed distribution metadata can disagree with the code that
        # is actually running (a stale dist-info, an editable build artifact,
        # or a second installed copy). Replicate the *running* code, but surface
        # the discrepancy for operators rather than silently pinning a possibly
        # unresolvable or mismatched version.
        if installed is not None and installed != module_version:
            _LOGGER.warning(
                "securedact-mcp running version (%s) differs from installed "
                "distribution metadata (%s); pinning the machine runtime to the "
                "running version",
                module_version,
                installed,
            )
        return module_version

    if installed:
        return installed

    raise AgentError(
        "could not determine the running securedact-mcp version; refusing to "
        "provision a machine runtime with an unknown package version"
    )


def _validate_version_pin(version: str) -> str:
    """Reject an invalid / injectable version pin (fail closed)."""

    if not version or not _VERSION_PIN_RE.match(version):
        raise AgentError(f"refusing to pin an invalid package version: {version!r}")
    return version


def _validate_local_wheel(wheel_path: str | Path) -> Path:
    """Ensure a controlled wheel is a local *.whl file, never a remote/URL source.

    Fail-closed: rejects remote schemes (``http(s)://``), non-``.whl`` paths, and
    any file that is not a regular local file. This blocks arbitrary source-path
    injection (e.g. ``/etc/passwd`` or a ``git+`` URL) from ever becoming an
    install target.
    """

    raw = str(wheel_path)
    if not raw.lower().endswith(".whl"):
        raise AgentError(f"controlled local wheel must be a *.whl file: {raw!r}")
    if _REMOTE_SCHEME_RE.match(raw):
        raise AgentError(f"refusing to install a remote wheel source: {raw!r}")
    path = Path(raw).resolve()
    if not path.is_file():
        raise AgentError(f"controlled local wheel not found: {path}")
    return path


# ---------------------------------------------------------------------------
# Dev / local-validation runtime source selection
# ---------------------------------------------------------------------------
#
# Two explicit, mutually-exclusive sources feed the secure machine runtime:
#
# * Released flow (default): install the EXACT pinned distribution
#   ``securedact-mcp==X.Y.Z`` from the package index. Production users never
#   depend on a source checkout.
# * Dev / local-validation flow (opt-in, explicit): build a *controlled local
#   wheel* from the current repository checkout and install that exact artifact.
#   This is the only supported way to provision a machine runtime from code that
#   is newer / unreleased relative to PyPI. It is never enabled implicitly.

_DEV_WHEEL_ENV = "SECUREDACT_RUNTIME_DEV_WHEEL"


def dev_local_wheel_requested() -> bool:
    """True only when the operator explicitly opted into dev/local wheel mode."""

    return os.getenv(_DEV_WHEEL_ENV, "").strip().lower() in {"1", "true", "yes", "y"}


def _repo_root() -> Path:
    """Locate the repository root (the dir holding ``pyproject.toml``)."""

    here = Path(__file__).resolve().parent
    for cand in here.parents:
        if (cand / "pyproject.toml").exists():
            return cand
    raise AgentError(
        "could not locate the repository root needed to build a controlled local wheel"
    )


def _wheel_contains(wheel_path: Path, member: str) -> bool:
    """Return True if the wheel's RECORD names ``member`` (suffix match)."""

    try:
        with zipfile.ZipFile(wheel_path) as zf:
            return any(n == member or n.endswith("/" + member) for n in zf.namelist())
    except (OSError, zipfile.BadZipFile):
        return False


# A trusted content digest of the controlled local wheel that was last installed
# into the machine runtime. Stored at the runtime root so that dev/local-validation
# mode can detect a *same-version* wheel rebuilt from changed source (e.g. a new
# checkout revision that still reports 0.4.2) and deterministically replace it. The
# bootstrap-import probe is intentionally NOT a freshness signal: multiple checkout
# revisions share the same package version and all contain the bootstrap, so it
# cannot distinguish a stale runtime from a fresh one.
_DEV_DIGEST_FILENAME = ".securedact_dev_wheel.sha256"

# Callable producing the "current checkout" digest for dev/local-validation mode.
# The default hashes the actual source tree; tests inject a deterministic value.
DevDigestFn = Callable[[Path], str]


def _compute_dev_source_digest(repo_root: Path) -> str:
    """Return a stable SHA-256 over the source that produces the dev wheel.

    Hashes ``pyproject.toml`` plus every file under ``src/`` in deterministic
    (sorted relative-path) order. A changed ``service_windows.py`` (or any other
    module) changes the digest, so a same-version dev wheel rebuilt from a new
    revision is detected as stale. The build is assumed deterministic.
    """

    import hashlib

    root = Path(repo_root).resolve()
    h = hashlib.sha256()

    def feed(path: Path, rel: str) -> None:
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(path.read_bytes())

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        feed(pyproject, "pyproject.toml")
    src = root / "src"
    if src.is_dir():
        for f in sorted(src.rglob("*")):
            if f.is_file():
                feed(f, str(f.relative_to(root).as_posix()))
    return h.hexdigest()


def _read_stored_dev_digest(runtime_path: Path) -> str | None:
    """Read the stored dev-wheel digest, or None if absent/corrupt."""

    marker = Path(runtime_path) / _DEV_DIGEST_FILENAME
    if not marker.is_file():
        return None
    try:
        return marker.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _store_dev_digest(runtime_path: Path, digest: str) -> None:
    """Persist the dev-wheel digest so future reruns can prove exact equality."""

    marker = Path(runtime_path) / _DEV_DIGEST_FILENAME
    marker.write_text(digest, encoding="utf-8")


def _default_wheel_builder(root: Path) -> Path:
    """Build a wheel from the checkout using the project's build tool.

    Prefers ``uv build`` (the project's lockfile-backed builder) and falls back to
    ``python -m build``. Fail-closed: raises if no wheel is produced.
    """

    out = root / "dist"
    out.mkdir(parents=True, exist_ok=True)
    candidates = [
        ["uv", "build", "--wheel", f"--out-dir={out}"],
        [sys.executable, "-m", "build", "--wheel", f"--out-dir={out}"],
    ]
    last_err = "no wheel builder available (uv / python -m build)"
    for cmd in candidates:
        try:
            completed = subprocess.run(  # noqa: S603 - cmd is a fixed builder list
                cmd,
                cwd=str(root),
                capture_output=True,
                text=True,
                check=False,
                env=dict(os.environ),
            )
        except FileNotFoundError as exc:  # builder not on PATH
            last_err = str(exc)
            continue
        if completed.returncode != 0:
            last_err = completed.stderr
            continue
        wheels = sorted(out.glob("*.whl"))
        if wheels:
            return wheels[-1].resolve()
        last_err = f"wheel build produced no artifact: {completed.stderr}"
    raise AgentError(f"failed to build controlled local wheel: {last_err}")


def build_local_runtime_wheel(
    repo_root: Path | str | None = None,
    *,
    wheel_builder: Callable[[Path], Path] | None = None,
) -> Path:
    """Build and validate a controlled local wheel from the current checkout.

    The wheel is validated to be a local file AND to actually contain
    ``securedact_mcp.agent.runtime_bootstrap`` — so a build produced from a stale
    or partial checkout can never silently become the runtime's install source.
    """

    root = Path(repo_root or _repo_root())
    builder = wheel_builder or _default_wheel_builder
    try:
        wheel = builder(root)
    except AgentError:
        raise
    except Exception as exc:  # never mask a build failure as success
        raise AgentError(f"controlled local wheel build failed: {exc}") from exc
    wheel = _validate_local_wheel(wheel)
    if not _wheel_contains(wheel, "securedact_mcp/agent/runtime_bootstrap.py"):
        raise AgentError(
            f"controlled local wheel {wheel} is missing "
            "securedact_mcp.agent.runtime_bootstrap; refusing to provision a "
            "machine runtime from a build that does not contain the managed-agent "
            "implementation. Build from a checkout that includes the agent package."
        )
    return wheel


def select_runtime_install_source(
    *,
    dev_local: bool = False,
    version: str | None = None,
    wheel_path: str | Path | None = None,
    _wheel_builder: Callable[[Path], Path] | None = None,
) -> str:
    """Return the exact install target for the secure machine runtime.

    Resolution (fail-closed, never ``latest`` / never a remote source):

    1. An explicit controlled local wheel (validated as a local ``*.whl`` only).
    2. Dev / local-validation mode: build a controlled local wheel from the
       current checkout and use it. This is the *only* path that provisions
       newer/unreleased running code into the runtime.
    3. Released mode: the exact pinned distribution ``securedact-mcp==<version>``
       (the running version unless explicitly overridden).
    """

    if wheel_path is not None:
        return str(_validate_local_wheel(wheel_path))
    if dev_local:
        return str(build_local_runtime_wheel(wheel_builder=_wheel_builder))
    ver = version or _resolve_securedact_version()
    ver = _validate_version_pin(ver)
    return f"securedact-mcp=={ver}"


def install_target_is_local_wheel(target: str | Path) -> bool:
    """True only when the resolved install target is a validated controlled local wheel.

    A controlled local wheel (the dev/local-validation artifact) can carry the
    *same* version as a distribution already installed in the machine runtime. pip
    would otherwise treat that as "already satisfied" and skip reinstall — leaving a
    stale same-version dist-info / package on disk. The released index pin
    (``securedact-mcp==X.Y.Z``) is never a wheel path, so it keeps the normal
    idempotent behaviour.
    """

    return str(target).lower().endswith(".whl")


def resolve_install_target(
    *,
    version: str | None = None,
    wheel_path: str | Path | None = None,
) -> str:
    """Return the exact pip install target for the secure machine runtime.

    Resolution order:
    1. A controlled local wheel (explicit, validated as a local file only).
    2. An explicit version pin (validated, no injection).
    3. The running securedact-mcp version (authoritative, fail-closed).

    Never resolves to ``"latest"`` or an untrusted/remote source.
    """

    if wheel_path is not None:
        return str(_validate_local_wheel(wheel_path))
    ver = version or _resolve_securedact_version()
    ver = _validate_version_pin(ver)
    return f"securedact-mcp=={ver}"


# ---------------------------------------------------------------------------
# ACL hardening of the runtime dir (SYSTEM/Admins full; service/user read-only)
# ---------------------------------------------------------------------------


def _harden_runtime_dir(
    runtime_path: Path,
    *,
    command_runner: CommandRunner,
    service_account: str | None = None,
    installing_user: str | None = None,
    include_service: bool = False,
) -> None:
    """Restrict the machine runtime so ordinary users cannot modify code.

    SYSTEM + Administrators: full control. The installing user: read + execute
    only. When ``include_service`` is True (the SECOND, post-SCM-creation phase)
    the service identity (vSA) is additionally granted read + execute — but only
    once the service exists in SCM, because the per-service SID ``NT
    SERVICE\\<name>`` is not resolvable by ``icacls`` / ``LookupAccountName``
    until then (ERROR_NONE_MAPPED / icacls exit 1332 on real Windows).

    The hardening is applied with a deterministic two-pass scheme (see
    :func:`_icacls_harden`) so that *every* object in the tree — directories AND
    existing leaf files such as ``Scripts\\python.exe`` — ends up with a usable
    ACE. A single ``/inheritance:r /T /grant:r ...(OI)(CI)...`` was leaving leaf
    files with an EMPTY (deny-all) DACL on real Windows, which broke execution.

    Fail-closed: any icacls failure aborts.
    """

    account = service_account or service_security.recommended_service_account()
    if sys.platform == "win32":  # pragma: no cover - platform specific
        import win32api

        user = installing_user or win32api.GetUserName()
    else:
        user = installing_user or os.environ.get("USERNAME") or os.environ.get("USER") or "SYSTEM"

    principals = [
        r"*S-1-5-18:(OI)(CI)F",
        r"*S-1-5-32-544:(OI)(CI)F",
    ]
    # The virtual-service-account ACE must NOT be applied before the service is
    # registered with SCM; otherwise the name-to-SID lookup fails (icacls 1332).
    if include_service and account not in service_security._SYSTEM_EQUIVALENTS:
        principals.append(f"{account}:(OI)(CI)RX")
    principals.append(f"{user}:(OI)(CI)RX")
    _icacls_harden(
        runtime_path,
        principals,
        command_runner=command_runner,
        recursive=True,
        fail_msg="harden runtime ACL",
    )


def _run_icacls_cmd(cmd: list[str], command_runner: CommandRunner, fail_msg: str) -> None:
    """Execute one icacls invocation and raise fail-closed on any error."""

    try:
        result = command_runner(cmd, RunInput())
    except Exception as exc:
        raise AgentError(f"failed to {fail_msg}; refusing: {exc}") from exc
    if result.returncode != 0:
        raise AgentError(f"failed to {fail_msg} (icacls={result.returncode}): {result.stderr}")


def _icacls_harden(
    path: Path,
    principals: Sequence[str],
    *,
    command_runner: CommandRunner,
    recursive: bool = True,
    fail_msg: str = "harden ACL",
) -> None:
    """Apply a restricted DACL deterministically with two icacls passes.

    Windows / icacls inheritance semantics (the root cause of the prior
    empty-DACL defect, reproduced on real Windows): an ACE that carries the
    container-inherit (``CI``) and/or object-inherit (``OI``) flags is **dropped
    on leaf files** (non-container objects). Windows treats such an ACE as
    "relevant for inheritance only", so the file itself receives no usable ACE
    and is left with an EMPTY DACL == deny-all for everyone. Consequently a
    single ``icacls <tree> /inheritance:r /T /grant:r ...(OI)(CI)...`` left
    existing runtime files (e.g. ``Scripts\\python.exe``) with no ACEs at all,
    which broke ``CreateProcess`` (WinError 5) and failed closed on launch.

    We therefore apply the ACL in two passes so the *entire* tree (directories
    and existing files) ends up usable:

    * Pass 1 (containers propagate): ``/inheritance:r [ /T ] /grant:r`` with
      ``(OI)(CI)`` ACEs. Removes inherited ACEs across the tree, sets explicit
      container ACEs that propagate to *future* children, and grants the
      principals on every directory. Leaf files receive nothing usable from this
      pass (their ``(OI)(CI)`` ACE is dropped by Windows).
    * Pass 2 (leaf files usable): ``[ /T ] /grant`` (APPEND, NOT ``:r``) with
      the same principals but WITHOUT the inherit flags. Every existing file gets
      a directly-effective, executable ACE. On directories this MERGES with the
      pass-1 ACE and preserves the ``(OI)(CI)`` propagation ACE, so future
      children still inherit the restricted ACL.

    ``/grant`` (append) in pass 2 deliberately does NOT use ``:r`` so it cannot
    strip the ``(OI)(CI)`` propagation ACEs set in pass 1 on directories.

    Fail-closed: any non-zero icacls exit aborts.
    """

    exe = _icacls_exe()
    container_grants: list[str] = []
    leaf_grants: list[str] = []
    for principal in principals:
        name, _, rights = principal.partition(":")
        base_rights = re.sub(r"\([^)]*\)", "", rights)
        container_grants.append(f"{name}:(OI)(CI){base_rights}")
        leaf_grants.append(f"{name}:{base_rights}")
    recursive_flag = ["/T"] if recursive else []

    # Pass 1: replace + remove inheritance (sets container propagation ACEs).
    cmd1 = [exe, str(path), "/inheritance:r", *recursive_flag, "/grant:r", *container_grants]
    _run_icacls_cmd(cmd1, command_runner, fail_msg)

    # Pass 2: append flag-less ACEs so existing leaf files become executable.
    cmd2 = [exe, str(path), *recursive_flag, "/grant", *leaf_grants]
    _run_icacls_cmd(cmd2, command_runner, fail_msg)


def _icacls_exe() -> str:
    """Return an absolute path to ``icacls.exe`` (avoids S607 partial-path use)."""

    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    return str(Path(sysroot) / "System32" / "icacls.exe")


def _harden_runtime_parent(
    runtime_path: Path,
    *,
    command_runner: CommandRunner,
    installing_user: str,
    data_dir: Path | str | None = None,
) -> None:
    """Phase-1 hardening of the *parent* data dir so the bootstrap can launch.

    The bootstrap (``install_service_from_runtime``) is executed by the **elevated
    interactive administrator** — not by the virtual service account, which does
    not exist until SCM phase 2 *inside* the bootstrap. Its ``CreateProcess`` must
    traverse ``C:\\ProgramData\\Securedact`` to reach ``runtime\\Scripts\\
    python.exe``. The data dir is only hardened later (two-phase, inside the
    bootstrap), so without an explicit ACE here the launch depends on the inherited
    ``C:\\ProgramData`` ACL and can fail with ``WinError 5`` (Access is denied) on
    hosts where that inheritance is absent or modified.

    We grant the launching principal explicit RX (plus SYSTEM/Administrators full)
    on the data-dir container with ``/inheritance:r`` but WITHOUT ``/T`` — the
    runtime subtree keeps its own Phase-1 ACL. Least privilege is preserved: no
    Users/Everyone, no LocalSystem fallback, and the installing user is RX only
    (never F). The vSA is intentionally NOT granted here (it is unresolvable until
    the SCM service exists).
    """

    expected_parent = service.resolve_service_data_dir(data_dir)
    parent = Path(runtime_path).resolve().parent
    # Only harden the Securedact data dir; never touch an unrelated parent.
    if parent != expected_parent.resolve():
        return
    principals = [
        r"*S-1-5-18:(OI)(CI)F",
        r"*S-1-5-32-544:(OI)(CI)F",
        f"{installing_user}:(OI)(CI)RX",
    ]
    # Container-only (no /T): the runtime subtree keeps its own hardened ACL, and
    # future data-dir children (logs, vaults) inherit the (OI)(CI) propagation ACE.
    # Two-pass so the container itself is usable even though it is a leaf of
    # ProgramData. Fail-closed.
    _icacls_harden(
        parent,
        principals,
        command_runner=command_runner,
        recursive=False,
        fail_msg="harden data-dir parent ACL",
    )


_TRUSTED_LAUNCH_SIDS = frozenset({"S-1-5-18", "S-1-5-32-544"})


def _trusted_has_rx(aces: Sequence[tuple[str, str, set[str]]]) -> bool:
    """True if SYSTEM or Administrators holds read+execute on ``path``."""

    for sid, atype, rights in aces:
        if atype != "allow":
            continue
        if sid in _TRUSTED_LAUNCH_SIDS and bool({"read", "modify", "write"} & rights):
            return True
    return False


def _require_runtime_launchable(
    runtime_python: Path,
    *,
    acl_provider: Callable[[Path], list[tuple[str, str, set[str]]]] | None = None,
) -> None:
    """Fail-closed guard that the launching principal can traverse + execute the
    secured runtime before ``CreateProcess`` is attempted.

    On real Windows this proves the data-dir parent, the runtime dir, and the
    interpreter itself grant SYSTEM/Administrators (the launching elevated
    identity is a member of Administrators) at least read+execute, and that the
    interpreter is not writable by an untrusted principal. Without a provider
    (non-Windows CI) it is a no-op.
    """

    if acl_provider is None:
        return
    rt = Path(runtime_python)
    # Ancestors we control and must be traversable: the runtime dir and the
    # data-dir parent of the runtime.
    for directory in (rt.parent.parent, rt.parent):
        try:
            aces = acl_provider(directory)
        except Exception as exc:
            raise AgentError(
                f"runtime launch precheck failed (unreadable ACL on {directory}): {exc}"
            ) from exc
        if not _trusted_has_rx(aces):
            raise AgentError(
                f"runtime path {directory} is not traversable by SYSTEM/Administrators; "
                "refusing to launch the secured runtime"
            )
    try:
        exe_aces = acl_provider(rt)
    except Exception as exc:
        raise AgentError(f"runtime launch precheck failed (unreadable ACL on {rt}): {exc}") from exc
    if service_security.untrusted_writers(exe_aces):
        raise AgentError(
            "secured runtime interpreter is writable by an untrusted principal; refusing to launch"
        )
    if not _trusted_has_rx(exe_aces):
        raise AgentError(
            "secured runtime interpreter is not executable by SYSTEM/Administrators; "
            "refusing to launch"
        )


def verify_runtime_tree_acl(
    runtime_path: Path,
    *,
    acl_provider: Callable[[Path], list[tuple[str, str, set[str]]]] | None,
    data_dir: Path | str | None = None,
    paths: Sequence[Path] | None = None,
    service_account: str | None = None,
) -> None:
    """Fail-closed post-hardening check of the REAL effective ACLs.

    Asserts that every critical runtime path AND the data-dir parent are:

    * not writable by any untrusted (non-SYSTEM / non-Administrators) principal —
      this catches a data-dir parent that still carries inherited ``Users``
      write/create rights (the second observed real-host defect), and any runtime
      path left user-writable; and
    * at least read+execute by SYSTEM/Administrators — this catches the primary
      defect where an existing leaf file (e.g. ``Scripts\\python.exe``) ended up
      with an EMPTY (deny-all) DACL after ``(OI)(CI)`` grants were dropped.

    Runs on the *actual* ACLs after hardening, before any registration token is
    consumed or the service is started. Fail-closed: any violation aborts. When
    ``acl_provider`` is ``None`` (non-Windows CI) it is a no-op.
    """

    if acl_provider is None:
        return
    runtime = Path(runtime_path)
    resolved_data = service.resolve_service_data_dir(data_dir)
    # The service account legitimately holds Full control on the *data dir* (its
    # The configured service identity legitimately holds Full control on the data
    # dir (its own store) and is added to the runtime tree as RX only. It is trusted
    # by its resolved SID via ``untrusted_writers(service_account=...)`` so the data
    # dir / parent are not false-flagged, while the runtime tree is still rejected
    # if anyone other than SYSTEM/Administrators can write it.
    critical = list(paths if paths is not None else _runtime_code_paths(runtime))
    critical.append(resolve_runtime_python(runtime))
    critical.extend([runtime, resolved_data, runtime.parent])
    seen: set[Path] = set()
    ordered: list[Path] = []
    for raw in critical:
        p = Path(raw)
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    for p in ordered:
        try:
            aces = acl_provider(p)
        except Exception as exc:
            raise AgentError(f"runtime ACL verify failed (unreadable ACL on {p}): {exc}") from exc
        # Trust the service identity by its resolved SID (covers the data dir /
        # parent, where the vSA legitimately holds Full control) without
        # special-casing any SID string or prefix.
        untrusted = service_security.untrusted_writers(aces, service_account=service_account)
        if untrusted:
            raise AgentError(
                f"path {p} is writable by an untrusted principal after hardening; refusing"
            )
        if not _trusted_has_rx(aces):
            raise AgentError(
                f"path {p} is not executable by SYSTEM/Administrators after hardening; refusing"
            )


# ---------------------------------------------------------------------------
# Runtime provisioning
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ProvisionResult:
    runtime_path: Path
    runtime_python: Path
    already_provisioned: bool
    hardened: bool


def _runtime_has_agent_bootstrap(runtime_path: Path, runner: CommandRunner) -> bool:
    """True only when the runtime python can import the managed-agent bootstrap.

    This proves the installed distribution actually contains the *currently
    running* managed-agent implementation — the concrete guard against a stale
    published package being installed into the machine runtime. The check goes
    through the injected runner (never a direct import) so it exercises the real
    runtime interpreter; if the interpreter is missing/corrupt the call fails and
    we treat the runtime as not-yet-provisioned (fail-closed, re-provision).
    """

    python = resolve_runtime_python(Path(runtime_path))
    try:
        result = runner(
            [str(python), "-c", "import securedact_mcp.agent.runtime_bootstrap"],
            RunInput(),
        )
    except Exception:
        return False
    return result.returncode == 0


def _runtime_has_google_imports(runtime_path: Path, runner: CommandRunner) -> bool:
    """True only when the machine runtime can import the Google provider deps.

    Guards against the exact real-Windows defect where the scheduled agent raised
    ``agent_execution_error`` because ``google.auth`` / ``google_auth_oauthlib`` /
    ``requests`` were absent from the machine runtime. The probe runs through the
    injected runner so it exercises the actual runtime interpreter.
    """

    python = resolve_runtime_python(Path(runtime_path))
    probe = "import " + ", ".join(GOOGLE_RUNTIME_IMPORTS)
    try:
        result = runner([str(python), "-c", probe], RunInput())
    except Exception:
        return False
    return result.returncode == 0


def _runtime_supports_google_auth(runtime_path: Path, runner: CommandRunner) -> bool:
    """True only when the runtime's bootstrap really carries the Google OAuth command.

    Guards the stale-distribution defect: the machine runtime is a separately
    installed package, so it can import ``runtime_bootstrap`` (the existing probe)
    while lacking the ``google-auth`` subcommand the wizard is about to invoke. This
    probe asserts the capability inside the runtime interpreter itself, so a stale
    runtime is re-provisioned instead of failing later during authorization.
    """

    python = resolve_runtime_python(Path(runtime_path))
    try:
        result = runner([str(python), "-c", GOOGLE_AUTH_CAPABILITY_CHECK], RunInput())
    except Exception:
        return False
    return result.returncode == 0


def _google_runtime_deps_ready(
    runtime_python: Path | None,
    command_runner: CommandRunner | None,
) -> bool:
    """Readiness gate: the machine runtime can actually perform Google work.

    ``runtime_python`` is the interpreter resolved by
    :func:`resolve_machine_runtime_python` — i.e. *exactly* the interpreter that
    :func:`_authorize_google_machine` will use. Probing anything else is what made
    setup report "Google dependencies: available" while authorization died with
    ``No module named 'google_auth_oauthlib'`` in a different interpreter.

    Both the provider imports *and* the runtime's ``google-auth`` bootstrap
    capability must hold. When there is no runtime interpreter at all there is
    nothing to probe (the provisioning gate owns that case), so it does not block.
    """

    if runtime_python is None:
        return True
    runtime = _runtime_root_for_python(Path(runtime_python))
    runner = command_runner or _default_runner
    return _runtime_has_google_imports(runtime, runner) and _runtime_supports_google_auth(
        runtime, runner
    )


def _google_extra_install_target() -> str:
    """Return the exact pinned ``securedact-mcp[google]`` install target.

    Uses the *running* securedact-mcp version (fail-closed, never ``latest``) so
    the machine runtime installs the same version it is provisioning, plus the
    declared Google extra. The base package itself is already satisfied by the
    primary install, so this second pip call resolves only the Google extra's
    dependencies (google-auth, google-auth-oauthlib, requests) into the runtime.
    """

    ver = _validate_version_pin(_resolve_securedact_version())
    return f"securedact-mcp[{GOOGLE_EXTRA}]=={ver}"


def provision_machine_runtime(
    runtime_path: Path | str | None = None,
    *,
    data_dir: Path | str | None = None,
    version: str | None = None,
    wheel_path: Path | str | None = None,
    base_python: str | None = None,
    command_runner: CommandRunner | None = None,
    acl_provider: Callable[[Path], list[tuple[str, str, set[str]]]] | None = None,
    force: bool = False,
    include_service_acl: bool = False,
    installing_user: str | None = None,
    dev_local: bool = False,
    wheel_builder: Callable[[Path], Path] | None = None,
    dev_digest_fn: DevDigestFn | None = None,
    google_enabled: bool = False,
) -> ProvisionResult:
    """Create / verify the admin-owned machine runtime for the service.

    Idempotent: if the runtime python already exists and passes security
    validation, it is returned unchanged. Otherwise an elevated, admin-owned
    venv is created, the pinned package installed, the ACL hardened, and the
    result re-validated (fail-closed).

    The runtime is installed/upgraded *by Administrator* and is never writable by
    ordinary users. Package source is the same pinned version as the CLI (or a
    controlled local wheel), never an arbitrary URL.
    """

    runtime = Path(runtime_path or default_runtime_path())
    runtime_python = resolve_runtime_python(runtime)
    runner = command_runner or _default_runner
    # DEV-ONLY baseline mode bypasses the custom runtime ACL hardening and the
    # code-path integrity gate; the simplest viable identity (LocalSystem) is used
    # by the active Task Scheduler backend (service_taskscheduler). Application/protocol security is preserved.
    baseline = service_security.is_dev_baseline_enabled()

    # Resolve the installing/elevated identity once and thread it through both
    # hardening steps so the principal that *launches* the bootstrap is explicitly
    # represented (RX) on the runtime and its parent data dir.
    if installing_user is None:
        if sys.platform == "win32":  # pragma: no cover - platform specific
            import win32api

            installing_user = win32api.GetUserName()
        else:
            installing_user = os.environ.get("USERNAME") or os.environ.get("USER") or "SYSTEM"

    # Resolve the exact install target. Released mode pins the running wizard
    # version (cheap: no build). Dev / local-validation mode DEFERS the controlled
    # local wheel build until after the fast-path decision below, so an already
    # fresh dev runtime is never rebuilt on every rerun.
    current_dev_digest: str | None = None
    install_target: str = ""
    if dev_local:
        # Trusted content digest of the *current checkout* (source-based, cheap).
        # The runtime stores the digest of the wheel it was last built from; when
        # they differ (a same-version dev wheel rebuilt from changed source) the
        # runtime is deterministically re-provisioned (rebuilt + force-reinstalled).
        current_dev_digest = (dev_digest_fn or _compute_dev_source_digest)(_repo_root())
    else:
        install_target = select_runtime_install_source(
            dev_local=False, version=version, wheel_path=wheel_path
        )

    # Fast idempotent path: already provisioned AND secure AND actually contains
    # the running managed-agent bootstrap. A runtime that is secure but missing
    # the agent package (a stale published build) must NOT be returned as
    # provisioned — it falls through to (re)provision below.
    if not force and runtime_python.exists():
        # In DEV-ONLY baseline mode the runtime security validation is skipped; the
        # runtime is still considered provisioned if the bootstrap imports.
        issues = (
            []
            if baseline
            else validate_runtime_security(
                runtime, acl_provider=acl_provider, paths=_runtime_code_paths(runtime)
            )
        )
        if not issues and _runtime_has_agent_bootstrap(runtime, runner):
            # When Google is selected the runtime must also carry the Google extra
            # AND a bootstrap that really exposes the ``google-auth`` command; a
            # bootstrap-present but Google-less (or stale-bootstrap) runtime is
            # re-provisioned so the scheduled agent never hits the missing-dependency
            # agent_execution_error and setup never routes authorization into a
            # runtime that would answer "invalid choice: 'google-auth'".
            google_ok = (not google_enabled) or (
                _runtime_has_google_imports(runtime, runner)
                and _runtime_supports_google_auth(runtime, runner)
            )
            if google_ok and not dev_local:
                return ProvisionResult(
                    runtime, runtime_python, already_provisioned=True, hardened=True
                )
            # Dev/local mode: a same-version dev wheel may be STALE relative to the
            # current checkout even though the bootstrap still imports (multiple
            # checkout revisions share the package version 0.4.2). The bootstrap
            # probe is therefore NOT a freshness signal; only a matching stored
            # artifact digest proves exact equality. A mismatch/missing digest means
            # the runtime is stale and must be rebuilt + reinstalled below.
            stored = _read_stored_dev_digest(runtime)
            if stored is not None and stored == current_dev_digest:
                return ProvisionResult(
                    runtime, runtime_python, already_provisioned=True, hardened=True
                )
            # Fall through to deterministic rebuild + reinstall (freshness mismatch).

    if not is_elevated():
        raise AgentError(
            "elevation_required: the managed-agent machine runtime must be "
            "provisioned by an Administrator (it installs code under "
            f"{runtime})."
        )

    runtime.mkdir(parents=True, exist_ok=True)

    # 1. Create the venv using a (possibly system) python. The venv's interpreter
    #    is copied under ProgramData, so it is admin-owned regardless of the
    #    bootstrapping interpreter.
    base = base_python or sys.executable
    created = runner([str(base), "-m", "venv", str(runtime)], RunInput())
    if created.returncode != 0:
        raise AgentError(f"failed to create machine runtime venv: {created.stderr}")

    # 2. Install the *exact same pinned* package (or a controlled local wheel),
    #    validated above as the running wizard version (or an explicit controlled
    #    source) — never an arbitrary URL or an unpinned "latest". A controlled
    #    local wheel is reinstalled explicitly so a stale same-version distribution
    #    in the runtime is replaced deterministically (see forced_reinstall below).
    if dev_local:
        # Build the controlled local wheel from the current checkout now (the
        # fast-path decided the existing runtime is stale) and install it.
        install_target = str(build_local_runtime_wheel(wheel_builder=wheel_builder))
    # A controlled local wheel (dev/local-validation artifact) may carry the same
    # version as a distribution already installed in the machine runtime. pip's
    # default "already satisfied" short-circuit would then SKIP reinstall and leave
    # a stale same-version dist-info / package on disk — the real-Windows defect
    # where a stale PyPI 0.4.2 without the agent package survived setup. Force a
    # clean reinstall of the validated wheel so it deterministically *replaces* any
    # same-version machine-runtime distribution. The released index pin keeps the
    # normal idempotent behaviour (no --force-reinstall, no dependency churn).
    forced_reinstall = install_target_is_local_wheel(install_target)
    pip_cmd = [str(runtime_python), "-m", "pip", "install", "--no-input"]
    if forced_reinstall:
        pip_cmd.append("--force-reinstall")
    pip_cmd.append(install_target)
    installed = runner(pip_cmd, RunInput())
    if installed.returncode != 0:
        raise AgentError(
            f"failed to install securedact-mcp into machine runtime: {installed.stderr}"
        )
    # When Google Workspace support is selected, install the declared Google extra
    # into the same machine runtime (never every optional extra unconditionally),
    # then fail closed if the provider's required imports are not importable.
    if google_enabled:
        google_target = _google_extra_install_target()
        google_cmd = [
            str(runtime_python),
            "-m",
            "pip",
            "install",
            "--no-input",
            google_target,
        ]
        gres = runner(google_cmd, RunInput())
        if gres.returncode != 0:
            raise AgentError(
                f"failed to install Google connector dependencies into machine "
                f"runtime: {gres.stderr}"
            )
        if not _runtime_has_google_imports(runtime, runner):
            raise AgentError(
                "Google connector dependencies failed to import from the machine "
                "runtime after install; refusing to finish provisioning"
            )
        if not _runtime_supports_google_auth(runtime, runner):
            raise AgentError(
                "the machine runtime's securedact_mcp.agent.runtime_bootstrap does "
                "not expose the machine-local Google authorization command "
                f"({', '.join(GOOGLE_AUTH_CAPABILITIES)}); the installed runtime "
                "distribution is stale relative to the running managed-agent code. "
                "Re-run setup from a released securedact-mcp wheel that contains it, "
                f"or enable dev/local validation mode ({_DEV_WHEEL_ENV}=1) to build "
                "and install a controlled local wheel from this checkout."
            )
    # Persist the dev-wheel digest so a future same-version rerun can prove the
    # runtime is byte-for-byte identical to the current checkout (idempotent skip).
    if dev_local and current_dev_digest is not None:
        _store_dev_digest(runtime, current_dev_digest)

    # 3. Harden the runtime so users cannot modify the code the service loads.
    #    During the initial managed-agent install the service does not yet exist,
    #    so the vSA SID is NOT resolvable; harden WITHOUT the service ACE here
    #    and let the active backend apply the final (vSA) ACL after service creation.
    #    For upgrades the service already exists, so include the service ACE.
    #    Skipped entirely in DEV-ONLY baseline mode (no icacls hardening).
    if not baseline:
        _harden_runtime_dir(
            runtime,
            command_runner=runner,
            installing_user=installing_user,
            include_service=include_service_acl,
        )
        # 3b. Harden the *parent* data dir (container only) so the elevated
        #     interactive administrator can traverse to the runtime and launch the
        #     bootstrap before the vSA / final ACL phase exists. See _harden_runtime_parent.
        _harden_runtime_parent(
            runtime,
            command_runner=runner,
            installing_user=installing_user,
            data_dir=data_dir,
        )

    # 4. Re-validate before declaring success (fail-closed). This checks that no
    #    untrusted principal can write the code paths. ``verify_runtime_tree_acl``
    #    then proves the REAL effective ACLs are correct end-to-end (catches the
    #    empty-DACL leaf-file defect and a too-permissive data-dir parent) before
    #    we hand the runtime to the caller (which may consume a registration token
    #    or start the service).
    if not _runtime_has_agent_bootstrap(runtime, runner):
        raise AgentError(
            "machine runtime was provisioned but does not contain "
            "securedact_mcp.agent.runtime_bootstrap; the installed package is "
            "stale relative to the running managed-agent code. Re-run setup from a "
            f"released securedact-mcp wheel, or enable dev/local validation mode "
            f"({_DEV_WHEEL_ENV}=1) to build and install a controlled local wheel "
            "from this checkout."
        )
    # Re-validate before declaring success (fail-closed). Skipped in DEV-ONLY
    # baseline mode, which trades these ACL checks for a minimal known-working
    # lifecycle. Application/protocol security is never skipped.
    if not baseline:
        issues = validate_runtime_security(
            runtime, acl_provider=acl_provider, paths=_runtime_code_paths(runtime)
        )
        if issues:
            raise AgentError(
                "machine runtime failed security validation: "
                + "; ".join(issues)
                + " | "
                + service_security.safe_deployment_hint()
            )
        verify_runtime_tree_acl(
            runtime,
            acl_provider=acl_provider,
            data_dir=data_dir,
            paths=_runtime_code_paths(runtime),
            service_account=service_security.recommended_service_account()
            if include_service_acl
            else None,
        )
    return ProvisionResult(
        runtime, runtime_python, already_provisioned=False, hardened=not baseline
    )


# ---------------------------------------------------------------------------
# Service install / control routed through the machine runtime python
# ---------------------------------------------------------------------------


def _safe_bootstrap_diagnostic(result: RunResult) -> str:
    """Extract a safe, non-empty diagnostic from a failed runtime-bootstrap child.

    The bootstrap emits its safe error as JSON on stdout (``{"error": "..."}``) and
    keeps secrets out of stderr/argv/env. We surface that message (falling back to
    stderr) so a non-zero bootstrap exit never yields an empty diagnostic, and we
    scrub it so registration tokens / credentials never leak into error output. The
    diagnostic therefore always names the failing operation and the safe Windows
    error code/message when available.
    """

    parts: list[str] = []
    try:
        payload = json.loads(result.stdout)
        if isinstance(payload, dict) and payload.get("error"):
            parts.append(str(payload["error"]))
    except Exception:
        if result.stdout.strip():
            parts.append(result.stdout.strip())
    if result.stderr.strip():
        parts.append(result.stderr.strip())
    text = " | ".join(p for p in parts if p)
    return scrub(text) or "bootstrap reported a non-zero exit with no diagnostic"


def _env_for(data_dir: Path) -> dict[str, str]:
    return {
        DEFAULT_DATA_DIR_ENV: str(data_dir),
        "PYTHONNOUSERSITE": "1",
    }


def _run_bootstrap(
    runner: CommandRunner,
    runtime_python: Path,
    subcommand: list[str],
    *,
    data_dir: Path,
) -> RunResult:
    argv = [
        str(runtime_python),
        "-m",
        "securedact_mcp.agent.runtime_bootstrap",
        *subcommand,
    ]
    return runner(argv, RunInput(env=_env_for(data_dir)))


def install_service_from_runtime(
    *,
    token: str | None = None,
    data_dir: Path | str | None = None,
    runtime_path: Path | str | None = None,
    control_plane_url: str | None = None,
    display_name: str | None = None,
    command_runner: CommandRunner | None = None,
    acl_provider: Callable[[Path], list[tuple[str, str, set[str]]]] | None = None,
    installing_user: str | None = None,
    dev_local: bool = False,
    google_enabled: bool = False,
) -> dict[str, object]:
    """Provision the machine runtime (idempotent) and install+start the task.

    The Task Scheduler backend (:mod:`securedact_mcp.agent.service_taskscheduler`)
    launches the *same proven foreground agent loop* from the machine-owned
    runtime, so no SCM ``ImagePath`` / ``pythonservice.exe`` host is required.

    When ``token`` is supplied the agent is registered (the one-time token is
    consumed in-memory only, never on the task command line, in the environment,
    or on disk). When ``token`` is ``None`` an existing valid registration is
    reused and only the scheduled task is (re)created — no new token is consumed.
    """

    provisioned = provision_machine_runtime(
        runtime_path=runtime_path,
        data_dir=data_dir,
        command_runner=command_runner,
        acl_provider=acl_provider,
        installing_user=installing_user,
        # The runtime is initially hardened WITHOUT the service ACE (the vSA is
        # added by the future production hardening pass, after the task exists).
        include_service_acl=False,
        dev_local=dev_local,
        google_enabled=google_enabled,
    )
    runtime_python = provisioned.runtime_python
    resolved_data = service.resolve_service_data_dir(data_dir)

    # Fail-closed pre-flight: prove the launching principal can traverse + execute
    # the secured runtime before attempting to launch it. Skipped in DEV-ONLY
    # baseline mode (one of the pre-start ACL assertions that is bypassed).
    if not service_security.is_dev_baseline_enabled():
        acl = acl_provider or service_security._default_acl_provider()
        _require_runtime_launchable(runtime_python, acl_provider=acl)

    try:
        result = service.install_service(
            data_dir=resolved_data,
            start=True,
            control_plane_url=control_plane_url,
            display_name=display_name,
            token=token,
        )
    except AgentError as exc:
        raise AgentError(f"managed-agent task install failed: {scrub(str(exc))}") from exc
    # Report the runtime that was actually provisioned so the caller never has to
    # guess it. The Google onboarding MUST authorize inside this exact interpreter;
    # when the wizard passed no runtime path it previously fell through to an
    # in-process import in the setup CLI's own Python (the RC defect).
    return {
        **result,
        "runtime_path": str(provisioned.runtime_path),
        "runtime_python": str(runtime_python),
    }


def verify_google_runtime(
    *,
    runtime_path: Path | str | None = None,
    data_dir: Path | str | None = None,
    command_runner: CommandRunner | None = None,
) -> dict[str, object]:
    """Prove the machine runtime interpreter can perform Google OAuth (no browser).

    This is the direct, operator-runnable equivalent of the two manual commands::

        C:\\ProgramData\\Securedact\\runtime\\Scripts\\python.exe -c
            "import google_auth_oauthlib, google.auth, requests; print('GOOGLE RUNTIME OK')"

        C:\\ProgramData\\Securedact\\runtime\\Scripts\\python.exe -m
            securedact_mcp.agent.runtime_bootstrap google-auth
            --data-dir C:\\ProgramData\\Securedact --loopback --verify

    Step 1 proves the Google extra is importable *in that interpreter*. Step 2 runs
    the real loopback authorization code path in the machine runtime up to (but not
    including) the browser and the token exchange: it imports the Google modules,
    resolves the machine-local config, binds the 127.0.0.1 listener, and builds the
    PKCE consent URL. No real token, no browser, no network, no customer prompt.

    Returns a JSON-safe report containing the exact interpreter and the exact argv
    of both commands, so a failing laptop retest shows *which* Python was used.
    Fails closed: ``ok`` is True only when both steps succeed.
    """

    runtime = Path(runtime_path or default_runtime_path())
    runtime_python = resolve_runtime_python(runtime)
    resolved_data = service.resolve_service_data_dir(data_dir)
    runner = command_runner or _default_runner

    import_argv = [str(runtime_python), "-c", GOOGLE_RUNTIME_IMPORT_CHECK]
    capability_argv = [str(runtime_python), "-c", GOOGLE_AUTH_CAPABILITY_CHECK]
    verify_argv = build_google_auth_argv(runtime_python, resolved_data, verify=True)

    report: dict[str, object] = {
        "ok": False,
        "runtime_path": str(runtime),
        "runtime_python": str(runtime_python),
        "runtime_python_exists": runtime_python.exists(),
        "data_dir": str(resolved_data),
        "import_command": import_argv,
        "capability_command": capability_argv,
        "verify_command": verify_argv,
        "imports_ok": False,
        "bootstrap_google_auth_ok": False,
        "loopback_verify_ok": False,
    }
    if not runtime_python.exists():
        report["error"] = (
            f"machine runtime interpreter not found at {runtime_python}; run "
            "'securedact-mcp setup --agent --google yes' from an elevated "
            "Administrator PowerShell to provision it"
        )
        return report

    def _run(argv: list[str]) -> RunResult:
        try:
            return runner(argv, RunInput(env=_env_for(resolved_data)))
        except Exception as exc:  # a runtime that cannot be launched is a hard stop
            return RunResult(returncode=1, stderr=scrub(str(exc)))

    imports = _run(import_argv)
    report["imports_ok"] = imports.returncode == 0 and GOOGLE_RUNTIME_OK_MARKER in imports.stdout
    report["import_output"] = scrub((imports.stdout or imports.stderr).strip())

    capability = _run(capability_argv)
    report["bootstrap_google_auth_ok"] = capability.returncode == 0
    if capability.returncode != 0:
        report["capability_output"] = scrub((capability.stderr or capability.stdout).strip())

    verified = _run(verify_argv)
    payload: dict[str, object] = {}
    try:
        payload = json.loads(verified.stdout)
    except Exception:
        payload = {}
    report["loopback_verify_ok"] = verified.returncode == 0 and bool(payload.get("verified"))
    # Echo only the non-secret verification facts (never the consent URL/state).
    report["loopback_verify"] = {
        key: payload.get(key)
        for key in (
            "interpreter",
            "imports_ok",
            "client_configured",
            "loopback_bound",
            "loopback_host",
            "loopback_port",
            "consent_url_built",
            "error",
        )
        if key in payload
    }
    if not payload:
        report["loopback_verify_output"] = scrub((verified.stderr or verified.stdout).strip())
    report["ok"] = bool(
        report["imports_ok"] and report["bootstrap_google_auth_ok"] and report["loopback_verify_ok"]
    )
    return report


def verify_heartbeat(
    data_dir: Path | str | None = None,
    *,
    runtime_path: Path | str | None = None,
    command_runner: CommandRunner | None = None,
) -> bool:
    """Attempt a heartbeat using the machine runtime and report Online/Offline.

    Returns True only when the runtime reports a registered agent id. Network
    failures or missing registration return False (do not fail the wizard).
    """

    runtime = Path(runtime_path or default_runtime_path())
    runtime_python = resolve_runtime_python(runtime)
    if not runtime_python.exists():
        return False
    resolved_data = service.resolve_service_data_dir(data_dir)
    runner = command_runner or _default_runner
    argv = [
        str(runtime_python),
        "-m",
        "securedact_mcp.agent.cli",
        "agent",
        "heartbeat",
    ]
    try:
        result = runner(argv, RunInput(env=_env_for(resolved_data)))
    except Exception:
        return False
    if result.returncode != 0:
        return False
    try:
        payload = json.loads(result.stdout)
    except Exception:
        return False
    return bool(payload.get("agent_id"))


def upgrade_runtime(
    *,
    runtime_path: Path | str | None = None,
    data_dir: Path | str | None = None,
    command_runner: CommandRunner | None = None,
    acl_provider: Callable[[Path], list[tuple[str, str, set[str]]]] | None = None,
    version: str | None = None,
    wheel_path: Path | str | None = None,
    force: bool = False,
    dev_local: bool = False,
    google_enabled: bool = False,
) -> dict[str, object]:
    """Securely upgrade the machine runtime, preserving all agent state.

    Admin-initiated, fail-closed: stop service -> re-provision runtime code
    (reinstall pinned package) -> re-validate ACLs -> restart service. The data
    dir (agent.json, credential vault, OAuth vault, bindings, state) is never
    touched, so registration, credentials, and Google bindings survive with no
    re-registration and no Google re-auth unless a credential itself is invalid.
    """

    if not is_elevated():
        raise AgentError(
            "elevation_required: the managed-agent runtime upgrade must be "
            "performed by an Administrator."
        )
    runtime = Path(runtime_path or default_runtime_path())
    runtime_python = resolve_runtime_python(runtime)
    resolved_data = service.resolve_service_data_dir(data_dir)
    runner = command_runner or _default_runner

    # Stop the service (best-effort) before touching its code.
    _run_bootstrap(runner, runtime_python, ["stop"], data_dir=resolved_data)

    # Re-provision *code only*; state lives in the separate data dir. The service
    # already exists, so re-apply the service ACE during this hardening pass.
    provision_machine_runtime(
        runtime_path=runtime,
        data_dir=resolved_data,
        version=version,
        wheel_path=wheel_path,
        command_runner=runner,
        acl_provider=acl_provider,
        force=force or True,
        include_service_acl=True,
        dev_local=dev_local,
        google_enabled=google_enabled,
    )

    # Post-upgrade security re-validation (fail-closed).
    issues = validate_runtime_security(runtime, acl_provider=acl_provider)
    if issues:
        raise AgentError("post-upgrade runtime security validation failed: " + "; ".join(issues))
    verify_runtime_tree_acl(
        runtime,
        acl_provider=acl_provider,
        data_dir=resolved_data,
        service_account=service_security.recommended_service_account(),
    )

    started = _run_bootstrap(runner, runtime_python, ["start"], data_dir=resolved_data)
    return {
        "upgraded": True,
        "runtime_path": str(runtime),
        "data_dir": str(resolved_data),
        "service_started": started.returncode == 0,
    }


# ---------------------------------------------------------------------------
# Setup-wizard Managed Agent module (platform/elevation aware, optional)
# ---------------------------------------------------------------------------


def _load_registered_config(data_dir: Path | str | None) -> Any | None:
    """Return the loaded agent config for ``data_dir``, or ``None`` if unregistered."""

    if data_dir is None:
        return None
    try:
        from .config import AgentFiles, load_config

        return load_config(AgentFiles.resolve(root=Path(data_dir) / "agent"))
    except Exception:
        return None


def _agent_already_registered(
    data_dir: Path | str | None = None, *, machine_root: bool = False
) -> bool:
    """Return True when a valid machine-agent registration already exists.

    Used to avoid consuming a fresh one-time registration token when the machine
    is merely being re-provisioned / upgraded. The managed agent's authoritative
    registration lives under the explicit machine data root
    (``C:\\ProgramData\\Securedact``), *not* the interactive user's
    ``%LOCALAPPDATA%\\Securedact`` profile. When ``machine_root`` is True (or
    ``data_dir`` is set), only that machine root is consulted, so a pre-existing
    user-profile ``agent.json`` can never masquerade as a machine registration.
    """

    from .config import AgentFiles, load_config

    if data_dir is not None:
        root = Path(data_dir)
    elif machine_root:
        root = service.resolve_service_data_dir(None)
    else:
        # Honour the control-plane data-dir override only; never silently fall
        # back to the user profile when a machine registration is what we need.
        root = service.resolve_service_data_dir(None)
    try:
        load_config(AgentFiles.resolve(root=root / "agent"))
        return True
    except Exception:
        return False


@dataclass(slots=True)
class GoogleOnboardingOutcome:
    """Result of the machine-local Google Workspace onboarding step."""

    selected: bool
    deps_ready: bool = False
    authorized: bool = False
    integration_id: str | None = None
    binding_verified: bool = False
    # The exact interpreter the Google readiness probe AND the Google authorization
    # ran in (``None`` when no machine runtime interpreter was available). Recorded
    # so the wizard/tests can prove which Python did the work instead of inferring it.
    runtime_python: Path | None = None

    @property
    def ready(self) -> bool:
        """True only when every Google readiness pre-condition is satisfied."""

        if not self.selected:
            return True
        return bool(
            self.deps_ready and self.authorized and self.integration_id and self.binding_verified
        )


# Message printed when the managed agent has no usable machine-owned runtime
# interpreter for Google authorization. We fail closed here instead of importing
# Google in the setup CLI's own interpreter: that accidental in-process fallback is
# what produced the misleading ``No module named 'google_auth_oauthlib'``.
NO_RUNTIME_FOR_GOOGLE_AUTH_MSG = (
    "Google authorization requires the machine-owned runtime interpreter "
    "({runtime_python}), which is not present. Google was NOT authorized. Re-run "
    "'securedact-mcp setup --agent --google yes' from an elevated Administrator "
    "PowerShell so the machine runtime is provisioned with the Google extra "
    "(verify it with 'securedact-mcp agent google-verify')."
)


def _authorize_google_machine(
    *,
    data_dir: Path,
    runtime_python: Path | None,
    command_runner: CommandRunner | None,
    input_fn: Callable[[str], str],
    output: Any,
    non_interactive: bool,
    secret_input_fn: Callable[[str], str],
    authorize_google_fn: Callable[..., bool] | None,
    google_byo: bool = False,
) -> bool:
    """Run machine-local Google OAuth in the machine-owned runtime interpreter.

    ``runtime_python`` is the interpreter resolved once by
    :func:`resolve_machine_runtime_python` — the same one the readiness probe used.
    When it exists (the supported, secure path) the authorization executes *inside*
    it via the local loopback flow, so the Google extra that the scheduled agent
    uses is the one that authorizes.

    When there is no machine runtime interpreter:

    * an explicitly injected ``authorize_google_fn`` (dev / embedders / tests) is
      used; otherwise
    * on Windows we FAIL CLOSED. Importing Google in the setup CLI's own
      interpreter was an accidental fallback: it raised
      ``ModuleNotFoundError: google_auth_oauthlib`` from a completely different
      Python than the one the readiness probe reported on, producing the
      contradictory "dependencies available / not authorized" pair;
    * on non-Windows (dev only, where there is no machine runtime at all) the
      in-process implementation remains available.
    """

    if runtime_python is not None:
        return _authorize_google_via_runtime(
            runtime_python,
            data_dir,
            command_runner,
            output,
            google_byo=google_byo,
        )
    if authorize_google_fn is not None:
        return bool(
            authorize_google_fn(
                data_dir,
                input_fn=input_fn,
                output=output,
                non_interactive=non_interactive,
                require_enabled=False,
            )
        )
    if sys.platform == "win32":
        print(
            NO_RUNTIME_FOR_GOOGLE_AUTH_MSG.format(
                runtime_python=resolve_runtime_python(default_runtime_path())
            ),
            file=output,
        )
        return False
    return bool(
        google_setup.authorize_google_machine(
            data_dir,
            input_fn=input_fn,
            output=output,
            non_interactive=non_interactive,
            require_enabled=False,
        )
    )


def build_google_auth_argv(
    runtime_python: Path | str,
    data_dir: Path | str,
    *,
    google_byo: bool = False,
    verify: bool = False,
) -> list[str]:
    """Return the exact argv used to run Google OAuth inside the machine runtime.

    Single source of truth for the command line, so the wizard, the verification
    command, and the tests all assert the same thing:

        <runtime python> -m securedact_mcp.agent.runtime_bootstrap google-auth
            --data-dir <machine root> --loopback [--google-byo] [--verify]

    No OAuth code/token/client secret is ever placed on this argv; ``--google-byo``
    is a non-secret selection marker only.
    """

    argv = [
        str(runtime_python),
        "-m",
        "securedact_mcp.agent.runtime_bootstrap",
        "google-auth",
        "--data-dir",
        str(data_dir),
        "--loopback",
    ]
    if google_byo:
        argv.append("--google-byo")
    if verify:
        argv.append("--verify")
    return argv


def _authorize_google_via_runtime(
    runtime_python: Path,
    data_dir: Path,
    command_runner: CommandRunner | None,
    output: Any,
    google_byo: bool = False,
) -> bool:
    """Authorize Google using the machine-owned runtime interpreter via loopback.

    The machine runtime opens the browser on 127.0.0.1, validates state, and
    exchanges the code in-process. Running authorization *inside the machine
    runtime* (which carries the Google extra) means a missing
    ``google_auth_oauthlib`` in the setup CLI's interpreter cannot break it, and
    we never ask the customer for an OAuth client secret.

    The default production path uses the SecuRedact-managed app. If the loopback
    flow does not complete, we fail closed (return False) — the caller reports
    the failure and, on the normal (managed) path, never prompts the customer
    for OAuth credentials. Fails closed on any non-zero runtime exit or malformed
    response.
    """

    runner = command_runner or _default_runner
    loopback_argv = build_google_auth_argv(runtime_python, data_dir, google_byo=google_byo)
    # Name the interpreter that performs the authorization, so the operator can see
    # (and the retest can prove) that it is the machine-owned runtime and not the
    # setup CLI's own Python.
    print(f"Google authorization interpreter: {runtime_python}", file=output)
    try:
        result = runner(loopback_argv, RunInput(env=_env_for(Path(data_dir))))
    except Exception as exc:  # a runtime that cannot be launched is a hard stop
        print(
            f"Google authorization could not run in the machine runtime: {scrub(str(exc))}",
            file=output,
        )
        return False
    if result.returncode != 0:
        print(
            "Google authorization could not be started in the machine runtime: "
            f"{scrub(result.stderr or result.stdout)}",
            file=output,
        )
        return False
    try:
        payload = json.loads(result.stdout)
    except Exception:
        print(
            "Google authorization failed: malformed machine-runtime response",
            file=output,
        )
        return False
    if not payload.get("authorized"):
        err = payload.get("error")
        print(
            "Google authorization failed" + (f": {scrub(str(err))}" if err else ""),
            file=output,
        )
        return False
    return True


def run_google_machine_onboarding(
    *,
    data_dir: Path,
    output: Any,
    input_fn: Callable[[str], str],
    secret_input_fn: Callable[[str], str],
    non_interactive: bool = False,
    google_integration_id: str | None = None,
    runtime_path: Path | str | None = None,
    command_runner: CommandRunner | None = None,
    authorize_google_fn: Callable[..., bool] | None = None,
    bind_google_fn: Callable[..., Any] | None = None,
    apply_google_env_fn: Callable[..., None] | None = None,
    verify_binding_fn: Callable[..., bool] | None = None,
    client_config_fn: Callable[..., bool] | None = None,
    deps_ready_fn: Callable[[], bool] | None = None,
    google_byo: bool = False,
) -> GoogleOnboardingOutcome:
    """Perform the machine-local Google onboarding and prove its post-conditions.

    Order (each step is a hard pre-condition of the next):

    1. the machine runtime can import the Google provider dependencies;
    2. Google is authorized *locally against the machine data root* (an existing
       valid machine token is reused; a missing OAuth client is collected once and
       persisted encrypted, then authorization is retried exactly once);
    3. the dashboard integration id is resolved (flag, non-secret env override,
       an already-bound id, or an explicit question);
    4. the machine-local connector binding is created/reused; and
    5. the binding is re-read from ``<machine root>/agent/connector-bindings.json``
       and proven to record exactly that integration id.

    Returns a :class:`GoogleOnboardingOutcome` whose ``ready`` property is the
    single fail-closed signal the wizard uses. Nothing here is ever silently
    skipped: every unmet pre-condition is reported and leaves ``ready`` False.

    ``runtime_path`` is the machine-owned runtime the caller actually provisioned.
    The interpreter inside it is resolved ONCE here and used for both the readiness
    probe and the authorization, so the two can never report on different Pythons.
    """

    _bind = bind_google_fn or google_setup.bind_google_machine
    _apply_env = apply_google_env_fn or google_setup.apply_google_machine_env
    _verify = verify_binding_fn or google_setup.verify_machine_binding
    _client_config = client_config_fn or google_setup.prompt_google_client_config
    # One resolution, one interpreter: the probe below and the authorization further
    # down are guaranteed to talk about the same Python.
    runtime_python = resolve_machine_runtime_python(runtime_path)
    _deps_ready = deps_ready_fn or (
        lambda: _google_runtime_deps_ready(runtime_python, command_runner)
    )

    outcome = GoogleOnboardingOutcome(selected=True, runtime_python=runtime_python)

    print(file=output)
    print("[Google Workspace]", file=output)
    print(
        "Machine runtime interpreter: "
        + (str(runtime_python) if runtime_python is not None else "not available"),
        file=output,
    )

    # 1. Required Google dependencies must be importable from the machine runtime,
    #    and that runtime's bootstrap must actually carry the google-auth command.
    outcome.deps_ready = bool(_deps_ready())
    if not outcome.deps_ready:
        print(
            "The machine runtime cannot perform Google work (missing Google "
            "connector dependencies, or a stale runtime whose bootstrap has no "
            "'google-auth' command); Google scans cannot run. Re-run setup so the "
            "Google extra and the current agent build are installed into the "
            "machine runtime, then check 'securedact-mcp agent google-verify'.",
            file=output,
        )
        return outcome

    # Publish only the non-secret enable flag at machine scope (and persist any
    # operator-supplied client config encrypted under the machine root).
    try:
        _apply_env(data_dir, enabled=True)
    except Exception as exc:  # pragma: no cover - non-fatal best-effort
        print(f"Google machine env not applied: {scrub(str(exc))}", file=output)

    # 2. Machine-local OAuth must be valid (reused idempotently when present). The
    #    authorization runs inside the *machine-owned runtime* (which carries the
    #    Google extra) whenever one is available, so a ``google_auth_oauthlib``
    #    import error in the setup CLI's own interpreter can never break it — and
    #    when no machine runtime exists we fail closed instead of importing Google
    #    in-process. A missing runtime dependency is an INSTALLATION/readiness
    #    failure, not a reason to ask the customer for OAuth credentials.
    print("Authorizing Google locally against the machine data root...", file=output)
    outcome.authorized = _authorize_google_machine(
        data_dir=data_dir,
        runtime_python=runtime_python,
        command_runner=command_runner,
        input_fn=input_fn,
        output=output,
        non_interactive=non_interactive,
        secret_input_fn=secret_input_fn,
        authorize_google_fn=authorize_google_fn,
        google_byo=google_byo,
    )
    if not outcome.authorized:
        # Only when the operator explicitly opts into BYO/enterprise (their own
        # Google Cloud OAuth app) do we collect a client id/secret. The default
        # production path is the SecuRedact-managed app, so a normal customer never
        # has to create their own Google Cloud project / OAuth application.
        if google_byo:
            collected = bool(
                _client_config(
                    data_dir,
                    input_fn=input_fn,
                    secret_input_fn=secret_input_fn,
                    output=output,
                    non_interactive=non_interactive,
                )
            )
            if collected:
                outcome.authorized = _authorize_google_machine(
                    data_dir=data_dir,
                    runtime_python=runtime_python,
                    command_runner=command_runner,
                    input_fn=input_fn,
                    output=output,
                    non_interactive=non_interactive,
                    secret_input_fn=secret_input_fn,
                    authorize_google_fn=authorize_google_fn,
                    google_byo=google_byo,
                )
        if not outcome.authorized:
            if not google_byo:
                print(
                    google_managed.MANAGED_CLIENT_NOT_CONFIGURED_MSG
                    + " Normal customers should not create their own Google Cloud "
                    "project; once the managed app is configured (set "
                    "SECUREDACT_GOOGLE_MANAGED_CLIENT_ID, or have it supplied by "
                    "packaging), re-run setup, or pass --google-byo to use your own "
                    "OAuth app (advanced/enterprise).",
                    file=output,
                )
            print(
                "Google authorization was not completed. No Google job can run until "
                "it is (finish it with 'securedact-mcp setup --agent --google yes').",
                file=output,
            )
            return outcome

    # 3. Resolve the dashboard integration id (ask clearly when not discoverable).
    try:
        outcome.integration_id = google_setup.resolve_google_integration_id(
            data_dir,
            google_integration_id=google_integration_id,
            non_interactive=non_interactive,
            input_fn=input_fn,
            output=output,
        )
    except AgentError as exc:
        print(f"Google Workspace integration ID rejected: {scrub(str(exc))}", file=output)
        return outcome
    if not outcome.integration_id:
        print(
            "No Google Workspace integration ID was provided, so the machine-local "
            "connector binding could not be created. Google jobs will fail with "
            "'no local connector binding' until it is supplied; re-run "
            "'securedact-mcp setup --agent --google yes --google-integration-id <id>'.",
            file=output,
        )
        return outcome

    # 4. Create (or idempotently reuse) the machine-local binding.
    registered = _load_registered_config(data_dir)
    if registered is None:
        print(
            "Agent is not registered locally; complete registration before "
            "binding the Google integration.",
            file=output,
        )
        return outcome
    files = AgentFiles.resolve(root=Path(data_dir) / "agent")
    try:
        binding = _bind(registered, outcome.integration_id, files=files)
    except AgentError as exc:
        print(f"Google connector binding failed: {scrub(str(exc))}", file=output)
        return outcome
    except Exception as exc:  # a store/IO failure must never look like success
        print(f"Google connector binding failed safely: {scrub(str(exc))}", file=output)
        return outcome

    # 5. Fail-closed post-condition: the binding really exists on the machine root.
    outcome.binding_verified = bool(_verify(data_dir, outcome.integration_id, files=files))
    if not outcome.binding_verified:
        print(
            "The Google connector binding could not be verified under "
            f"{files.connector_bindings}; refusing to report the agent as ready.",
            file=output,
        )
        return outcome
    print(
        f"Local connector bound: {binding.integration_id} -> {binding.platform}",
        file=output,
    )
    print(f"Binding file: {files.connector_bindings}", file=output)
    return outcome


def run_managed_agent_module(
    *,
    input_fn: Callable[[str], str],
    output: Any,
    secret_input_fn: Callable[[str], str] | None = None,
    token: str | None = None,
    control_plane_url: str | None = None,
    display_name: str | None = None,
    data_dir: Path | str | None = None,
    runtime_path: Path | str | None = None,
    command_runner: CommandRunner | None = None,
    acl_provider: Callable[[Path], list[tuple[str, str, set[str]]]] | None = None,
    elevated_check: Callable[[], bool] | None = None,
    elevate: Callable[[Sequence[str]], int] | None = None,
    rerun_argv: Sequence[str] | None = None,
    agent: str | None = None,
    agent_elevated: bool = False,
    non_interactive: bool = False,
    dev_local: bool | None = None,
    google: str | None = None,
    google_integration_id: str | None = None,
    google_byo: bool | None = None,
    authorize_google_fn: Callable[..., bool] | None = None,
    bind_google_fn: Callable[..., Any] | None = None,
    apply_google_env_fn: Callable[..., None] | None = None,
    verify_google_binding_fn: Callable[..., bool] | None = None,
    google_client_config_fn: Callable[..., bool] | None = None,
    google_deps_ready_fn: Callable[[], bool] | None = None,
    google_selection_fn: Callable[..., bool] | None = None,
) -> int:
    """Orchestrate the Managed Agent setup step inside ``securedact-mcp setup``.

    Returns 0 when the agent is installed, skipped safely, or unsupported; 2 on a
    hard failure. The registration token is never echoed or persisted.

    When Google Workspace managed scanning is selected (explicitly, by detected
    machine configuration, or by the interactive question) the module performs the
    full machine onboarding -- Google deps, machine-local OAuth, and the
    machine-local connector binding -- and refuses to report the Managed Agent as
    ready until all three exist.
    """

    import getpass

    _elevated = elevated_check or is_elevated
    _secret_input = secret_input_fn or getpass.getpass

    # Authoritative machine data root for the managed agent. All managed-agent
    # state (registration, credential vault, OAuth, bindings, logs, the scheduled
    # task) lives here — never in the interactive user's %LOCALAPPDATA% profile.
    machine_data_dir = service.resolve_service_data_dir(data_dir)

    # Resume detection: this process is the already-elevated continuation of a
    # managed-agent setup when (a) the caller passed the explicit marker, (b) we
    # are already running elevated, or (c) the marker was inherited from the parent
    # that requested elevation. In any of these cases we must NOT re-prompt for
    # elevation, so the continuation runs exactly once.
    _resume = agent_elevated or _elevated() or os.environ.get(AGENT_ELEVATED_ENV) == "1"

    print(file=output)
    print("[Managed Agent]", file=output)
    print(
        "The managed agent lets your SecuRedact dashboard schedule privacy scans "
        "on this computer. Files and detected values stay local.",
        file=output,
    )

    if sys.platform != "win32":
        print(
            "The managed-agent background service is only supported on Windows. "
            "On this platform the foreground 'securedact-mcp agent run' remains "
            "available; skipping the service install.",
            file=output,
        )
        return 0

    if agent == "no":
        print("Managed Agent: skipped by request.", file=output)
        return 0

    # Default (interactive wizard) path: confirm with the user.
    requested = agent == "yes"
    if agent is None and not non_interactive:
        try:
            answer = input_fn("Install managed background agent? [Y/n] ").strip().casefold()
        except (EOFError, StopIteration):
            answer = "n"
        requested = answer in {"", "y", "yes"}

    if not requested:
        print("Managed Agent: skipped.", file=output)
        return 0

    # Elevation preflight — fail closed, never partially install. The elevated
    # continuation is re-launched with an explicit resume marker so it never
    # re-enters this prompt (and thus never re-triggers the whole elevation
    # sequence). A declined/failed elevation is handled safely, not treated as a
    # successful hand-off.
    if not _resume:
        print(file=output)
        print(
            "Administrator rights are required to install the managed-agent "
            "scheduled task. The task runs under the SYSTEM account and must load "
            f"Python code from a machine-owned path ({default_runtime_path()}) that "
            "ordinary users cannot modify.",
            file=output,
        )
        if non_interactive:
            print(
                "Non-interactive run cannot elevate. Re-run this step from an "
                "elevated Administrator PowerShell:",
                file=output,
            )
            print("    securedact-mcp setup --agent", file=output)
            return 0
        try:
            confirm = (
                input_fn("Relaunch setup elevated to install the agent now? [y/N] ")
                .strip()
                .casefold()
            )
        except (EOFError, StopIteration):
            confirm = "n"
        if confirm in {"y", "yes"}:
            # The re-launched child resumes the onboarding exactly once. The
            # resume signal is carried authoritatively on argv as the
            # ``--agent-elevated`` marker (see ``build_elevation_argv``), which the
            # CLI wires to ``agent_elevated``; we deliberately do NOT mutate the
            # parent's global ``os.environ`` here so the marker cannot leak across
            # processes/tests. ``AGENT_ELEVATED_ENV`` remains available as an
            # explicit external override only.
            handler = elevate or self_elevate
            # The elevated continuation is launched with the same RC interpreter
            # that initiated setup (``sys.executable``) followed by the module-form
            # argv, so it can never resolve a different/global install via PATH.
            # An explicit Google selection is forwarded (non-secret only) so the
            # elevated continuation -- which performs the Google machine onboarding
            # -- cannot lose it across the UAC boundary.
            target = [
                sys.executable,
                *build_elevation_argv(
                    google=google,
                    google_integration_id=google_integration_id,
                    google_byo=google_byo if google_byo is not None else False,
                ),
            ]
            code = handler(list(rerun_argv) if rerun_argv is not None else target)
            if code != 0:
                # UAC denied or the elevated launch failed: stop safely without
                # raising _ElevationHandoff (which would pretend success).
                print(
                    "Elevation was declined or failed. To finish later, run from an "
                    "elevated Administrator PowerShell: securedact-mcp setup --agent",
                    file=output,
                )
                return 0
            # The child process takes over; exit this (unelevated) instance.
            raise _ElevationHandoff(code)
        print(
            "Elevation declined. To finish later, run from an elevated "
            "Administrator PowerShell: securedact-mcp setup --agent",
            file=output,
        )
        return 0

    # Reuse an existing valid *machine* registration when present (never consume a
    # new token unless one is genuinely required). A stale user-profile
    # registration must NOT satisfy this check.
    if _agent_already_registered(data_dir=machine_data_dir):
        token = None
        print(file=output)
        print(
            "Existing agent registration found; reusing it (no new registration token consumed).",
            file=output,
        )
    else:
        # Collect the one-time registration token (never echoed, never persisted).
        if token is None:
            print(file=output)
            print("To connect this computer to your SecuRedact dashboard:", file=output)
            print("  1. Open https://www.securedact.com", file=output)
            print("  2. Dashboard -> Local Agents -> Add agent", file=output)
            print("  3. Copy the one-time registration token", file=output)
            try:
                token = _secret_input("Registration token: ")
            except EOFError:
                print("No registration token provided; aborting agent install.", file=output)
                return 2
        token = (token or "").strip()
        if not token:
            print("Empty registration token; aborting agent install.", file=output)
            return 2

    # Google Workspace onboarding selection. The wizard itself decides -- an
    # explicit ``--google`` choice (including one forwarded across the UAC
    # boundary), the non-secret ``SECUREDACT_GOOGLE_ENABLED`` override, detected
    # machine-local Google configuration, or a plain interactive question. An
    # operator never has to know a hidden environment flag, and Google is never
    # forced on a machine where it is not configured/selected.
    _select_google = google_selection_fn or google_setup.resolve_google_selection
    google_enabled = bool(
        _select_google(
            machine_data_dir,
            google=google,
            non_interactive=non_interactive,
            input_fn=input_fn,
            output=output,
        )
    )
    # BYO (bring-your-own Google Cloud OAuth app) is an explicit advanced/enterprise
    # option. The default production path is the SecuRedact-managed app, so normal
    # customers never have to create their own Google Cloud project.
    byo = google_byo if google_byo is not None else os.getenv(google_setup.GOOGLE_BYO_ENV) == "1"

    # Provision secure runtime + install + start. Google deps are installed into
    # the machine runtime here when selected (never every optional extra). The
    # authoritative machine data root is threaded through so registration is written
    # directly there (never to the interactive user's profile).
    _dev_local = dev_local if dev_local is not None else dev_local_wheel_requested()
    try:
        result = install_service_from_runtime(
            token=token,
            data_dir=machine_data_dir,
            runtime_path=runtime_path,
            control_plane_url=control_plane_url,
            display_name=display_name,
            command_runner=command_runner,
            dev_local=_dev_local,
            google_enabled=google_enabled,
        )
    except AgentError as exc:
        print(f"Managed Agent install failed safely: {scrub(str(exc))}", file=output)
        return 2

    print(file=output)
    print("Machine runtime:", result.get("data_dir"), file=output)
    print("Service:", result.get("service_name"), "as", result.get("account"), file=output)
    print("Registered agent:", result.get("agent_id"), file=output)

    # The runtime that was ACTUALLY provisioned above is authoritative for every
    # subsequent runtime-scoped step (Google authorization, heartbeat). Passing
    # ``runtime_path`` (which is normally ``None``, because neither the setup CLI nor
    # the wizard supplies it) made the Google authorization believe there was no
    # machine runtime and fall back to an in-process import in the setup CLI's own
    # interpreter -> ``No module named 'google_auth_oauthlib'`` while the readiness
    # probe (which did default to ProgramData) reported "available".
    resolved_runtime_path: Path | str | None = result.get("runtime_path") or runtime_path  # type: ignore[assignment]

    # --- Google Workspace onboarding (only when configured/selected) -----------
    resolved_data = machine_data_dir
    google_outcome = GoogleOnboardingOutcome(selected=google_enabled)
    if google_enabled:
        google_outcome = run_google_machine_onboarding(
            data_dir=resolved_data,
            output=output,
            input_fn=input_fn,
            secret_input_fn=_secret_input,
            non_interactive=non_interactive,
            google_integration_id=google_integration_id,
            runtime_path=resolved_runtime_path,
            command_runner=command_runner,
            google_byo=byo,
            authorize_google_fn=authorize_google_fn,
            bind_google_fn=bind_google_fn,
            apply_google_env_fn=apply_google_env_fn,
            verify_binding_fn=verify_google_binding_fn,
            client_config_fn=google_client_config_fn,
            deps_ready_fn=google_deps_ready_fn,
        )
        if not google_outcome.ready:
            # Fail closed: the Managed Agent must NOT be reported as ready (and the
            # heartbeat/"setup complete" milestone must not be printed) while a
            # required Google pre-condition is missing. A missing machine-local
            # binding is exactly the defect that made scheduled Google jobs fail
            # with 'no local connector binding for integration_id ...'.
            print(file=output)
            print(
                "Managed Agent: NOT ready - Google Workspace was selected but the "
                "machine-local Google onboarding is incomplete.",
                file=output,
            )
            print(
                f"  Google dependencies: {'available' if google_outcome.deps_ready else 'missing'}",
                file=output,
            )
            print(
                "  Google runtime interpreter: "
                + (
                    str(google_outcome.runtime_python)
                    if google_outcome.runtime_python is not None
                    else "not available"
                ),
                file=output,
            )
            print(
                f"  Machine-local Google OAuth: "
                f"{'valid' if google_outcome.authorized else 'not authorized'}",
                file=output,
            )
            print(
                "  Machine connector binding: "
                f"{'present' if google_outcome.binding_verified else 'missing'}",
                file=output,
            )
            print(
                "  Finish it with: securedact-mcp setup --agent --google yes "
                "--google-integration-id <dashboard integration ID>",
                file=output,
            )
            return 2

    print(file=output)
    print("Starting managed agent...", file=output)
    online = verify_heartbeat(
        data_dir=cast("str | None", result.get("data_dir")),
        runtime_path=resolved_runtime_path,
        command_runner=command_runner,
    )
    print("Status:", "Online" if online else "Installed (heartbeat pending)", file=output)
    print("Managed Agent: setup complete.", file=output)
    return 0


class _ElevationHandoff(Exception):
    """Internal signal that control was handed to an elevated child process."""

    def __init__(self, code: int) -> None:
        super().__init__(f"elevation handoff (child exit {code})")
        self.code = code
