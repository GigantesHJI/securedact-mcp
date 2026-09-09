# SPDX-License-Identifier: Apache-2.0
"""Customer-facing SecuRedact managed-agent bootstrap launcher.

This is the *zero-PowerShell* entry point a Business customer runs after
downloading the installer from the dashboard.

Two production paths converge on this file:

1. **PyInstaller-frozen EXE** (preferred v0.6.0 path): ``pyinstaller`` bundles
   this script together with the ``securedact_mcp.agent.installer`` module and
   an embedded Python 3.12 interpreter into a single signed Windows EXE. The
   dashboard issues a download link like
   ``SecuRedactInstaller-0.6.0.exe?bootstrap=...`` and the customer simply
   double-clicks it; a normal UAC prompt elevates the same process; no
   PowerShell is ever opened.

2. **Direct script** (smoke test / developer path): running
   ``python scripts/install_agent_bootstrap.py --config
   securedact-bootstrap.json`` from an elevated Administrator PowerShell or
   cmd. This path is for developer verification only; customers always use (1).

What this script does
---------------------
* Verifies a bootstrap config file is reachable (next to the EXE, in the cwd,
  or via ``--config``/``SECUREDACT_BOOTSTRAP_CONFIG``).
* Validates the bounded config (rejects unknown fields, expired tokens,
  invalid shapes).
* UAC-elevates the same process (no new window, no PowerShell) by re-launching
  itself with the existing ``deploy.self_elevate`` machinery.
* Runs the canonical installer pipeline from
  :mod:`securedact_mcp.agent.installer` and reports the bounded result as JSON
  on stdout (the dashboard's "Return to Dashboard" button can poll the same
  installer exit-code to know whether the install succeeded).

What this script does NOT do
----------------------------
* Does not require a pre-installed Python on the customer's machine (the
  PyInstaller EXE ships its own).
* Does not display or accept the ``srr_*`` token from the customer.
* Does not invoke pip / venv directly; the embedded ``deploy`` module does
  that with full hardening.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

# When packaged as a PyInstaller onedir EXE, ``sys.executable`` is the
# bootstrap EXE and the real CPython interpreter lives at
# ``sys._MEIPASS/python.exe``. When run as a plain script, ``sys.executable``
# is the host interpreter. The launcher resolves a *real* interpreter below and
# passes it to ``provision_machine_runtime`` / ``run_install`` so the
# ProgramData venv is created from a genuine CPython — not the bootloader.

# ---------------------------------------------------------------------------
# Real-interpreter resolution (clean-machine installability proof)
# ---------------------------------------------------------------------------

# The exact Python that ships inside the PyInstaller onedir bundle. The
# provisioned runtime venv is created FROM this interpreter so the resulting
# ``C:\\ProgramData\\Securedact\\runtime\\Scripts\\python.exe`` is a genuine,
# self-contained CPython 3.12 (not a bootloader re-exec, not a redirector that
# depends on a temp dir).
PYTHON_EMBEDDED_NAME = "python.exe"

EXPECTED_PYTHON_VERSION = "3.12"


def _resolve_embedded_python() -> Path | None:
    """Return the path to the real Python interpreter shipped in the bundle.

    PyInstaller onedir places the genuine CPython in ``sys._MEIPASS``. A one-
    file build has no `_MEIPASS` (bootloader); in that case this returns None
    and the installer fails-closed with a clear message rather than silently
    falling back to the bootloader.
    """

    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidate = Path(meipass) / PYTHON_EMBEDDED_NAME
        if candidate.is_file():
            return candidate
    return None


def _validate_python_version(python: Path, runner: Any | None) -> bool:
    """Return True iff ``python`` reports exactly CPython 3.12.x."""

    try:
        import subprocess

        completed = subprocess.run(  # noqa: S603
            [
                str(python),
                "-c",
                "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception:
        return False
    if completed.returncode != 0:
        return False
    reported = (completed.stdout or "").strip()
    return reported == EXPECTED_PYTHON_VERSION


def assert_real_python_available() -> Path:
    """Resolve and validate the bundled real interpreter; fail-closed.

    On a completely clean Windows machine the only Python is the one shipped in
    the PyInstaller onedir bundle. The bootloader (one-file) EXE is NOT usable
    as a venv base — it re-execs the bootstrap entry script — so its presence is
    treated as a hard error.
    """

    embedded = _resolve_embedded_python()
    if embedded is None:
        raise RuntimeError(
            "the SecuRedact installer requires the bundled CPython interpreter "
            "(sys._MEIPASS/python.exe). If you are running the onefile EXE directly, "
            "use the onedir build instead; if you are running the .py script, a "
            "host Python 3.12 must be available at runtime."
        )
    if not _validate_python_version(embedded, None):
        raise RuntimeError(
            f"the bundled interpreter {embedded} did not report CPython {EXPECTED_PYTHON_VERSION}"
        )
    return embedded


def _resolve_config_path(explicit: str | None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env = os.environ.get("SECUREDACT_BOOTSTRAP_CONFIG")
    if env:
        candidates.append(Path(env))
    exe_dir = Path(sys.executable).resolve().parent
    candidates.append(exe_dir / "securedact-bootstrap.json")
    candidates.append(Path.cwd() / "securedact-bootstrap.json")
    for cand in candidates:
        if cand.is_file():
            return cand
    raise FileNotFoundError(
        "no bootstrap config file found; pass --config <path> or set "
        "SECUREDACT_BOOTSTRAP_CONFIG, or place 'securedact-bootstrap.json' "
        f"next to the installer EXE. Searched: {[str(c) for c in candidates]}"
    )


def _ensure_elevated(elevate_fn: Callable[..., Any]) -> int | None:
    """Trigger UAC elevation if not already elevated.

    Returns the elevated child's exit code when we hand off, or ``None`` to
    continue the install in the current process (already elevated or
    non-Windows).
    """

    from securedact_mcp.agent.deploy import is_elevated  # local import: not available everywhere

    if is_elevated():
        return None
    # Re-launch the same script elevated. The bootstrap config path is
    # forwarded via SECUREDACT_BOOTSTRAP_CONFIG so the child reads the same
    # file; the registration token is NEVER placed on argv.
    config_env = os.environ.get("SECUREDACT_BOOTSTRAP_CONFIG", "")
    if not config_env:
        # Find the config and propagate its path through the environment.
        try:
            cfg = _resolve_config_path(None)
        except FileNotFoundError as exc:
            print(json.dumps({"error": "bootstrap_config_missing", "message": str(exc)}))
            return 2
        os.environ["SECUREDACT_BOOTSTRAP_CONFIG"] = str(cfg)
    target = [sys.executable, *sys.argv]
    result: int | None = elevate_fn(target)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="securedact-installer-launcher",
        description="Customer-facing SecuRedact managed-agent installer (zero PowerShell).",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to the bootstrap config JSON (or set SECUREDACT_BOOTSTRAP_CONFIG).",
    )
    parser.add_argument(
        "--upgrade",
        action="store_true",
        help="upgrade the existing runtime instead of consuming a new token",
    )
    parser.add_argument(
        "--heartbeat-timeout",
        type=float,
        default=30.0,
        help="seconds to wait for the initial heartbeat (default: 30)",
    )
    parser.add_argument(
        "--skip-elevation",
        action="store_true",
        help="developer-only: do not request UAC elevation (use for "
        "non-Windows or already-elevation-aware test harnesses).",
    )
    args = parser.parse_args(argv)

    # Resolve the config path so the elevated child re-reads the same file
    # (the srr_* token stays in the JSON file, never on argv).
    try:
        cfg_path = _resolve_config_path(args.config)
    except FileNotFoundError as exc:
        print(json.dumps({"error": "bootstrap_config_missing", "message": str(exc)}))
        return 2
    os.environ["SECUREDACT_BOOTSTRAP_CONFIG"] = str(cfg_path)

    if not args.skip_elevation and sys.platform == "win32":
        from securedact_mcp.agent.deploy import self_elevate

        child_code = _ensure_elevated(self_elevate)
        if child_code is not None:
            # Elevated child has finished; propagate its exit code.
            return int(child_code) if isinstance(child_code, int) else 0

    # We are now elevated (or non-Windows, or developer mode). Run the
    # canonical installer pipeline via the package entry point.
    from securedact_mcp.agent import installer

    try:
        config = installer.load_bootstrap_config_from_path(cfg_path)
    except installer.BootstrapConfigError as exc:
        print(json.dumps({"error": "bootstrap_config_invalid", "message": str(exc)}))
        return 2
    if args.upgrade:
        result = installer.run_upgrade(config)
    else:
        # When frozen as a PyInstaller onedir EXE, assert the bundled real
        # CPython is present and hand it to the installer so the ProgramData
        # runtime venv is created from a genuine interpreter -- never the
        # bootloader. In non-frozen runs (script / dev / test) ``run_install``
        # resolves the interpreter itself (falling back to ``sys.executable``).
        base_python = None
        if getattr(sys, "frozen", False):
            embedded = assert_real_python_available()
            base_python = str(embedded)
        result = installer.run_install(
            config,
            base_python=base_python,
            heartbeat_timeout_seconds=args.heartbeat_timeout,
        )
    print(json.dumps(result.to_dict()))
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
