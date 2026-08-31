# SPDX-License-Identifier: Apache-2.0
"""Managed-agent background persistence lifecycle (AGENT-018).

This module is the platform-neutral surface used by the CLI. On Windows it
delegates to :mod:`securedact_mcp.agent.service_taskscheduler` (Windows Task
Scheduler). On every other platform the service subcommands fail closed with a
clear, customer-readable ``AgentServiceUnsupportedError`` — no fragile startup
hacks, no silent no-ops.

Persistence mechanism (changed from the original pywin32 Windows Service)
-----------------------------------------------------------------------
The original persistence layer used ``pywin32`` / ``pythonservice.exe`` (a
native Windows Service). Empirically that host configuration repeatedly failed
to start on this real Windows machine with ``WinError 1053`` (the SCM timed out
before the service reported RUNNING), while the normal foreground agent command
already worked. The chosen replacement is **Windows Task Scheduler**, which
launches the *same proven agent loop* (``python -m securedact_mcp.agent.cli
run``) as a normal, non-interactive process at system startup.

The legacy pywin32 ``service_windows`` package is retained in the tree only as a
clearly-disabled reference implementation; it is NOT wired into the active
lifecycle below (the active backend is Task Scheduler), so the production
vSA/ACL/runtime-integrity hardening path is not silently re-enabled. That
hardening is reintroduced only after the Task Scheduler lifecycle is proven.

* Start automatically at Windows startup (``BootTrigger``), running whether or
  not an interactive PowerShell window is open.
* Use the machine runtime
  (``C:\\ProgramData\\Securedact\\runtime\\Scripts\\python.exe``) and the shared
  machine data directory (``C:\\ProgramData\\Securedact``).
* Never put registration tokens, agent credentials, OAuth tokens, lease secrets,
  or entitlement JWTs on the task command line; load them from the local vault.
* Prevent duplicate agent instances (Task Scheduler ``IgnoreNew`` + the
  in-process single-instance lock).
* Restart/retry after unexpected process failure where Task Scheduler supports
  it.
* Hidden / non-interactive.
* Clean install/start/stop/status/uninstall/upgrade operations; idempotent on
  rerun; preserve agent state across upgrade.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .config import AgentFiles, load_config
from .errors import AgentError
from .safe_log import scrub
from .service_lock import agent_instance_lock

# The active Windows persistence backend. The legacy ``pywin32`` / SCM service
# path is intentionally NOT used here (see module docstring). This constant is
# asserted by tests so the production pywin32 hardening path cannot be silently
# re-enabled.
ACTIVE_PERSISTENCE_BACKEND = "taskscheduler"

logger = logging.getLogger(__name__)

SERVICE_NAME = "SecuredactAgent"
SERVICE_DISPLAY_NAME = "SecuRedact Managed Agent"
SERVICE_DESCRIPTION = (
    "SecuRedact local managed-agent daemon: heartbeats to the SecuRedact control "
    "plane and executes queued Google privacy scans locally. Runs with no console "
    "window and starts automatically on boot."
)

DEFAULT_IDLE_SLEEP = 30.0
LOCK_FILENAME = "agent.lock"


class AgentServiceUnsupportedError(AgentError):
    """Raised when the managed-agent service is requested on an unsupported OS."""


def is_windows_service_supported() -> bool:
    return sys.platform == "win32"


def _require_windows() -> None:
    if not is_windows_service_supported():
        raise AgentServiceUnsupportedError(
            "The managed-agent background service is only supported on Windows. "
            "On this platform use 'securedact-mcp agent run' in the foreground, or "
            "schedule it with your platform's native service manager."
        )


def default_windows_data_dir() -> Path:
    """Return the machine-wide default agent data root (ProgramData/Securedact)."""

    program_data = os.getenv("ProgramData") or r"C:\ProgramData"
    return Path(program_data) / "Securedact"


def resolve_service_data_dir(explicit: str | Path | None) -> Path:
    """Resolve the agent data root for the service.

    Precedence: explicit argument > ``SECUREDACT_APP_DATA_DIR`` > machine-wide
    default (Windows) / user default (other platforms).
    """

    if explicit is not None:
        return Path(explicit).expanduser()
    override = os.getenv("SECUREDACT_APP_DATA_DIR")
    if override:
        return Path(override).expanduser()
    if is_windows_service_supported():
        return default_windows_data_dir()
    from securedact_core.app_paths import SecuredactPaths

    return SecuredactPaths.resolve().root


def build_service_env(data_dir: Path) -> dict[str, str]:
    """Build the service process environment.

    Only non-secret operational variables are exported. The registration token,
    agent credential, OAuth token, lease secrets, and entitlement JWT are NEVER
    placed here — they live in OS-protected local storage keyed by the data dir.
    """

    env: dict[str, str] = {
        "SECUREDACT_AGENT_DATA_DIR": str(data_dir),
        "SECUREDACT_AGENT_SERVICE": "1",
        # Disable Python user-site so a normal user cannot plant a user-site
        # package/DLL/sitecustomize.py that LocalSystem would import (Section 4).
        "PYTHONNOUSERSITE": "1",
    }

    # The SCM-hosted service process is ``pythonservice.exe`` (a frozen pywin32
    # executable). Its interpreter sys.path does NOT include the installing
    # Python's site-packages or the project source, so it cannot ``import
    # securedact_mcp`` and the service never reaches SvcDoRun -> SCM times out
    # with WinError 1053 ("did not respond ... in a timely fashion"). CPython
    # reads PYTHONPATH at interpreter startup and prepends it to sys.path, so we
    # export the directories needed to import the agent package and its
    # dependencies. This is minimal startup-path wiring, not security hardening,
    # and applies identically to baseline (LocalSystem) and production (vSA).
    env["PYTHONPATH"] = _service_pythonpath()
    return env


def _service_pythonpath() -> str:
    """Compute a PYTHONPATH that lets the SCM host import the agent package.

    Returns the project source root (parent of the ``securedact_mcp`` package)
    plus every ``site-packages`` directory on the installing interpreter's
    sys.path, de-duplicated and in stable order. These are directories only; no
    secret material is involved. Returns "" when nothing resolvable is found.
    """

    import importlib.util
    import sys

    candidates: list[str] = []
    spec = importlib.util.find_spec("securedact_mcp")
    if spec is not None and spec.submodule_search_locations:
        pkg_parent = str(Path(next(iter(spec.submodule_search_locations))).parent)
        candidates.append(pkg_parent)
    for entry in sys.path:
        entry_str = str(Path(entry)) if entry else ""
        if entry_str and Path(entry_str).name == "site-packages":
            candidates.append(entry_str)
    # De-duplicate while preserving order.
    seen: set[str] = set()
    ordered: list[str] = []
    for cand in candidates:
        if cand and cand not in seen:
            seen.add(cand)
            ordered.append(cand)
    return os.pathsep.join(ordered)


# ---------------------------------------------------------------------------
# Logging / diagnostics
# ---------------------------------------------------------------------------


class _ScrubFormatter(logging.Formatter):
    """Formatter that redacts secrets from every emitted line (defense in depth)."""

    def format(self, record: logging.LogRecord) -> str:
        return scrub(super().format(record))


def configure_service_logging(data_dir: Path, *, level: int = logging.INFO) -> Path:
    """Attach a rotating, fully-scrubbed file handler under ``<data_dir>/logs``."""

    log_path = data_dir / "logs"
    log_path.mkdir(parents=True, exist_ok=True)
    file_path = log_path / "agent-service.log"

    root = logging.getLogger()
    if root.level == logging.NOTSET or root.level > level:
        root.setLevel(level)

    handler = logging.handlers.RotatingFileHandler(
        file_path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    handler.setFormatter(_ScrubFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    # Avoid double-attaching across reloads.
    if not any(
        isinstance(h, logging.handlers.RotatingFileHandler)
        and getattr(h, "baseFilename", None) == handler.baseFilename
        for h in root.handlers
    ):
        root.addHandler(handler)
    return file_path


# ---------------------------------------------------------------------------
# Service run loop (used by the Windows service host process)
# ---------------------------------------------------------------------------


def run_service_loop(
    *,
    stop: Callable[[], bool] | None = None,
    idle_sleep: float = DEFAULT_IDLE_SLEEP,
    data_dir: str | Path | None = None,
    agent_runner: Any | None = None,
) -> int:
    """Run the agent loop as a managed service.

    Resolves the (already-registered) agent config from the service data dir,
    acquires the single-instance lock, configures scrubbed diagnostics logging,
    and runs :func:`run_agent_loop` until ``stop()`` is true or the loop exits.
    Returns the number of iterations executed.
    """

    from . import agent_runner as _agent_runner

    runner = agent_runner or _agent_runner
    root = resolve_service_data_dir(data_dir)
    files = AgentFiles.resolve(root=root / "agent")
    log_file = configure_service_logging(root)

    try:
        config = load_config(files)
    except AgentError as exc:
        logger.error("agent not registered; cannot start service: %s", scrub(str(exc)))
        return 2

    logger.info(
        "service starting agent_id=%s version=%s data_dir=%s log=%s",
        config.agent_id,
        config.agent_version,
        root,
        log_file,
    )

    lock_path = files.root / LOCK_FILENAME
    with agent_instance_lock(lock_path) as acquired:
        if not acquired:
            logger.error(
                "another SecuRedact agent loop is already running (lock=%s); exiting",
                lock_path,
            )
            return 3
        logger.info("single-instance lock acquired; entering agent loop")
        iterations: int = runner.run_agent_loop(
            config,
            idle_sleep=idle_sleep,
            stop=stop,
            files=files,
        )
    logger.info("service stopped after %d iterations", iterations)
    return iterations


# ---------------------------------------------------------------------------
# High-level lifecycle API (Windows delegates to service_taskscheduler)
# ---------------------------------------------------------------------------


def install_service(
    data_dir: str | Path | None = None,
    *,
    start: bool = True,
    control_plane_url: str | None = None,
    display_name: str | None = None,
    token: str | None = None,
) -> dict[str, object]:
    _require_windows()
    from . import service_taskscheduler

    return service_taskscheduler.install_windows_service(
        data_dir,
        start=start,
        control_plane_url=control_plane_url,
        display_name=display_name,
        token=token,
    )


def start_service() -> dict[str, object]:
    _require_windows()
    from . import service_taskscheduler

    return service_taskscheduler.start_windows_service()


def stop_service() -> dict[str, object]:
    _require_windows()
    from . import service_taskscheduler

    return service_taskscheduler.stop_windows_service()


def uninstall_service() -> dict[str, object]:
    _require_windows()
    from . import service_taskscheduler

    return service_taskscheduler.uninstall_windows_service()


def query_service_status() -> dict[str, object]:
    _require_windows()
    from . import service_taskscheduler

    return service_taskscheduler.query_windows_service()


def service_log_path(data_dir: str | Path | None = None) -> Path:
    root = resolve_service_data_dir(data_dir)
    return root / "logs" / "agent-service.log"
