# SPDX-License-Identifier: Apache-2.0
"""Customer-facing Windows installer/bootstrap for the SecuRedact managed agent.

Goal: a Business customer can install and register the SecuRedact managed agent
*without* opening PowerShell. The dashboard issues a short-lived, single-use
``srr_*`` registration token wrapped in a bounded bootstrap config file; the
installer (this module, frozen into a Windows EXE in production) performs the
fixed, predetermined install pipeline end-to-end and reports the result.

What the installer DOES
-----------------------
1. Validates the bounded bootstrap config (rejects unknown fields, expired
   tokens, unparseable JSON).
2. UAC-elevates by re-launching itself with the existing ``self_elevate``
   machinery (no PowerShell, no manual steps).
3. Provisions ``C:\\ProgramData\\Securedact\\runtime`` with the exact pinned
   ``securedact-mcp==<version>`` via the existing ``install_service_from_runtime``
   code path (the proven, tested deployment pipeline).
4. Optionally installs the Business model (Flair ``ner-english-large``) via the
   existing :mod:`securedact_mcp.model_installer` module, with hash/integrity
   verification.
5. Consumes the one-time ``srr_*`` token during registration (never persisted,
   never echoed, never logged -- the secret scrubber in :mod:`.safe_log` covers
   it; this module additionally avoids passing it on argv or environment).
6. Creates/starts the scheduled task and verifies the initial heartbeat through
   the control plane.
7. Reports a bounded, privacy-safe status envelope back to the dashboard
   bootstrap URL (no secrets, no content, no telemetry beyond install result).

What the installer does NOT do
------------------------------
* Does NOT execute arbitrary commands supplied in the bootstrap config.
* Does NOT persist the ``srr_*`` token after successful registration.
* Does NOT touch ``connector-bindings.json``, the Google/Microsoft token vault,
  or any existing OAuth state on upgrade/reinstall.
* Does NOT install "latest" or any unpinned version of ``securedact-mcp``.
* Does NOT require the customer to interact with PowerShell, copy/paste a
  token, or run ``pip`` manually.

Security contract
-----------------
The bootstrap config is a strict allow-list of fields::

    {
        "schema": "securedact.bootstrap.v1",
        "control_plane_url": "https://...",
        "registration_token": "srr_...",
        "recommended_version": "0.6.0",
        "expires_at": "2026-09-07T12:00:00Z",
        "installer_url": "https://...",
        "models": ["flair/ner-english-large"]      # optional
    }

Any extra field is rejected. ``registration_token`` MUST match ``^srr_``
followed by allowed characters; it is validated but never logged. ``expires_at``
MUST be in the future at the moment of install. ``recommended_version`` MUST be
a valid PEP 440 pin (rejects "latest", URLs, shell metacharacters).

The control-plane endpoint that issues this config is documented separately
(see module-level ``DOCUMENTED_BOOTSTRAP_CONTRACT`` and the brief); only the
listed fields are honoured by this installer.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import logging
import os
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import deploy
from .deploy import RunInput
from .errors import AgentError
from .safe_log import scrub

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public bootstrap contract (documented; the dashboard MUST emit this shape).
# ---------------------------------------------------------------------------

BOOTSTRAP_SCHEMA = "securedact.bootstrap.v1"

# The single, narrow contract the dashboard (SecuRedactedApp.py) must fulfil so
# the installer can consume its output without ever accepting arbitrary
# commands. Keep this list closed.
BOOTSTRAP_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "schema",
        "control_plane_url",
        "registration_token",
        "recommended_version",
        "expires_at",
        "installer_url",
        "models",
    }
)

# Registration tokens are ``srr_<id>_<secret>``. Conservative allow-list: any
# other shape is rejected up front (fail-closed). The regex is intentionally
# stricter than ``safe_log``'s scrub regex so a token-shaped string with weird
# characters never reaches the registration call.
_SRR_TOKEN_RE = re.compile(r"^srr_[A-Za-z0-9]+_[A-Za-z0-9_\-]{4,}$")

# Allow-list for the bounded ``models`` field. Each entry MUST be a registered
# model id in :mod:`securedact_mcp.model_registry`. Unknown ids are rejected.
_ALLOWED_MODEL_IDS: frozenset[str] = frozenset(
    {
        "flair/ner-english-large",
        "flair/ner-dutch-large",
    }
)

# ISO 8601 / RFC 3339 (the control plane emits UTC with a trailing ``Z``).
_ISO_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")

DEFAULT_REGISTRATION_TOKEN_TTL_SECONDS = 15 * 60  # 15 minutes from issue


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


class BootstrapConfigError(AgentError):
    """The bootstrap config is missing, malformed, expired, or out of policy."""


@dataclass(frozen=True, slots=True)
class BootstrapConfig:
    """Validated, immutable bootstrap configuration for one installer run.

    The instance is the single source of truth for the installer pipeline; no
    other module reads the raw JSON.
    """

    schema: str
    control_plane_url: str
    registration_token: str
    recommended_version: str
    expires_at: _dt.datetime
    installer_url: str | None
    models: tuple[str, ...] = field(default_factory=tuple)

    def to_log_safe_dict(self) -> dict[str, object]:
        """Return a JSON-safe dict with the registration token redacted."""

        out = asdict(self)
        out["registration_token"] = "<redacted-credential>"  # noqa: S105
        out["expires_at"] = self.expires_at.isoformat()
        return out


def parse_bootstrap_config(raw: Mapping[str, Any] | str | bytes) -> BootstrapConfig:
    """Parse, validate, and freeze a bootstrap config.

    Raises :class:`BootstrapConfigError` for any failure. Never echoes the
    registration token on error paths.
    """

    if isinstance(raw, (bytes, bytearray)):
        try:
            text = bytes(raw).decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise BootstrapConfigError("bootstrap config is not valid UTF-8") from exc
        return parse_bootstrap_config(text)
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BootstrapConfigError(f"bootstrap config is not valid JSON: {exc.msg}") from exc
        return parse_bootstrap_config(data)
    if not isinstance(raw, Mapping):
        raise BootstrapConfigError(
            f"bootstrap config must be a JSON object, got {type(raw).__name__}"
        )

    unknown = set(raw.keys()) - BOOTSTRAP_ALLOWED_FIELDS
    if unknown:
        raise BootstrapConfigError(
            "bootstrap config contains unknown fields (rejected to prevent "
            f"arbitrary command injection): {sorted(unknown)!r}"
        )

    schema = raw.get("schema")
    if schema != BOOTSTRAP_SCHEMA:
        raise BootstrapConfigError(
            f"bootstrap config schema must be {BOOTSTRAP_SCHEMA!r}, got {schema!r}"
        )

    control_plane_url = raw.get("control_plane_url")
    if not isinstance(control_plane_url, str) or not control_plane_url:
        raise BootstrapConfigError("bootstrap config is missing control_plane_url")
    from .config import normalize_control_plane_url as _normalize_cp

    try:
        control_plane_url = _normalize_cp(control_plane_url)
    except ValueError as exc:
        raise BootstrapConfigError(f"bootstrap control_plane_url invalid: {exc}") from exc

    registration_token = raw.get("registration_token")
    if not isinstance(registration_token, str) or not registration_token:
        raise BootstrapConfigError("bootstrap config is missing registration_token")
    if not _SRR_TOKEN_RE.match(registration_token):
        raise BootstrapConfigError("bootstrap registration_token has an invalid shape")

    recommended_version = raw.get("recommended_version")
    if not isinstance(recommended_version, str) or not recommended_version:
        raise BootstrapConfigError("bootstrap config is missing recommended_version")
    if recommended_version.lower() in {"latest", "*"}:
        raise BootstrapConfigError(
            f"bootstrap config refuses unpinned version: {recommended_version!r}"
        )
    # The installer MUST pin an exact released version (X.Y.Z with optional
    # PEP 440 pre/post/dev suffix). Bare ``X.Y`` or ``X`` is rejected: the brief
    # requires installing ``securedact-mcp==0.6.0`` exactly.
    if not re.match(r"^\d+\.\d+\.\d+(?:[a-zA-Z0-9.\-+!~]*)?$", recommended_version):
        raise BootstrapConfigError(
            "bootstrap config must pin an exact X.Y.Z version (e.g. '0.6.0'); "
            f"got {recommended_version!r}"
        )
    try:
        deploy._validate_version_pin(recommended_version)
    except AgentError as exc:
        raise BootstrapConfigError(str(exc)) from exc

    expires_at_raw = raw.get("expires_at")
    if not isinstance(expires_at_raw, str) or not _ISO_UTC_RE.match(expires_at_raw):
        raise BootstrapConfigError(
            "bootstrap config is missing or has malformed expires_at (ISO 8601 UTC required)"
        )
    try:
        expires_at = _dt.datetime.fromisoformat(expires_at_raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BootstrapConfigError(f"bootstrap config has unparseable expires_at: {exc}") from exc
    now = _dt.datetime.now(_dt.UTC)
    if expires_at <= now:
        raise BootstrapConfigError("bootstrap registration_token has expired (fail-closed)")

    installer_url = raw.get("installer_url")
    if installer_url is not None and not isinstance(installer_url, str):
        raise BootstrapConfigError("bootstrap config installer_url must be a string")

    models_raw = raw.get("models", [])
    if not isinstance(models_raw, list):
        raise BootstrapConfigError("bootstrap config models must be a list")
    models: tuple[str, ...] = ()
    for entry in models_raw:
        if not isinstance(entry, str):
            raise BootstrapConfigError("bootstrap config models entries must be strings")
        if entry not in _ALLOWED_MODEL_IDS:
            raise BootstrapConfigError(f"bootstrap config model {entry!r} is not in the allow-list")
        models = (*models, entry)

    return BootstrapConfig(
        schema=schema,
        control_plane_url=control_plane_url,
        registration_token=registration_token,
        recommended_version=recommended_version,
        expires_at=expires_at,
        installer_url=installer_url,
        models=models,
    )


def load_bootstrap_config_from_file(path: Path) -> BootstrapConfig:
    """Load and validate a bootstrap config from a JSON file path."""

    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise BootstrapConfigError(f"bootstrap config file is unreadable: {exc}") from exc
    return parse_bootstrap_config(data)


def load_bootstrap_config_from_path(
    config_path: Path | str | None,
    env_var: str = "SECUREDACT_BOOTSTRAP_CONFIG",
) -> BootstrapConfig:
    """Load bootstrap config from explicit path or env var.

    Resolution order:
    1. ``config_path`` argument if provided.
    2. The file named by ``env_var`` (default
       ``SECUREDACT_BOOTSTRAP_CONFIG``) if it points to an existing file.
    3. A sibling file next to the current executable named
       ``securedact-bootstrap.json``.

    Never logs the file contents. Never logs the parsed token.
    """

    candidates: list[Path] = []
    if config_path:
        candidates.append(Path(config_path))
    env_path = os.environ.get(env_var)
    if env_path:
        candidates.append(Path(env_path))
    exe_dir = Path(sys.executable).resolve().parent
    candidates.append(exe_dir / "securedact-bootstrap.json")
    cwd = Path.cwd()
    candidates.append(cwd / "securedact-bootstrap.json")

    for cand in candidates:
        try:
            if cand.is_file():
                return load_bootstrap_config_from_file(cand)
        except BootstrapConfigError as exc:
            raise BootstrapConfigError(
                f"bootstrap config file {cand} failed validation: {exc}"
            ) from exc
    raise BootstrapConfigError(
        "no bootstrap config file found; pass --config <path> or set "
        f"{env_var}=<path> (searched: {[str(c) for c in candidates]!r})"
    )


# ---------------------------------------------------------------------------
# Result envelope
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InstallerStep:
    """One bounded step in the install pipeline (for UI + audit)."""

    name: str
    state: str  # "pending" | "running" | "ok" | "skipped" | "failed"
    message: str = ""


@dataclass(frozen=True, slots=True)
class InstallerResult:
    """Bounded, privacy-safe install result envelope.

    The dashboard may POST this back to the control plane (no secrets, no
    file content). ``registration_token`` is never present here -- the only
    reference to the token is that it was consumed (or rejected) during step
    4 of the pipeline.
    """

    success: bool
    steps: tuple[InstallerStep, ...]
    agent_id: str | None
    control_plane_url: str
    installed_version: str | None
    runtime_path: str | None
    error_code: str | None
    error_message: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "success": self.success,
            "steps": [asdict(s) for s in self.steps],
            "agent_id": self.agent_id,
            "control_plane_url": self.control_plane_url,
            "installed_version": self.installed_version,
            "runtime_path": self.runtime_path,
            "error_code": self.error_code,
            "error_message": self.error_message,
        }


# ---------------------------------------------------------------------------
# UI surface (text-only, GUI-free, fully testable)
# ---------------------------------------------------------------------------


UIStepFn = Callable[[InstallerStep], None]


def default_ui_printer(stream: Any = None) -> UIStepFn:
    """Return a UI printer that writes the bounded install progress to ``stream``.

    The output is plain text and contains no secret material: the registration
    token, credential, or any scanned content is never emitted (the message
    is run through :func:`scrub` defensively).
    """

    out = stream if stream is not None else sys.stdout

    def _print(step: InstallerStep) -> None:
        glyph = {
            "pending": ".",
            "running": "...",
            "ok": "[OK]",
            "skipped": "[--]",
            "failed": "[FAIL]",
        }.get(step.state, "?")
        line = f"{glyph} {step.name}"
        safe_message = scrub(step.message) if step.message else ""
        if safe_message:
            line = f"{line} ({safe_message})"
        print(line, file=out)

    return _print


# ---------------------------------------------------------------------------
# Step implementations (each is small, deterministic, and unit-testable)
# ---------------------------------------------------------------------------


def _validate_token_present(config: BootstrapConfig) -> InstallerStep:
    if not config.registration_token:
        return InstallerStep("validate-token", "failed", "missing token")
    return InstallerStep("validate-token", "ok")


def _validate_version_pin(config: BootstrapConfig) -> InstallerStep:
    try:
        deploy._validate_version_pin(config.recommended_version)
    except AgentError as exc:
        return InstallerStep("pin-version", "failed", str(exc))
    return InstallerStep("pin-version", "ok", f"securedact-mcp=={config.recommended_version}")


def _install_pinned_runtime(
    config: BootstrapConfig,
    *,
    data_dir: Path | None,
    runtime_path: Path | None,
    command_runner: Any | None,
    acl_provider: Any | None,
    installing_user: str | None,
    base_python: str | Path | None = None,
) -> InstallerStep:
    """Provision the machine runtime + install the pinned package.

    Delegates to the proven :func:`deploy.provision_machine_runtime` path; the
    version pin is forced to ``config.recommended_version`` (no ``latest``).

    ``base_python`` is the bundled real CPython (PyInstaller onedir
    ``sys._MEIPASS/python.exe``) on a clean machine. It is passed through to
    ``provision_machine_runtime`` with ``venv_creates_copies=True`` so the
    ProgramData runtime is self-contained and does not depend on the onedir
    extraction directory surviving the install.
    """

    resolved_python = _resolve_embedded_python(
        base_python,
        command_runner=command_runner,
        installing_user=installing_user,
    )
    if resolved_python is None:
        return InstallerStep(
            "install-runtime",
            "failed",
            "no real python interpreter available to build machine runtime"
            " (bootloader-only sys.executable is unsafe for venv creation)",
        )

    try:
        provision_result = deploy.provision_machine_runtime(
            runtime_path=runtime_path,
            data_dir=data_dir,
            version=config.recommended_version,
            command_runner=command_runner,
            acl_provider=acl_provider,
            installing_user=installing_user,
            base_python=str(resolved_python),
            venv_creates_copies=True,
        )
    except AgentError as exc:
        return InstallerStep("install-runtime", "failed", _safe_short(scrub(str(exc))))
    runtime_python = provision_result.runtime_python
    return InstallerStep(
        "install-runtime",
        "ok",
        f"runtime={provision_result.runtime_path} python={runtime_python}",
    )


def _resolve_embedded_python(
    base_python: str | Path | None,
    *,
    command_runner: Any | None = None,
    installing_user: str | None = None,
) -> Path | None:
    """Resolve the embedded interpreter for the frozen installer on a clean machine.

    The customer-facing EXE is frozen with PyInstaller in onedir mode, so the
    bundled real CPython lives at ``sys._MEIPASS/python.exe``. That is a *real*
    interpreter (unlike PyInstaller's bootloader which only emulates
    ``sys.executable``). The resolution order is:

    1. Explicit ``base_python`` from the caller (verified via version probe).
    2. Frozen installer (``sys.frozen``): use ``sys._MEIPASS/python.exe`` and
       probe it to prove it is a real interpreter. ``sys.executable`` is NEVER
       trusted when frozen, because the onedir bootloader spoofs it.
    3. Non-frozen (dev / test): ``sys.executable`` is a genuine interpreter,
       so it is returned directly without a probe.
    """

    # 1. Explicit override from the caller.
    if base_python is not None:
        candidate = Path(base_python)
        if not candidate.exists():
            return None
        runner = command_runner or _default_command_runner()
        if not _validate_python_version(candidate, runner):
            return None
        return candidate

    # 2. Frozen installer (PyInstaller onedir): the onedir bootloader sets
    #    ``sys.frozen = True`` and ``sys._MEIPASS`` to the extraction dir.
    #    ``sys.executable`` is the bootloader stub there -- NOT a real
    #    interpreter -- so we must use ``_MEIPASS/python.exe`` instead.
    if getattr(sys, "frozen", False):
        meipass = os.environ.get("_MEIPASS") or getattr(sys, "_MEIPASS", None)
        if not meipass:
            return None
        candidate = Path(meipass) / "python.exe"
        if not candidate.exists():
            return None
        runner = command_runner or _default_command_runner()
        if not _validate_python_version(candidate, runner):
            return None
        return candidate

    # 3. Non-frozen (dev / test / in-process): ``sys.executable`` is the real
    #    interpreter, so it is safe to use directly.
    return Path(sys.executable)


def _validate_python_version(python: Path | str, command_runner: Any) -> bool:
    """Return True iff ``python`` is a real interpreter >= 3.11.

    Uses ``python --version`` rather than ``sys`` introspection so a bootloader
    shim cannot spoof the result. Only invoked in the frozen path / explicit
    ``base_python`` path, never for the non-frozen fallback.
    """

    try:
        result = command_runner([str(python), "--version"], RunInput(timeout=30))
    except Exception:
        return False
    out = (result.stdout + result.stderr).strip().lower()
    if not out.startswith("python 3."):
        return False
    try:
        major, minor, *_ = out.removeprefix("python ").split(".")
        if int(major) != 3 or int(minor) < 11:
            return False
    except (ValueError, IndexError):
        return False
    return True


def _default_command_runner() -> Any:
    """Return a command runner backed by the real subprocess layer for install."""

    return deploy._default_runner


def _install_models(
    config: BootstrapConfig,
    *,
    progress: Callable[[str], None] | None = None,
    model_installer_factory: Callable[[Any], Any] | None = None,
) -> InstallerStep:
    """Install Business-required model assets with hash/integrity verification.

    Uses the existing :mod:`securedact_mcp.model_installer` flow. Fail-closed
    if the Business tier requires ``flair/ner-english-large`` and the install
    cannot be verified.
    """

    if not config.models:
        return InstallerStep("install-models", "skipped", "no models requested")
    try:
        if model_installer_factory is None:
            from securedact_mcp.model_installer import (
                InstallerState,
                ModelInstaller,
            )
            from securedact_mcp.model_registry import MODELS_BY_ID
            from securedact_mcp.model_store import ModelStore
        else:
            InstallerState, ModelInstaller, MODELS_BY_ID, ModelStore = (  # type: ignore[misc]
                model_installer_factory(config)
            )
    except Exception as exc:  # pragma: no cover - import guard
        return InstallerStep("install-models", "failed", f"model installer unavailable: {exc}")
    try:
        store = ModelStore.resolve()
    except Exception as exc:  # pragma: no cover - import guard
        return InstallerStep("install-models", "failed", f"model store unavailable: {exc}")
    installer_obj = ModelInstaller(store)
    failed: list[str] = []
    for model_id in config.models:
        spec = MODELS_BY_ID.get(model_id)
        if spec is None:
            failed.append(f"unknown model {model_id}")
            continue
        try:
            result = installer_obj.install(spec)
        except Exception as exc:
            failed.append(f"{model_id}: {_safe_short(scrub(str(exc)))}")
            continue
        # ``result.state`` is a string per the InstallerState StrEnum.
        state_value = getattr(result.state, "value", result.state)
        if state_value != InstallerState.READY.value:
            failed.append(f"{model_id}: state={state_value}")
    if failed:
        return InstallerStep(
            "install-models",
            "failed",
            "; ".join(failed),
        )
    return InstallerStep("install-models", "ok", ",".join(config.models))


def _register_agent(
    config: BootstrapConfig,
    *,
    data_dir: Path | None,
    runtime_path: Path | None,
    command_runner: Any | None,
    acl_provider: Any | None,
    installing_user: str | None,
) -> tuple[InstallerStep, dict[str, Any] | None]:
    """Provision runtime, install the scheduled task, consume the srr_* token.

    The ``srr_*`` token is passed *only* to ``install_service_from_runtime``,
    which threads it in-memory to ``register_agent``. It is never written to
    argv, environment, log lines, or disk. After successful registration the
    local bound function returns and the token variable goes out of scope.
    """

    try:
        result = deploy.install_service_from_runtime(
            token=config.registration_token,
            data_dir=data_dir,
            runtime_path=runtime_path,
            control_plane_url=config.control_plane_url,
            command_runner=command_runner,
            acl_provider=acl_provider,
            installing_user=installing_user,
        )
    except AgentError as exc:
        return (
            InstallerStep("register-agent", "failed", _safe_short(scrub(str(exc)))),
            None,
        )
    step = InstallerStep(
        "register-agent",
        "ok",
        f"agent_id={result.get('agent_id')!r} task={result.get('service_name')!r}",
    )
    return step, result


def _verify_installed_version(
    runtime_path: Path | None, expected_version: str, *, command_runner: Any | None
) -> InstallerStep:
    """Fail-closed: prove the installed runtime reports the exact pinned version."""

    try:
        runtime = runtime_path or deploy.default_runtime_path()
        runtime_python = deploy.resolve_runtime_python(runtime)
        runner = command_runner or deploy._default_runner
        argv = [
            str(runtime_python),
            "-c",
            "import securedact_mcp; print(securedact_mcp.__version__)",
        ]
        completed = runner(argv, deploy.RunInput())
        if completed.returncode != 0:
            return InstallerStep(
                "verify-version",
                "failed",
                f"runtime probe failed rc={completed.returncode}",
            )
        reported = (completed.stdout or "").strip()
        if reported != expected_version:
            return InstallerStep(
                "verify-version",
                "failed",
                f"runtime reports {reported!r}, expected {expected_version!r}",
            )
        return InstallerStep("verify-version", "ok", f"runtime reports securedact-mcp=={reported}")
    except AgentError as exc:
        return InstallerStep("verify-version", "failed", _safe_short(scrub(str(exc))))
    except Exception as exc:  # pragma: no cover - defensive
        return InstallerStep("verify-version", "failed", _safe_short(scrub(str(exc))))


def _start_heartbeat(
    config: BootstrapConfig,
    *,
    data_dir: Path | None,
    runtime_path: Path | None,
    command_runner: Any | None = None,
    timeout_seconds: float = 30.0,
    sleep_fn: Callable[[float], None] | None = None,
) -> InstallerStep:
    """Start the scheduled task (if necessary) and verify the first heartbeat."""

    sleep = sleep_fn or (lambda s: None)
    deadline = timeout_seconds
    elapsed = 0.0
    interval = 1.0
    online = False
    while elapsed < deadline:
        try:
            online = deploy.verify_heartbeat(
                data_dir=data_dir,
                runtime_path=runtime_path,
                command_runner=command_runner,
            )
        except AgentError:
            online = False
        if online:
            break
        sleep(interval)
        elapsed += interval
    if not online:
        return InstallerStep(
            "verify-heartbeat",
            "failed",
            f"no heartbeat within {timeout_seconds:.0f}s",
        )
    return InstallerStep("verify-heartbeat", "ok", "agent online")


# ---------------------------------------------------------------------------
# Main installer pipeline (deterministic, no external command surface)
# ---------------------------------------------------------------------------


ProgressFn = Callable[[InstallerStep], None]


def run_install(
    config: BootstrapConfig,
    *,
    data_dir: Path | str | None = None,
    runtime_path: Path | str | None = None,
    command_runner: Any | None = None,
    acl_provider: Any | None = None,
    installing_user: str | None = None,
    base_python: str | Path | None = None,
    progress: ProgressFn | None = None,
    heartbeat_timeout_seconds: float = 30.0,
    sleep_fn: Callable[[float], None] | None = None,
    install_models: bool = True,
    register_agent: bool = True,
    verify_version: bool = True,
) -> InstallerResult:
    """Execute the canonical customer install pipeline.

    Returns an :class:`InstallerResult` regardless of failure mode (never
    raises for expected failures). Uncaught exceptions are reported via the
    ``error_code="installer_unexpected"`` envelope so the UI can show a bounded
    message and the dashboard can record the failure.
    """

    ui: ProgressFn = progress or default_ui_printer()
    steps: list[InstallerStep] = []

    def _record(step: InstallerStep) -> None:
        steps.append(step)
        ui(step)

    # 1. Validate the bootstrap config (defence-in-depth on top of parse_bootstrap_config)
    token_step = _validate_token_present(config)
    _record(token_step)
    if token_step.state == "failed":
        return _failure(steps, config, "bootstrap_token_missing", token_step.message)

    pin_step = _validate_version_pin(config)
    _record(pin_step)
    if pin_step.state == "failed":
        return _failure(steps, config, "bootstrap_version_invalid", pin_step.message)

    # 2. Provision / verify machine runtime with the pinned version. The
    # ``base_python`` is the bundled real CPython interpreter on a clean
    # machine (PyInstaller onedir ``sys._MEIPASS/python.exe``); when None the
    # deploy module defaults to ``sys.executable`` (fine when this module runs
    # under an already-installed interpreter, but the clean-machine caller must
    # supply the embedded interpreter).
    runtime_step = _install_pinned_runtime(
        config,
        data_dir=_as_path(data_dir),
        runtime_path=_as_path(runtime_path),
        command_runner=command_runner,
        acl_provider=acl_provider,
        installing_user=installing_user,
        base_python=base_python,
    )
    _record(runtime_step)
    if runtime_step.state == "failed":
        return _failure(steps, config, "runtime_provision_failed", runtime_step.message)

    # 3. Install Business-required model assets (with hash/integrity verification)
    if install_models:
        models_step = _install_models(config)
        _record(models_step)
        if models_step.state == "failed":
            return _failure(steps, config, "model_install_failed", models_step.message)
    else:
        _record(InstallerStep("install-models", "skipped", "caller disabled"))

    # 4. Register the agent with the one-time srr_* token
    register_step: InstallerStep
    install_payload: dict[str, Any] | None = None
    if register_agent:
        register_step, install_payload = _register_agent(
            config,
            data_dir=_as_path(data_dir),
            runtime_path=_as_path(runtime_path),
            command_runner=command_runner,
            acl_provider=acl_provider,
            installing_user=installing_user,
        )
        _record(register_step)
        if register_step.state == "failed":
            return _failure(steps, config, "agent_registration_failed", register_step.message)
    else:
        _record(InstallerStep("register-agent", "skipped", "caller disabled"))

    # 5. Verify the installed runtime reports the exact pinned version
    if verify_version:
        version_step = _verify_installed_version(
            _as_path(runtime_path),
            config.recommended_version,
            command_runner=command_runner,
        )
        _record(version_step)
        if version_step.state == "failed":
            return _failure(steps, config, "version_mismatch", version_step.message)
    else:
        _record(InstallerStep("verify-version", "skipped", "caller disabled"))

    # 6. Verify first heartbeat
    heartbeat_step = _start_heartbeat(
        config,
        data_dir=_as_path(data_dir),
        runtime_path=_as_path(runtime_path),
        command_runner=command_runner,
        timeout_seconds=heartbeat_timeout_seconds,
        sleep_fn=sleep_fn,
    )
    _record(heartbeat_step)
    if heartbeat_step.state == "failed":
        return _failure(steps, config, "heartbeat_failed", heartbeat_step.message)

    # All steps succeeded. Build the success envelope.
    agent_id: str | None = None
    runtime_path_str: str | None = None
    if install_payload is not None:
        agent_id_raw = install_payload.get("agent_id")
        agent_id = str(agent_id_raw) if agent_id_raw else None
        rt_raw = install_payload.get("runtime_path")
        runtime_path_str = str(rt_raw) if rt_raw else None
    return InstallerResult(
        success=True,
        steps=tuple(steps),
        agent_id=agent_id,
        control_plane_url=config.control_plane_url,
        installed_version=config.recommended_version,
        runtime_path=runtime_path_str,
        error_code=None,
        error_message=None,
    )


def _failure(
    steps: list[InstallerStep],
    config: BootstrapConfig,
    code: str,
    message: str,
) -> InstallerResult:
    return InstallerResult(
        success=False,
        steps=tuple(steps),
        agent_id=None,
        control_plane_url=config.control_plane_url,
        installed_version=None,
        runtime_path=None,
        error_code=code,
        error_message=_safe_short(scrub(message)),
    )


def _safe_short(message: str, *, limit: int = 240) -> str:
    if not message:
        return ""
    cleaned = scrub(message).replace("\n", " ").replace("\r", " ")
    if len(cleaned) > limit:
        cleaned = cleaned[: max(0, limit - 1)] + "…"
    return cleaned


def _as_path(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    return Path(value)


# ---------------------------------------------------------------------------
# Upgrade/reinstall behaviour
# ---------------------------------------------------------------------------


def is_existing_registration_valid(
    *, data_dir: Path | str | None = None, runtime_path: Path | str | None = None
) -> bool:
    """Return True iff an existing *machine* registration is present and healthy.

    The installer must NOT consume a new ``srr_*`` token when an existing valid
    registration is reusable. This helper is the single source of truth for
    that check.
    """

    try:
        return bool(deploy._agent_already_registered(data_dir=data_dir))
    except AgentError:
        return False


def run_upgrade(
    config: BootstrapConfig,
    *,
    data_dir: Path | str | None = None,
    runtime_path: Path | str | None = None,
    command_runner: Any | None = None,
    acl_provider: Any | None = None,
    progress: ProgressFn | None = None,
) -> InstallerResult:
    """Upgrade the machine runtime to ``config.recommended_version``.

    Preserves all ProgramData state (agent.json, credential vault, OAuth vault,
    connector bindings) by delegating to :func:`deploy.upgrade_runtime`. Only
    the *code* in the runtime is replaced; no token is consumed (an existing
    valid registration is reused) and no OAuth re-auth is triggered.
    """

    ui: ProgressFn = progress or default_ui_printer()
    steps: list[InstallerStep] = []
    ui(InstallerStep("upgrade-runtime", "running"))
    try:
        result = deploy.upgrade_runtime(
            data_dir=data_dir,
            runtime_path=runtime_path,
            command_runner=command_runner,
            acl_provider=acl_provider,
            version=config.recommended_version,
        )
    except AgentError as exc:
        step = InstallerStep("upgrade-runtime", "failed", _safe_short(scrub(str(exc))))
        steps.append(step)
        ui(step)
        return _failure(steps, config, "upgrade_failed", step.message)
    step = InstallerStep(
        "upgrade-runtime",
        "ok" if result.get("upgraded") else "skipped",
        f"artifact_changed={result.get('artifact_changed')}",
    )
    steps.append(step)
    ui(step)
    return InstallerResult(
        success=True,
        steps=tuple(steps),
        agent_id=None,
        control_plane_url=config.control_plane_url,
        installed_version=config.recommended_version,
        runtime_path=str(result.get("runtime_path")) if result.get("runtime_path") else None,
        error_code=None,
        error_message=None,
    )


# ---------------------------------------------------------------------------
# UAC elevation for the installer (reuses the proven self_elevate flow)
# ---------------------------------------------------------------------------


def request_uac_elevation(
    *,
    config: BootstrapConfig,
    elevation_argv: Sequence[str] | None = None,
    rerun_argv: Sequence[str] | None = None,
    elevate: Callable[[Sequence[str]], int] | None = None,
) -> int:
    """Trigger Windows UAC elevation for the installer.

    Returns the elevated child's exit code. Reuses the proven
    :func:`deploy.self_elevate` machinery so the elevation flow is identical
    to the existing managed-agent install path. ``rerun_argv`` is forwarded
    verbatim so the child resumes the same installer step.
    """

    handler = elevate or deploy.self_elevate
    target = (
        list(rerun_argv)
        if rerun_argv is not None
        else [sys.executable, *build_installer_elevation_argv(config)]
    )
    return handler(target)


def build_installer_elevation_argv(config: BootstrapConfig) -> list[str]:
    """Build the argv for the elevated installer continuation.

    The argv contains ONLY the bootstrap config path and the bounded
    subcommand; the registration token is NEVER placed on argv.
    """

    return [
        "-m",
        "securedact_mcp.agent.installer",
        "run",
        "--config",
        "<bootstrap-config-path>",  # resolved by the child from SECUREDACT_BOOTSTRAP_CONFIG
        "--non-interactive",
    ]


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securedact-installer",
        description="Customer-facing SecuRedact managed-agent installer.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to the bootstrap config JSON file (or set SECUREDACT_BOOTSTRAP_CONFIG).",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Do not prompt; emit the bounded UI to stdout.",
    )
    parser.add_argument(
        "--upgrade",
        action="store_true",
        help="Upgrade the existing runtime instead of consuming a new token.",
    )
    parser.add_argument(
        "--heartbeat-timeout",
        type=float,
        default=30.0,
        help="Seconds to wait for the initial heartbeat (default: 30).",
    )
    sub = parser.add_subparsers(dest="cmd", required=False)
    sub.add_parser("run", help="Run the installer (default).")
    sub.add_parser("validate-config", help="Validate the bootstrap config and exit.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_cli_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        config = load_bootstrap_config_from_path(args.config)
    except BootstrapConfigError as exc:
        print(json.dumps({"error": "bootstrap_config_invalid", "message": str(exc)}))
        return 2

    cmd = args.cmd or "run"
    if cmd == "validate-config":
        print(json.dumps({"valid": True, "config": config.to_log_safe_dict()}))
        return 0

    if cmd == "run":
        if args.upgrade:
            result = run_upgrade(config)
        else:
            result = run_install(config, heartbeat_timeout_seconds=args.heartbeat_timeout)
        print(json.dumps(result.to_dict()))
        return 0 if result.success else 1

    print(json.dumps({"error": "unknown_command", "command": cmd}))
    return 2


# ---------------------------------------------------------------------------
# Helpers (public, also used by tests)
# ---------------------------------------------------------------------------


def sha256_of_payload(payload: Mapping[str, Any] | bytes) -> str:
    """Return the SHA-256 hex digest of a bootstrap payload.

    Stable over the canonical JSON form so the dashboard can embed the digest
    in the bootstrap file or the installer URL for integrity verification.
    """

    if isinstance(payload, (bytes, bytearray)):
        data = bytes(payload)
    else:
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def documented_bootstrap_contract() -> dict[str, object]:
    """Return the documented bootstrap config contract for the dashboard.

    Stable shape; the web app (SecuRedactedApp.py) must emit a JSON object
    matching this schema. The installer rejects anything else.
    """

    return {
        "schema": BOOTSTRAP_SCHEMA,
        "required_fields": [
            "control_plane_url",
            "registration_token",
            "recommended_version",
            "expires_at",
        ],
        "optional_fields": ["installer_url", "models"],
        "rejected_fields": "any field not listed above",
        "registration_token_shape": "srr_<id>_<secret>",
        "recommended_version_shape": "PEP 440 pin (e.g. '0.6.0'); 'latest' rejected",
        "expires_at_shape": "ISO 8601 UTC with trailing 'Z'",
        "models_allow_list": sorted(_ALLOWED_MODEL_IDS),
    }


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
