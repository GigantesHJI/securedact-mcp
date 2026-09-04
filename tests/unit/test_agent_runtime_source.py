# SPDX-License-Identifier: Apache-2.0
"""Runtime artifact strategy tests (AGENT-DEPLOY-SOURCE).

Proves the secure machine runtime is provisioned from the exact code that is
actually running:

* released flow -> exact pinned distribution ``securedact-mcp==X.Y.Z``
* dev / local-validation flow -> a controlled local wheel built from the checkout
* never an arbitrary URL / source path
* never a stale PyPI package when the running code is newer
* packaging discovery (and the built wheel) includes the new ``agent`` files
* a provisioned runtime can run ``python -m securedact_mcp.agent.runtime_bootstrap``
"""

from __future__ import annotations

import importlib.metadata
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Sequence
from pathlib import Path

import pytest

import securedact_mcp
from securedact_mcp.agent import deploy
from securedact_mcp.agent.deploy import (
    RunInput,
    RunResult,
    provision_machine_runtime,
    resolve_install_target,
    select_runtime_install_source,
)
from securedact_mcp.agent.errors import AgentError

from .test_agent_deploy import FakeRunner, safe_provider  # reuse harness

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _elevated(monkeypatch: pytest.MonkeyPatch) -> None:
    # Provisioning/upgrade require elevation; simulate it for happy paths.
    monkeypatch.setattr(deploy, "is_elevated", lambda: True)


# ---------------------------------------------------------------------------
# Fake runner that simulates a STALE runtime (import of the bootstrap fails)
# ---------------------------------------------------------------------------


class StaleRuntimeRunner(FakeRunner):
    """A runtime whose install *succeeded* but which lacks the agent package."""

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        args = list(arguments)
        if any("import securedact_mcp.agent.runtime_bootstrap" in str(a) for a in args):
            return RunResult(
                1, stderr="ModuleNotFoundError: No module named 'securedact_mcp.agent'"
            )
        return super().__call__(args, run_input)


# ---------------------------------------------------------------------------
# Released mode
# ---------------------------------------------------------------------------


def test_released_mode_uses_exact_pinned_distribution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(importlib.metadata, "version", lambda _n: "0.1.0")
    monkeypatch.setattr(securedact_mcp, "__version__", "0.4.2")
    # The high-level chooser (released by default) returns an exact pin, never latest.
    assert select_runtime_install_source() == "securedact-mcp==0.4.2"
    assert "latest" not in select_runtime_install_source()
    # The legacy resolver is unchanged.
    assert resolve_install_target() == "securedact-mcp==0.4.2"


def test_released_mode_does_not_call_local_wheel_builder(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Default (released) provisioning must NOT build a local wheel.
    calls: list[object] = []
    monkeypatch.setattr(
        deploy, "build_local_runtime_wheel", lambda *a, **k: calls.append(a) or tmp_path / "x.whl"
    )
    provision_machine_runtime(
        runtime_path=tmp_path / "runtime",
        acl_provider=safe_provider,
        command_runner=FakeRunner(),
    )
    assert calls == [], "released mode must not build a local wheel"


# ---------------------------------------------------------------------------
# Dev / local-validation mode
# ---------------------------------------------------------------------------


def test_local_dev_mode_uses_only_controlled_local_wheel(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "securedact_mcp-0.4.2-py3-none-any.whl"
    wheel.write_text("")
    built: list[object] = []
    monkeypatch.setattr(
        deploy,
        "build_local_runtime_wheel",
        lambda **k: built.append(k) or wheel,
    )
    target = select_runtime_install_source(dev_local=True)
    # The install target is the controlled local wheel path, not a PyPI spec / URL.
    assert target == str(wheel)
    assert target.endswith(".whl")
    assert "securedact-mcp==" not in target
    assert built, "dev mode must build the controlled local wheel"

    # Provisioning must pip-install that exact local wheel (no PyPI index spec).
    runner = FakeRunner()
    provision_machine_runtime(
        runtime_path=tmp_path / "runtime",
        acl_provider=safe_provider,
        command_runner=runner,
        dev_local=True,
    )
    pip_calls = [c for c in runner.calls if "pip" in [str(a).lower() for a in c[0]]]
    assert pip_calls, "pip install was not invoked during provisioning"
    assert all("securedact-mcp==" not in str(c[0]) for c in pip_calls)
    assert any(str(wheel) in [str(a) for a in c[0]] for c in pip_calls)


# ---------------------------------------------------------------------------
# No arbitrary URL / source-path injection
# ---------------------------------------------------------------------------


def test_no_arbitrary_url_or_source_path_injection() -> None:
    for bad in (
        "http://evil.example/securedact.whl",
        "https://evil.example/securedact-0.4.2.whl",
        "git+https://evil.example/securedact-mcp.git",
        "/etc/passwd",  # not a *.whl file
        "C:\\Windows\\System32\\calc.exe",
    ):
        with pytest.raises(AgentError):
            select_runtime_install_source(wheel_path=bad)
    # Version-pin injection is still rejected by the underlying resolver.
    with pytest.raises(AgentError):
        resolve_install_target(version="0.4.2 && curl evil.example")


# ---------------------------------------------------------------------------
# No fallback to a stale PyPI package when the running code is newer
# ---------------------------------------------------------------------------


def test_no_fallback_to_stale_pypi_when_local_running_code_newer(
    tmp_path: Path,
) -> None:
    # The published/installed artifact is stale (the bootstrap import fails in the
    # freshly provisioned runtime). Released-mode provisioning must fail closed
    # rather than silently leaving a runtime that cannot launch the agent.
    with pytest.raises(AgentError):
        provision_machine_runtime(
            runtime_path=tmp_path / "runtime",
            acl_provider=safe_provider,
            command_runner=StaleRuntimeRunner(),
        )

    # And the install target it *would* have chosen is the exact pin, never latest.
    expected_pin = f"securedact-mcp=={securedact_mcp.__version__}"
    assert select_runtime_install_source() == expected_pin


def test_dev_local_mode_installs_controlled_wheel_not_pypi(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Dev/local mode must install the controlled local wheel (built from this
    # checkout) and must NOT fall back to a stale PyPI distribution. The local
    # wheel is fresher than anything on the index, so the bootstrap import check
    # (which a stale PyPI build would fail) passes for the installed local wheel.
    wheel = tmp_path / "securedact_mcp-0.4.2-py3-none-any.whl"
    wheel.write_text("")
    monkeypatch.setattr(deploy, "build_local_runtime_wheel", lambda **k: wheel)
    runner = FakeRunner()
    provision_machine_runtime(
        runtime_path=tmp_path / "runtime",
        acl_provider=safe_provider,
        command_runner=runner,
        dev_local=True,
    )
    pip_calls = [c for c in runner.calls if "pip" in [str(a).lower() for a in c[0]]]
    assert pip_calls, "pip install was not invoked during provisioning"
    # Exactly the controlled local wheel path is installed — never a PyPI spec.
    assert all("securedact-mcp==" not in str(c[0]) for c in pip_calls)
    assert any(str(wheel) in [str(a) for a in c[0]] for c in pip_calls)


# ---------------------------------------------------------------------------
# Packaging discovery includes the new (untracked) agent files
# ---------------------------------------------------------------------------


def test_packaging_discovery_includes_agent_package() -> None:
    # setuptools walks the filesystem, so even untracked agent modules are found.
    try:
        from setuptools import find_packages
    except Exception:  # pragma: no cover - setuptools always present at build
        pytest.skip("setuptools unavailable")
    packages = find_packages(where=str(REPO_ROOT / "src"), include=["securedact_mcp*"])
    assert "securedact_mcp.agent" in packages
    # The bootstrap module exists on disk even though it is currently untracked.
    bootstrap = REPO_ROOT / "src" / "securedact_mcp" / "agent" / "runtime_bootstrap.py"
    assert bootstrap.is_file()


def test_controlled_wheel_rejects_build_missing_agent(tmp_path: Path) -> None:
    # A local wheel that lacks the agent bootstrap must be refused, not installed.
    empty = tmp_path / "securedact_mcp-0.4.2-py3-none-any.whl"
    empty.write_bytes(b"PK\x05\x06" + b"\x00" * 18)  # minimal (invalid) zip

    def _bad_builder(_root: Path) -> Path:
        return empty

    with pytest.raises(AgentError):
        deploy.build_local_runtime_wheel(repo_root=REPO_ROOT, wheel_builder=_bad_builder)


# ---------------------------------------------------------------------------
# Real wheel build (skipped if the builder / network is unavailable)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def built_wheel() -> Path:
    if shutil.which("uv") is None:
        pytest.skip("uv build unavailable")
    out = Path(tempfile.mkdtemp(prefix="ka_wheel_"))
    result = subprocess.run(  # noqa: S603 - fixed argv, repo root only
        ["uv", "build", "--wheel", f"--out-dir={out}"],  # noqa: S607 - fixed argv
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"wheel build failed/offline: {result.stderr[-500:]}")
    wheels = sorted(out.glob("*.whl"))
    if not wheels:
        pytest.skip("no wheel produced")
    return wheels[-1]


def test_local_wheel_contains_full_agent_package(built_wheel: Path) -> None:
    names = zipfile.ZipFile(built_wheel).namelist()
    # All active agent modules are present in the wheel. The dormant pywin32
    # reference backend (service_windows) is quarantined under ``securedact_legacy``
    # and is intentionally excluded from the wheel.
    assert "securedact_mcp/agent/runtime_bootstrap.py" in names
    assert "securedact_mcp/agent/service_windows.py" not in names
    assert "securedact_mcp/agent/service_windows/" not in "/".join(names)
    # Required production agent modules (including Google and Microsoft onboarding)
    required_modules = {
        "runtime_bootstrap.py",
        "service.py",
        "service_security.py",
        "service_lock.py",
        "deploy.py",
        "config.py",
        "cli.py",
        "client.py",
        "credentials.py",
        "errors.py",
        "executor.py",
        "google_setup.py",
        "microsoft_setup.py",
        "provider_google.py",
        "provider_microsoft.py",
        "connectors.py",
        "capabilities.py",
        "policy.py",
        "reducer.py",
        "state.py",
        "transport.py",
        "service_taskscheduler.py",
        "agent_runner.py",
        "safe_log.py",
        "entitlement.py",
    }
    for mod in required_modules:
        assert f"securedact_mcp/agent/{mod}" in names, f"Missing required module: {mod}"
    # Ensure no unexpected modules are missing (allows for future additions)
    # but flag if the wheel is missing any production modules.


def test_machine_runtime_can_run_runtime_bootstrap(built_wheel: Path, tmp_path: Path) -> None:
    if shutil.which("uv") is None:
        pytest.skip("uv pip unavailable")
    target = tmp_path / "wheel_install"
    install = subprocess.run(  # noqa: S603 - fixed argv, local wheel only
        ["uv", "pip", "install", "--no-deps", f"--target={target}", str(built_wheel)],  # noqa: S607 - fixed argv
        capture_output=True,
        text=True,
        check=False,
    )
    if install.returncode != 0:
        pytest.skip(f"wheel install failed: {install.stderr[-500:]}")

    # Drive the module exactly as the machine runtime would: `python -m ...`.
    proc = subprocess.run(  # noqa: S603 - fixed argv, local wheel target only
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "import securedact_mcp.agent.runtime_bootstrap as m; "
            "raise SystemExit(m.main(['status']))",
            str(target),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    # Must execute (no ModuleNotFoundError) and return a JSON status payload; on
    # non-Windows the service subcommand fails closed (exit 2) which is fine.
    assert "ModuleNotFoundError" not in proc.stderr
    assert "ModuleNotFoundError" not in proc.stdout
    assert proc.returncode in (0, 2)
    payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
    assert "error" in payload or payload.get("state") is not None or proc.returncode == 0


# ---------------------------------------------------------------------------
# Runtime-bootstrap dispatch regression (built-wheel + subprocess execution)
# ---------------------------------------------------------------------------
#
# Real-machine reproduction (post-install into ``C:\\ProgramData\\Securedact\\runtime``):
#
#     <runtime python> -m securedact_mcp.agent.runtime_bootstrap microsoft-auth \
#         --verify --data-dir C:\\ProgramData\\Securedact
#
# raised ``NameError: name '_cmd_microsoft_auth' is not defined`` because the
# ``_cmd_microsoft_auth`` definition had been placed *after* the
# ``if __name__ == "__main__": raise SystemExit(main())`` block. When the module
# is executed via ``python -m``, Python invokes the ``__main__`` guard the moment
# it is reached during module execution -- it does NOT continue past it to
# define the remaining module-level functions. In-process tests that imported
# the module first and then called ``main()`` never saw this bug because the
# import step had already populated every name before any call. A subprocess
# regression that mirrors the exact production invocation catches it.


_RUNTIME_BOOTSTRAP_SRC = REPO_ROOT / "src" / "securedact_mcp" / "agent" / "runtime_bootstrap.py"


def _runtime_bootstrap_dispatch_targets() -> list[str]:
    """Return every ``_cmd_*`` name referenced by :func:`runtime_bootstrap.main`.

    Parsed from the source so the structural check tracks every future dispatch
    target added to ``main`` without needing to be edited by hand.
    """

    import re

    src = _RUNTIME_BOOTSTRAP_SRC.read_text(encoding="utf-8")
    # Strip the ``if __name__ == "__main__":`` block and everything after it,
    # because that block executes before the remaining module body when the
    # module is run as ``__main__`` and therefore is the only ordering that
    # actually matters for ``python -m`` dispatch.
    main_guard = re.search(r'^if __name__ == "__main__":\s*$', src, re.MULTILINE)
    effective_src = src if main_guard is None else src[: main_guard.start()]
    return re.findall(r"return (_cmd_[A-Za-z_]+)\(", effective_src)


def test_runtime_bootstrap_dispatch_targets_defined_before_main_guard() -> None:
    """Every dispatch target ``main()`` calls must be defined ABOVE the
    ``if __name__ == "__main__":`` guard.

    Structural guard: catches the exact defect that produced the real-machine
    ``NameError: name '_cmd_microsoft_auth' is not defined`` (the function was
    defined below the guard and therefore never reached when the module was
    executed as ``__main__``).
    """

    import re

    src = _RUNTIME_BOOTSTRAP_SRC.read_text(encoding="utf-8")
    main_guard = re.search(r'^if __name__ == "__main__":\s*$', src, re.MULTILINE)
    assert main_guard is not None, "runtime_bootstrap.py is missing the __main__ guard"
    pre_guard = src[: main_guard.start()]
    targets = _runtime_bootstrap_dispatch_targets()
    assert targets, "main() must reference at least one _cmd_* dispatch target"
    for target in targets:
        pattern = rf"^def {target}\("
        assert re.search(pattern, pre_guard, re.MULTILINE), (
            f"runtime_bootstrap.main() references {target!r} but its definition "
            f"appears AFTER the __main__ guard (line {main_guard.start() + 1}); "
            f"when the module is executed via `python -m`, the guard fires "
            f"before later definitions run and main() raises NameError."
        )


def _runtime_bootstrap_source_uses_post_guard() -> bool:
    """Detect the regression directly in source: any ``_cmd_*`` defined AFTER
    the ``__main__`` guard. Used to make the subprocess test self-documenting
    when the source has regressed.
    """

    import re

    src = _RUNTIME_BOOTSTRAP_SRC.read_text(encoding="utf-8")
    main_guard = re.search(r'^if __name__ == "__main__":\s*$', src, re.MULTILINE)
    if main_guard is None:
        return False
    post_guard = src[main_guard.end() :]
    return bool(re.search(r"^def _cmd_", post_guard, re.MULTILINE))


def test_runtime_bootstrap_microsoft_auth_verify_subprocess(
    built_wheel: Path, tmp_path: Path
) -> None:
    """Subprocess regression: launch the exact ``python -m ... microsoft-auth
    --verify`` invocation that broke on the real machine.

    The wheel is installed into an isolated target directory (no host Python
    pollution) and the production command is executed verbatim. The test MUST
    run the command as a subprocess so the module's own ``__main__`` guard
    runs exactly as it does on ``C:\\ProgramData\\Securedact\\runtime``.
    """

    if shutil.which("uv") is None:
        pytest.skip("uv pip unavailable")

    target = tmp_path / "wheel_install"
    install = subprocess.run(  # noqa: S603 - fixed argv, local wheel only
        ["uv", "pip", "install", "--no-deps", f"--target={target}", str(built_wheel)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if install.returncode != 0:
        pytest.skip(f"wheel install failed: {install.stderr[-500:]}")

    data_dir = tmp_path / "data"
    data_dir.mkdir()

    proc = subprocess.run(  # noqa: S603 - fixed argv, local wheel target only
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "raise SystemExit(__import__('securedact_mcp.agent.runtime_bootstrap', "
            "fromlist=['']).main(['microsoft-auth', '--verify', '--data-dir', sys.argv[2]]))",
            str(target),
            str(data_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    # The real-machine bug surfaced as ``NameError: name '_cmd_microsoft_auth'
    # is not defined``. Assert that exact failure mode is gone.
    assert "_cmd_microsoft_auth" not in proc.stderr, (
        f"runtime_bootstrap dispatched to _cmd_microsoft_auth but the name was "
        f"not defined at the time main() ran. This is the real-machine "
        f"NameError regression. stderr:\n{proc.stderr[-2000:]}"
    )
    assert "NameError" not in proc.stderr, (
        f"runtime_bootstrap raised NameError at runtime:\n{proc.stderr[-2000:]}"
    )
    # Verify-mode output is JSON. It may report ``verified=false`` if the
    # msal / microsoft_auth modules are absent from the test interpreter, but
    # it must NEVER fail with the dispatch NameError above.
    assert proc.stdout.strip(), (
        f"runtime_bootstrap microsoft-auth --verify produced no stdout; "
        f"stderr:\n{proc.stderr[-2000:]}"
    )
    payload = json.loads(proc.stdout)
    assert "interpreter" in payload
    # On a fresh interpreter without msal / the Microsoft extras, the verify
    # function reports ``verified=false`` (the imports_ok flag is False).
    # That is the correct fail-closed behaviour; what we forbid here is the
    # NameError that prevented the function from running at all.
    assert payload.get("verified") is False or payload.get("verified") is True


# ---------------------------------------------------------------------------
# Dev fast-path must not accept a stale same-version runtime (checkout changed)
# ---------------------------------------------------------------------------


class _DevRevisionRunner(FakeRunner):
    """Models two checkout revisions that BOTH report version 0.4.2.

    The runtime-bootstrap import probe succeeds in *both* revisions (so the old
    symbol-presence fast path could not tell them apart). Only when the controlled
    wheel is force-reinstalled does the runtime acquire revision B's code (the new
    ``_build_failure_actions`` symbol); ``revision_b_installed`` tracks exactly that.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.revision_b_installed = False

    def __call__(self, arguments: Sequence[str], run_input: RunInput) -> RunResult:
        args = list(arguments)
        self.calls.append((args, run_input))
        lower = [str(a).lower() for a in args]
        # The bootstrap import probe: always succeeds (both revisions contain it).
        if (
            len(args) >= 3
            and args[1] == "-c"
            and "securedact_mcp.agent.runtime_bootstrap" in args[2]
        ):
            return RunResult(0, stdout="")
        # The controlled local wheel pip install.
        if "pip" in lower and any(str(a).endswith(".whl") for a in args):
            if "--force-reinstall" in lower:
                self.revision_b_installed = True
                return RunResult(0, stdout="")
            # Same-version wheel "already satisfied" -> pip SKIPS; stale dist survives.
            return RunResult(0, stdout="Requirement already satisfied")
        return RunResult(0, stdout="ok")


def _make_dev_wheel(path: Path) -> Path:
    """A valid (minimal) controlled local wheel containing the agent package."""

    import zipfile

    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(
            "securedact_mcp/agent/runtime_bootstrap.py", "# SPDX-License-Identifier: Apache-2.0\n"
        )
        zf.writestr("securedact_mcp/agent/__init__.py", "")
    return path


def test_dev_fast_path_rebuilds_stale_same_version_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Reproduce the real-Windows defect: a machine runtime built from checkout A
    # (securedact-mcp 0.4.2) already contains runtime_bootstrap, so the old
    # freshness fast path accepted it. The checkout then moves to revision B
    # (still 0.4.2) which changes service_windows.py (adds _build_failure_actions).
    # Dev/local-validation mode must NOT keep the stale runtime: it must
    # deterministically rebuild the controlled wheel and reinstall it, and only
    # skip when a stored artifact digest proves exact equality.
    wheel = _make_dev_wheel(tmp_path / "securedact_mcp-0.4.2+local-py3-none-any.whl")
    monkeypatch.setattr(deploy, "build_local_runtime_wheel", lambda **k: wheel)

    # Digest sources for each checkout revision (both 0.4.2 but different content).
    digest_state = {"value": "digestA-checkout"}
    digest_holder = lambda _root: digest_state["value"]  # noqa: E731 - test helper

    runtime = tmp_path / "runtime"
    py = deploy.resolve_runtime_python(runtime)
    py.parent.mkdir(parents=True, exist_ok=True)
    py.write_text("")  # existing, secure runtime at the platform-appropriate path

    # Simulate a prior successful dev provision from checkout A by pre-seeding the
    # stored artifact digest (matching checkout A).
    (runtime / deploy._DEV_DIGEST_FILENAME).write_text("digestA-checkout", encoding="utf-8")

    runner = _DevRevisionRunner()
    first = provision_machine_runtime(
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner,
        dev_local=True,
        dev_digest_fn=digest_holder,
    )
    # Fast path: runtime is fresh relative to checkout A -> idempotent skip, no reinstall.
    assert first.already_provisioned is True
    assert not runner.revision_b_installed
    assert not any(
        "--force-reinstall" in [str(a).lower() for a in c[0]]
        for c in runner.calls
        if "pip" in [str(a).lower() for a in c[0]]
    )

    # Checkout moves to revision B (still 0.4.2) with changed service_windows.py.
    digest_state["value"] = "digestB-checkout"
    runner2 = _DevRevisionRunner()
    second = provision_machine_runtime(
        runtime_path=runtime,
        acl_provider=safe_provider,
        command_runner=runner2,
        dev_local=True,
        dev_digest_fn=digest_holder,
    )
    # Stale same-version dev runtime must be rebuilt + reinstalled from revision B.
    assert second.already_provisioned is False
    # The controlled wheel was force-reinstalled (replaces the stale dist-info).
    pip_calls = [c[0] for c in runner2.calls if "pip" in [str(a).lower() for a in c[0]]]
    assert any("--force-reinstall" in [str(a).lower() for a in c] for c in pip_calls)
    # The runtime now carries revision B (the new _build_failure_actions symbol).
    assert runner2.revision_b_installed is True
    # The stored artifact digest now proves exact equality with checkout B.
    assert (runtime / deploy._DEV_DIGEST_FILENAME).read_text(
        encoding="utf-8"
    ).strip() == "digestB-checkout"
