# SPDX-License-Identifier: Apache-2.0
"""Regession tests for the PyInstaller onedir installer spec.

These guard the specific build assumptions that previously caused the
v0.6.0 Windows build to silently degrade into a one-file EXE with no
bundled ``python.exe``:

* The spec must NOT resolve the bootstrap script relative to the spec
  directory (the ``scripts/scripts/...`` defect).
* The spec must produce an onedir (COLLECT) layout, not a one-file EXE.
* The spec must bundle a genuine ``python.exe`` alongside ``python312.dll``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = REPO_ROOT / "scripts" / "installer.spec"
SCRIPTS_DIR = REPO_ROOT / "scripts"
BOOTSTRAP_PATH = SCRIPTS_DIR / "install_agent_bootstrap.py"


@pytest.fixture(scope="module")
def spec_text() -> str:
    return SPEC_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


def test_bootstrap_entry_point_exists() -> None:
    """The file referenced by Analysis must exist on disk."""
    assert BOOTSTRAP_PATH.is_file(), (
        f"{BOOTSTRAP_PATH} is referenced by installer.spec but does not exist"
    )


def test_spec_does_not_use_relative_scripts_path(spec_text: str) -> None:
    """The scripts/scripts/install_agent_bootstrap.py defect must not recur.

    PyInstaller resolves Analysis(script=...) entries relative to the spec
    file's directory (SPECPATH). A bare ``"scripts/install_agent_bootstrap.py"``
    therefore becomes ``scripts/scripts/...``. The spec must use an absolute
    path derived from SPECPATH instead.
    """
    bad = re.search(r'\[\s*"scripts/install_agent_bootstrap\.py"\s*\]', spec_text)
    assert bad is None, (
        "installer.spec still uses the bare relative path "
        "['scripts/install_agent_bootstrap.py'] which PyInstaller resolves "
        "relative to the spec directory, producing scripts/scripts/..."
    )


def test_spec_script_path_is_absolute(spec_text: str) -> None:
    """The Analysis script argument must be an absolute/variable, not a bare
    repo-root-relative string that PyInstaller would misinterpret."""
    match = re.search(r"BOOTSTRAP_SCRIPT\s*=\s*(.+)", spec_text)
    assert match, "installer.spec must define BOOTSTRAP_SCRIPT"
    expr = match.group(1)
    assert "os.path.join" in expr, (
        f"BOOTSTRAP_SCRIPT must use os.path.join (absolute path), got: {expr!r}"
    )
    assert "install_agent_bootstrap" in expr


def test_spec_pathex_is_absolute(spec_text: str) -> None:
    """pathex must point to <repo>/src, not scripts/src.

    The old defect used ``pathex=["src"]`` which PyInstaller resolved
    relative to the spec directory (scripts/src). The corrected spec must
    use ``os.path.join(REPO_ROOT, "src")`` instead.
    """
    bad = re.search(r'pathex=\[\s*"src"\s*\]', spec_text)
    assert bad is None, (
        "installer.spec still uses pathex=['src'] which PyInstaller resolves "
        "relative to the spec directory (scripts/src)."
    )
    assert re.search(r"os\.path\.join\(REPO_ROOT", spec_text), (
        "pathex must use os.path.join(REPO_ROOT, ...), not a bare 'src'."
    )


def test_spec_pathex_resolves_correctly(spec_text: str) -> None:
    """pathex[0] must compute to <repo>/src, not <repo>/scripts/src."""
    assert "os.path.join(REPO_ROOT" in spec_text, (
        "pathex must use os.path.join(REPO_ROOT, ...), not a bare string."
    )
    repo_root_var = REPO_ROOT
    expected_src = repo_root_var / "src"
    assert expected_src.is_dir(), "src/ directory must exist at repo root"


# ---------------------------------------------------------------------------
# onedir (COLLECT) requirement
# ---------------------------------------------------------------------------


def test_spec_has_collect(spec_text: str) -> None:
    """The spec MUST contain COLLECT — without it PyInstaller emits a
    one-file EXE whose _MEIPASS is a temp dir deleted on exit."""
    assert "COLLECT" in spec_text, (
        "installer.spec must include COLLECT(...) for onedir mode. "
        "Without it, the build produces a one-file EXE and the frozen "
        "bootstrap cannot find python.exe via sys._MEIPASS."
    )


def test_spec_exe_has_no_binaries(spec_text: str) -> None:
    """The EXE constructor must NOT carry a.binaries/a.zipfiles/a.datas.
    Including them causes PyInstaller to append the PKG to the EXE
    (one-file behaviour) even when COLLECT is present, bloating the bootloader
    and breaking the persistent _MEIPASS/python.exe contract."""
    # Find the EXE(...) call and check it doesn't list a.binaries.
    exe_match = re.search(r"exe\s*=\s*EXE\((.*?)\)", spec_text, re.DOTALL)
    assert exe_match, "installer.spec must define exe = EXE(...)"
    exe_body = exe_match.group(1)
    assert "a.binaries" not in exe_body or "a.zipfiles" not in exe_body, (
        "EXE must not include a.binaries/a.zipfiles/a.datas — that causes one-file "
        "PKG embedding. Move them to COLLECT only."
    )


# ---------------------------------------------------------------------------
# Bundled real CPython
# ---------------------------------------------------------------------------


def test_spec_bundles_python_exe(spec_text: str) -> None:
    """The spec must explicitly add the genuine CPython python.exe as a
    binary so it lands in the onedir tree. PyInstaller 6.x onedir does NOT
    emit python.exe automatically."""
    assert "_base_executable" in spec_text, (
        "installer.spec must reference sys._base_executable to locate the "
        "real CPython python.exe for bundling."
    )
    assert "python.exe" in spec_text, "installer.spec must bundle python.exe as a binary."


def test_spec_bundles_python_dll(spec_text: str) -> None:
    """python312.dll must also be bundled alongside python.exe so the
    interpreter can execute independently."""
    assert "python" in spec_text.lower() and "dll" in spec_text.lower(), (
        "installer.spec must bundle python312.dll alongside python.exe."
    )


def test_spec_embedded_binaries_use_dot_dest(spec_text: str) -> None:
    """Embedded binaries must use dest '.' so they land at the root of the
    onedir tree alongside python312.dll in _internal/."""
    # The _embedded_binaries list must append to "." destination.
    assert re.search(r"\(.*?,\s*[\"']\.[\"']\)", spec_text), (
        "installer.spec embedded binaries must use dest '.' for COLLECT placement."
    )


def test_spec_bundles_python_stdlib_zip(spec_text: str) -> None:
    """A ``python312.zip`` (real CPython stdlib archive) must be bundled alongside
    ``python.exe`` so the standalone interpreter can resolve ``venv`` and
    ``ensurepip`` modules — ``base_library.zip`` alone is insufficient because
    it uses PyInstaller's pre-compiled format, not the CPython import search
    protocol."""
    assert "python312.zip" in spec_text, (
        "installer.spec must bundle python312.zip so the standalone "
        "python.exe can find the standard library for venv creation."
    )
