# SPDX-License-Identifier: Apache-2.0
# PyInstaller (onedir) spec for the SecuRedact Business managed-agent installer.
#
# WHY ONEDIR (not onefile)
# -----------------------
# A PyInstaller *one-file* build makes `sys.executable` resolve to the bootloader
# EXE, whose temporary `_MEIxxxxxx` extraction dir is deleted when the process
# exits. That breaks two things in the install path:
#
#   1. `deploy.provision_machine_runtime` runs
#      `[sys.executable, "-m", "venv", <runtime>]` to create
#      `C:\ProgramData\Securedact\runtime`. With the onefile bootloader as the
#      "base interpreter" the subprocess re-execs the bootstrap entry script
#      with argv `['-m','venv',...]`, whose argparse rejects `-m` -> SystemExit(2)
#      -> provisioning fails.
#
#   2. Even if one passed a real base, CPython 3.7.2+ `venv` writes *redirector*
#      `python.exe` files (pyvenv.cfg `home=` -> base dir). A one-file boot dir
#      is a temp dir deleted on exit, so the provisioned runtime python.exe
#      would be dead once the installer returned.
#
# A *onedir* build keeps a real `python.exe` at
# `dist/SecuRedactInstaller-0.6.0/_internal/python.exe` (the genuine CPython
# interpreter that PyInstaller bundles), under the `_internal/` directory --
# PyInstaller 6.x onedir colocates bundled CPython and dependencies there. The
# bootstrap sets `base_python = <sys._MEIPASS>/python.exe` (see
# scripts/install_agent_bootstrap.py) and passes it to
# `provision_machine_runtime`. Because `sys._MEIPASS` points at the
# `_internal/` directory (NOT next to the bootloader EXE, which lives in the
# outer onedir root), `<sys._MEIPASS>/python.exe` resolves to that same
# bundled interpreter. In addition we pass `venv_creates_copies=True` so
# CPython copies the interpreter files verbatim (not redirectors), yielding a
# fully self-contained `C:\ProgramData\Securedact\runtime\Scripts/python.exe`
# that survives the installer directory being moved or deleted.
#
# Distribution model: the `dist/SecuRedactInstaller-0.6.0\*` tree is packaged
# into a signed MSIX (preferred) or a signed self-extracting EXE wrapper.
#
# Build (Windows host, Python 3.12, Visual Studio build tools):
#
#     uv run --with pyinstaller python -m PyInstaller \
#         --noconfirm scripts/installer.spec
#
# Output: dist/SecuRedactInstaller-0.6.0/  (onedir tree)
#
# Code-signing (PUBLIC RELEASE only): apply the signing certificate to every
# executable in the onedir tree (the bootstrap EXE and python.exe) with
# signtool:
#
#     SignTool sign /fd SHA256 /tr http://timestamp.digicert.com \
#         /td SHA256 /f <pfx> /p <password> \
#         dist/SecuRedactInstaller-0.6.0/*.exe \
#         dist/SecuRedactInstaller-0.6.0/_internal/*.exe
#
# Internal smoke test: leave the tree unsigned; Windows will allow execution
# for Patrick's manual verification via the onedir layout.
# -*- mode: python ; coding: utf-8 -*-

# Resolve paths explicitly relative to THIS spec file's directory so the build
# is independent of the caller's current working directory. PyInstaller injects
# ``SPECPATH`` at spec-load time and resolves Analysis() script/pathex entries
# relative to it -- so a bare "scripts/install_agent_bootstrap.py" becomes
# SPECPATH/scripts/... (i.e. scripts/scripts/...). Compute absolute paths here.
import os

SPEC_DIR = os.path.abspath(SPECPATH)  # .../scripts
REPO_ROOT = os.path.dirname(SPEC_DIR)  # .../securedact-mcp

# The single bootstrap entry point that PyInstaller freezes (zero-PowerShell
# customer installer launcher).
BOOTSTRAP_SCRIPT = os.path.join(SPEC_DIR, "install_agent_bootstrap.py")

block_cipher = None

# --- Bundled real CPython for the onedir installer ---------------------------
# PyInstaller's onedir mode automatically ships ``python312.dll`` and the
# standard library inside ``_internal/``. It does NOT emit a standalone
# ``python.exe`` that the frozen bootstrap can hand to ``python -m venv``.
# The bootstrap (``install_agent_bootstrap._resolve_embedded_python``) looks
# for ``sys._MEIPASS/python.exe``. We must therefore add the genuine
# CPython interpreter and its DLL explicitly so they land under ``_internal/``
# (PyInstaller 6.x onedir routes COLLECT ``dest="."`` binaries into
# ``_internal/``), which is exactly where ``sys._MEIPASS`` points. This is NOT
# next to the bootloader: the bootloader EXE lives in the outer onedir root
# while the bundled CPython interpreter lives under ``_internal/``.
#
# ``sys._base_executable`` resolves through any ``uv``/wrapper to the real
# CPython 3.12 install (e.g. C:\...Python312\python.exe) -- the same
# interpreter from which PyInstaller collected ``python312.dll``.
import sys as _sys

_python_dir = os.path.dirname(os.path.abspath(_sys._base_executable))
_embedded_binaries = []
_candidate_exe = os.path.join(_python_dir, "python.exe")
if os.path.isfile(_candidate_exe):
    _embedded_binaries.append((_candidate_exe, "."))
_candidate_dll = os.path.join(
    _python_dir, f"python{_sys.version_info.major}{_sys.version_info.minor}.dll"
)
if os.path.isfile(_candidate_dll):
    _embedded_binaries.append((_candidate_dll, "."))

# CPython's ``python.exe`` searches its own directory for ``python312.zip``
# to locate the platform-independent standard library. PyInstaller's
# ``base_library.zip`` is a different format (pre-compiled .pyc) that the
# standalone interpreter cannot read, so ``python -m venv`` fails with
# "Could not find platform independent libraries". We must ship a real
# ``python312.zip`` containing the stdlib (minus site-packages and test,
# which are either redundant with the onedir packages or unnecessary).
import zipfile
from pathlib import Path as _Path

_lib_dir = _Path(_python_dir) / "Lib"
_pyver = f"python{_sys.version_info.major}{_sys.version_info.minor}"
_stdlib_zip = _Path(_python_dir) / f"{_pyver}.zip"
if not _stdlib_zip.is_file() and _lib_dir.is_dir():
    _exclude = {"site-packages", "test", "__pycache__", "asyncio", "tkinter"}
    with zipfile.ZipFile(_stdlib_zip, "w", zipfile.ZIP_DEFLATED) as _zf:
        for _root, _dirs, _files in os.walk(_lib_dir):
            _dirs[:] = [d for d in _dirs if d not in _exclude]
            for _f in _files:
                if _f.endswith(".pyc"):
                    continue
                _src = _Path(_root) / _f
                _arc = _src.relative_to(_Path(_python_dir))
                _zf.write(_src, _arc)
_embedded_binaries.append((str(_stdlib_zip), "."))

hiddenimports = [
    "securedact_mcp",
    "securedact_mcp.agent.installer",
    "securedact_mcp.agent.deploy",
    "securedact_mcp.agent.runtime_bootstrap",
    "securedact_mcp.agent.service_taskscheduler",
    "securedact_mcp.agent.service",
    "securedact_mcp.agent.service_security",
    "securedact_mcp.agent.service_lock",
    "securedact_mcp.agent.credentials",
    "securedact_mcp.agent.config",
    "securedact_mcp.agent.agent_runner",
    "securedact_mcp.agent.cli",
    "securedact_mcp.agent.errors",
    "securedact_mcp.agent.safe_log",
    "securedact_mcp.agent.client",
    "securedact_mcp.agent.capabilities",
    "securedact_mcp.agent.connectors",
    "securedact_mcp.agent.executor",
    "securedact_mcp.agent.policy",
    "securedact_mcp.agent.provider_google",
    "securedact_mcp.agent.provider_microsoft",
    "securedact_mcp.agent.state",
    "securedact_mcp.agent.transport",
    "securedact_mcp.agent.entitlement",
    "securedact_mcp.model_installer",
    "securedact_mcp.model_registry",
    "securedact_mcp.model_store",
    "securedact_mcp.model_verifier_client",
    # ensurepip wheels: the provisioned venv uses `python -m venv` (no
    # --without-pip), so ensurepip's bundled wheels MUST be shipped. We keep
    # ensurepip and pip ON (not in excludes) for that reason.
    "ensurepip",
    "pip",
]

a = Analysis(
    [BOOTSTRAP_SCRIPT],
    pathex=[os.path.join(REPO_ROOT, "src")],
    binaries=_embedded_binaries,
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Trim what we don't need in the install-time bundle; the managed
        # agent runtime re-resolves any of these on demand.
        "tkinter",
        "test",
        "unittest",
        "pydoc",
        "doctest",
        # --- Heavy ML stacks: lazily imported inside detector functions
        # within securedact_core.detectors.*. The installer bootstrap never
        # executes those code paths — model inference runs in the provisioned
        # ProgramData runtime, not in the frozen installer. PyInstaller's
        # static analysis discovers the lazy imports and would otherwise pull
        # in the entire torch/scipy/sklearn/transformers tree (~1 GB).
        # Excluding a top-level package excludes all submodules automatically.
        "torch",
        "functorch",
        "torchgen",
        "transformers",
        "scipy",
        "sklearn",
        "huggingface_hub",
        "tokenizers",
        "sentencepiece",
        "onnxruntime",
        "onnx",
        "numpy",
        "PIL",
        "matplotlib",
        "networkx",
        "accelerate",
        "gdown",
        "boto3",
        "botocore",
        "google",
        # The managed runtime (provisioned in ProgramData) installs its own
        # copies of these; do not duplicate into the installer.
        "pytest",
        "hypothesis",
        "mypy",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    [],
    name="SecuRedactInstaller",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # shows the bounded progress UI
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,  # sign with signtool post-build (every .exe)
    entitlements_file=None,
)
# onedir (COLLECT) is REQUIRED, not optional: the bootstrap resolves the
# bundled real CPython via ``sys._MEIPASS/python.exe``. In onedir mode
# ``sys._MEIPASS`` is the persistent ``dist/SecuRedactInstaller-0.6.0/_internal/``
# directory, which contains the genuine ``python.exe`` (PyInstaller 6.x onedir
# places bundled CPython + dependencies under ``_internal/``). The EXE above carries only the
# scripts + PYZ as the bootloader; all binaries, zip data, and datas go in
# the COLLECT directory so they remain as real on-disk files (not appended
# into a one-file PKG archive). Without this pattern the build silently
# degrades to one-file behaviour -- the PKG gets appended to SecuRedactInstaller.exe,
# ``python.exe`` is never emitted, and ``_resolve_embedded_python()`` fails-closed.
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="SecuRedactInstaller-0.6.0",
)
