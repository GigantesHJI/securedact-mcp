"""Inspect built distributions for required and forbidden repository content."""

from __future__ import annotations

import argparse
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

FORBIDDEN_PARTS = {
    ".env",
    ".git",
    ".cache",
    ".locks",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "apps",
    "build",
    "logs",
    "mappings",
    "model-packs",
    "models",
    "snapshots",
    "blobs",
    "node_modules",
    "safe-copies",
    "src-tauri",
}
FORBIDDEN_NAMES = {"securedact_api", "securedact_providers"}
FORBIDDEN_SUFFIXES = {
    ".bin",
    ".ckpt",
    ".db",
    ".key",
    ".log",
    ".model",
    ".onnx",
    ".p12",
    ".pem",
    ".pfx",
    ".pt",
    ".pth",
    ".safetensors",
    ".sqlite",
    ".sqlite3",
    ".zip",
}
MAX_ARCHIVE_MEMBER_BYTES = 5 * 1024 * 1024


def _validate_member(name: str, size: int) -> list[str]:
    errors: list[str] = []
    path = PurePosixPath(name)
    lowered_parts = {part.casefold() for part in path.parts}
    if path.is_absolute() or ".." in path.parts:
        errors.append(f"unsafe archive path: {name}")
    if lowered_parts & FORBIDDEN_PARTS:
        errors.append(f"forbidden path in archive: {name}")
    if lowered_parts & FORBIDDEN_NAMES:
        errors.append(f"unrelated Securedact package in archive: {name}")
    if any(part.startswith("models--") for part in lowered_parts):
        errors.append(f"Hugging Face model cache in archive: {name}")
    if path.suffix.casefold() in FORBIDDEN_SUFFIXES:
        errors.append(f"forbidden artifact type in archive: {name}")
    if size > MAX_ARCHIVE_MEMBER_BYTES:
        errors.append(f"archive member exceeds 5 MiB: {name}")
    return errors


def inspect_wheel(path: Path) -> list[str]:
    errors: list[str] = []
    names: set[str] = set()
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            names.add(member.filename)
            errors.extend(_validate_member(member.filename, member.file_size))
    required_suffixes = {
        "securedact_mcp/cli.py",
        "securedact_mcp/model_installer.py",
        "securedact_mcp/model_registry.py",
        "securedact_mcp/model_store.py",
        "securedact_mcp/model_verifier.py",
        "securedact_mcp/model_verifier_client.py",
        "securedact_mcp/runtime_environment.py",
        "securedact_mcp/runtime_lifecycle.py",
        "securedact_mcp/server.py",
        "securedact_mcp/__main__.py",
        "securedact_core/engine.py",
        "securedact_core/production.py",
        "securedact_core/detectors/lexicons/special_categories.v1.json",
    }
    for required in required_suffixes:
        if not any(name.endswith(required) for name in names):
            errors.append(f"wheel is missing required content: {required}")
    return errors


def inspect_sdist(path: Path) -> list[str]:
    errors: list[str] = []
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            errors.extend(_validate_member(member.name, member.size))
    return errors


def validate_artifacts(directory: Path) -> list[str]:
    errors: list[str] = []
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1:
        errors.append(f"expected one wheel, found {len(wheels)}")
    if len(sdists) != 1:
        errors.append(f"expected one source distribution, found {len(sdists)}")
    for wheel in wheels:
        errors.extend(inspect_wheel(wheel))
    for sdist in sdists:
        errors.extend(inspect_sdist(sdist))
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path, default=Path("dist"))
    arguments = parser.parse_args()
    errors = validate_artifacts(arguments.directory.resolve())
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Release artifact validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
