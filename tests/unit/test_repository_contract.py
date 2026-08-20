from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.validate_repo import (  # noqa: E402
    MCP_REGISTRY_PACKAGE_IDENTIFIER,
    MCP_REGISTRY_SERVER_NAME,
    tracked_candidates,
    validate_registry_metadata,
    validate_repository,
)


def test_repository_is_valid() -> None:
    assert validate_repository(ROOT) == []


def test_repository_scan_does_not_read_ignored_agent_state(tmp_path: Path) -> None:
    (tmp_path / ".aider.chat.history.md").write_text("private local history", encoding="utf-8")
    cache = tmp_path / ".aider.tags.cache.v4"
    cache.mkdir()
    (cache / "cache.db").write_bytes(b"local cache")
    agents = tmp_path / ".agents"
    agents.mkdir()
    (agents / "state.md").write_text("local state", encoding="utf-8")

    assert tracked_candidates(tmp_path) == []


def test_package_metadata_and_console_entry_point_match_server() -> None:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)

    assert (ROOT / "src" / "securedact_mcp" / "server.py").exists()
    assert pyproject["project"]["name"] == "securedact-mcp"
    assert pyproject["project"]["scripts"]["securedact-mcp"] == "securedact_mcp.cli:main"
    assert (ROOT / "MODEL_ASSET_LICENSES.json").is_file()


def test_client_json_examples_are_valid_and_generic() -> None:
    for name in ("cursor-mcp.json", "windsurf-mcp.json"):
        content = (ROOT / "examples" / name).read_text(encoding="utf-8")
        configuration = json.loads(content)

        assert "<USERNAME>" in content
        assert "Intel" not in content
        assert configuration["mcpServers"]["securedact"]["args"] == [
            "-m",
            "securedact_mcp",
        ]


def test_desktop_gateway_and_provider_packages_are_absent() -> None:
    relative_paths = {
        path.relative_to(ROOT).as_posix().lower()
        for path in ROOT.rglob("*")
        if ".git" not in path.parts
    }
    assert not any("src-tauri" in path for path in relative_paths)
    assert not any("apps/desktop" in path for path in relative_paths)
    assert not any("securedact_api" in path for path in relative_paths)
    assert not any("securedact_providers" in path for path in relative_paths)


def test_windows_bootstrap_uses_only_local_trusted_commands() -> None:
    script = (ROOT / "scripts" / "install-securedact-mcp.ps1").read_text(encoding="utf-8")
    lowered = script.casefold()
    for forbidden in (
        "executionpolicy",
        "invoke-webrequest",
        "irm ",
        "iex",
        "curl",
        "wget",
        "winget",
        "git-xet",
        "git clone",
        "hf download",
        "-verb runas",
    ):
        assert forbidden not in lowered
    assert "py -3.12" in script
    assert "-m venv" in script
    assert "models verify" in script
    assert "smoke_test_entrypoint.py" in script


def test_normal_model_installer_has_no_shell_or_cli_downloader_dependency() -> None:
    installer = (ROOT / "src" / "securedact_mcp" / "model_installer.py").read_text(encoding="utf-8")
    lowered = installer.casefold()
    assert "snapshot_download" in installer
    for forbidden in (
        "import subprocess",
        "os.system",
        "git clone",
        "git-xet",
        "hf download",
        "invoke-webrequest",
        "curl ",
        "wget ",
    ):
        assert forbidden not in lowered

    with (ROOT / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)
    ml_dependencies = "\n".join(pyproject["project"]["optional-dependencies"]["ml"])
    assert "huggingface-hub" in ml_dependencies
    assert "flair" in ml_dependencies
    assert "torch" in ml_dependencies
    assert "git-xet" not in ml_dependencies


def test_server_json_registry_metadata_matches_package() -> None:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)
    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    package = server["packages"][0]

    assert server["name"] == MCP_REGISTRY_SERVER_NAME
    assert server["version"] == pyproject["project"]["version"]
    assert package["registryType"] == "pypi"
    assert package["identifier"] == MCP_REGISTRY_PACKAGE_IDENTIFIER
    assert package["version"] == pyproject["project"]["version"]
    assert package["transport"] == {"type": "stdio"}


def test_readme_contains_registry_ownership_marker() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    marker = f"<!-- mcp-name: {MCP_REGISTRY_SERVER_NAME} -->"
    assert marker in readme


def _registry_fixture(root: Path, *, version: str, marker: bool) -> None:
    (root / "pyproject.toml").write_text(
        '[project]\nname = "securedact-mcp"\nversion = "0.2.1"\n',
        encoding="utf-8",
    )
    readme = "<!-- mcp-name: io.github.GigantesHJI/securedact-mcp -->\n" if marker else ""
    (root / "README.md").write_text(readme, encoding="utf-8")
    (root / "server.json").write_text(
        json.dumps(
            {
                "name": "io.github.GigantesHJI/securedact-mcp",
                "version": version,
                "packages": [
                    {
                        "registryType": "pypi",
                        "identifier": "securedact-mcp",
                        "version": version,
                        "transport": {"type": "stdio"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_registry_version_drift_is_rejected(tmp_path: Path) -> None:
    _registry_fixture(tmp_path, version="0.2.0", marker=True)

    errors = validate_registry_metadata(tmp_path)

    assert any("version must match" in error for error in errors)


def test_registry_ownership_marker_drift_is_rejected(tmp_path: Path) -> None:
    _registry_fixture(tmp_path, version="0.2.1", marker=False)

    errors = validate_registry_metadata(tmp_path)

    assert any("ownership marker" in error for error in errors)
