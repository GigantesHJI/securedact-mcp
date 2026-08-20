"""Validate the publishable repository boundary without reading ignored user data."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

REQUIRED_FILES = {
    ".editorconfig",
    ".env.example",
    ".gitattributes",
    ".gitleaks.toml",
    ".gitignore",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/security_issue.md",
    ".github/CODEOWNERS",
    ".github/dependabot.yml",
    ".github/pull_request_template.md",
    ".github/actions-lock.yml",
    ".github/workflows/benchmark-scheduled.yml",
    ".github/workflows/ci-essential.yml",
    ".github/workflows/codeql.yml",
    ".github/workflows/real-model-benchmark.yml",
    ".github/workflows/release.yml",
    ".github/workflows/security.yml",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE.md",
    "MANIFEST.in",
    "MODEL_ASSET_LICENSES.json",
    "NOTICE",
    "README.md",
    "SECURITY.md",
    "server.json",
    "docs/architecture.md",
    "docs/benchmarking.md",
    "docs/benchmark-migration.md",
    "docs/ci-troubleshooting.md",
    "docs/compatibility.md",
    "docs/conflict-resolution.md",
    "docs/governance.md",
    "docs/codex.md",
    "docs/cursor.md",
    "docs/installation.md",
    "docs/mcp-tools.md",
    "docs/model-installation.md",
    "docs/privacy-model.md",
    "docs/public-api.md",
    "docs/release.md",
    "docs/releasing.md",
    "docs/restoration-sessions.md",
    "docs/rollback.md",
    "docs/supply-chain.md",
    "docs/testing.md",
    "docs/threat-model.md",
    "docs/troubleshooting.md",
    "docs/upgrading.md",
    "docs/versioning.md",
    "docs/vulnerability-releases.md",
    "docs/windsurf.md",
    "examples/codex-config.toml",
    "examples/cursor-mcp.json",
    "examples/synthetic-test-prompts.md",
    "examples/windsurf-mcp.json",
    "pyproject.toml",
    "uv.lock",
    "requirements-dev.txt",
    "scripts/run_privacy_tests.py",
    "scripts/install-securedact-mcp.ps1",
    "scripts/release_metadata.py",
    "scripts/smoke_test_mcp.py",
    "scripts/validate_dependency_licenses.py",
    "scripts/smoke_test_entrypoint.py",
    "scripts/validate_release_artifacts.py",
    "scripts/validate_repository_size.py",
    "scripts/validate_repo.py",
    "scripts/validate_workflows.py",
    "scripts/verify.py",
    "src/securedact_core/api.py",
    "src/securedact_core/detectors/credentials_detector.py",
    "src/securedact_core/policy_loader.py",
    "src/securedact_core/production.py",
    "src/securedact_core/restoration.py",
    "src/securedact_eval/cli.py",
    "src/securedact_eval/metrics.py",
    "src/securedact_eval/performance.py",
    "src/securedact_eval/quality.py",
    "src/securedact_mcp/runtime_lifecycle.py",
    "tests/integration/test_managed_stdio_subprocess.py",
    "tests/privacy_corpus/nl/mcp_email_regression.json",
    "tests/unit/test_email_detector.py",
    "tests/unit/test_production_detector_stack.py",
    "tests/unit/test_runtime_lifecycle.py",
    "benchmarks/baselines/quality-deterministic.json",
    "benchmarks/README.md",
    "benchmarks/fixtures/smoke/manifest.json",
    "benchmarks/generators/profiles.yml",
    "benchmarks/registry/sources.yml",
    "benchmarks/corpora/manifest.json",
    "benchmarks/thresholds.json",
    "integrations/codex/README.md",
    "integrations/cursor/README.md",
    "integrations/windsurf/README.md",
}

FORBIDDEN_PATH_PARTS = {
    "apps/desktop",
    "securedact_api",
    "securedact_providers",
    "src-tauri",
    "node_modules",
    "safe-copies",
    "safe-copy-output",
    "placeholder-mappings",
}

FORBIDDEN_SUFFIXES = {
    ".bin",
    ".ckpt",
    ".db",
    ".egg",
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
    ".whl",
    ".zip",
}

TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".example",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

SECRET_PATTERNS = {
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "generic private key": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "OpenAI-style live key": re.compile(r"\bsk-(?!test-)[A-Za-z0-9_-]{20,}\b"),
}

EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
ALLOWED_EMAIL_DOMAINS = {
    "example.co.uk",
    "example.com",
    "example.net",
    "example.org",
    "example.test",
    "securedact.com",
}
MARKDOWN_LINK_PATTERN = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
WINDOWS_USER_PATH_PATTERN = re.compile(r"C:\\Users\\(?!<USERNAME>\\)[^\\\s]+\\", re.IGNORECASE)
MAX_FILE_SIZE = 5 * 1024 * 1024
MCP_REGISTRY_SERVER_NAME = "io.github.GigantesHJI/securedact-mcp"
MCP_REGISTRY_PACKAGE_IDENTIFIER = "securedact-mcp"


def tracked_candidates(root: Path) -> list[Path]:
    """Return repository files while excluding Git metadata and ignored-style output."""
    excluded_directories = {
        ".git",
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tmp",
        ".venv",
        ".verify-venv",
        ".clean-venv",
        "__pycache__",
        "build",
        "dist",
        "htmlcov",
        "logs",
        "models",
        "model-packs",
        "tmp",
        "temp",
    }
    excluded_local_files = {"regex-test.txt"}
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.name not in excluded_local_files
        and not any(
            part in excluded_directories or part == ".agents" or part.startswith(".aider")
            for part in path.relative_to(root).parts
        )
    )


def validate_markdown_links(root: Path, files: list[Path]) -> list[str]:
    errors: list[str] = []
    for path in files:
        if path.suffix.lower() != ".md":
            continue
        content = path.read_text(encoding="utf-8")
        for raw_target in MARKDOWN_LINK_PATTERN.findall(content):
            target = raw_target.strip().split("#", 1)[0]
            if not target or "://" in target or target.startswith(("mailto:", "#")):
                continue
            resolved = (path.parent / target).resolve()
            try:
                resolved.relative_to(root.resolve())
            except ValueError:
                errors.append(f"{path.relative_to(root)} links outside the repository: {target}")
                continue
            if not resolved.exists():
                errors.append(f"{path.relative_to(root)} has a broken link: {target}")
    return errors


def validate_workflow_pins(root: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted((root / ".github" / "workflows").glob("*.yml")):
        content = path.read_text(encoding="utf-8")
        for action in re.findall(r"^\s*-\s+uses:\s*([^\s#]+)", content, re.MULTILINE):
            if action.startswith("./"):
                continue
            _separator, marker, revision = action.rpartition("@")
            if not marker or not re.fullmatch(r"[0-9a-f]{40}", revision):
                errors.append(
                    f"workflow action is not pinned to a full commit SHA: {path.name}:{action}"
                )
        if not re.search(r"^permissions:\s*$", content, re.MULTILINE):
            errors.append(f"workflow has no explicit top-level permissions: {path.name}")
    return errors


def validate_registry_metadata(root: Path) -> list[str]:
    """Pin server.json and the README ownership marker to the package version."""
    errors: list[str] = []
    server_path = root / "server.json"
    if not server_path.is_file():
        return errors
    try:
        server = json.loads(server_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        return [f"invalid JSON in server.json: {error}"]
    if not isinstance(server, dict):
        return ["server.json must contain a JSON object"]

    pyproject_path = root / "pyproject.toml"
    pyproject: dict[str, object] = {}
    if pyproject_path.is_file():
        with pyproject_path.open("rb") as handle:
            pyproject = tomllib.load(handle)
    project = pyproject.get("project")
    package_version = str(project.get("version", "")) if isinstance(project, dict) else ""

    if server.get("name") != MCP_REGISTRY_SERVER_NAME:
        errors.append(f"server.json name must be {MCP_REGISTRY_SERVER_NAME}")
    if server.get("version") != package_version:
        errors.append(f"server.json version must match the package version ({package_version})")

    packages = server.get("packages")
    if not isinstance(packages, list) or not packages:
        errors.append("server.json must declare at least one package")
    else:
        package = packages[0]
        if not isinstance(package, dict):
            errors.append("server.json packages[0] must be an object")
        else:
            if package.get("registryType") != "pypi":
                errors.append("server.json package registryType must be pypi")
            if package.get("identifier") != MCP_REGISTRY_PACKAGE_IDENTIFIER:
                errors.append(
                    f"server.json package identifier must be {MCP_REGISTRY_PACKAGE_IDENTIFIER}"
                )
            if package.get("version") != package_version:
                errors.append(
                    f"server.json package version must match the package version "
                    f"({package_version})"
                )
            transport = package.get("transport")
            if not isinstance(transport, dict) or transport.get("type") != "stdio":
                errors.append("server.json package transport must be stdio")

    readme_path = root / "README.md"
    readme = readme_path.read_text(encoding="utf-8") if readme_path.is_file() else ""
    marker = f"<!-- mcp-name: {MCP_REGISTRY_SERVER_NAME} -->"
    if marker not in readme:
        errors.append(f"README is missing the registry ownership marker: {marker}")
    return errors


def validate_repository(root: Path, *, require_implementation: bool = False) -> list[str]:
    errors: list[str] = []
    files = tracked_candidates(root)
    relative_files = {path.relative_to(root).as_posix() for path in files}

    missing = sorted(REQUIRED_FILES - relative_files)
    errors.extend(f"missing required file: {path}" for path in missing)
    errors.extend(validate_workflow_pins(root))

    for path in files:
        relative = path.relative_to(root).as_posix()
        lowered = relative.lower()
        if any(part in lowered for part in FORBIDDEN_PATH_PARTS):
            errors.append(f"forbidden repository path: {relative}")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            errors.append(f"forbidden artifact type: {relative}")
        if path.stat().st_size > MAX_FILE_SIZE:
            errors.append(f"file exceeds 5 MiB repository limit: {relative}")

        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"text-like file is not UTF-8: {relative}")
            continue

        if WINDOWS_USER_PATH_PATTERN.search(content):
            errors.append(f"personal Windows path found: {relative}")

        synthetic_fixture = relative.startswith(
            (
                "tests/",
                "benchmarks/corpora/",
                "benchmarks/fixtures/",
                "examples/synthetic-test-prompts.md",
            )
        )
        if relative != "scripts/validate_repo.py" and not synthetic_fixture:
            for name, pattern in SECRET_PATTERNS.items():
                if pattern.search(content):
                    errors.append(f"possible {name} found: {relative}")

        for domain in EMAIL_PATTERN.findall(content):
            if not synthetic_fixture and domain.casefold() not in ALLOWED_EMAIL_DOMAINS:
                errors.append(f"non-example email address found in {relative}: *.{domain}")

    readme_path = root / "README.md"
    if readme_path.exists():
        readme = readme_path.read_text(encoding="utf-8")
        required_statements = (
            "does not automatically intercept every prompt",
            "does not redistribute these model weights",
            "`prepare_for_external_ai`",
            "`analyze_text`",
            "`redact_text`",
            "`restore_text`",
            "`create_safe_copy`",
        )
        for statement in required_statements:
            if statement not in readme:
                errors.append(f"README is missing required statement: {statement}")

    pyproject_path = root / "pyproject.toml"
    pyproject: dict[str, object] = {}
    if pyproject_path.exists():
        with pyproject_path.open("rb") as handle:
            pyproject = tomllib.load(handle)

    server_path = root / "src" / "securedact_mcp" / "server.py"
    implementation_present = server_path.exists()
    if require_implementation and not implementation_present:
        errors.append(
            "server implementation is required but src/securedact_mcp/server.py is absent"
        )
    if not implementation_present and ("project" in pyproject or "build-system" in pyproject):
        errors.append("package metadata is present but the MCP implementation is absent")
    if implementation_present:
        server_source = server_path.read_text(encoding="utf-8").casefold()
        lifecycle_path = root / "src" / "securedact_mcp" / "runtime_lifecycle.py"
        runtime_controls = server_source + (
            lifecycle_path.read_text(encoding="utf-8").casefold() if lifecycle_path.exists() else ""
        )
        if "snapshot_download" in server_source or "model_installer" in server_source:
            errors.append("MCP runtime must not invoke the model downloader")
        for required in (
            "initializednotification",
            "contextual_model_initializing",
            "build_production_engine",
            "runtimelifecycle",
        ):
            if required not in runtime_controls:
                errors.append(f"MCP runtime is missing cold-start/privacy control: {required}")
        project = pyproject.get("project")
        if not isinstance(project, dict):
            errors.append("implementation is present but [project] metadata is missing")
        else:
            scripts = project.get("scripts")
            if not isinstance(scripts, dict):
                errors.append("implementation is present but [project.scripts] is missing")
            elif scripts.get("securedact-mcp") != "securedact_mcp.cli:main":
                errors.append("securedact-mcp console entry point is missing or incorrect")
            elif scripts.get("securedact-eval") != "securedact_eval.cli:main":
                errors.append("securedact-eval console entry point is missing or incorrect")
            if project.get("name") != "securedact-mcp":
                errors.append("project name must be securedact-mcp")
            if project.get("license") != "Apache-2.0":
                errors.append("project license expression must be Apache-2.0")
            license_files = project.get("license-files")
            if not isinstance(license_files, list) or not {"LICENSE.md", "NOTICE"}.issubset(
                license_files
            ):
                errors.append("project metadata must package LICENSE.md and NOTICE")
            dependencies = project.get("dependencies")
            if not isinstance(dependencies, list):
                errors.append("runtime dependencies are missing")
            elif any(
                forbidden in str(dependency).casefold()
                for dependency in dependencies
                for forbidden in ("fastapi", "httpx", "uvicorn")
            ):
                errors.append("desktop/API/provider dependency found in runtime metadata")
            optional_dependencies = project.get("optional-dependencies")
            ml_dependencies = (
                optional_dependencies.get("ml") if isinstance(optional_dependencies, dict) else None
            )
            if not isinstance(ml_dependencies, list) or not all(
                any(required in str(dependency).casefold() for dependency in ml_dependencies)
                for required in ("flair", "huggingface-hub", "torch")
            ):
                errors.append("ml extra must include Flair, huggingface-hub, and PyTorch")

        registered_tools = set(
            re.findall(
                r"@server\.tool\(\)\s+def\s+([a-z0-9_]+)",
                server_path.read_text(encoding="utf-8"),
            )
        )
        expected_tools = {
            "prepare_for_external_ai",
            "analyze_text",
            "redact_text",
            "restore_text",
            "create_safe_copy",
        }
        if registered_tools != expected_tools:
            errors.append(
                f"registered MCP tools differ from documented contract: {sorted(registered_tools)}"
            )

    production_path = root / "src" / "securedact_core" / "production.py"
    if production_path.exists():
        production = production_path.read_text(encoding="utf-8")
        for required_detector in ('"regex"', '"credentials"', '"contextual_rules"'):
            if required_detector not in production:
                errors.append(
                    f"production factory is missing deterministic detector: {required_detector}"
                )

    email_fixture = root / "tests" / "privacy_corpus" / "nl" / "mcp_email_regression.json"
    if email_fixture.exists():
        fixture = email_fixture.read_text(encoding="utf-8")
        for required in ("Emma de Vries", "emma@example.com", '"type": "email"'):
            if required not in fixture:
                errors.append(f"Dutch MCP email regression fixture is incomplete: {required}")

    registry_path = root / "src" / "securedact_mcp" / "model_registry.py"
    if registry_path.exists():
        registry = registry_path.read_text(encoding="utf-8")
        for repository in (
            "flair/ner-english-large",
            "flair/ner-dutch-large",
            "FacebookAI/xlm-roberta-large",
        ):
            if repository not in registry:
                errors.append(f"model registry is missing official repository: {repository}")
        for moving in ('upstream_revision="main"', 'upstream_revision="master"'):
            if moving in registry:
                errors.append(f"moving model revision found in registry: {moving}")
        revisions = re.findall(r'upstream_revision="([^"]+)"', registry)
        if len(revisions) != 3 or any(
            not re.fullmatch(r"[0-9a-f]{40}", item) for item in revisions
        ):
            errors.append(
                "model registry must contain exactly three immutable model/runtime revisions"
            )
        for required in (
            "config.json",
            "sentencepiece.bpe.model",
            "tokenizer.json",
            "tokenizer_config.json",
        ):
            if required not in registry:
                errors.append(f"runtime dependency registry is missing required file: {required}")

    installer_path = root / "src" / "securedact_mcp" / "model_installer.py"
    if installer_path.exists():
        installer = installer_path.read_text(encoding="utf-8").casefold()
        for forbidden in ("subprocess", "os.system", "popen(", "git clone", "hf download"):
            if forbidden in installer:
                errors.append(f"forbidden downloader mechanism in model installer: {forbidden}")
        for required in (
            "snapshot_download",
            "allow_patterns",
            "token=false",
            "smoke_test",
        ):
            if required not in installer:
                errors.append(f"model installer is missing security control: {required}")
        for deprecated in ("resume_download", "local_dir_use_symlinks"):
            if deprecated in installer:
                errors.append(f"deprecated Hugging Face argument in model installer: {deprecated}")

    verifier_path = root / "src" / "securedact_mcp" / "model_verifier_client.py"
    if verifier_path.exists():
        verifier = verifier_path.read_text(encoding="utf-8")
        for required in ("PYTHONNOUSERSITE", "capture_output=True"):
            if required not in verifier:
                errors.append(f"isolated model verifier is missing control: {required}")
    environment_path = root / "src" / "securedact_mcp" / "runtime_environment.py"
    if environment_path.exists():
        environment_source = environment_path.read_text(encoding="utf-8")
        for required in (
            "HF_HOME",
            "HF_HUB_CACHE",
            "TRANSFORMERS_CACHE",
            "HF_HUB_OFFLINE",
            "TRANSFORMERS_OFFLINE",
        ):
            if required not in environment_source:
                errors.append(f"managed runtime environment is missing control: {required}")

    cli_path = root / "src" / "securedact_mcp" / "cli.py"
    if cli_path.exists():
        cli = cli_path.read_text(encoding="utf-8")
        lowered_cli = cli.casefold()
        for required in (
            "--accept-upstream-terms",
            "awaiting_consent",
            'choices=("english", "dutch", "all", "none")',
        ):
            if required not in lowered_cli:
                errors.append(f"guided installer CLI is missing consent control: {required}")

    bootstrap_path = root / "scripts" / "install-securedact-mcp.ps1"
    if bootstrap_path.exists():
        bootstrap = bootstrap_path.read_text(encoding="utf-8").casefold()
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
            if forbidden in bootstrap:
                errors.append(f"forbidden command in Windows bootstrap: {forbidden}")

    for example in ("examples/cursor-mcp.json", "examples/windsurf-mcp.json"):
        example_path = root / example
        if example_path.exists():
            try:
                json.loads(example_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as error:
                errors.append(f"invalid JSON in {example}: {error}")

    codex_example = root / "examples" / "codex-config.toml"
    if codex_example.exists():
        with codex_example.open("rb") as handle:
            tomllib.load(handle)

    errors.extend(validate_registry_metadata(root))
    errors.extend(validate_markdown_links(root, files))
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the parent of scripts/)",
    )
    parser.add_argument(
        "--require-implementation",
        action="store_true",
        help="fail unless the reviewed server and package metadata are present",
    )
    arguments = parser.parse_args()

    errors = validate_repository(
        arguments.root.resolve(),
        require_implementation=arguments.require_implementation,
    )
    if errors:
        print("Repository validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    state = (
        "standalone-server"
        if (arguments.root / "src" / "securedact_mcp" / "server.py").exists()
        else "missing-implementation"
    )
    print(f"Repository validation passed ({state} state).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
