from __future__ import annotations

import hashlib
import os
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .model_registry import (
    IMMUTABLE_REVISION_PATTERN,
    MODELS_BY_LANGUAGE,
    SupportedModel,
    SupportedRuntimeComponent,
    model_for_id,
    runtime_components_for_model,
)

CONFIG_SCHEMA_VERSION = 1
MANIFEST_SCHEMA_VERSION = 2
LEGACY_MANIFEST_SCHEMA_VERSION = 1
MAX_LOCAL_MANIFEST_BYTES = 1_000_000
FORBIDDEN_MODEL_PATH_PARTS = {".venv", "venv", "site-packages", "downloads"}
FORBIDDEN_EXECUTABLE_SUFFIXES = {
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".exe",
    ".js",
    ".msi",
    ".ps1",
    ".py",
    ".scr",
    ".sh",
}


class ModelStorageError(RuntimeError):
    """Base error for managed model configuration or integrity failures."""


class ModelPathError(ModelStorageError):
    """A model storage path crosses a prohibited boundary."""


class ModelIntegrityError(ModelStorageError):
    """An installed model does not match its pinned registry entry."""

    def __init__(
        self,
        message: str,
        failure_code: str = "contextual_model_integrity_failed",
    ) -> None:
        super().__init__(message)
        self.failure_code = failure_code


class ModelConfigurationError(ModelStorageError):
    """The language/model configuration is invalid and cannot be recovered."""


class InstalledFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    size: int = Field(ge=1)
    sha256: str
    component_id: str | None = None
    upstream_repo: str | None = None
    upstream_revision: str | None = None
    storage: str | None = None
    relative_path: str | None = None

    @field_validator("sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        normalized = value.casefold()
        if len(normalized) != 64 or any(
            character not in "0123456789abcdef" for character in normalized
        ):
            raise ValueError("sha256 must be a 64-character hexadecimal digest")
        return normalized


class ModelInstallationManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    model_id: str
    language: str
    upstream_repo: str
    upstream_revision: str
    installed_at: datetime
    securedact_version: str
    entrypoint: str
    files: dict[str, InstalledFile]

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        if self.schema_version not in {
            LEGACY_MANIFEST_SCHEMA_VERSION,
            MANIFEST_SCHEMA_VERSION,
        }:
            raise ValueError("unsupported model installation manifest schema")
        if not IMMUTABLE_REVISION_PATTERN.fullmatch(self.upstream_revision):
            raise ValueError("upstream revision must be an immutable commit")
        if self.installed_at.tzinfo is None or self.installed_at.utcoffset() is None:
            raise ValueError("installed_at must include a timezone")
        if self.entrypoint not in self.files:
            raise ValueError("entrypoint must be present in files")
        if self.schema_version == MANIFEST_SCHEMA_VERSION:
            for record in self.files.values():
                if (
                    record.component_id is None
                    or record.upstream_repo is None
                    or record.upstream_revision is None
                    or record.storage not in {"model", "runtime_cache"}
                    or record.relative_path is None
                ):
                    raise ValueError("versioned file provenance is incomplete")
                if not IMMUTABLE_REVISION_PATTERN.fullmatch(record.upstream_revision):
                    raise ValueError("file revision must be an immutable commit")
        return self


class ModelConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = CONFIG_SCHEMA_VERSION
    enabled_languages: list[str] = Field(default_factory=list)
    active_models: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_configuration(self) -> Self:
        if self.schema_version != CONFIG_SCHEMA_VERSION:
            raise ValueError("unsupported model configuration schema")
        if len(self.enabled_languages) != len(set(self.enabled_languages)):
            raise ValueError("duplicate enabled language")
        if set(self.enabled_languages) != set(self.active_models):
            raise ValueError("enabled languages and active models differ")
        for language, model_id in self.active_models.items():
            registered = MODELS_BY_LANGUAGE.get(language)
            if registered is None or registered.id != model_id:
                raise ValueError("configuration references an unsupported language or model")
        return self


@dataclass(frozen=True, slots=True)
class ModelStoragePaths:
    app_root: Path
    model_root: Path
    staging_root: Path
    rollback_root: Path
    config_path: Path

    @property
    def runtime_cache_root(self) -> Path:
        return self.model_root / ".runtime-cache"

    @classmethod
    def resolve(
        cls,
        *,
        model_dir_override: str | Path | None = None,
        app_data_override: str | Path | None = None,
        cwd: Path | None = None,
    ) -> ModelStoragePaths:
        legacy_environment_root = os.getenv("SECUREDACT_APP_DATA_DIR")
        legacy_app_root = app_data_override or legacy_environment_root
        if legacy_app_root:
            app_root = Path(legacy_app_root).expanduser().resolve()
        elif sys.platform == "win32":
            local_app_data = os.getenv("LOCALAPPDATA")
            if not local_app_data:
                raise ModelPathError("The local application-data directory is unavailable")
            app_root = (Path(local_app_data) / "Securedact" / "MCP").resolve()
        elif sys.platform == "darwin":
            app_root = (
                Path.home() / "Library" / "Application Support" / "Securedact MCP"
            ).resolve()
        else:
            data_home = os.getenv("XDG_DATA_HOME")
            base = Path(data_home).expanduser() if data_home else Path.home() / ".local" / "share"
            app_root = (base / "securedact-mcp").resolve()

        explicit_model_root = model_dir_override or os.getenv("SECUREDACT_MODEL_DIR")
        if explicit_model_root:
            supplied = Path(explicit_model_root).expanduser()
            if not supplied.is_absolute():
                raise ModelPathError("SECUREDACT_MODEL_DIR must be an absolute path")
            model_root = supplied.resolve()
        else:
            model_root = (app_root / "models").resolve()
        _validate_model_root(model_root, cwd=cwd)

        return cls(
            app_root=app_root,
            model_root=model_root,
            staging_root=model_root / ".staging",
            rollback_root=model_root / ".rollback",
            config_path=app_root / "model-config.json",
        )

    def ensure(self) -> None:
        for path in (
            self.app_root,
            self.model_root,
            self.staging_root,
            self.rollback_root,
            self.runtime_cache_root,
            self.runtime_cache_root / "hub",
        ):
            path.mkdir(parents=True, exist_ok=True)
            if is_unsafe_link(path):
                raise ModelPathError("Managed model storage contains a linked directory")


@dataclass(frozen=True, slots=True)
class VerifiedModel:
    model: SupportedModel
    root: Path
    entrypoint: Path
    manifest: ModelInstallationManifest


@dataclass(frozen=True, slots=True)
class ManagedModelState:
    """One integrity-checked view of the managed model configuration."""

    config_found: bool
    configuration: ModelConfiguration | None
    active_models: dict[str, SupportedModel]
    verified_models: dict[str, VerifiedModel]
    failed_languages: tuple[str, ...]
    failure_codes: dict[str, str]


def _validate_model_root(path: Path, *, cwd: Path | None = None) -> None:
    if path == Path(path.anchor):
        raise ModelPathError("Models may not be installed at a filesystem root")
    lowered_parts = {part.casefold() for part in path.parts}
    if lowered_parts & FORBIDDEN_MODEL_PATH_PARTS:
        raise ModelPathError(
            "The configured model directory is not an allowed installation location"
        )

    working_directory = (cwd or Path.cwd()).resolve()
    # This boundary is deliberately exact.  A user's application-data directory
    # is normally a descendant of their home directory, which is also a common
    # process working directory.  Repository containment is checked separately
    # below, so rejecting descendants here would reject the managed store too.
    if path == working_directory:
        raise ModelPathError("Models may not be installed in the current working directory")

    if any((ancestor / ".git").exists() for ancestor in (path, *path.parents)):
        raise ModelPathError("Models may not be installed inside a Git repository")

    temporary_root = Path(tempfile.gettempdir()).resolve()
    try:
        path.relative_to(temporary_root)
    except ValueError:
        pass
    else:
        raise ModelPathError("Models may not be installed in a temporary directory")

    if sys.platform == "win32":
        forbidden_roots = tuple(
            Path(value).resolve()
            for name in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)")
            if (value := os.getenv(name))
        )
    else:
        forbidden_roots = tuple(
            Path(value) for value in ("/bin", "/etc", "/opt", "/sbin", "/usr", "/var")
        )
    for forbidden in forbidden_roots:
        try:
            path.relative_to(forbidden)
        except ValueError:
            continue
        raise ModelPathError("Models may not be installed in a system directory")


def is_unsafe_link(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def package_version() -> str:
    try:
        return version("securedact-mcp")
    except PackageNotFoundError:
        return "0.2.0"


def _version_tuple(value: str) -> tuple[int, int, int]:
    base = value.split("+", 1)[0].split("-", 1)[0]
    parts = base.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        raise ModelIntegrityError("The Securedact or model version is invalid")
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


class ModelStore:
    def __init__(self, paths: ModelStoragePaths | None = None) -> None:
        self.paths = paths or ModelStoragePaths.resolve()

    @classmethod
    def resolve(cls) -> ModelStore:
        """Resolve the single managed store used by setup, diagnostics, and runtime."""

        return cls(ModelStoragePaths.resolve())

    def model_path(self, model: SupportedModel) -> Path:
        root = (self.paths.model_root / model.id).resolve()
        if root.parent != self.paths.model_root.resolve():
            raise ModelPathError("The model identifier escaped managed storage")
        return root

    def read_configuration(self) -> ModelConfiguration | None:
        if not self.paths.config_path.exists():
            return None
        try:
            if is_unsafe_link(self.paths.config_path):
                raise ModelConfigurationError("The model configuration is not a regular file")
            return ModelConfiguration.model_validate_json(self.paths.config_path.read_bytes())
        except ModelConfigurationError:
            raise
        except Exception as exc:
            raise ModelConfigurationError(
                "The model configuration is corrupt. Run `securedact-mcp install` to repair it."
            ) from exc

    def load_or_recover_configuration(self) -> ModelConfiguration | None:
        try:
            return self.read_configuration()
        except ModelConfigurationError as original:
            recovered: dict[str, str] = {}
            for language, model in MODELS_BY_LANGUAGE.items():
                try:
                    self.verify_model(model)
                except ModelIntegrityError:
                    continue
                recovered[language] = model.id
            if not recovered:
                raise original
            configuration = ModelConfiguration(
                enabled_languages=sorted(recovered),
                active_models=recovered,
            )
            self.write_configuration(configuration)
            return configuration

    def load_managed_state(self) -> ManagedModelState:
        """Load active model IDs and verify their installed snapshots once."""

        config_found = self.paths.config_path.is_file()
        configuration = self.load_or_recover_configuration()
        if configuration is None:
            installed = self.installed_models()
            if installed:
                configuration = self.configure_languages(sorted(installed))
                config_found = True

        active_models: dict[str, SupportedModel] = {}
        verified_models: dict[str, VerifiedModel] = {}
        failed_languages: list[str] = []
        failure_codes: dict[str, str] = {}
        if configuration is not None:
            for language, model_id in configuration.active_models.items():
                model = model_for_id(model_id)
                active_models[language] = model
                try:
                    verified_models[language] = self.verify_model(model)
                except ModelIntegrityError as exc:
                    failed_languages.append(language)
                    failure_codes[language] = exc.failure_code

        return ManagedModelState(
            config_found=config_found,
            configuration=configuration,
            active_models=active_models,
            verified_models=verified_models,
            failed_languages=tuple(failed_languages),
            failure_codes=failure_codes,
        )

    def write_configuration(self, configuration: ModelConfiguration) -> None:
        self.paths.ensure()
        temporary = self.paths.config_path.with_name(
            f".{self.paths.config_path.name}.{os.getpid()}.tmp"
        )
        payload = configuration.model_dump_json(indent=2) + "\n"
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.paths.config_path)
        finally:
            temporary.unlink(missing_ok=True)

    def configure_languages(self, languages: list[str]) -> ModelConfiguration:
        unique = sorted(set(languages))
        configuration = ModelConfiguration(
            enabled_languages=unique,
            active_models={language: MODELS_BY_LANGUAGE[language].id for language in unique},
        )
        self.write_configuration(configuration)
        return configuration

    def manifest_for_files(
        self,
        model: SupportedModel,
        files: dict[str, InstalledFile],
        runtime_files: dict[str, InstalledFile] | None = None,
    ) -> ModelInstallationManifest:
        records = {
            relative: InstalledFile(
                size=record.size,
                sha256=record.sha256,
                component_id=model.id,
                upstream_repo=model.upstream_repo,
                upstream_revision=model.upstream_revision,
                storage="model",
                relative_path=relative,
            )
            for relative, record in files.items()
        }
        records.update(runtime_files or {})
        return ModelInstallationManifest(
            schema_version=MANIFEST_SCHEMA_VERSION,
            model_id=model.id,
            language=model.language,
            upstream_repo=model.upstream_repo,
            upstream_revision=model.upstream_revision,
            installed_at=datetime.now(UTC),
            securedact_version=package_version(),
            entrypoint=model.required_files[0],
            files=records,
        )

    def write_manifest(self, root: Path, manifest: ModelInstallationManifest) -> None:
        target = root / "manifest.json"
        temporary = root / ".manifest.json.tmp"
        try:
            temporary.write_text(
                manifest.model_dump_json(indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    def runtime_component_root(self, component: SupportedRuntimeComponent) -> Path:
        return self.paths.runtime_cache_root / "hub" / component.cache_repository_name

    @staticmethod
    def runtime_component_relative_paths(
        component: SupportedRuntimeComponent,
    ) -> dict[str, str]:
        prefix = f"hub/{component.cache_repository_name}"
        paths = {
            f"runtime/{component.id}/refs/main": f"{prefix}/refs/main",
        }
        paths.update(
            {
                f"runtime/{component.id}/{relative}": (
                    f"{prefix}/snapshots/{component.upstream_revision}/{relative}"
                )
                for relative in component.required_files
            }
        )
        return paths

    def runtime_component_records(
        self,
        component: SupportedRuntimeComponent,
        *,
        cache_root: Path | None = None,
    ) -> dict[str, InstalledFile]:
        root = (cache_root or self.paths.runtime_cache_root).resolve()
        expected_paths = self.runtime_component_relative_paths(component)
        records: dict[str, InstalledFile] = {}
        expected_actual = {relative for relative in expected_paths.values()}
        component_root = root / "hub" / component.cache_repository_name
        if not component_root.is_dir() or is_unsafe_link(component_root):
            raise ModelIntegrityError(
                "A required managed runtime component is missing",
                "contextual_model_dependency_missing",
            )
        actual: set[str] = set()
        for path in component_root.rglob("*"):
            if path.is_dir():
                if is_unsafe_link(path):
                    raise ModelIntegrityError("A managed runtime component contains a linked path")
                continue
            if is_unsafe_link(path):
                raise ModelIntegrityError("A managed runtime component contains a linked path")
            if path.suffix.casefold() in FORBIDDEN_EXECUTABLE_SUFFIXES:
                raise ModelIntegrityError("A managed runtime component contains an executable")
            actual.add(path.relative_to(root).as_posix())
        if actual != expected_actual:
            missing = expected_actual - actual
            raise ModelIntegrityError(
                "A managed runtime component layout is incomplete or unexpected",
                (
                    "contextual_model_dependency_missing"
                    if missing
                    else "contextual_model_integrity_failed"
                ),
            )

        for logical, relative in expected_paths.items():
            path = root / relative
            size = path.stat().st_size
            digest = _hash_file(path)
            if relative.endswith("/refs/main"):
                expected_content = component.upstream_revision.encode("ascii")
                if path.read_bytes() != expected_content:
                    raise ModelIntegrityError(
                        "A managed runtime component revision pointer is invalid"
                    )
            else:
                filename = Path(relative).name
                if size != component.expected_sizes[filename]:
                    raise ModelIntegrityError("A managed runtime component size is invalid")
                if digest != component.expected_hashes[filename]:
                    raise ModelIntegrityError("A managed runtime component hash is invalid")
            records[logical] = InstalledFile(
                size=size,
                sha256=digest,
                component_id=component.id,
                upstream_repo=component.upstream_repo,
                upstream_revision=component.upstream_revision,
                storage="runtime_cache",
                relative_path=relative,
            )
        return records

    def primary_checkpoint_records(self, model: SupportedModel) -> dict[str, InstalledFile]:
        """Validate only the pinned checkpoint, permitting repair of legacy manifests."""

        root = self.model_path(model)
        if not root.is_dir() or is_unsafe_link(root):
            raise ModelIntegrityError("The installed model directory is missing or unsafe")
        allowed = set(model.required_files) | set(model.optional_files) | {"manifest.json"}
        actual: set[str] = set()
        for path in root.rglob("*"):
            if path.is_dir():
                if is_unsafe_link(path):
                    raise ModelIntegrityError("The installed model contains a linked directory")
                continue
            relative = path.relative_to(root).as_posix()
            if is_unsafe_link(path) or path.suffix.casefold() in FORBIDDEN_EXECUTABLE_SUFFIXES:
                raise ModelIntegrityError("The installed model contains an unsafe file")
            actual.add(relative)
        if not set(model.required_files).issubset(actual) or not actual.issubset(allowed):
            raise ModelIntegrityError("The installed model checkpoint layout cannot be repaired")
        records: dict[str, InstalledFile] = {}
        for relative in model.required_files:
            path = root / relative
            size = path.stat().st_size
            digest = _hash_file(path)
            if size != model.expected_sizes[relative] or digest != model.expected_hashes[relative]:
                raise ModelIntegrityError("The installed checkpoint does not match pinned metadata")
            records[relative] = InstalledFile(size=size, sha256=digest)
        return records

    def verify_model(self, model: SupportedModel) -> VerifiedModel:
        registered = model_for_id(model.id)
        if registered != model:
            raise ModelIntegrityError("The model does not match the supported registry")
        root = self.model_path(model)
        manifest_path = root / "manifest.json"
        try:
            if not root.is_dir() or is_unsafe_link(root):
                raise ModelIntegrityError("The installed model directory is missing or unsafe")
            if (
                is_unsafe_link(manifest_path)
                or manifest_path.stat().st_size > MAX_LOCAL_MANIFEST_BYTES
            ):
                raise ModelIntegrityError(
                    "The local model manifest is missing or unsafe",
                    "contextual_model_manifest_invalid",
                )
            manifest = ModelInstallationManifest.model_validate_json(manifest_path.read_bytes())
        except ModelIntegrityError:
            raise
        except Exception as exc:
            raise ModelIntegrityError(
                "The local model manifest is corrupt",
                "contextual_model_manifest_invalid",
            ) from exc

        if (
            manifest.model_id != model.id
            or manifest.language != model.language
            or manifest.upstream_repo != model.upstream_repo
            or manifest.upstream_revision != model.upstream_revision
        ):
            raise ModelIntegrityError("The installed model provenance does not match the registry")
        if _version_tuple(package_version()) < _version_tuple(model.minimum_securedact_version):
            raise ModelIntegrityError("The installed model requires a newer Securedact version")
        components = runtime_components_for_model(model)
        if components and manifest.schema_version != MANIFEST_SCHEMA_VERSION:
            raise ModelIntegrityError(
                "The installed model manifest requires managed runtime dependency repair",
                "contextual_model_dependency_missing",
            )

        allowed = set(model.required_files) | set(model.optional_files)
        actual_files: set[str] = set()
        for path in root.rglob("*"):
            if path.is_dir():
                if path != root and is_unsafe_link(path):
                    raise ModelIntegrityError("The installed model contains a linked directory")
                continue
            relative = path.relative_to(root).as_posix()
            if relative == "manifest.json":
                continue
            if is_unsafe_link(path):
                raise ModelIntegrityError("The installed model contains a linked file")
            if path.suffix.casefold() in FORBIDDEN_EXECUTABLE_SUFFIXES:
                raise ModelIntegrityError("The installed model contains an executable file")
            actual_files.add(relative)
        if not set(model.required_files).issubset(actual_files) or not actual_files.issubset(
            allowed
        ):
            raise ModelIntegrityError("The installed model file layout is incomplete or unexpected")
        model_records = {
            logical: record
            for logical, record in manifest.files.items()
            if record.storage in {None, "model"}
        }
        if set(model_records) != actual_files:
            raise ModelIntegrityError("The local model manifest file set is incorrect")

        expected_sizes = model.expected_sizes
        expected_hashes = model.expected_hashes
        for relative in sorted(actual_files):
            path = root / relative
            record = model_records[relative]
            size = path.stat().st_size
            digest = _hash_file(path)
            if size != record.size or digest != record.sha256:
                raise ModelIntegrityError("The installed model failed local integrity validation")
            if relative in expected_sizes and size != expected_sizes[relative]:
                raise ModelIntegrityError("The installed model size differs from upstream metadata")
            if relative in expected_hashes and digest != expected_hashes[relative]:
                raise ModelIntegrityError("The installed model hash differs from upstream metadata")

            if manifest.schema_version == MANIFEST_SCHEMA_VERSION and (
                record.component_id != model.id
                or record.upstream_repo != model.upstream_repo
                or record.upstream_revision != model.upstream_revision
                or record.storage != "model"
                or record.relative_path != relative
            ):
                raise ModelIntegrityError("The installed model file provenance is invalid")

        runtime_records = {
            logical: record
            for logical, record in manifest.files.items()
            if record.storage == "runtime_cache"
        }
        expected_runtime: dict[str, InstalledFile] = {}
        for component in components:
            expected_runtime.update(self.runtime_component_records(component))
        if set(runtime_records) != set(expected_runtime):
            raise ModelIntegrityError("The managed runtime dependency manifest is incomplete")
        for logical, expected in expected_runtime.items():
            if runtime_records[logical] != expected:
                raise ModelIntegrityError("A managed runtime dependency manifest record is invalid")

        entrypoint = root / manifest.entrypoint
        return VerifiedModel(model=model, root=root, entrypoint=entrypoint, manifest=manifest)

    def installed_models(self) -> dict[str, VerifiedModel]:
        installed: dict[str, VerifiedModel] = {}
        for language, model in MODELS_BY_LANGUAGE.items():
            try:
                installed[language] = self.verify_model(model)
            except ModelIntegrityError:
                continue
        return installed

    def remove_model(self, model: SupportedModel) -> bool:
        import shutil

        root = self.model_path(model)
        if not root.exists():
            return False
        if not root.is_dir() or is_unsafe_link(root):
            raise ModelPathError("The managed model location is unsafe")
        shutil.rmtree(root)
        configuration = self.read_configuration()
        if configuration and model.language in configuration.enabled_languages:
            remaining = [
                language
                for language in configuration.enabled_languages
                if language != model.language
            ]
            self.configure_languages(remaining)
        required_by_remaining: set[str] = set()
        for candidate in MODELS_BY_LANGUAGE.values():
            if candidate.id == model.id:
                continue
            try:
                self.primary_checkpoint_records(candidate)
            except ModelIntegrityError:
                continue
            required_by_remaining.update(candidate.runtime_component_ids)
        for component in runtime_components_for_model(model):
            if component.id in required_by_remaining:
                continue
            component_root = self.runtime_component_root(component)
            if component_root.exists():
                if not component_root.is_dir() or is_unsafe_link(component_root):
                    raise ModelPathError("The managed runtime component location is unsafe")
                shutil.rmtree(component_root)
        return True
