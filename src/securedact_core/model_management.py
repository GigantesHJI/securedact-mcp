from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import stat
import threading
import time
import zipfile
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import IO, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .app_paths import SecuredactPaths

SUPPORTED_MANIFEST_SCHEMA = 1
DEFAULT_APP_VERSION = "0.1.1"
DEFAULT_MAX_PACK_BYTES = 6 * 1024 * 1024 * 1024
DEFAULT_MAX_FILE_COUNT = 2_000
MAX_MANIFEST_BYTES = 1_000_000
MODEL_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ModelState(StrEnum):
    MISSING = "missing"
    DISCOVERED = "discovered"
    VALIDATING = "validating"
    INVALID = "invalid"
    INCOMPATIBLE = "incompatible"
    INSTALLING = "installing"
    INSTALLED = "installed"
    LOADING = "loading"
    READY = "ready"
    FAILED = "failed"


class IntegrityStatus(StrEnum):
    UNKNOWN = "unknown"
    VERIFIED = "verified"
    FAILED = "failed"


class ModelInstallStage(StrEnum):
    OPENING_PACK = "OPENING_PACK"
    READING_MANIFEST = "READING_MANIFEST"
    VALIDATING_LAYOUT = "VALIDATING_LAYOUT"
    EXTRACTING = "EXTRACTING"
    VERIFYING_HASHES = "VERIFYING_HASHES"
    INSTALLING = "INSTALLING"
    LOADING_MODEL = "LOADING_MODEL"
    READY = "READY"


class ModelInstallErrorCode(StrEnum):
    FILE_NOT_FOUND = "MODEL_FILE_NOT_FOUND"
    ACCESS_DENIED = "MODEL_ACCESS_DENIED"
    FILE_LOCKED = "MODEL_FILE_LOCKED"
    INVALID_ZIP = "MODEL_INVALID_ZIP"
    MANIFEST_MISSING = "MODEL_MANIFEST_MISSING"
    MANIFEST_INVALID = "MODEL_MANIFEST_INVALID"
    UNSUPPORTED_SCHEMA = "MODEL_UNSUPPORTED_SCHEMA"
    INCOMPATIBLE_VERSION = "MODEL_INCOMPATIBLE_VERSION"
    UNSAFE_PATH = "MODEL_UNSAFE_PATH"
    SYMLINK_NOT_ALLOWED = "MODEL_SYMLINK_NOT_ALLOWED"
    TOO_MANY_FILES = "MODEL_TOO_MANY_FILES"
    PACK_TOO_LARGE = "MODEL_PACK_TOO_LARGE"
    INSUFFICIENT_SPACE = "MODEL_INSUFFICIENT_DISK_SPACE"
    FILE_MISSING = "MODEL_FILE_MISSING"
    UNEXPECTED_FILE = "MODEL_UNEXPECTED_FILE"
    SIZE_MISMATCH = "MODEL_SIZE_MISMATCH"
    HASH_MISMATCH = "MODEL_HASH_MISMATCH"
    ENTRYPOINT_MISSING = "MODEL_ENTRYPOINT_MISSING"
    TOKENIZER_MISSING = "MODEL_TOKENIZER_MISSING"
    STAGING_FAILED = "MODEL_STAGING_FAILED"
    INSTALL_DESTINATION_FAILED = "MODEL_INSTALL_DESTINATION_FAILED"
    ATOMIC_REPLACE_FAILED = "MODEL_ATOMIC_REPLACE_FAILED"
    MODEL_LOAD_FAILED = "MODEL_LOAD_FAILED"
    ALREADY_INSTALLING = "MODEL_ALREADY_INSTALLING"
    CANCELLED = "MODEL_INSTALL_CANCELLED"
    UNKNOWN = "MODEL_INSTALL_UNKNOWN"


MODEL_INSTALL_MESSAGES: dict[ModelInstallErrorCode, str] = {
    ModelInstallErrorCode.FILE_NOT_FOUND: "The selected model pack no longer exists.",
    ModelInstallErrorCode.ACCESS_DENIED: "Windows denied access to the selected model pack or model storage.",
    ModelInstallErrorCode.FILE_LOCKED: "The model pack or destination is currently in use by another application.",
    ModelInstallErrorCode.INVALID_ZIP: "The selected file is not a valid Securedact model ZIP.",
    ModelInstallErrorCode.MANIFEST_MISSING: "The model pack does not contain manifest.json at its root.",
    ModelInstallErrorCode.MANIFEST_INVALID: "The model pack manifest is invalid.",
    ModelInstallErrorCode.UNSUPPORTED_SCHEMA: "This model pack uses an unsupported manifest schema.",
    ModelInstallErrorCode.INCOMPATIBLE_VERSION: "This model pack is incompatible with this Securedact version.",
    ModelInstallErrorCode.UNSAFE_PATH: "The model pack contains an unsafe path.",
    ModelInstallErrorCode.SYMLINK_NOT_ALLOWED: "The model pack contains links or unsupported encrypted entries.",
    ModelInstallErrorCode.TOO_MANY_FILES: "The model pack exceeds configured safety limits because it contains too many files.",
    ModelInstallErrorCode.PACK_TOO_LARGE: "The model pack exceeds configured safety limits for total size.",
    ModelInstallErrorCode.INSUFFICIENT_SPACE: "There is not enough free disk space to install this model pack safely.",
    ModelInstallErrorCode.FILE_MISSING: "A file declared by the manifest is missing.",
    ModelInstallErrorCode.UNEXPECTED_FILE: "The model pack contains a file not declared by the manifest.",
    ModelInstallErrorCode.SIZE_MISMATCH: "A model file does not match the size declared by the manifest.",
    ModelInstallErrorCode.HASH_MISMATCH: "A model file failed SHA-256 integrity validation.",
    ModelInstallErrorCode.ENTRYPOINT_MISSING: "The model entrypoint is missing.",
    ModelInstallErrorCode.TOKENIZER_MISSING: "The model tokenizer files are incomplete.",
    ModelInstallErrorCode.STAGING_FAILED: "Securedact could not create a secure model staging directory.",
    ModelInstallErrorCode.INSTALL_DESTINATION_FAILED: "Securedact could not write to its local model directory.",
    ModelInstallErrorCode.ATOMIC_REPLACE_FAILED: "Securedact could not safely activate the verified model.",
    ModelInstallErrorCode.MODEL_LOAD_FAILED: "The model was installed, but Flair could not load it.",
    ModelInstallErrorCode.ALREADY_INSTALLING: "Another model installation is already in progress.",
    ModelInstallErrorCode.CANCELLED: "Model installation was cancelled safely.",
    ModelInstallErrorCode.UNKNOWN: "The model installation failed safely.",
}


class ModelInstallProgress(BaseModel):
    stage: ModelInstallStage
    percent: float = Field(ge=0, le=100)
    validated_files: int = Field(ge=0)
    total_files: int = Field(ge=0)
    processed_bytes: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    cancellable: bool = True


def validate_model_id(value: str) -> str:
    if not MODEL_ID_PATTERN.fullmatch(value):
        raise ValueError("model_id must contain only safe lowercase identifier characters")
    return value


def validate_relative_pack_path(value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise ValueError("Model file paths must be non-empty POSIX relative paths")
    path = PurePosixPath(value)
    if path.is_absolute() or path.anchor or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("Model file paths must remain inside the model pack")
    if any(":" in part for part in path.parts):
        raise ValueError("Model file paths may not contain drive or stream separators")
    return path.as_posix()


class ModelManifestFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    sha256: str
    size: int = Field(ge=0)

    _safe_path = field_validator("path")(validate_relative_pack_path)

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        normalized = value.lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("sha256 must be a 64-character hexadecimal digest")
        return normalized


class ModelManifestSignature(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: str
    key_id: str
    signature: str


class ModelManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    model_id: str
    display_name: str = Field(min_length=1, max_length=160)
    language: str = Field(min_length=2, max_length=16, pattern=r"^[A-Za-z0-9-]+$")
    model_type: Literal["flair-sequence-tagger"]
    securedact_min_version: str
    securedact_max_version: str | None = None
    created_at: datetime
    files: list[ModelManifestFile] = Field(min_length=1)
    entrypoint: str
    tokenizer_root: str
    signatures: list[ModelManifestSignature] = Field(default_factory=list)

    _safe_model_id = field_validator("model_id")(validate_model_id)
    _safe_entrypoint = field_validator("entrypoint")(validate_relative_pack_path)
    _safe_tokenizer_root = field_validator("tokenizer_root")(validate_relative_pack_path)

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must include a timezone")
        return value

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: int) -> int:
        if value != SUPPORTED_MANIFEST_SCHEMA:
            raise ValueError("Unsupported model manifest schema version")
        return value

    @model_validator(mode="after")
    def validate_file_set(self) -> Self:
        normalized = [item.path.casefold() for item in self.files]
        if len(normalized) != len(set(normalized)):
            raise ValueError("Duplicate model file paths are not allowed")
        declared = set(normalized)
        if self.entrypoint.casefold() not in declared:
            raise ValueError("The model entrypoint must be declared in files")
        if not self.entrypoint.casefold().startswith("model/"):
            raise ValueError("The model entrypoint must be stored below model/")
        if self.tokenizer_root.casefold() != "tokenizer":
            raise ValueError("tokenizer_root must be tokenizer")
        tokenizer_prefix = self.tokenizer_root.casefold().rstrip("/") + "/"
        if not any(path.startswith(tokenizer_prefix) for path in declared):
            raise ValueError("tokenizer_root must contain at least one declared file")
        return self


class ModelStatus(BaseModel):
    state: ModelState
    model_id: str | None = None
    display_name: str | None = None
    language: str | None = None
    model_type: str | None = None
    created_at: datetime | None = None
    integrity: IntegrityStatus = IntegrityStatus.UNKNOWN
    compatible: bool | None = None
    active: bool = False
    required: bool = True
    unsafe_development_mode: bool = False
    development_override: bool = False
    message: str | None = None
    validated_at: datetime | None = None
    diagnostic_code: ModelInstallErrorCode | None = None
    request_id: str | None = None
    progress: ModelInstallProgress | None = None


class ModelInstallResult(BaseModel):
    installed: bool
    replaced: bool = False
    status: ModelStatus


class InstalledModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    root: Path
    manifest: ModelManifest
    entrypoint: Path
    tokenizer_root: Path


class ModelManagementError(RuntimeError):
    def __init__(
        self,
        code: ModelInstallErrorCode | str,
        safe_message: str | None = None,
        *,
        stage: ModelInstallStage | None = None,
        request_id: str | None = None,
    ) -> None:
        legacy_codes = {
            "entrypoint": ModelInstallErrorCode.ENTRYPOINT_MISSING,
            "unsafe_path": ModelInstallErrorCode.UNSAFE_PATH,
            "invalid_manifest": ModelInstallErrorCode.MANIFEST_INVALID,
            "incompatible": ModelInstallErrorCode.INCOMPATIBLE_VERSION,
            "missing": ModelInstallErrorCode.FILE_NOT_FOUND,
            "pack_limits": ModelInstallErrorCode.PACK_TOO_LARGE,
            "file_set": ModelInstallErrorCode.FILE_MISSING,
            "size_mismatch": ModelInstallErrorCode.SIZE_MISMATCH,
            "hash_mismatch": ModelInstallErrorCode.HASH_MISMATCH,
            "model_id_mismatch": ModelInstallErrorCode.MANIFEST_INVALID,
            "staging": ModelInstallErrorCode.STAGING_FAILED,
            "duplicate_path": ModelInstallErrorCode.UNSAFE_PATH,
            "unsafe_archive": ModelInstallErrorCode.SYMLINK_NOT_ALLOWED,
            "archive_size": ModelInstallErrorCode.SIZE_MISMATCH,
            "invalid_archive": ModelInstallErrorCode.INVALID_ZIP,
            "unsafe_source": ModelInstallErrorCode.UNSAFE_PATH,
            "installing": ModelInstallErrorCode.ALREADY_INSTALLING,
            "installation_failed": ModelInstallErrorCode.UNKNOWN,
        }
        try:
            normalized = (
                code
                if isinstance(code, ModelInstallErrorCode)
                else legacy_codes[code]
                if code in legacy_codes
                else ModelInstallErrorCode(code)
            )
        except ValueError:
            normalized = ModelInstallErrorCode.UNKNOWN
        message = safe_message or MODEL_INSTALL_MESSAGES[normalized]
        super().__init__(message)
        self.code = normalized
        self.safe_message = message
        self.stage = stage
        self.request_id = request_id

    def as_detail(self) -> dict[str, str | None]:
        return {
            "code": self.code.value,
            "message": self.safe_message,
            "stage": self.stage.value if self.stage else None,
            "request_id": self.request_id,
        }


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+][A-Za-z0-9.-]+)?", value)
    if not match:
        raise ModelManagementError(
            ModelInstallErrorCode.MANIFEST_INVALID,
            "The model pack contains an invalid version.",
        )
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    return path.is_symlink() or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _hash_stream(stream: IO[bytes]) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _manifest_from_archive(
    archive: zipfile.ZipFile,
    *,
    max_pack_bytes: int = DEFAULT_MAX_PACK_BYTES,
    max_file_count: int = DEFAULT_MAX_FILE_COUNT,
) -> tuple[ModelManifest, list[zipfile.ZipInfo], int]:
    members: list[zipfile.ZipInfo] = []
    names: set[str] = set()
    total_size = 0
    for info in archive.infolist():
        raw_name = info.filename.rstrip("/") if info.is_dir() else info.filename
        try:
            safe_name = validate_relative_pack_path(raw_name)
        except ValueError as exc:
            raise ModelManagementError(ModelInstallErrorCode.UNSAFE_PATH) from exc
        if info.is_dir():
            continue
        key = safe_name.casefold()
        if key in names:
            raise ModelManagementError(
                ModelInstallErrorCode.UNSAFE_PATH,
                "The model archive contains duplicate paths.",
            )
        names.add(key)
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode) or info.flag_bits & 0x1:
            raise ModelManagementError(ModelInstallErrorCode.SYMLINK_NOT_ALLOWED)
        total_size += info.file_size
        members.append(info)
        if len(members) > max_file_count + 1:
            raise ModelManagementError(ModelInstallErrorCode.TOO_MANY_FILES)
        if total_size > max_pack_bytes:
            raise ModelManagementError(ModelInstallErrorCode.PACK_TOO_LARGE)
    try:
        manifest_info = next(
            info for info in members if info.filename.casefold() == "manifest.json"
        )
    except StopIteration as exc:
        raise ModelManagementError(ModelInstallErrorCode.MANIFEST_MISSING) from exc
    if manifest_info.file_size > MAX_MANIFEST_BYTES:
        raise ModelManagementError(ModelInstallErrorCode.MANIFEST_INVALID)
    try:
        raw = archive.read(manifest_info)
        payload = json.loads(raw)
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelManagementError(ModelInstallErrorCode.MANIFEST_INVALID) from exc
    if not isinstance(payload, dict):
        raise ModelManagementError(ModelInstallErrorCode.MANIFEST_INVALID)
    if payload.get("schema_version") != SUPPORTED_MANIFEST_SCHEMA:
        raise ModelManagementError(ModelInstallErrorCode.UNSUPPORTED_SCHEMA)
    try:
        manifest = ModelManifest.model_validate(payload)
    except Exception as exc:
        raise ModelManagementError(ModelInstallErrorCode.MANIFEST_INVALID) from exc
    declared = {item.path.casefold() for item in manifest.files}
    actual = names - {"manifest.json"}
    missing = declared - actual
    unexpected = actual - declared
    if missing:
        raise ModelManagementError(ModelInstallErrorCode.FILE_MISSING)
    if unexpected:
        raise ModelManagementError(ModelInstallErrorCode.UNEXPECTED_FILE)
    return manifest, members, total_size


def verify_model_pack(
    source: str | Path,
    *,
    max_pack_bytes: int = DEFAULT_MAX_PACK_BYTES,
    max_file_count: int = DEFAULT_MAX_FILE_COUNT,
) -> ModelManifest:
    """Stream-verify a release pack with the exact contract used by installation."""
    path = Path(source)
    try:
        if not path.is_file():
            raise ModelManagementError(ModelInstallErrorCode.FILE_NOT_FOUND)
        if path.suffix.casefold() != ".zip":
            raise ModelManagementError(ModelInstallErrorCode.INVALID_ZIP)
        with zipfile.ZipFile(path) as archive:
            manifest, _members, _total = _manifest_from_archive(
                archive,
                max_pack_bytes=max_pack_bytes,
                max_file_count=max_file_count,
            )
            for expected in manifest.files:
                try:
                    info = archive.getinfo(expected.path)
                except KeyError as exc:
                    raise ModelManagementError(ModelInstallErrorCode.FILE_MISSING) from exc
                if info.file_size != expected.size:
                    raise ModelManagementError(ModelInstallErrorCode.SIZE_MISMATCH)
                with archive.open(info) as stream:
                    digest = _hash_stream(stream)
                if not secrets.compare_digest(digest, expected.sha256):
                    raise ModelManagementError(ModelInstallErrorCode.HASH_MISMATCH)
            return manifest
    except ModelManagementError:
        raise
    except PermissionError as exc:
        raise ModelManagementError(ModelInstallErrorCode.ACCESS_DENIED) from exc
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError) as exc:
        raise ModelManagementError(ModelInstallErrorCode.INVALID_ZIP) from exc


class ModelManager:
    """Provider-independent discovery, integrity validation, and atomic installation."""

    def __init__(
        self,
        paths: SecuredactPaths | None = None,
        *,
        app_version: str = DEFAULT_APP_VERSION,
        configured_model_id: str | None = None,
        require_flair: bool = True,
        max_pack_bytes: int = DEFAULT_MAX_PACK_BYTES,
        max_file_count: int = DEFAULT_MAX_FILE_COUNT,
    ) -> None:
        self.paths = paths or SecuredactPaths.resolve()
        self.app_version = app_version
        self.configured_model_id = (
            validate_model_id(configured_model_id) if configured_model_id else None
        )
        self.require_flair = require_flair
        self.max_pack_bytes = max_pack_bytes
        self.max_file_count = max_file_count
        self._lock = threading.RLock()
        self._install_lock = threading.Lock()
        self._cancel_install = threading.Event()
        self._active_model: InstalledModel | None = None
        self._development_override = False
        self._request_id: str | None = None
        self._progress: ModelInstallProgress | None = None
        self._diagnostic_code: ModelInstallErrorCode | None = None
        self._status = ModelStatus(
            state=ModelState.DISCOVERED,
            model_id=self.active_model_id,
            required=require_flair,
            unsafe_development_mode=not require_flair,
            development_override=False,
        )

    @property
    def active_config_path(self) -> Path:
        return self.paths.models / ".active-model.json"

    @property
    def active_model_id(self) -> str | None:
        if self.configured_model_id:
            return self.configured_model_id
        try:
            data = json.loads(self.active_config_path.read_text(encoding="utf-8"))
            value = data.get("model_id")
            return validate_model_id(value) if isinstance(value, str) else None
        except (OSError, ValueError, json.JSONDecodeError):
            return None

    def _safe_status(
        self,
        state: ModelState,
        *,
        manifest: ModelManifest | None = None,
        message: str | None = None,
        integrity: IntegrityStatus = IntegrityStatus.UNKNOWN,
        compatible: bool | None = None,
        diagnostic_code: ModelInstallErrorCode | None = None,
    ) -> ModelStatus:
        model_id = manifest.model_id if manifest else self.active_model_id
        return ModelStatus(
            state=state,
            model_id=model_id,
            display_name=manifest.display_name if manifest else None,
            language=manifest.language if manifest else None,
            model_type=manifest.model_type if manifest else None,
            created_at=manifest.created_at if manifest else None,
            integrity=integrity,
            compatible=compatible,
            active=(
                state != ModelState.MISSING
                and model_id is not None
                and model_id == self.active_model_id
            ),
            required=self.require_flair,
            unsafe_development_mode=not self.require_flair,
            development_override=self._development_override,
            message=message,
            validated_at=datetime.now(UTC) if integrity != IntegrityStatus.UNKNOWN else None,
            diagnostic_code=diagnostic_code,
            request_id=self._request_id,
            progress=self._progress,
        )

    def _set_progress(
        self,
        stage: ModelInstallStage,
        *,
        processed_bytes: int = 0,
        total_bytes: int = 0,
        validated_files: int = 0,
        total_files: int = 0,
        cancellable: bool = True,
        manifest: ModelManifest | None = None,
    ) -> None:
        percent = (
            min(100.0, round((processed_bytes / total_bytes) * 100, 1))
            if total_bytes
            else (100.0 if stage == ModelInstallStage.READY else 0.0)
        )
        self._progress = ModelInstallProgress(
            stage=stage,
            percent=percent,
            validated_files=validated_files,
            total_files=total_files,
            processed_bytes=processed_bytes,
            total_bytes=total_bytes,
            cancellable=cancellable,
        )
        state = (
            ModelState.LOADING
            if stage == ModelInstallStage.LOADING_MODEL
            else ModelState.READY
            if stage == ModelInstallStage.READY
            else ModelState.INSTALLING
        )
        message = stage.value.replace("_", " ").title()
        self._status = self._safe_status(state, manifest=manifest, message=message)

    def _check_cancelled(self, *, stage: ModelInstallStage) -> None:
        if self._cancel_install.is_set():
            raise ModelManagementError(
                ModelInstallErrorCode.CANCELLED,
                stage=stage,
                request_id=self._request_id,
            )

    def _ensure_disk_space(self, staging: Path, required_bytes: int) -> None:
        try:
            free = shutil.disk_usage(staging).free
        except OSError:
            return
        reserve = min(max(64 * 1024 * 1024, required_bytes // 100), 512 * 1024 * 1024)
        if free < required_bytes + reserve:
            raise ModelManagementError(
                ModelInstallErrorCode.INSUFFICIENT_SPACE,
                stage=ModelInstallStage.VALIDATING_LAYOUT,
                request_id=self._request_id,
            )

    def cancel_install(self) -> bool:
        if not self._install_lock.locked():
            return False
        progress = self._progress
        if progress is not None and not progress.cancellable:
            return False
        self._cancel_install.set()
        return True

    def _log_install_event(
        self,
        *,
        stage: ModelInstallStage,
        success: bool | None = None,
        code: ModelInstallErrorCode | None = None,
        pack_filename: str | None = None,
        model_id: str | None = None,
        schema_version: int | None = None,
        expected_file_count: int | None = None,
        validated_file_count: int | None = None,
        elapsed_ms: float | None = None,
        total_bytes: int | None = None,
    ) -> None:
        try:
            self.paths.ensure()
            target = self.paths.logs / "model-install.jsonl"
            event = {
                "timestamp": datetime.now(UTC).isoformat(),
                "request_id": self._request_id,
                "pack_filename": pack_filename,
                "model_id": model_id,
                "schema_version": schema_version,
                "stage": stage.value,
                "error_category": code.value if code else None,
                "expected_file_count": expected_file_count,
                "validated_file_count": validated_file_count,
                "elapsed_ms": round(elapsed_ms, 2) if elapsed_ms is not None else None,
                "total_bytes": total_bytes,
                "success": success,
            }
            with target.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, separators=(",", ":")) + "\n")
        except OSError:
            logging.getLogger("securedact.model_install").warning(
                "model_install_log_unavailable stage=%s", stage.value
            )

    def status(self) -> ModelStatus:
        with self._lock:
            return self._status.model_copy(deep=True)

    @property
    def current_model(self) -> InstalledModel | None:
        with self._lock:
            return self._active_model

    def resolve_active_model(self) -> InstalledModel | None:
        self.paths.ensure()
        model_id = self.active_model_id
        if model_id is None:
            with self._lock:
                self._active_model = None
                self._status = self._safe_status(
                    ModelState.MISSING,
                    message="Privacy model not installed",
                )
            return None
        try:
            model = self.validate_installed_model(model_id)
        except ModelManagementError:
            return None
        with self._lock:
            self._active_model = model
            self._status = self._safe_status(
                ModelState.INSTALLED,
                manifest=model.manifest,
                integrity=IntegrityStatus.VERIFIED,
                compatible=True,
            )
        return model

    def resolve_development_override(self, value: str | Path) -> InstalledModel | None:
        """Resolve a manifest-backed direct path without weakening integrity checks."""
        try:
            supplied = Path(value).expanduser().resolve(strict=True)
            root = supplied if supplied.is_dir() else supplied.parent
            if supplied.is_file() and supplied.parent.name == "model":
                root = supplied.parent.parent
            manifest = self._read_manifest(root)
            model = self._validate_tree(root, manifest)
            if supplied.is_file() and supplied != model.entrypoint:
                raise ModelManagementError(
                    "entrypoint", "The development model path is not the manifest entrypoint"
                )
        except (OSError, ModelManagementError):
            with self._lock:
                self._development_override = True
                self._active_model = None
                self._status = self._safe_status(
                    ModelState.INVALID,
                    message="The development model override failed integrity validation",
                    integrity=IntegrityStatus.FAILED,
                )
            return None
        with self._lock:
            self._development_override = True
            self.configured_model_id = manifest.model_id
            self._active_model = model
            self._status = self._safe_status(
                ModelState.INSTALLED,
                manifest=manifest,
                integrity=IntegrityStatus.VERIFIED,
                compatible=True,
            )
        return model

    def _model_root(self, model_id: str) -> Path:
        safe_id = validate_model_id(model_id)
        root = self.paths.models / safe_id
        if root.parent.resolve() != self.paths.models.resolve():
            raise ModelManagementError("unsafe_path", "The model identifier is unsafe")
        return root

    def _read_manifest(self, root: Path) -> ModelManifest:
        path = root / "manifest.json"
        try:
            if _is_reparse_point(path) or path.stat().st_size > MAX_MANIFEST_BYTES:
                raise ModelManagementError("invalid_manifest", "The model manifest is invalid")
            raw = path.read_bytes()
            return ModelManifest.model_validate_json(raw)
        except ModelManagementError:
            raise
        except Exception as exc:
            raise ModelManagementError(
                "invalid_manifest", "The model manifest is malformed"
            ) from exc

    def _check_compatibility(self, manifest: ModelManifest) -> None:
        current = _version_tuple(self.app_version)
        if current < _version_tuple(manifest.securedact_min_version):
            raise ModelManagementError(
                "incompatible", "The model pack requires a newer Securedact version"
            )
        if manifest.securedact_max_version and current > _version_tuple(
            manifest.securedact_max_version
        ):
            raise ModelManagementError(
                "incompatible", "The model pack is incompatible with this Securedact version"
            )

    def _validate_tree(
        self,
        root: Path,
        manifest: ModelManifest,
        *,
        verify_hashes: bool = True,
    ) -> InstalledModel:
        try:
            root_resolved = root.resolve(strict=True)
        except OSError as exc:
            raise ModelManagementError("missing", "The privacy model is missing") from exc
        if not root.is_dir() or _is_reparse_point(root):
            raise ModelManagementError(
                "unsafe_path", "The model pack contains an unsafe filesystem object"
            )
        self._check_compatibility(manifest)

        declared = {item.path.casefold(): item for item in manifest.files}
        actual: set[str] = set()
        file_count = 0
        total_size = 0
        for candidate in root.rglob("*"):
            if _is_reparse_point(candidate):
                raise ModelManagementError(
                    "unsafe_path", "The model pack contains a link or reparse point"
                )
            if not candidate.is_file():
                continue
            relative = candidate.relative_to(root).as_posix()
            if relative == "manifest.json":
                continue
            actual.add(relative.casefold())
            file_count += 1
            size = candidate.stat().st_size
            total_size += size
            if file_count > self.max_file_count or total_size > self.max_pack_bytes:
                raise ModelManagementError(
                    "pack_limits", "The model pack exceeds configured safety limits"
                )

        if actual != set(declared):
            raise ModelManagementError("file_set", "The model pack has missing or unexpected files")

        for _key, expected in declared.items():
            candidate = root / Path(PurePosixPath(expected.path))
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(root_resolved)
            except (OSError, ValueError) as exc:
                raise ModelManagementError(
                    "unsafe_path", "A model file escapes the model directory"
                ) from exc
            size = resolved.stat().st_size
            if size != expected.size:
                raise ModelManagementError(
                    "size_mismatch", "The model pack failed integrity validation"
                )
            if verify_hashes:
                with resolved.open("rb") as stream:
                    digest = _hash_stream(stream)
                if not secrets.compare_digest(digest, expected.sha256):
                    raise ModelManagementError(ModelInstallErrorCode.HASH_MISMATCH)

        return InstalledModel(
            root=root_resolved,
            manifest=manifest,
            entrypoint=(root_resolved / Path(PurePosixPath(manifest.entrypoint))),
            tokenizer_root=(root_resolved / Path(PurePosixPath(manifest.tokenizer_root))),
        )

    def validate_installed_model(self, model_id: str) -> InstalledModel:
        self.paths.ensure()
        with self._lock:
            self._status = self._safe_status(ModelState.VALIDATING)
        root = self._model_root(model_id)
        if not root.exists():
            error = ModelManagementError("missing", "Privacy model not installed")
            with self._lock:
                self._status = self._safe_status(ModelState.MISSING, message=error.safe_message)
            raise error
        manifest: ModelManifest | None = None
        try:
            manifest = self._read_manifest(root)
            if manifest.model_id != model_id:
                raise ModelManagementError(
                    "model_id_mismatch",
                    "The model manifest identifier does not match its installation",
                )
            model = self._validate_tree(root, manifest)
        except ModelManagementError as exc:
            state = (
                ModelState.INCOMPATIBLE
                if exc.code == ModelInstallErrorCode.INCOMPATIBLE_VERSION
                else ModelState.INVALID
            )
            with self._lock:
                self._status = self._safe_status(
                    state,
                    manifest=manifest,
                    message=exc.safe_message,
                    integrity=IntegrityStatus.FAILED,
                    compatible=False if state == ModelState.INCOMPATIBLE else None,
                )
            raise
        return model

    def list_models(self) -> list[ModelStatus]:
        self.paths.ensure()
        prior_status = self.status()
        output: list[ModelStatus] = []
        for candidate in sorted(self.paths.models.iterdir(), key=lambda path: path.name):
            if candidate.name.startswith(".") or not candidate.is_dir():
                continue
            try:
                model = self.validate_installed_model(candidate.name)
                output.append(
                    self._safe_status(
                        ModelState.READY
                        if self.status().state == ModelState.READY
                        and candidate.name == self.active_model_id
                        else ModelState.INSTALLED,
                        manifest=model.manifest,
                        integrity=IntegrityStatus.VERIFIED,
                        compatible=True,
                    )
                )
            except (ModelManagementError, ValueError):
                output.append(
                    ModelStatus(
                        state=ModelState.INVALID,
                        model_id=candidate.name
                        if MODEL_ID_PATTERN.fullmatch(candidate.name)
                        else None,
                        integrity=IntegrityStatus.FAILED,
                        required=self.require_flair,
                        unsafe_development_mode=not self.require_flair,
                        development_override=self._development_override,
                        message="The installed model failed validation",
                    )
                )
        with self._lock:
            self._status = prior_status
        return output

    def _new_staging_directory(self) -> Path:
        try:
            self.paths.ensure()
        except PermissionError as exc:
            raise ModelManagementError(ModelInstallErrorCode.ACCESS_DENIED) from exc
        except OSError as exc:
            raise ModelManagementError(ModelInstallErrorCode.STAGING_FAILED) from exc
        for _attempt in range(10):
            directory = self.paths.model_staging / f"install-{secrets.token_hex(16)}"
            try:
                directory.mkdir(mode=0o700)
                return directory
            except FileExistsError:
                continue
            except PermissionError as exc:
                raise ModelManagementError(ModelInstallErrorCode.ACCESS_DENIED) from exc
            except OSError as exc:
                raise ModelManagementError(ModelInstallErrorCode.STAGING_FAILED) from exc
        raise ModelManagementError(ModelInstallErrorCode.STAGING_FAILED)

    def _validate_zip_members(
        self, archive: zipfile.ZipFile
    ) -> tuple[ModelManifest, list[zipfile.ZipInfo]]:
        manifest, members, _total_size = _manifest_from_archive(
            archive,
            max_pack_bytes=self.max_pack_bytes,
            max_file_count=self.max_file_count,
        )
        return manifest, members

    def _stage_zip(self, source: Path, staging: Path) -> ModelManifest:
        try:
            with zipfile.ZipFile(source) as archive:
                with self._lock:
                    self._set_progress(ModelInstallStage.READING_MANIFEST)
                manifest, members = self._validate_zip_members(archive)
                declared = {item.path.casefold(): item for item in manifest.files}
                total_bytes = sum(item.size for item in manifest.files)
                self._ensure_disk_space(staging, total_bytes)
                processed = 0
                validated = 0
                with self._lock:
                    self._set_progress(
                        ModelInstallStage.VALIDATING_LAYOUT,
                        total_bytes=total_bytes,
                        total_files=len(manifest.files),
                        manifest=manifest,
                    )
                for info in members:
                    self._check_cancelled(stage=ModelInstallStage.EXTRACTING)
                    relative = validate_relative_pack_path(info.filename)
                    destination = staging / Path(PurePosixPath(relative))
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    if relative.casefold() == "manifest.json":
                        destination.write_bytes(archive.read(info))
                        continue
                    expected = declared[relative.casefold()]
                    digest = hashlib.sha256()
                    written = 0
                    with archive.open(info) as source_stream, destination.open("xb") as output:
                        while chunk := source_stream.read(1024 * 1024):
                            self._check_cancelled(stage=ModelInstallStage.EXTRACTING)
                            output.write(chunk)
                            digest.update(chunk)
                            written += len(chunk)
                            processed += len(chunk)
                            with self._lock:
                                self._set_progress(
                                    ModelInstallStage.EXTRACTING,
                                    processed_bytes=processed,
                                    total_bytes=total_bytes,
                                    validated_files=validated,
                                    total_files=len(manifest.files),
                                    manifest=manifest,
                                )
                    if written != info.file_size or written != expected.size:
                        raise ModelManagementError(
                            ModelInstallErrorCode.SIZE_MISMATCH,
                            stage=ModelInstallStage.VERIFYING_HASHES,
                        )
                    if not secrets.compare_digest(digest.hexdigest(), expected.sha256):
                        raise ModelManagementError(
                            ModelInstallErrorCode.HASH_MISMATCH,
                            stage=ModelInstallStage.VERIFYING_HASHES,
                        )
                    validated += 1
                    with self._lock:
                        self._set_progress(
                            ModelInstallStage.VERIFYING_HASHES,
                            processed_bytes=processed,
                            total_bytes=total_bytes,
                            validated_files=validated,
                            total_files=len(manifest.files),
                            manifest=manifest,
                        )
                self._validate_tree(staging, manifest, verify_hashes=False)
                return manifest
        except ModelManagementError:
            raise
        except PermissionError as exc:
            raise ModelManagementError(
                ModelInstallErrorCode.ACCESS_DENIED,
                stage=ModelInstallStage.EXTRACTING,
            ) from exc
        except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            raise ModelManagementError(ModelInstallErrorCode.INVALID_ZIP) from exc
        except OSError as exc:
            code = (
                ModelInstallErrorCode.FILE_LOCKED
                if getattr(exc, "winerror", None) in {32, 33}
                else ModelInstallErrorCode.INVALID_ZIP
            )
            raise ModelManagementError(code) from exc

    def _stage_directory(self, source: Path, staging: Path) -> ModelManifest:
        if not source.is_dir() or _is_reparse_point(source):
            raise ModelManagementError(ModelInstallErrorCode.UNSAFE_PATH)
        manifest = self._read_manifest(source)
        self._validate_tree(source, manifest, verify_hashes=False)
        total_bytes = sum(item.size for item in manifest.files)
        self._ensure_disk_space(staging, total_bytes)
        processed = 0
        validated = 0
        try:
            shutil.copy2(source / "manifest.json", staging / "manifest.json")
            for item in manifest.files:
                self._check_cancelled(stage=ModelInstallStage.EXTRACTING)
                relative = Path(PurePosixPath(item.path))
                destination = staging / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                written = 0
                with (
                    (source / relative).open("rb") as input_stream,
                    destination.open("xb") as output,
                ):
                    while chunk := input_stream.read(1024 * 1024):
                        self._check_cancelled(stage=ModelInstallStage.EXTRACTING)
                        output.write(chunk)
                        digest.update(chunk)
                        written += len(chunk)
                        processed += len(chunk)
                        with self._lock:
                            self._set_progress(
                                ModelInstallStage.EXTRACTING,
                                processed_bytes=processed,
                                total_bytes=total_bytes,
                                validated_files=validated,
                                total_files=len(manifest.files),
                                manifest=manifest,
                            )
                if written != item.size:
                    raise ModelManagementError(ModelInstallErrorCode.SIZE_MISMATCH)
                if not secrets.compare_digest(digest.hexdigest(), item.sha256):
                    raise ModelManagementError(ModelInstallErrorCode.HASH_MISMATCH)
                validated += 1
                with self._lock:
                    self._set_progress(
                        ModelInstallStage.VERIFYING_HASHES,
                        processed_bytes=processed,
                        total_bytes=total_bytes,
                        validated_files=validated,
                        total_files=len(manifest.files),
                        manifest=manifest,
                    )
            self._validate_tree(staging, manifest, verify_hashes=False)
            return manifest
        except ModelManagementError:
            raise
        except PermissionError as exc:
            raise ModelManagementError(ModelInstallErrorCode.ACCESS_DENIED) from exc
        except OSError as exc:
            raise ModelManagementError(ModelInstallErrorCode.INSTALL_DESTINATION_FAILED) from exc

    def install(self, source: str | Path, *, activate: bool = True) -> ModelInstallResult:
        if not self._install_lock.acquire(blocking=False):
            raise ModelManagementError(ModelInstallErrorCode.ALREADY_INSTALLING)
        prior_status = self.status()
        prior_model = self.current_model
        staging: Path | None = None
        backup: Path | None = None
        final: Path | None = None
        manifest: ModelManifest | None = None
        replaced = False
        started = time.perf_counter()
        pack_filename: str | None = None
        with self._lock:
            self._request_id = secrets.token_hex(8)
            self._diagnostic_code = None
            self._cancel_install.clear()
            self._set_progress(ModelInstallStage.OPENING_PACK)
        try:
            try:
                source_path = Path(source).expanduser().resolve(strict=True)
            except FileNotFoundError as exc:
                raise ModelManagementError(ModelInstallErrorCode.FILE_NOT_FOUND) from exc
            except PermissionError as exc:
                raise ModelManagementError(ModelInstallErrorCode.ACCESS_DENIED) from exc
            pack_filename = source_path.name
            if source_path.is_file() and source_path.suffix.casefold() != ".zip":
                raise ModelManagementError(ModelInstallErrorCode.INVALID_ZIP)
            staging = self._new_staging_directory()
            manifest = (
                self._stage_directory(source_path, staging)
                if source_path.is_dir()
                else self._stage_zip(source_path, staging)
            )
            final = self._model_root(manifest.model_id)
            with self._lock:
                total_bytes = sum(item.size for item in manifest.files)
                self._set_progress(
                    ModelInstallStage.INSTALLING,
                    processed_bytes=total_bytes,
                    total_bytes=total_bytes,
                    validated_files=len(manifest.files),
                    total_files=len(manifest.files),
                    cancellable=False,
                    manifest=manifest,
                )
                if final.exists():
                    if not final.is_dir() or _is_reparse_point(final):
                        raise ModelManagementError(ModelInstallErrorCode.UNSAFE_PATH)
                    backup = self.paths.model_staging / f"backup-{secrets.token_hex(16)}"
                    try:
                        os.replace(final, backup)
                    except PermissionError as exc:
                        raise ModelManagementError(ModelInstallErrorCode.ACCESS_DENIED) from exc
                    except OSError as exc:
                        raise ModelManagementError(ModelInstallErrorCode.FILE_LOCKED) from exc
                    replaced = True
                try:
                    os.replace(staging, final)
                    staging = None
                except OSError as exc:
                    if backup is not None and not final.exists():
                        os.replace(backup, final)
                        backup = None
                    raise ModelManagementError(ModelInstallErrorCode.ATOMIC_REPLACE_FAILED) from exc
                installed = self._validate_tree(final, manifest, verify_hashes=False)
                if activate:
                    self.activate(manifest.model_id, validated=installed)
                self._active_model = (
                    installed if manifest.model_id == self.active_model_id else self._active_model
                )
                self._status = self._safe_status(
                    ModelState.INSTALLED,
                    manifest=manifest,
                    integrity=IntegrityStatus.VERIFIED,
                    compatible=True,
                )
            if backup is not None:
                shutil.rmtree(backup)
                backup = None
            self._log_install_event(
                stage=ModelInstallStage.INSTALLING,
                success=True,
                pack_filename=pack_filename,
                model_id=manifest.model_id,
                schema_version=manifest.schema_version,
                expected_file_count=len(manifest.files),
                validated_file_count=len(manifest.files),
                elapsed_ms=(time.perf_counter() - started) * 1000,
                total_bytes=sum(item.size for item in manifest.files),
            )
            return ModelInstallResult(installed=True, replaced=replaced, status=self.status())
        except ModelManagementError as exc:
            exc.request_id = exc.request_id or self._request_id
            if final is not None and backup is not None:
                try:
                    if final.exists():
                        shutil.rmtree(final)
                    os.replace(backup, final)
                    backup = None
                except OSError:
                    pass
            with self._lock:
                self._diagnostic_code = exc.code
                if (
                    prior_model is not None
                    and prior_status.state in {ModelState.INSTALLED, ModelState.READY}
                    and prior_model.root.exists()
                ):
                    self._active_model = prior_model
                    self._progress = None
                    self._status = prior_status.model_copy(
                        update={
                            "message": exc.safe_message,
                            "diagnostic_code": exc.code,
                            "request_id": self._request_id,
                            "progress": None,
                        }
                    )
                else:
                    state = (
                        ModelState.INCOMPATIBLE
                        if exc.code == ModelInstallErrorCode.INCOMPATIBLE_VERSION
                        else ModelState.FAILED
                        if exc.code
                        in {
                            ModelInstallErrorCode.ACCESS_DENIED,
                            ModelInstallErrorCode.FILE_LOCKED,
                            ModelInstallErrorCode.STAGING_FAILED,
                            ModelInstallErrorCode.INSTALL_DESTINATION_FAILED,
                            ModelInstallErrorCode.ATOMIC_REPLACE_FAILED,
                            ModelInstallErrorCode.INSUFFICIENT_SPACE,
                            ModelInstallErrorCode.UNKNOWN,
                        }
                        else ModelState.INVALID
                    )
                    self._status = self._safe_status(
                        state,
                        message=exc.safe_message,
                        integrity=IntegrityStatus.FAILED,
                        compatible=False if state == ModelState.INCOMPATIBLE else None,
                        diagnostic_code=exc.code,
                    )
            self._log_install_event(
                stage=exc.stage
                or (self._progress.stage if self._progress else ModelInstallStage.OPENING_PACK),
                success=False,
                code=exc.code,
                pack_filename=pack_filename,
                model_id=manifest.model_id if manifest else None,
                schema_version=manifest.schema_version if manifest else None,
                expected_file_count=len(manifest.files) if manifest else None,
                validated_file_count=self._progress.validated_files if self._progress else 0,
                elapsed_ms=(time.perf_counter() - started) * 1000,
                total_bytes=self._progress.total_bytes if self._progress else None,
            )
            raise
        except Exception as exc:
            if final is not None and backup is not None:
                try:
                    if final.exists():
                        shutil.rmtree(final)
                    os.replace(backup, final)
                    backup = None
                except OSError:
                    pass
            error = ModelManagementError(
                ModelInstallErrorCode.UNKNOWN,
                request_id=self._request_id,
                stage=self._progress.stage if self._progress else ModelInstallStage.OPENING_PACK,
            )
            with self._lock:
                self._diagnostic_code = error.code
                if (
                    prior_model is not None
                    and prior_status.state in {ModelState.INSTALLED, ModelState.READY}
                    and prior_model.root.exists()
                ):
                    self._active_model = prior_model
                    self._progress = None
                    self._status = prior_status.model_copy(
                        update={
                            "message": error.safe_message,
                            "diagnostic_code": error.code,
                            "request_id": self._request_id,
                            "progress": None,
                        }
                    )
                else:
                    self._status = self._safe_status(
                        ModelState.FAILED,
                        message=error.safe_message,
                        diagnostic_code=error.code,
                    )
            self._log_install_event(
                stage=error.stage or ModelInstallStage.OPENING_PACK,
                success=False,
                code=error.code,
                pack_filename=pack_filename,
                model_id=manifest.model_id if manifest else None,
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )
            raise error from exc
        finally:
            if staging is not None:
                shutil.rmtree(staging, ignore_errors=True)
            if backup is not None and backup.exists() and final is not None and final.exists():
                shutil.rmtree(backup, ignore_errors=True)
            self._cancel_install.clear()
            self._install_lock.release()

    def activate(self, model_id: str, *, validated: InstalledModel | None = None) -> ModelStatus:
        self.paths.ensure()
        model = validated or self.validate_installed_model(model_id)
        temporary = self.paths.models / f".active-{secrets.token_hex(8)}.json"
        temporary.write_text(json.dumps({"model_id": model_id}) + "\n", encoding="utf-8")
        os.replace(temporary, self.active_config_path)
        self.configured_model_id = model_id
        self._active_model = model
        self._status = self._safe_status(
            ModelState.INSTALLED,
            manifest=model.manifest,
            integrity=IntegrityStatus.VERIFIED,
            compatible=True,
        )
        return self.status()

    def remove(self, model_id: str) -> ModelStatus:
        self.paths.ensure()
        with self._install_lock:
            root = self._model_root(model_id)
            if root.exists():
                if not root.is_dir() or _is_reparse_point(root):
                    raise ModelManagementError(
                        "unsafe_path", "The installed model location is unsafe"
                    )
                shutil.rmtree(root)
            if model_id == self.active_model_id:
                self.configured_model_id = None
                self.active_config_path.unlink(missing_ok=True)
                self._active_model = None
                self._status = self._safe_status(
                    ModelState.MISSING, message="Privacy model not installed"
                )
            return self.status()

    def mark_loading(self) -> None:
        with self._lock:
            manifest = self._active_model.manifest if self._active_model else None
            total_bytes = sum(item.size for item in manifest.files) if manifest else 0
            self._progress = ModelInstallProgress(
                stage=ModelInstallStage.LOADING_MODEL,
                percent=99.0,
                validated_files=len(manifest.files) if manifest else 0,
                total_files=len(manifest.files) if manifest else 0,
                processed_bytes=total_bytes,
                total_bytes=total_bytes,
                cancellable=False,
            )
            self._status = self._safe_status(
                ModelState.LOADING,
                manifest=manifest,
                integrity=IntegrityStatus.VERIFIED if manifest else IntegrityStatus.UNKNOWN,
                compatible=True if manifest else None,
                message="Privacy model is loading",
            )

    def mark_ready(self) -> None:
        with self._lock:
            manifest = self._active_model.manifest if self._active_model else None
            total_bytes = sum(item.size for item in manifest.files) if manifest else 0
            self._progress = ModelInstallProgress(
                stage=ModelInstallStage.READY,
                percent=100.0,
                validated_files=len(manifest.files) if manifest else 0,
                total_files=len(manifest.files) if manifest else 0,
                processed_bytes=total_bytes,
                total_bytes=total_bytes,
                cancellable=False,
            )
            self._status = self._safe_status(
                ModelState.READY,
                manifest=manifest,
                integrity=IntegrityStatus.VERIFIED if manifest else IntegrityStatus.UNKNOWN,
                compatible=True if manifest else None,
            )

    def mark_failed(self) -> None:
        with self._lock:
            manifest = self._active_model.manifest if self._active_model else None
            self._diagnostic_code = ModelInstallErrorCode.MODEL_LOAD_FAILED
            self._status = self._safe_status(
                ModelState.FAILED,
                manifest=manifest,
                integrity=IntegrityStatus.VERIFIED if manifest else IntegrityStatus.UNKNOWN,
                compatible=True if manifest else None,
                message=MODEL_INSTALL_MESSAGES[ModelInstallErrorCode.MODEL_LOAD_FAILED],
                diagnostic_code=ModelInstallErrorCode.MODEL_LOAD_FAILED,
            )
