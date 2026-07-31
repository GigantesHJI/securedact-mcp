from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from .model_registry import (
    MODELS_BY_ID,
    OFFICIAL_HF_ENDPOINT,
    SupportedModel,
)
from .model_store import (
    FORBIDDEN_EXECUTABLE_SUFFIXES,
    InstalledFile,
    ModelIntegrityError,
    ModelStore,
    VerifiedModel,
    is_unsafe_link,
)

MAX_MODEL_FILES = 16
MAX_MODEL_BYTES = 3 * 1024 * 1024 * 1024
MAX_DOWNLOAD_METADATA_BYTES = 16 * 1024 * 1024
DOWNLOAD_ATTEMPTS = 3
DOWNLOAD_TIMEOUT_SECONDS = 30
DOWNLOAD_RESERVE_BYTES = 256 * 1024 * 1024


class InstallerState(StrEnum):
    NOT_INSTALLED = "not_installed"
    AWAITING_CONSENT = "awaiting_consent"
    DOWNLOADING = "downloading"
    VALIDATING = "validating"
    TESTING = "testing"
    READY = "ready"
    CANCELLED = "cancelled"
    CORRUPT = "corrupt"
    INCOMPATIBLE = "incompatible"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class InstallationProgress:
    state: InstallerState
    model_id: str
    message: str


@dataclass(frozen=True, slots=True)
class ModelInstallationResult:
    state: InstallerState
    model: VerifiedModel
    already_installed: bool = False


class ModelDownloadError(RuntimeError):
    """An allowlisted model could not be downloaded or installed safely."""


class SnapshotDownload(Protocol):
    def __call__(self, **kwargs: Any) -> str: ...


ProgressCallback = Callable[[InstallationProgress], None]
CancelCheck = Callable[[], bool]
SmokeTest = Callable[[Path], None]


def _default_snapshot_download(**kwargs: Any) -> str:
    download_variables = {
        "HF_HUB_DOWNLOAD_TIMEOUT": str(DOWNLOAD_TIMEOUT_SECONDS),
        "HF_HUB_ETAG_TIMEOUT": "15",
        "HF_HUB_DISABLE_TELEMETRY": "1",
    }
    previous_values = {name: os.environ.get(name) for name in download_variables}
    os.environ.update(download_variables)
    try:
        try:
            from huggingface_hub import snapshot_download  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ModelDownloadError(
                'Model installation requires `python -m pip install "securedact-mcp[ml]"`.'
            ) from exc
        return str(snapshot_download(**kwargs))
    finally:
        for name, previous in previous_values.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous


def offline_flair_load_test(entrypoint: Path) -> None:
    offline_variables = {
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
    }
    previous_values = {name: os.environ.get(name) for name in offline_variables}
    os.environ.update(offline_variables)
    try:
        try:
            from flair.models.sequence_tagger_model import (  # type: ignore[import-not-found]
                SequenceTagger,
            )
        except ImportError as exc:
            raise ModelDownloadError(
                'Model validation requires `python -m pip install "securedact-mcp[ml]"`.'
            ) from exc
        try:
            SequenceTagger.load(entrypoint)
        except Exception as exc:
            raise ModelDownloadError(
                "The downloaded Flair model failed its local load test"
            ) from exc
    finally:
        # A multi-model installation still needs network access for the next
        # approved snapshot. Runtime loading independently enforces offline mode.
        for name, previous in previous_values.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


class ModelInstaller:
    def __init__(
        self,
        store: ModelStore,
        *,
        snapshot_download: SnapshotDownload | None = None,
        smoke_test: SmokeTest | None = None,
        progress: ProgressCallback | None = None,
        cancel_check: CancelCheck | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        attempts: int = DOWNLOAD_ATTEMPTS,
    ) -> None:
        self.store = store
        self.snapshot_download = snapshot_download or _default_snapshot_download
        self.smoke_test = smoke_test or offline_flair_load_test
        self.progress = progress or (lambda _event: None)
        self.cancel_check = cancel_check or (lambda: False)
        self.sleeper = sleeper
        self.attempts = max(1, min(attempts, DOWNLOAD_ATTEMPTS))

    def _emit(self, state: InstallerState, model: SupportedModel, message: str) -> None:
        self.progress(InstallationProgress(state=state, model_id=model.id, message=message))

    def _check_cancelled(self, model: SupportedModel) -> None:
        if self.cancel_check():
            self._emit(InstallerState.CANCELLED, model, "Model installation was cancelled safely")
            raise ModelDownloadError("Model installation was cancelled safely")

    def _validate_registry_entry(self, model: SupportedModel) -> None:
        if MODELS_BY_ID.get(model.id) != model:
            raise ModelDownloadError("The requested model is not in the Securedact allowlist")
        if len(model.required_files) > MAX_MODEL_FILES:
            raise ModelDownloadError("The model exceeds the supported file-count limit")
        total_size = sum(model.expected_sizes.values())
        if total_size <= 0 or total_size > MAX_MODEL_BYTES:
            raise ModelDownloadError("The model exceeds the supported download-size limit")

    def _ensure_disk_space(self, required_bytes: int) -> None:
        self.store.paths.ensure()
        free = shutil.disk_usage(self.store.paths.staging_root).free
        reserve = max(DOWNLOAD_RESERVE_BYTES, required_bytes // 10)
        if free < required_bytes + reserve:
            raise ModelDownloadError("Insufficient free disk space for safe model installation")

    def _download(self, model: SupportedModel, destination: Path) -> Path:
        last_error: Exception | None = None
        for attempt in range(1, self.attempts + 1):
            self._check_cancelled(model)
            try:
                result = self.snapshot_download(
                    repo_id=model.upstream_repo,
                    revision=model.upstream_revision,
                    allow_patterns=list(model.required_files),
                    local_dir=str(destination),
                    endpoint=OFFICIAL_HF_ENDPOINT,
                    token=False,
                    local_files_only=False,
                    force_download=False,
                    resume_download=True,
                    local_dir_use_symlinks=False,
                    etag_timeout=15,
                    max_workers=4,
                    library_name="securedact-mcp",
                )
                root = Path(result).resolve(strict=True)
                root.relative_to(destination.resolve())
                return root
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                last_error = exc
                if attempt < self.attempts:
                    self.sleeper(float(2 ** (attempt - 1)))
        raise ModelDownloadError(
            "The official Hugging Face download failed after bounded retries"
        ) from last_error

    def _materialize(
        self,
        model: SupportedModel,
        snapshot_root: Path,
        payload: Path,
    ) -> dict[str, InstalledFile]:
        allowed = set(model.required_files)
        discovered_files = 0
        discovered_bytes = 0
        for discovered in snapshot_root.rglob("*"):
            relative = discovered.relative_to(snapshot_root).as_posix()
            if is_unsafe_link(discovered):
                raise ModelIntegrityError("The downloaded snapshot contains a linked path")
            if discovered.is_dir():
                continue
            discovered_files += 1
            discovered_bytes += discovered.stat().st_size
            if discovered_files > MAX_MODEL_FILES:
                raise ModelIntegrityError("The downloaded snapshot exceeds the file-count limit")
            if discovered_bytes > MAX_MODEL_BYTES + MAX_DOWNLOAD_METADATA_BYTES:
                raise ModelIntegrityError("The downloaded snapshot exceeds the size limit")
            if discovered.suffix.casefold() in FORBIDDEN_EXECUTABLE_SUFFIXES:
                raise ModelIntegrityError("The downloaded snapshot contains an executable file")
            if relative not in allowed and not relative.startswith(".cache/huggingface/"):
                raise ModelIntegrityError("The downloaded snapshot contains an unexpected file")
        payload.mkdir(parents=True, exist_ok=False)
        records: dict[str, InstalledFile] = {}
        for relative in model.required_files:
            candidate = snapshot_root / relative
            if is_unsafe_link(candidate):
                raise ModelIntegrityError("The downloaded snapshot contains an unsafe file")
            source = candidate.resolve(strict=True)
            source.relative_to(snapshot_root.resolve())
            if not source.is_file():
                raise ModelIntegrityError("The downloaded snapshot contains an unsafe file")
            if source.suffix.casefold() in FORBIDDEN_EXECUTABLE_SUFFIXES:
                raise ModelIntegrityError("The downloaded snapshot contains an executable file")
            target = payload / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, target)
            size = target.stat().st_size
            digest = _hash_file(target)
            if size != model.expected_sizes[relative]:
                raise ModelIntegrityError("The downloaded model size differs from pinned metadata")
            if digest != model.expected_hashes[relative]:
                raise ModelIntegrityError("The downloaded model hash differs from pinned metadata")
            records[relative] = InstalledFile(size=size, sha256=digest)
        return records

    def _activate(self, model: SupportedModel, payload: Path) -> VerifiedModel:
        final = self.store.model_path(model)
        backup: Path | None = None
        if final.exists():
            backup = self.store.paths.rollback_root / f"{model.id}-{secrets.token_hex(8)}"
            os.replace(final, backup)
        try:
            os.replace(payload, final)
            verified = self.store.verify_model(model)
        except Exception:
            if final.exists():
                shutil.rmtree(final, ignore_errors=True)
            if backup is not None and backup.exists():
                os.replace(backup, final)
            raise
        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)
        return verified

    def install(self, model: SupportedModel) -> ModelInstallationResult:
        self._validate_registry_entry(model)
        try:
            installed = self.store.verify_model(model)
        except ModelIntegrityError:
            installed = None
        if installed is not None:
            self._emit(InstallerState.TESTING, model, "Testing existing model compatibility")
            try:
                self.smoke_test(installed.entrypoint)
            except ModelDownloadError:
                self._emit(
                    InstallerState.INCOMPATIBLE,
                    model,
                    "The installed model is incompatible with the local ML runtime",
                )
                raise
            self._emit(InstallerState.READY, model, "Existing verified model is ready")
            return ModelInstallationResult(
                state=InstallerState.READY,
                model=installed,
                already_installed=True,
            )

        required_bytes = sum(model.expected_sizes.values())
        self._ensure_disk_space(required_bytes)
        staging = self.store.paths.staging_root / f"install-{secrets.token_hex(16)}"
        download_root = staging / "download"
        payload = staging / "payload"
        staging.mkdir(parents=True, exist_ok=False)
        try:
            self._check_cancelled(model)
            self._emit(InstallerState.DOWNLOADING, model, "Downloading from official Hugging Face")
            snapshot_root = self._download(model, download_root)
            self._check_cancelled(model)
            self._emit(InstallerState.VALIDATING, model, "Validating pinned files and hashes")
            records = self._materialize(model, snapshot_root, payload)
            shutil.rmtree(download_root, ignore_errors=True)
            manifest = self.store.manifest_for_files(model, records)
            self.store.write_manifest(payload, manifest)
            self._check_cancelled(model)
            self._emit(InstallerState.TESTING, model, "Running offline Flair model-load test")
            self.smoke_test(payload / manifest.entrypoint)
            verified = self._activate(model, payload)
            self._emit(InstallerState.READY, model, "Model installed and verified")
            return ModelInstallationResult(state=InstallerState.READY, model=verified)
        except KeyboardInterrupt as exc:
            self._emit(InstallerState.CANCELLED, model, "Model installation was cancelled safely")
            raise ModelDownloadError("Model installation was cancelled safely") from exc
        except ModelIntegrityError:
            self._emit(
                InstallerState.CORRUPT, model, "Downloaded model failed integrity validation"
            )
            raise
        except Exception:
            self._emit(InstallerState.FAILED, model, "Model installation failed safely")
            raise
        finally:
            shutil.rmtree(staging, ignore_errors=True)
