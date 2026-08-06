# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
import stat
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .app_paths import SecuredactPaths
from .models import PrivacyAction
from .policies import PROFILE_SCHEMA_VERSION, Policy, PolicyRegistry
from .taxonomy import CRITICAL_TYPES, SPECIAL_CATEGORY_TYPES

MAX_POLICY_FILE_BYTES = 64 * 1024
MAX_POLICY_FILES = 64
SUPPORTED_POLICY_SUFFIXES = frozenset({".json", ".yaml", ".yml"})


class PolicyLoadErrorCode(StrEnum):
    DIRECTORY_INVALID = "policy_directory_invalid"
    FILE_UNSAFE = "policy_file_unsafe"
    FILE_TOO_LARGE = "policy_file_too_large"
    FILE_INVALID = "policy_file_invalid"
    SCHEMA_UNSUPPORTED = "policy_schema_unsupported"
    DUPLICATE_NAME = "policy_duplicate_name"
    INVARIANT_VIOLATION = "policy_invariant_violation"


class PolicyLoadError(RuntimeError):
    """A local policy could not be loaded; messages never include file content."""

    def __init__(self, code: PolicyLoadErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


def _is_reparse_point(path: Path) -> bool:
    try:
        details = path.lstat()
    except OSError as exc:
        raise PolicyLoadError(PolicyLoadErrorCode.FILE_UNSAFE) from exc
    attributes = getattr(details, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


class LocalPolicyLoader:
    """Load declarative policy files from one explicitly controlled directory."""

    def __init__(
        self,
        directory: Path,
        *,
        max_file_bytes: int = MAX_POLICY_FILE_BYTES,
        max_files: int = MAX_POLICY_FILES,
    ) -> None:
        self.directory = directory
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files

    @classmethod
    def from_environment(cls) -> LocalPolicyLoader:
        configured = os.getenv("SECUREDACT_POLICY_DIR")
        directory = (
            Path(configured).expanduser()
            if configured
            else SecuredactPaths.resolve().root / "policies"
        )
        return cls(directory)

    def load(self, base: PolicyRegistry | None = None) -> PolicyRegistry:
        registry = base or PolicyRegistry()
        if not self.directory.exists():
            return registry
        if not self.directory.is_dir() or _is_reparse_point(self.directory):
            raise PolicyLoadError(PolicyLoadErrorCode.DIRECTORY_INVALID)

        files = sorted(
            (
                path
                for path in self.directory.iterdir()
                if path.suffix.casefold() in SUPPORTED_POLICY_SUFFIXES
            ),
            key=lambda path: path.name.casefold(),
        )
        if len(files) > self.max_files:
            raise PolicyLoadError(PolicyLoadErrorCode.DIRECTORY_INVALID)

        for path in files:
            policy = self._load_file(path)
            try:
                registry.register(policy)
            except ValueError as exc:
                raise PolicyLoadError(PolicyLoadErrorCode.DUPLICATE_NAME) from exc
        return registry

    def _load_file(self, path: Path) -> Policy:
        if not path.is_file() or _is_reparse_point(path):
            raise PolicyLoadError(PolicyLoadErrorCode.FILE_UNSAFE)
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise PolicyLoadError(PolicyLoadErrorCode.FILE_UNSAFE) from exc
        if size > self.max_file_bytes:
            raise PolicyLoadError(PolicyLoadErrorCode.FILE_TOO_LARGE)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise PolicyLoadError(PolicyLoadErrorCode.FILE_UNSAFE) from exc
        if len(raw) > self.max_file_bytes:
            raise PolicyLoadError(PolicyLoadErrorCode.FILE_TOO_LARGE)
        try:
            payload: Any = yaml.safe_load(raw.decode("utf-8"))
        except (UnicodeDecodeError, yaml.YAMLError) as exc:
            raise PolicyLoadError(PolicyLoadErrorCode.FILE_INVALID) from exc
        if not isinstance(payload, dict) or any(not isinstance(key, str) for key in payload):
            raise PolicyLoadError(PolicyLoadErrorCode.FILE_INVALID)
        if payload.get("schema_version") != PROFILE_SCHEMA_VERSION:
            raise PolicyLoadError(PolicyLoadErrorCode.SCHEMA_UNSUPPORTED)
        if "built_in" in payload:
            raise PolicyLoadError(PolicyLoadErrorCode.FILE_INVALID)
        try:
            policy = Policy.model_validate({**payload, "built_in": False})
        except ValidationError as exc:
            raise PolicyLoadError(PolicyLoadErrorCode.FILE_INVALID) from exc
        self._validate_invariants(policy)
        return policy

    @staticmethod
    def _validate_invariants(policy: Policy) -> None:
        protected_types = CRITICAL_TYPES | SPECIAL_CATEGORY_TYPES
        if any(
            policy.action_for(entity_type) == PrivacyAction.ALLOW for entity_type in protected_types
        ):
            raise PolicyLoadError(PolicyLoadErrorCode.INVARIANT_VIOLATION)
        if (
            not policy.residual_validation_enabled
            or policy.residual_on_failure != "block"
            or policy.expose_raw_values
            or policy.expose_mapping
        ):
            raise PolicyLoadError(PolicyLoadErrorCode.INVARIANT_VIOLATION)
