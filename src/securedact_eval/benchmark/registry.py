# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


class SourceFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    url: HttpUrl
    size: int = Field(gt=0)
    sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    etag_md5: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")

    @model_validator(mode="after")
    def require_approved_digest(self) -> SourceFile:
        if self.sha256 is None and self.etag_md5 is None:
            raise ValueError("source_file_digest_required")
        return self


class SourceDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,79}$")
    title: str
    version: str = Field(min_length=1)
    homepage: HttpUrl
    retrieval_location: HttpUrl
    adapter: str
    tier: Literal["public", "external", "restricted"]
    allowed_tiers: list[Literal["public", "external", "restricted"]]
    enabled: bool
    license_spdx: str
    license_url: HttpUrl
    attribution: str
    commercial_use: bool | None
    raw_redistribution: bool | None
    annotation_redistribution: bool | None
    derivative_works: bool | None
    attribution_obligations: str
    share_alike_obligations: str
    access_restrictions: str
    languages: list[str]
    label_mapping: dict[str, str] = Field(default_factory=dict)
    files: list[SourceFile] = Field(default_factory=list)
    review_date: date
    reviewer: str
    approval_status: Literal["approved", "template", "rejected"]
    notes: str = ""

    @model_validator(mode="after")
    def validate_legal_review(self) -> SourceDefinition:
        if self.enabled:
            if self.approval_status != "approved" or self.license_spdx == "NOASSERTION":
                raise ValueError("enabled_source_must_be_approved")
            if self.tier not in self.allowed_tiers or not self.files:
                raise ValueError("enabled_source_scope_invalid")
            if any(
                value is None
                for value in (
                    self.commercial_use,
                    self.raw_redistribution,
                    self.annotation_redistribution,
                    self.derivative_works,
                )
            ):
                raise ValueError("enabled_source_rights_unknown")
            if self.tier == "public" and (not self.commercial_use or not self.raw_redistribution):
                raise ValueError("public_source_terms_incompatible")
        return self


class SourceRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    registry_version: Literal[1]
    sources: list[SourceDefinition]

    @model_validator(mode="after")
    def unique_ids(self) -> SourceRegistry:
        ids = [source.id for source in self.sources]
        if len(ids) != len(set(ids)):
            raise ValueError("source_registry_duplicate_id")
        return self

    def require(self, source_id: str) -> SourceDefinition:
        match = next((source for source in self.sources if source.id == source_id), None)
        if match is None:
            raise ValueError("source_not_registered")
        if not match.enabled:
            raise ValueError("source_not_enabled")
        if match.approval_status != "approved":
            raise ValueError("source_not_approved")
        return match


def load_registry(path: Path) -> SourceRegistry:
    try:
        return SourceRegistry.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ValueError("source_registry_invalid") from exc


def verify_source_file(path: Path, approved: SourceFile) -> None:
    if not path.is_file() or path.stat().st_size != approved.size:
        raise ValueError("source_file_size_mismatch")
    algorithm = "sha256" if approved.sha256 is not None else "md5"
    digest = hashlib.new(algorithm, usedforsecurity=algorithm != "md5")
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    expected = approved.sha256 or approved.etag_md5
    if digest.hexdigest() != expected:
        raise ValueError("source_file_digest_mismatch")
