# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from securedact_core import EntityType, PrivacyAction


class Annotation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    start: int = Field(ge=0)
    end: int = Field(gt=0)
    entity_type: EntityType
    expected_action: PrivacyAction | None = None
    text: str | None = None
    assertion_type: Literal[
        "current",
        "negated",
        "uncertain",
        "hypothetical",
        "quotation",
        "historical",
        "family_history",
        "general_discussion",
        "organization_level",
        "near_miss",
    ] = "current"
    provenance: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_span(self) -> Annotation:
        if self.end <= self.start:
            raise ValueError("annotation end must be greater than start")
        return self


class CorpusSample(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{2,79}$")
    language: str = Field(pattern=r"^[a-z]{2,8}$")
    domain: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,39}$")
    text: str = Field(max_length=100_000)
    entities: list[Annotation] = Field(default_factory=list)
    source: str = "legacy-curated"
    tier: Literal["public", "external", "restricted"] = "public"
    format: str = Field(default="plain_text", pattern=r"^[a-z][a-z0-9_-]{1,39}$")
    split: (
        Literal[
            "train",
            "development",
            "validation",
            "release_gate",
            "private_release_gate",
            "adversarial",
            "adversarial_challenge",
            "negative",
            "external",
            "restricted",
            "private_holdout",
        ]
        | None
    ) = None
    transformation: str = "original"
    transformation_chain: list[str] = Field(default_factory=lambda: ["original"], min_length=1)
    transformation_support: Literal["supported", "partial", "deliberately_unsupported"] = (
        "supported"
    )
    template_group: str | None = None
    source_record_group: str | None = None
    source_document_group: str | None = None
    transformation_parent: str | None = None
    entity_value_group: str | None = None
    seed_group: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_annotations(self) -> CorpusSample:
        if self.transformation_chain[-1] != self.transformation:
            raise ValueError("transformation chain must end at the declared transformation")
        for item in self.entities:
            if item.end > len(self.text):
                raise ValueError("annotation exceeds sample text")
            if item.text is not None and self.text[item.start : item.end] != item.text:
                raise ValueError("annotation text does not match sample span")
        return self


class CorpusFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    corpus_version: Literal[1]
    split: Literal["development", "validation", "release_gate", "adversarial", "negative"]
    samples: list[CorpusSample]
