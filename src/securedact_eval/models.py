# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from securedact_core import EntityType, PrivacyAction


class Annotation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    start: int = Field(ge=0)
    end: int = Field(gt=0)
    entity_type: EntityType
    expected_action: PrivacyAction | None = None

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

    @model_validator(mode="after")
    def validate_annotations(self) -> CorpusSample:
        for item in self.entities:
            if item.end > len(self.text):
                raise ValueError("annotation exceeds sample text")
        return self


class CorpusFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    corpus_version: Literal[1]
    split: Literal["development", "validation", "release_gate", "adversarial", "negative"]
    samples: list[CorpusSample]
