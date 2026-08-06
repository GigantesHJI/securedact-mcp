# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class BenchmarkProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]{2,39}$")
    description: str
    documents: int = Field(ge=1)
    minimum_entities: int = Field(ge=0)
    dutch_fraction: float = Field(ge=0, le=1)
    seed: int = Field(ge=0)
    tier: Literal["public", "external", "restricted"]
    commit_allowed: bool = False
    adapter_only: bool = False
    include_private_holdout: bool = False


def load_profiles(path: Path) -> dict[str, BenchmarkProfile]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("profile_version") != 1:
        raise ValueError("benchmark_profiles_invalid")
    raw_profiles = payload.get("profiles")
    if not isinstance(raw_profiles, list):
        raise ValueError("benchmark_profiles_invalid")
    profiles = {
        item.name: item
        for item in (BenchmarkProfile.model_validate(profile) for profile in raw_profiles)
    }
    if len(profiles) != len(raw_profiles):
        raise ValueError("benchmark_profile_duplicate")
    return profiles
