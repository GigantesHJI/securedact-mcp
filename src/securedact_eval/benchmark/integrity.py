# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import re
import unicodedata
from collections import defaultdict
from difflib import SequenceMatcher
from hashlib import sha256

from pydantic import BaseModel, ConfigDict, Field

from ..models import CorpusSample

TOKEN = re.compile(r"\w+", re.UNICODE)
APPROXIMATE_SIMILARITY_MINIMUM = 0.85


class IntegrityReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool
    sample_count: int
    duplicate_ids: list[list[str]] = Field(default_factory=list)
    exact_duplicates: list[list[str]] = Field(default_factory=list)
    normalized_duplicates: list[list[str]] = Field(default_factory=list)
    approximate_duplicates: list[list[str]] = Field(default_factory=list)
    leakage: dict[str, list[list[str]]] = Field(default_factory=dict)
    offset_errors: list[str] = Field(default_factory=list)
    unicode_errors: list[str] = Field(default_factory=list)
    provenance_errors: list[str] = Field(default_factory=list)
    overlap_errors: list[str] = Field(default_factory=list)
    transformation_errors: list[str] = Field(default_factory=list)


def normalize_text(text: str) -> str:
    return " ".join(TOKEN.findall(unicodedata.normalize("NFKC", text).casefold()))


def _simhash(text: str) -> int:
    vector = [0] * 64
    tokens = normalize_text(text).split()
    shingles = (
        tokens if len(tokens) < 3 else [" ".join(tokens[i : i + 3]) for i in range(len(tokens) - 2)]
    )
    for shingle in shingles:
        value = int.from_bytes(sha256(shingle.encode("utf-8")).digest()[:8], "big")
        for bit in range(64):
            vector[bit] += 1 if value & (1 << bit) else -1
    return sum(1 << bit for bit, weight in enumerate(vector) if weight >= 0)


def _duplicate_groups(samples: list[CorpusSample], key: object) -> list[list[str]]:
    grouped: dict[object, list[str]] = defaultdict(list)
    for sample in samples:
        grouped[key(sample)].append(sample.id)  # type: ignore[operator]
    return sorted(sorted(ids) for ids in grouped.values() if len(ids) > 1)


def validate_integrity(samples: list[CorpusSample]) -> IntegrityReport:
    duplicate_ids = _duplicate_groups(samples, lambda sample: sample.id)
    exact = _duplicate_groups(samples, lambda sample: sample.text)
    normalized = _duplicate_groups(samples, lambda sample: normalize_text(sample.text))
    approximate: list[list[str]] = []
    hashes = [(sample, normalize_text(sample.text), _simhash(sample.text)) for sample in samples]
    buckets: dict[tuple[int, int], list[int]] = defaultdict(list)
    compared: set[tuple[int, int]] = set()
    for index, (right, right_normalized, right_hash) in enumerate(hashes):
        candidates: set[int] = set()
        for band in range(4):
            key = (band, (right_hash >> (band * 16)) & 0xFFFF)
            candidates.update(buckets[key])
            buckets[key].append(index)
        for left_index in candidates:
            pair = (left_index, index)
            if pair in compared:
                continue
            compared.add(pair)
            left, left_normalized, left_hash = hashes[left_index]
            if left.split == right.split or left.text == right.text:
                continue
            similarity = SequenceMatcher(
                None, left_normalized, right_normalized, autojunk=False
            ).ratio()
            if (
                left_hash ^ right_hash
            ).bit_count() <= 2 and similarity >= APPROXIMATE_SIMILARITY_MINIMUM:
                approximate.append(sorted([left.id, right.id]))

    leakage: dict[str, list[list[str]]] = {}
    for attribute in (
        "template_group",
        "source_record_group",
        "source_document_group",
        "transformation_parent",
        "entity_value_group",
        "seed_group",
    ):
        groups: dict[str, list[CorpusSample]] = defaultdict(list)
        for sample in samples:
            value = getattr(sample, attribute)
            if value:
                groups[value].append(sample)
        violations = [
            sorted(item.id for item in values)
            for values in groups.values()
            if len({item.split for item in values}) > 1
        ]
        if violations:
            leakage[attribute] = sorted(violations)

    offsets: list[str] = []
    provenance: list[str] = []
    overlaps: list[str] = []
    transformations: list[str] = []
    unicode_errors: list[str] = []
    sample_ids = {sample.id for sample in samples}
    for sample in samples:
        if sample.text != unicodedata.normalize("NFC", sample.text):
            unicode_errors.append(sample.id)
        for number, entity in enumerate(sample.entities):
            if entity.end > len(sample.text) or (
                entity.text is not None and sample.text[entity.start : entity.end] != entity.text
            ):
                offsets.append(f"{sample.id}:{number}")
            if entity.text is None or not entity.provenance:
                provenance.append(f"{sample.id}:{number}")
        for left_index, left_entity in enumerate(sample.entities):
            for right_index, right_entity in enumerate(
                sample.entities[left_index + 1 :], left_index + 1
            ):
                if left_entity.start >= right_entity.end or right_entity.start >= left_entity.end:
                    continue
                nested = (
                    left_entity.start <= right_entity.start and left_entity.end >= right_entity.end
                ) or (
                    right_entity.start <= left_entity.start and right_entity.end >= left_entity.end
                )
                if not nested:
                    overlaps.append(f"{sample.id}:{left_index}:{right_index}")
        if sample.transformation_parent is not None and (
            sample.transformation_parent == sample.id
            or sample.transformation_parent not in sample_ids
        ):
            transformations.append(sample.id)
    valid = not any(
        (
            duplicate_ids,
            exact,
            normalized,
            approximate,
            leakage,
            offsets,
            unicode_errors,
            provenance,
            overlaps,
            transformations,
        )
    )
    return IntegrityReport(
        valid=valid,
        sample_count=len(samples),
        duplicate_ids=duplicate_ids,
        exact_duplicates=exact,
        normalized_duplicates=normalized,
        approximate_duplicates=sorted(approximate),
        leakage=leakage,
        offset_errors=offsets,
        unicode_errors=unicode_errors,
        provenance_errors=provenance,
        overlap_errors=overlaps,
        transformation_errors=transformations,
    )
