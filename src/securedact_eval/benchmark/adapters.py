# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from securedact_core import EntityType

from ..models import Annotation, CorpusSample

MULTICONER_TYPES: dict[str, EntityType] = {
    "PER": EntityType.PERSON,
    "PERSON": EntityType.PERSON,
    "LOC": EntityType.LOCATION,
    "LOCATION": EntityType.LOCATION,
    "GRP": EntityType.ORGANIZATION,
    "CORP": EntityType.ORGANIZATION,
}


@dataclass(frozen=True, slots=True)
class AdapterResult:
    samples: list[CorpusSample]
    unmapped_labels: dict[str, int]
    attribution: str


def _bio_samples(
    sentences: Iterable[list[tuple[str, str]]],
    *,
    language: str,
    unmapped: dict[str, int] | None = None,
) -> Iterator[CorpusSample]:
    for number, sentence in enumerate(sentences):
        tokens = [token for token, _label in sentence]
        text = " ".join(tokens)
        offsets: list[tuple[int, int]] = []
        cursor = 0
        for token in tokens:
            offsets.append((cursor, cursor + len(token)))
            cursor += len(token) + 1
        entities: list[Annotation] = []
        active_type: EntityType | None = None
        active_start = 0
        active_end = 0
        for index, (_token, raw_label) in enumerate(sentence):
            prefix, _, name = raw_label.partition("-")
            mapped = MULTICONER_TYPES.get(name.upper()) if prefix in {"B", "I"} else None
            if prefix in {"B", "I"} and mapped is None and unmapped is not None:
                unmapped[name.upper()] = unmapped.get(name.upper(), 0) + 1
            if prefix == "I" and mapped == active_type:
                active_end = offsets[index][1]
                continue
            if active_type is not None:
                entities.append(
                    Annotation(
                        start=active_start,
                        end=active_end,
                        text=text[active_start:active_end],
                        entity_type=active_type,
                        provenance={"adapter": "multiconer-1"},
                    )
                )
            active_type = mapped
            if mapped is not None:
                active_start, active_end = offsets[index]
        if active_type is not None:
            entities.append(
                Annotation(
                    start=active_start,
                    end=active_end,
                    text=text[active_start:active_end],
                    entity_type=active_type,
                    provenance={"adapter": "multiconer-1"},
                )
            )
        yield CorpusSample(
            id=f"multiconer-{language}-{number:08d}",
            language=language,
            domain="multiconer",
            text=text,
            entities=entities,
            source="multiconer-1",
            tier="external",
            format="conll",
            split="external",
            source_record_group=f"multiconer-{language}-{number:08d}",
            source_document_group=f"multiconer-{language}-{number:08d}",
        )


def read_multiconer(path: Path, *, language: str) -> Iterator[CorpusSample]:
    """Read MultiCoNER-1 token/label files without retaining the raw source."""

    sentences: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            if current:
                sentences.append(current)
                current = []
            continue
        columns = line.split()
        if len(columns) < 2:
            raise ValueError("multiconer_row_invalid")
        current.append((columns[0], columns[-1]))
    if current:
        sentences.append(current)
    yield from _bio_samples(sentences, language=language)


def adapt_multiconer(path: Path, *, language: str) -> AdapterResult:
    sentences: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            if current:
                sentences.append(current)
                current = []
            continue
        columns = line.split()
        if len(columns) < 2:
            raise ValueError("multiconer_row_invalid")
        current.append((columns[0], columns[-1]))
    if current:
        sentences.append(current)
    unmapped: dict[str, int] = {}
    samples = list(_bio_samples(sentences, language=language, unmapped=unmapped))
    return AdapterResult(
        samples=samples,
        unmapped_labels=dict(sorted(unmapped.items())),
        attribution="MultiCoNER 1 dataset contributors; licensed CC BY 4.0; adapted by Securedact.",
    )


def read_dutch_open_government(
    path: Path,
    *,
    source_id: str,
    text_field: str = "text",
    id_field: str = "id",
) -> Iterator[CorpusSample]:
    """Generic adapter for pre-approved Dutch CSV or JSONL government extracts."""

    if path.suffix.casefold() == ".csv":
        with path.open(encoding="utf-8-sig", newline="") as handle:
            rows: Iterable[dict[str, Any]] = csv.DictReader(handle)
            yield from _government_rows(rows, source_id, text_field, id_field)
        return
    if path.suffix.casefold() == ".jsonl":
        rows = (json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line)
        yield from _government_rows(rows, source_id, text_field, id_field)
        return
    raise ValueError("government_adapter_format_unsupported")


def _government_rows(
    rows: Iterable[dict[str, Any]], source_id: str, text_field: str, id_field: str
) -> Iterator[CorpusSample]:
    for number, row in enumerate(rows):
        text = row.get(text_field)
        record_id = row.get(id_field, number)
        if not isinstance(text, str) or not text.strip():
            raise ValueError("government_adapter_text_missing")
        yield CorpusSample(
            id=f"{source_id}-{str(record_id).casefold().replace(' ', '-')}",
            language="nl",
            domain="government",
            text=text,
            entities=[],
            source=source_id,
            tier="external",
            format=path_format(row),
            split="external",
            source_record_group=f"{source_id}-{record_id}",
            source_document_group=f"{source_id}-{record_id}",
        )


def path_format(_row: dict[str, Any]) -> str:
    # Kept stable across CSV and JSONL so format grouping does not reveal a local filename.
    return "government_record"
