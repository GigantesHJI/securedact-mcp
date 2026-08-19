from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass

from .models import Detection, EntityType, RedactionMode, RedactionResult

_PERSON_NAME_PART = re.compile(r"[^\W\d_]+(?:['\u2019\-][^\W\d_]+)*", re.UNICODE)


@dataclass(frozen=True, slots=True)
class _PersonResolution:
    """Ephemeral request-local PERSON groups; values never leave this transformation."""

    group_by_index: dict[int, str]
    group_count: int
    aliases_merged: int
    ambiguous_mentions: int


def _normalized_person_parts(value: str) -> tuple[str, ...]:
    return tuple(part.casefold() for part in _PERSON_NAME_PART.findall(value))


def _resolve_person_aliases(entities: list[Detection]) -> _PersonResolution:
    """Group only exact names and unambiguous one-token PERSON aliases.

    A short form may match the exact first or last token of one distinct full
    normalized name. Multiple compatible full names make the short form
    ambiguous; it receives a separate group and is never assigned by recency.
    """

    mentions = [
        (index, entity, _normalized_person_parts(entity.text))
        for index, entity in enumerate(entities)
        if entity.entity_type == EntityType.PERSON
    ]
    full_names = {parts for _index, _entity, parts in mentions if len(parts) >= 2}
    provisional: dict[int, tuple[str, object]] = {}
    ambiguous_mentions = 0
    aliases_merged = 0

    for index, entity, parts in mentions:
        if not parts:
            provisional[index] = ("span", (entity.start, entity.end))
            continue
        if len(parts) >= 2:
            provisional[index] = ("full", parts)
            continue

        short = parts[0]
        compatible = {
            full_name for full_name in full_names if short in {full_name[0], full_name[-1]}
        }
        if len(compatible) == 1:
            provisional[index] = ("full", next(iter(compatible)))
            aliases_merged += 1
        elif len(compatible) > 1:
            provisional[index] = ("ambiguous", parts)
            ambiguous_mentions += 1
        else:
            provisional[index] = ("short", parts)

    first_position: dict[tuple[str, object], tuple[int, int]] = {}
    for index, entity, _parts in mentions:
        key = provisional[index]
        first_position[key] = min(
            first_position.get(key, (entity.start, index)),
            (entity.start, index),
        )
    group_ids = {
        key: f"person-group-{number}"
        for number, (key, _position) in enumerate(
            sorted(first_position.items(), key=lambda item: item[1]),
            start=1,
        )
    }
    return _PersonResolution(
        group_by_index={index: group_ids[key] for index, key in provisional.items()},
        group_count=len(group_ids),
        aliases_merged=aliases_merged,
        ambiguous_mentions=ambiguous_mentions,
    )


def redact_text(
    text: str,
    entities: list[Detection],
    mode: RedactionMode = RedactionMode.TYPED_TOKENS,
) -> RedactionResult:
    expanded = list(entities)
    occupied = {(entity.start, entity.end, entity.entity_type) for entity in expanded}
    occupied_spans = [(entity.start, entity.end) for entity in expanded]
    for entity in entities:
        if len(entity.text) < 4:
            continue
        for match in re.finditer(re.escape(entity.text), text):
            span_key = (match.start(), match.end(), entity.entity_type)
            if span_key in occupied:
                continue
            if any(
                match.start() < existing_end and existing_start < match.end()
                for existing_start, existing_end in occupied_spans
            ):
                continue
            expanded.append(
                Detection(
                    **entity.model_dump(exclude={"id", "start", "end", "text"}),
                    start=match.start(),
                    end=match.end(),
                    text=match.group(0),
                )
            )
            occupied.add(span_key)
            occupied_spans.append((match.start(), match.end()))
    ordered = sorted(expanded, key=lambda item: (item.start, item.end))
    person_resolution = _resolve_person_aliases(ordered)
    counters: defaultdict[str, int] = defaultdict(int)
    known_values: dict[tuple[str, str], str] = {}
    mapping: dict[str, str] = {}
    replacements: list[tuple[Detection, str]] = []
    custom_by_value: dict[tuple[str, str], str] = {}
    custom_owners: dict[str, tuple[str, str]] = {}

    def identity_key(index: int, entity: Detection) -> tuple[str, str]:
        person_group = person_resolution.group_by_index.get(index)
        return (
            (EntityType.PERSON.value, person_group)
            if person_group is not None
            else (entity.entity_type.value, entity.text)
        )

    for index, entity in enumerate(ordered):
        if entity.replacement is None:
            continue
        expected_prefix = f"[{entity.entity_type.value.upper()}_"
        if not entity.replacement.startswith(expected_prefix):
            raise ValueError("A custom pseudonym must preserve the entity category")
        value_key = identity_key(index, entity)
        existing_for_value = custom_by_value.get(value_key)
        if existing_for_value is not None and existing_for_value != entity.replacement:
            raise ValueError("One source entity cannot receive multiple pseudonyms")
        existing_owner = custom_owners.get(entity.replacement)
        if existing_owner is not None and existing_owner != value_key:
            raise ValueError("Different source entities must receive different pseudonyms")
        custom_by_value[value_key] = entity.replacement
        custom_owners[entity.replacement] = value_key

    for index, entity in enumerate(ordered):
        if replacements and entity.start < replacements[-1][0].end:
            raise ValueError("Entities must not overlap")
        if text[entity.start : entity.end] != entity.text:
            raise ValueError("Entity offsets do not match source text")
        if (
            entity.start > 0 and text[entity.start - 1].isalnum() and text[entity.start].isalnum()
        ) or (
            entity.end < len(text) and text[entity.end - 1].isalnum() and text[entity.end].isalnum()
        ):
            raise ValueError("A replacement may not split an alphanumeric identifier")
        if mode == RedactionMode.REMOVE:
            placeholder = "[REDACTED]"
        else:
            value_key = identity_key(index, entity)
            placeholder = known_values.get(value_key, "")
            if not placeholder:
                placeholder = custom_by_value.get(value_key, "")
            if not placeholder:
                while True:
                    counters[entity.entity_type.value] += 1
                    placeholder = (
                        f"[{entity.entity_type.value.upper()}_{counters[entity.entity_type.value]}]"
                    )
                    if placeholder not in custom_owners:
                        break
            if value_key not in known_values:
                known_values[value_key] = placeholder
                mapping[placeholder] = entity.text
        replacements.append((entity, placeholder))

    sanitized_text = text
    for entity, placeholder in reversed(replacements):
        sanitized_text = sanitized_text[: entity.start] + placeholder + sanitized_text[entity.end :]
    counts = Counter(entity.entity_type.value for entity in ordered)
    return RedactionResult(
        sanitized_text=sanitized_text,
        mapping=mapping,
        entities=ordered,
        entity_counts=dict(counts),
    )


def restore_text(text: str, mapping: dict[str, str]) -> str:
    if not mapping:
        return text
    placeholders = sorted((key for key in mapping if key), key=len, reverse=True)
    if not placeholders:
        return text
    pattern = re.compile("|".join(re.escape(placeholder) for placeholder in placeholders))
    return pattern.sub(lambda match: mapping[match.group(0)], text)
