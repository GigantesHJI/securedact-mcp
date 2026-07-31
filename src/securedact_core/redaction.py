from __future__ import annotations

import re
from collections import Counter, defaultdict

from .models import Detection, RedactionMode, RedactionResult


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
    counters: defaultdict[str, int] = defaultdict(int)
    known_values: dict[tuple[str, str], str] = {}
    mapping: dict[str, str] = {}
    replacements: list[tuple[Detection, str]] = []

    for entity in ordered:
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
            value_key = (entity.entity_type.value, entity.text)
            placeholder = known_values.get(value_key, "")
            if not placeholder:
                counters[entity.entity_type.value] += 1
                placeholder = (
                    f"[{entity.entity_type.value.upper()}_{counters[entity.entity_type.value]}]"
                )
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
