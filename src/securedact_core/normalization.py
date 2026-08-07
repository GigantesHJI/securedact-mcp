from __future__ import annotations

import html
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass

HTML_ENTITY_PATTERN = re.compile(
    r"&(?:#[0-9]{1,7}|#[xX][0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});"
)
PERCENT_BYTE_PATTERN = re.compile(r"(?:%[0-9A-Fa-f]{2})+")
ZERO_WIDTH_CHARACTERS = frozenset({"\u00ad", "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"})
PUNCTUATION_EQUIVALENTS = {
    "\u2018": "'",
    "\u2019": "'",
    "\u201a": "'",
    "\u201b": "'",
    "\u2032": "'",
    "\u02bc": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u201e": '"',
    "\u201f": '"',
    "\u2033": '"',
    "\u2010": "-",
    "\u2011": "-",
    "\u2012": "-",
    "\u2013": "-",
    "\u2014": "-",
    "\u2015": "-",
    "\u2212": "-",
}


@dataclass(frozen=True, slots=True)
class _MappedCharacter:
    value: str
    source_start: int
    source_end: int


@dataclass(frozen=True, slots=True)
class NormalizedText:
    """A detector view whose character spans map back to the source string."""

    original: str
    text: str
    source_ranges: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        if len(self.text) != len(self.source_ranges):
            raise ValueError("normalized text and source map lengths differ")
        previous_start = 0
        for start, end in self.source_ranges:
            if not 0 <= start < end <= len(self.original):
                raise ValueError("normalized source range is invalid")
            if start < previous_start:
                raise ValueError("normalized source ranges are not monotonic")
            previous_start = start

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        if not 0 <= start < end <= len(self.text):
            raise ValueError("normalized span is invalid")
        return self.source_ranges[start][0], self.source_ranges[end - 1][1]

    def original_text(self, start: int, end: int) -> str:
        source_start, source_end = self.original_span(start, end)
        return self.original[source_start:source_end]


def _range(characters: list[_MappedCharacter]) -> tuple[int, int]:
    return characters[0].source_start, characters[-1].source_end


def _mapped_output(
    value: str,
    source_start: int,
    source_end: int,
) -> list[_MappedCharacter]:
    return [_MappedCharacter(character, source_start, source_end) for character in value]


def _unicode_normalize(characters: list[_MappedCharacter]) -> list[_MappedCharacter]:
    output: list[_MappedCharacter] = []
    index = 0
    while index < len(characters):
        end = index + 1
        while end < len(characters) and unicodedata.combining(characters[end].value):
            end += 1
        cluster = characters[index:end]
        normalized = unicodedata.normalize("NFKC", "".join(item.value for item in cluster))
        source_start, source_end = _range(cluster)
        output.extend(_mapped_output(normalized, source_start, source_end))
        index = end
    return output


def _replace_pattern(
    characters: list[_MappedCharacter],
    pattern: re.Pattern[str],
    decode: Callable[[str], str],
) -> list[_MappedCharacter]:
    text = "".join(item.value for item in characters)
    output: list[_MappedCharacter] = []
    cursor = 0
    for match in pattern.finditer(text):
        output.extend(characters[cursor : match.start()])
        matched = characters[match.start() : match.end()]
        replacement = decode(match.group(0))
        if replacement == match.group(0):
            output.extend(matched)
        else:
            source_start, source_end = _range(matched)
            output.extend(_mapped_output(replacement, source_start, source_end))
        cursor = match.end()
    output.extend(characters[cursor:])
    return output


def _decode_percent_run(
    run: list[_MappedCharacter],
) -> list[_MappedCharacter]:
    output: list[_MappedCharacter] = []
    index = 0
    while index < len(run):
        first_byte = int(run[index + 1].value + run[index + 2].value, 16)
        width = (
            1
            if first_byte < 0x80
            else 2
            if 0xC2 <= first_byte <= 0xDF
            else 3
            if 0xE0 <= first_byte <= 0xEF
            else 4
            if 0xF0 <= first_byte <= 0xF4
            else 0
        )
        encoded_width = width * 3
        chunk = run[index : index + encoded_width]
        if not width or len(chunk) != encoded_width:
            output.extend(run[index : index + 3])
            index += 3
            continue
        try:
            decoded = bytes(
                int("".join(item.value for item in chunk[offset + 1 : offset + 3]), 16)
                for offset in range(0, encoded_width, 3)
            ).decode("utf-8")
        except UnicodeDecodeError:
            output.extend(run[index : index + 3])
            index += 3
            continue
        source_start, source_end = _range(chunk)
        output.extend(_mapped_output(decoded, source_start, source_end))
        index += encoded_width
    return output


def _decode_percent(characters: list[_MappedCharacter]) -> list[_MappedCharacter]:
    text = "".join(item.value for item in characters)
    output: list[_MappedCharacter] = []
    cursor = 0
    for match in PERCENT_BYTE_PATTERN.finditer(text):
        output.extend(characters[cursor : match.start()])
        output.extend(_decode_percent_run(characters[match.start() : match.end()]))
        cursor = match.end()
    output.extend(characters[cursor:])
    return output


def _collapse_whitespace(characters: list[_MappedCharacter]) -> list[_MappedCharacter]:
    output: list[_MappedCharacter] = []
    index = 0
    while index < len(characters):
        if not characters[index].value.isspace():
            output.append(characters[index])
            index += 1
            continue
        end = index + 1
        while end < len(characters) and characters[end].value.isspace():
            end += 1
        source_start, source_end = _range(characters[index:end])
        output.append(_MappedCharacter(" ", source_start, source_end))
        index = end
    return output


def normalize_for_detection(text: str, *, casefold: bool = False) -> NormalizedText:
    """Normalize a detector-only view without losing original Python string offsets."""

    characters = [_MappedCharacter(value, index, index + 1) for index, value in enumerate(text)]
    characters = _unicode_normalize(characters)
    characters = _replace_pattern(characters, HTML_ENTITY_PATTERN, html.unescape)
    characters = _decode_percent(characters)
    characters = _unicode_normalize(characters)
    characters = [
        _MappedCharacter(
            PUNCTUATION_EQUIVALENTS.get(item.value, item.value),
            item.source_start,
            item.source_end,
        )
        for item in characters
        if item.value not in ZERO_WIDTH_CHARACTERS
    ]
    characters = _collapse_whitespace(characters)
    if casefold:
        characters = [
            mapped
            for item in characters
            for mapped in _mapped_output(item.value.casefold(), item.source_start, item.source_end)
        ]
    return NormalizedText(
        original=text,
        text="".join(item.value for item in characters),
        source_ranges=tuple((item.source_start, item.source_end) for item in characters),
    )
