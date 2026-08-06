# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import unicodedata
from collections import Counter
from collections.abc import Callable
from hashlib import sha256
from html import escape as html_escape
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from faker import Faker

from securedact_core import EntityType, PrivacyAction

from ..models import Annotation, CorpusSample
from .integrity import validate_integrity
from .manifest import BenchmarkManifest, sha256_file, write_manifest
from .profiles import BenchmarkProfile

GENERATOR_VERSION = "2.5.1"
type AssertionType = Literal[
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
]
type TransformationSupport = Literal["supported", "partial", "deliberately_unsupported"]
type BenchmarkSplit = Literal["train", "development", "validation", "release_gate"]
ASSERTION_TYPES: tuple[AssertionType, ...] = (
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
)
TRANSFORMATIONS: tuple[tuple[str, TransformationSupport], ...] = (
    ("original", "supported"),
    ("casing", "supported"),
    ("whitespace-insertion", "partial"),
    ("whitespace-removal", "partial"),
    ("line-wrapping", "supported"),
    ("punctuation-spacing", "supported"),
    ("url-encoding", "partial"),
    ("html-entities", "partial"),
    ("unicode-normalization", "supported"),
    ("zero-width", "deliberately_unsupported"),
    ("homoglyph", "deliberately_unsupported"),
    ("fullwidth", "partial"),
    ("ocr-like", "deliberately_unsupported"),
    ("dutch-surname-prefix", "supported"),
    ("initials", "partial"),
    ("apostrophe", "supported"),
    ("hyphenation", "partial"),
    ("spaced-iban", "supported"),
    ("split-phone", "partial"),
    ("email-obfuscation", "deliberately_unsupported"),
    ("nested-overlap", "partial"),
)
TEMPLATES = (
    ("healthcare", "medical_letter"),
    ("government", "case_note"),
    ("finance", "csv_row"),
    ("legal", "legal_form"),
    ("support", "support_ticket"),
    ("human_resources", "email_thread"),
    ("technology", "json_record"),
    ("education", "meeting_minutes"),
    ("customer_support", "chat"),
    ("general", "prose"),
    ("technology", "source_code"),
    ("technology", "configuration"),
    ("operations", "log_record"),
    ("government", "form"),
    ("technology", "yaml_record"),
    ("technology", "xml_record"),
    ("general", "markdown"),
    ("finance", "invoice"),
)

NEGATIVE_TEXTS = (
    "The clinic publishes general information about seasonal allergies.",
    "The council debated political participation without attributing an opinion.",
    "The museum exhibition discusses religions in European history.",
    "Public organization Example Research Foundation opens at nine.",
    "May and June are release milestones, not people.",
    "The product name Paris Edition is printed on the box.",
    "version=2.4.0 uuid=00000000-0000-0000-0000-000000000000",
    "sha256=d2a84f4b8b650937ec8f73cd8be2c74f",
    "localhost 127.0.0.1 and 192.0.2.10 are reserved test hosts.",
    "Visit docs.example.invalid for placeholder documentation.",
    "password_variable = 'placeholder'; token_count = 0",
    "No individual was diagnosed; this is a hypothetical training scenario.",
    "A quotation mentioned an opinion but attributed it to a fictional novel.",
    "Family history is discussed without identifying any family member.",
)

SPECIAL_VALUES: tuple[tuple[str, EntityType], ...] = (
    ("fictional ethnic heritage assertion", EntityType.RACIAL_OR_ETHNIC_ORIGIN),
    ("fictional political opinion assertion", EntityType.POLITICAL_OPINION),
    ("fictional religious belief assertion", EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF),
    ("fictional philosophical belief assertion", EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF),
    ("fictional trade-union membership assertion", EntityType.TRADE_UNION_MEMBERSHIP),
    ("fictional genetic test assertion", EntityType.GENETIC_DATA),
    ("fictional biometric identification assertion", EntityType.BIOMETRIC_DATA),
    ("fictional health-status assertion", EntityType.HEALTH_DATA),
    ("fictional sex-life assertion", EntityType.SEX_LIFE),
    ("fictional sexual-orientation assertion", EntityType.SEXUAL_ORIENTATION),
)


def _safe_slug(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())[:24]


def _split_for_template(template_number: int) -> BenchmarkSplit:
    return ("train", "development", "validation", "release_gate")[template_number % 4]


def _annotated_text(
    template: str,
    values: list[tuple[str, EntityType]],
    *,
    assertion_type: AssertionType,
    sample_id: str,
    nested: bool = False,
) -> tuple[str, list[Annotation]]:
    normalized_values = [(unicodedata.normalize("NFC", value), kind) for value, kind in values]
    text = unicodedata.normalize(
        "NFC", template.format(*[value for value, _kind in normalized_values])
    )
    entities: list[Annotation] = []
    cursor = 0
    for number, (value, kind) in enumerate(normalized_values):
        start = text.index(value, cursor)
        end = start + len(value)
        cursor = end
        entities.append(
            Annotation(
                start=start,
                end=end,
                text=value,
                entity_type=kind,
                expected_action=PrivacyAction.REDACT,
                assertion_type=assertion_type,
                provenance={
                    "source": "faker-40.35.0",
                    "generator": GENERATOR_VERSION,
                    "sample": sample_id,
                    "field": str(number),
                    "fictional": "true",
                },
            )
        )
    if nested and entities and len(entities[0].text or "") > 4:
        parent = entities[0]
        nested_start = parent.start + 1
        nested_end = parent.end - 1
        entities.append(
            Annotation(
                start=nested_start,
                end=nested_end,
                text=text[nested_start:nested_end],
                entity_type=EntityType.UNKNOWN_SENSITIVE,
                expected_action=PrivacyAction.REVIEW,
                assertion_type=assertion_type,
                provenance={
                    "source": "faker-40.35.0",
                    "generator": GENERATOR_VERSION,
                    "sample": sample_id,
                    "field": "nested-overlap",
                    "fictional": "true",
                },
            )
        )
    return text, entities


def _fullwidth(value: str) -> str:
    return "".join(
        chr(ord(character) + 0xFEE0) if "!" <= character <= "~" else character
        for character in value
    )


def _identity(value: str) -> str:
    return value


def _whitespace(value: str) -> str:
    return " ".join(value)


def _remove_whitespace(value: str) -> str:
    return "".join(value.split())


def _url_encoded(value: str) -> str:
    return quote(value, safe="")


def _html_entities(value: str) -> str:
    return html_escape(value).replace("@", "&#64;")


def _decomposed(value: str) -> str:
    return unicodedata.normalize("NFD", value)


def _zero_width(value: str) -> str:
    return "\u200b".join(value)


def _homoglyph(value: str) -> str:
    return value.replace("a", "\u0430").replace("A", "\u0391")


def _ocr(value: str) -> str:
    return value.replace("O", "0").replace("l", "1")


def _surname_prefix(value: str) -> str:
    return f"van der {value}"


def _initials(value: str) -> str:
    return ". ".join(part[:1] for part in value.split()) + "."


def _apostrophe(value: str) -> str:
    return f"{value}'s"


def _hyphenated(value: str) -> str:
    return value.replace(" ", "-")


def _spaced(value: str) -> str:
    compact = value.replace(" ", "")
    return " ".join(compact[index : index + 4] for index in range(0, len(compact), 4))


def _split(value: str) -> str:
    return " - ".join(value.split())


def _obfuscated(value: str) -> str:
    return value.replace("@", " [at] ").replace(".", " [dot] ")


VALUE_TRANSFORMERS: dict[str, Callable[[str], str]] = {
    "apostrophe": _apostrophe,
    "casing": str.swapcase,
    "dutch-surname-prefix": _surname_prefix,
    "email-obfuscation": _obfuscated,
    "fullwidth": _fullwidth,
    "homoglyph": _homoglyph,
    "html-entities": _html_entities,
    "hyphenation": _hyphenated,
    "initials": _initials,
    "ocr-like": _ocr,
    "spaced-iban": _spaced,
    "split-phone": _split,
    "unicode-normalization": _decomposed,
    "url-encoding": _url_encoded,
    "whitespace-insertion": _whitespace,
    "whitespace-removal": _remove_whitespace,
    "zero-width": _zero_width,
}


def _transform(
    template: str,
    values: list[tuple[str, EntityType]],
    transformation: str,
) -> tuple[str, list[tuple[str, EntityType]]]:
    transform_value = VALUE_TRANSFORMERS.get(transformation, _identity)
    if transformation == "casing":
        template = template.swapcase()
    elif transformation == "line-wrapping":
        template = template.replace(" | ", "\n").replace("; ", ";\n")
    elif transformation == "punctuation-spacing":
        template = template.replace(":", " : ").replace("=", " = ")
    return template, [(transform_value(value), kind) for value, kind in values]


def _sample(index: int, profile: BenchmarkProfile, *, language: str) -> CorpusSample:
    template_number = index % len(TEMPLATES)
    domain, document_format = TEMPLATES[template_number]
    locale = "nl_NL" if language == "nl" else "en_US"
    fake = Faker(locale)
    fake.seed_instance(profile.seed + index)
    sample_id = f"synthetic-{profile.name.replace('.', '-')}-{index:08d}"
    transformation, support = TRANSFORMATIONS[index % len(TRANSFORMATIONS)]
    positive_index = index - (index // 5 + 1) if index % 5 else index
    assertion_type = ASSERTION_TYPES[positive_index % len(ASSERTION_TYPES)]
    split = _split_for_template(template_number)

    if index % 5 == 0:
        negative = NEGATIVE_TEXTS[(index // 5) % len(NEGATIVE_TEXTS)]
        clean = (
            f"Algemene procesnotitie {index}: {negative}"
            if language == "nl"
            else f"General process note {index}: {negative}"
        )
        fingerprint = sha256(f"{profile.seed}:{index}:negative".encode()).hexdigest()
        clean += " synthetic markers " + " ".join(
            fingerprint[offset : offset + 8] for offset in range(0, 32, 8)
        )
        return CorpusSample(
            id=sample_id,
            language=language,
            domain=domain,
            text=clean,
            entities=[],
            source="faker-synthetic",
            tier=profile.tier,
            format=document_format,
            split=split,
            transformation=transformation,
            transformation_chain=(
                ["original"] if transformation == "original" else ["original", transformation]
            ),
            transformation_support=support,
            template_group=f"negative-{language}-{template_number}",
            source_record_group=sample_id,
            source_document_group=sample_id,
            entity_value_group=sample_id,
            seed_group=sample_id,
            metadata={"synthetic": True, "negative": True},
        )

    person = fake.name()
    email = f"case{profile.seed + index}@example.invalid"
    customer = f"CUST-{profile.seed % 10_000:04d}-{index:08d}"
    case = f"CASE-{index:08d}"
    phone = f"+31 20 {1000000 + index:07d}"
    choices: tuple[tuple[str, EntityType], ...] = (
        (person, EntityType.PERSON),
        (email, EntityType.EMAIL),
        (customer, EntityType.CUSTOMER_NUMBER),
        (case, EntityType.CASE_NUMBER),
        (phone, EntityType.PHONE),
        (f"sk-test-benchmark-{profile.seed + index:016d}", EntityType.API_TOKEN),
        (f"session_test_{profile.seed + index:016d}", EntityType.SESSION_TOKEN),
        (f"NL00 TEST {index:04d} {profile.seed % 10000:04d}", EntityType.IBAN),
    )
    if index % 2 == 0:
        first = (person, EntityType.PERSON)
        special_index = index // 2
        special_rank = special_index - special_index // 5 - 1
        second = SPECIAL_VALUES[special_rank % len(SPECIAL_VALUES)]
    else:
        first = choices[(index + template_number) % len(choices)]
        second = choices[(index + template_number + 3) % len(choices)]
    if language == "nl":
        formats = (
            "Medische brief — Betrokkene: {0}; contact: {1}. Alleen voor behandeling.",
            "Zaaknotitie | waarde={0} | tweede_waarde={1} | status=concept",
            "rekening,referentie\n{0},{1}",
            "Juridisch formulier: partij '{0}'; dossier '{1}'.",
            "Ticket #{0}\nGemelde contactwaarde: {1}",
            "Van: {0}\nOnderwerp: personeelszaak {1}",
            '{{"record":"{0}","contact":"{1}","synthetic":true}}',
            "Notulen: deelnemer {0}; actiehouder {1}.",
            "Chat — gebruiker: {0}\nagent: Ik noteer {1} alleen in deze test.",
            "In fictieve algemene tekst staat {0}; een tweede waarde is {1}.",
            "const syntheticRecord = '{0}'; // paired with {1}",
            "primary: {0}\nsecondary: {1}\nmode: synthetic",
            "INFO synthetic_event primary={0} secondary={1}",
            "Formulier\nVeld A: {0}\nVeld B: {1}",
            "record: '{0}'\ncontact: '{1}'\nsynthetic: true",
            '<record synthetic="true"><primary>{0}</primary><secondary>{1}</secondary></record>',
            "## Fictieve notitie\n- Primair: {0}\n- Secundair: {1}",
            "FACTUUR (TEST) | klant {0} | referentie {1}",
        )
    else:
        formats = (
            "Medical letter — Subject: {0}; contact: {1}. Treatment use only.",
            "Case note | value={0} | second_value={1} | status=draft",
            "account,reference\n{0},{1}",
            "Legal form: party '{0}'; file '{1}'.",
            "Ticket #{0}\nReported contact value: {1}",
            "From: {0}\nSubject: personnel case {1}",
            '{{"record":"{0}","contact":"{1}","synthetic":true}}',
            "Minutes: participant {0}; action owner {1}.",
            "Chat — user: {0}\nagent: I will record {1} only in this test.",
            "In fictional general prose, {0} appears beside {1}.",
            "const syntheticRecord = '{0}'; // paired with {1}",
            "primary: {0}\nsecondary: {1}\nmode: synthetic",
            "INFO synthetic_event primary={0} secondary={1}",
            "Form\nField A: {0}\nField B: {1}",
            "record: '{0}'\ncontact: '{1}'\nsynthetic: true",
            '<record synthetic="true"><primary>{0}</primary><secondary>{1}</secondary></record>',
            "## Fictional note\n- Primary: {0}\n- Secondary: {1}",
            "INVOICE (TEST) | customer {0} | reference {1}",
        )
    # Stable fictional record references prevent accidental cross-template near duplicates.
    fingerprint = sha256(f"{profile.seed}:{index}:positive".encode()).hexdigest()
    reference = "-".join(fingerprint[offset : offset + 8] for offset in range(0, 32, 8))
    suffix = f" [synthetic-record:{index:08d}:{reference}]"
    selected_template, selected_values = _transform(
        formats[template_number] + suffix, [first, second], transformation
    )
    text, entities = _annotated_text(
        selected_template,
        selected_values,
        assertion_type=assertion_type,
        sample_id=sample_id,
        nested=transformation == "nested-overlap",
    )
    entity_digest = sha256("\0".join(item.text or "" for item in entities).encode()).hexdigest()[
        :16
    ]
    return CorpusSample(
        id=sample_id,
        language=language,
        domain=domain,
        text=text,
        entities=entities,
        source="faker-synthetic",
        tier=profile.tier,
        format=document_format,
        split=split,
        transformation=transformation,
        transformation_chain=(
            ["original"] if transformation == "original" else ["original", transformation]
        ),
        transformation_support=support,
        template_group=f"positive-{language}-{template_number}",
        source_record_group=sample_id,
        source_document_group=sample_id,
        entity_value_group=f"values-{entity_digest}-{index:08d}",
        seed_group=sample_id,
        metadata={
            "synthetic": True,
            "fictional": True,
            "locale": locale,
            "template": template_number,
            "unsupported_example_retained": support == "deliberately_unsupported",
            "transformation_applied": True,
            "slug": _safe_slug(person),
        },
    )


def generate_samples(profile: BenchmarkProfile) -> list[CorpusSample]:
    if profile.adapter_only:
        raise ValueError("benchmark_profile_requires_adapter")
    dutch = round(profile.documents * profile.dutch_fraction)
    samples = [
        _sample(index, profile, language="nl" if index < dutch else "en")
        for index in range(profile.documents)
    ]
    if sum(len(sample.entities) for sample in samples) < profile.minimum_entities:
        raise ValueError("benchmark_profile_entity_minimum_not_met")
    return samples


def generate_profile(
    profile: BenchmarkProfile,
    output_dir: Path,
    *,
    repository_root: Path | None = None,
    allow_repository_output: bool = False,
) -> BenchmarkManifest:
    output = output_dir.resolve(strict=False)
    inside_repository = False
    if repository_root is not None:
        try:
            output.relative_to(repository_root.resolve())
            inside_repository = True
        except ValueError:
            inside_repository = False
        if inside_repository and (not allow_repository_output or not profile.commit_allowed):
            raise ValueError("benchmark_profile_must_use_external_workspace")
    if profile.tier == "restricted" and inside_repository:
        raise ValueError("restricted_benchmark_in_repository_forbidden")
    output.mkdir(parents=True, exist_ok=True)
    samples = generate_samples(profile)
    integrity = validate_integrity(samples)
    if not integrity.valid:
        raise ValueError(f"benchmark_integrity_failed:{integrity.model_dump_json()}")
    corpus_path = output / "corpus.jsonl"
    with corpus_path.open("w", encoding="utf-8", newline="\n") as handle:
        for sample in samples:
            handle.write(
                json.dumps(sample.model_dump(mode="json"), ensure_ascii=False, sort_keys=True)
            )
            handle.write("\n")
    languages = Counter(sample.language for sample in samples)
    sources = Counter(sample.source for sample in samples)
    splits = Counter(sample.split or "unspecified" for sample in samples)
    assertions = Counter(entity.assertion_type for sample in samples for entity in sample.entities)
    categories = Counter(
        entity.entity_type.value for sample in samples for entity in sample.entities
    )
    domains = Counter(sample.domain for sample in samples)
    transformations = Counter(sample.transformation for sample in samples)
    templates = Counter(str(sample.metadata.get("template", "negative")) for sample in samples)
    lock_path = (repository_root or Path.cwd()) / "uv.lock"
    if not lock_path.is_file():
        raise ValueError("benchmark_dependency_lock_missing")
    manifest = BenchmarkManifest(
        profile=profile.name,
        generator_version=GENERATOR_VERSION,
        seed=profile.seed,
        dependency_lock_digest=sha256_file(lock_path),
        tier=profile.tier,
        document_count=len(samples),
        entity_count=sum(len(sample.entities) for sample in samples),
        negative_count=sum(not sample.entities for sample in samples),
        adversarial_count=sum(sample.transformation != "original" for sample in samples),
        mixed_entity_count=sum(
            len({entity.entity_type for entity in sample.entities}) > 1 for sample in samples
        ),
        language_counts=dict(sorted(languages.items())),
        source_counts=dict(sorted(sources.items())),
        split_counts=dict(sorted(splits.items())),
        assertion_type_counts=dict(sorted(assertions.items())),
        category_counts=dict(sorted(categories.items())),
        domain_counts=dict(sorted(domains.items())),
        transformation_counts=dict(sorted(transformations.items())),
        template_family_counts=dict(sorted(templates.items())),
        files={"corpus.jsonl": sha256_file(corpus_path)},
        generation={
            "synthetic_only": True,
            "faker_version": "40.35.0",
            "contains_raw_source_data": False,
            "deterministic": True,
        },
    )
    write_manifest(output / "manifest.json", manifest)
    return manifest


def load_jsonl(path: Path) -> list[CorpusSample]:
    return [
        CorpusSample.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]
