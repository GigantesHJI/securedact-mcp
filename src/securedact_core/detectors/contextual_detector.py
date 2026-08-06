from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

from ..models import (
    Detection,
    DetectionSource,
    EntityType,
    IndirectDisclosureRisk,
    SensitiveAssertion,
    TextSpan,
)

LEXICON_PATH = Path(__file__).with_name("lexicons") / "special_categories.v1.json"

NAME_WORD = (
    r"(?:[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ]+(?:['’.-][A-Za-zÀ-ÖØ-öø-ÿ]+)*"
    r"|[A-ZÀ-ÖØ-Þ](?:['’.-][A-Za-zÀ-ÖØ-öø-ÿ]+)+"
    r"|[A-ZÀ-ÖØ-Þ]\.)"
)
NAME_PATTERN = re.compile(
    rf"\b{NAME_WORD}"
    rf"(?:\s+(?:(?:de|den|der|van|von|al|el)\s+)?{NAME_WORD}){{0,3}}\b"
)
SELF_NAME_WORD = NAME_WORD
SELF_NAME_PATTERN = re.compile(
    r"(?i:\b(?:my name is|mijn naam is)\s+)"
    rf"(?P<name>{SELF_NAME_WORD}(?:\s+(?:(?:de|den|der|van|von|al|el)\s+)?"
    rf"{SELF_NAME_WORD}){{0,3}})\b"
)
PRONOUN_PATTERN = re.compile(
    r"\b(?:she|he|her|his|they|their|the patient|patient|zij|ze|hij|haar|zijn|de patiënt)\b",
    re.IGNORECASE,
)
NEGATION_PATTERN = re.compile(
    r"\b(?:not|never|no longer|geen|niet|nooit)\b",
    re.IGNORECASE,
)
RELATIONSHIP_PATTERN = re.compile(
    r"\b(?:her|his|their|haar|zijn|hun)\s+"
    r"(?:mother|father|spouse|wife|husband|child|guardian|manager|"
    r"moeder|vader|partner|echtgenote|echtgenoot|kind|voogd|manager)\b"
    r"|\b(?:the|de)\s+(?:mother|father|parent|guardian|moeder|vader|ouder|voogd)\s+(?:of|van)\b"
    r"|\b(?:emergency contact|patient of|noodcontact|patiënt van)\b",
    re.IGNORECASE,
)
DOSAGE_PATTERN = re.compile(
    r"\b\d+(?:[.,]\d+)?\s*(?:mg|mcg|µg|g|ml|units?)"
    r"(?:\s+(?:once|twice|three times|daily|weekly|per day|"
    r"eenmaal|tweemaal|dagelijks|wekelijks|per dag))?(?:\s+daily|\s+daags)?\b",
    re.IGNORECASE,
)
MEDICATION_PATTERN = re.compile(
    r"\b(?:metformin|insulin|lisinopril|atorvastatin|amoxicillin|"
    r"metformine|insuline)\b",
    re.IGNORECASE,
)
CONDITION_PATTERN = re.compile(
    r"\b(?:type\s*2\s*diabetes|diabetes\s*type\s*2|hypertension|"
    r"high blood pressure|cancer|asthma|depression|hoge bloeddruk|kanker)\b",
    re.IGNORECASE,
)
INDIRECT_HIGH_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"attends?\s+(?:a\s+)?mosque",
        r"services?\s+every\s+(?:friday|sunday)",
        r"\b(?:her wife|his husband|haar vrouw|zijn man)\b",
        r"\bunion dues\b",
        r"\bchemotherapy session\b",
        r"\bfingerprint template\b",
        r"\biris scan\b",
        r"\bvoiceprint\b",
    )
)


def _load_lexicon(path: Path = LEXICON_PATH) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Special-category lexicon must be an object")
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported special-category lexicon schema")
    if not isinstance(data.get("categories"), dict):
        raise ValueError("Special-category lexicon has no categories")
    return cast(dict[str, Any], data)


class ContextualPrivacyDetector:
    """Local English/Dutch contextual rules with assertion-level subject linking.

    This deterministic contextual layer complements Flair. It deliberately does not
    declare itself as the required statistical detector, so it can never make a
    missing required Flair model appear ready.
    """

    name = "contextual_rules"
    contextual = False

    def __init__(self, lexicon_path: Path | None = None) -> None:
        data = _load_lexicon(lexicon_path or LEXICON_PATH)
        self.schema_version = int(data["schema_version"])
        self.categories = {
            EntityType(key): tuple(sorted(values, key=len, reverse=True))
            for key, values in data["categories"].items()
        }
        self.relations = tuple(sorted(data["relations"], key=len, reverse=True))
        self.general_markers = tuple(
            marker.casefold() for marker in data["general_discussion_markers"]
        )
        relation_pattern = "|".join(re.escape(value) for value in self.relations)
        self._relation_pattern = re.compile(rf"\b(?:{relation_pattern})\b", re.IGNORECASE)

    def detect(self, text: str) -> list[Detection]:
        detections, _ = self._analyze(text)
        return detections

    def detect_assertions(self, text: str) -> list[SensitiveAssertion]:
        _, assertions = self._analyze(text)
        return assertions

    def _analyze(self, text: str) -> tuple[list[Detection], list[SensitiveAssertion]]:
        detections: list[Detection] = []
        assertions: list[SensitiveAssertion] = []
        known_people: list[Detection] = []
        relationship_person_ids: set[str] = set()

        for match in SELF_NAME_PATTERN.finditer(text):
            start, end = match.span("name")
            detections.append(
                Detection(
                    start=start,
                    end=end,
                    text=text[start:end],
                    entity_type=EntityType.PERSON,
                    confidence=1.0,
                    source=DetectionSource.CONTEXTUAL,
                    rule="self_identified_person",
                    precedence=70,
                )
            )

        for match in NAME_PATTERN.finditer(text):
            if self._looks_like_non_person(match.group(0)):
                continue
            person = Detection(
                start=match.start(),
                end=match.end(),
                text=match.group(0),
                entity_type=EntityType.PERSON,
                confidence=0.82,
                source=DetectionSource.CONTEXTUAL,
                rule="contextual_person_candidate",
                precedence=20,
            )
            known_people.append(person)

        for sentence_start, sentence_end, sentence in self._sentences(text):
            lowered = sentence.casefold()
            general_discussion = any(marker in lowered for marker in self.general_markers)
            relationships = list(RELATIONSHIP_PATTERN.finditer(sentence))
            if relationships:
                relationship_person_ids.update(
                    person.id
                    for person in known_people
                    if sentence_start <= person.start < sentence_end
                )
            for match in relationships:
                detections.append(
                    Detection(
                        start=sentence_start + match.start(),
                        end=sentence_start + match.end(),
                        text=match.group(0),
                        entity_type=EntityType.RELATIONSHIP,
                        confidence=0.88,
                        source=DetectionSource.CONTEXTUAL,
                        rule="relationship_phrase",
                        precedence=45,
                        rationale_code="person_relationship_context",
                    )
                )

            if general_discussion:
                continue

            sentence_people = [
                person for person in known_people if sentence_start <= person.start < sentence_end
            ]
            pronoun = PRONOUN_PATTERN.search(sentence)
            record_subject_reference = bool(
                pronoun
                and re.search(
                    r"\b(?:the patient|patient|de patiÃ«nt)\b",
                    sentence,
                    re.IGNORECASE,
                )
            )
            linked_people = (
                sentence_people
                or self._nearest_people(
                    known_people,
                    sentence_start,
                    limit=1,
                )
                if pronoun
                else sentence_people
            )

            for category, concepts in self.categories.items():
                concept_matches = [
                    (
                        concept,
                        re.search(
                            rf"(?<!\w){re.escape(concept)}(?!\w)",
                            sentence,
                            re.IGNORECASE,
                        ),
                    )
                    for concept in concepts
                ]
                concept_matches = [
                    (concept, match) for concept, match in concept_matches if match is not None
                ]
                if not concept_matches:
                    continue

                # Prefer the actual special-category identifier over a nearby
                # descriptive label. This avoids replacing only "DNA profile"
                # or "Fingerprint template" while leaving its identifier.
                preferred_match = None
                if category == EntityType.GENETIC_DATA:
                    preferred_match = next(
                        (
                            match
                            for concept, match in concept_matches
                            if concept.casefold() in {"brca1", "brca2"}
                        ),
                        None,
                    )
                elif category == EntityType.BIOMETRIC_DATA:
                    preferred_match = next(
                        (
                            match
                            for match in re.finditer(
                                r"(?<![A-Z0-9])(?:BIO|FACE|IRIS|VOICE)-"
                                r"[A-Z0-9][A-Z0-9._/-]{1,125}[A-Z0-9]",
                                sentence,
                                re.IGNORECASE,
                            )
                            if any(character.isdigit() for character in match.group())
                        ),
                        None,
                    )
                elif category == EntityType.SEXUAL_ORIENTATION:
                    preferred_match = next(
                        (
                            match
                            for concept, match in concept_matches
                            if concept.casefold()
                            in {
                                "bisexual",
                                "biseksueel",
                                "lesbian",
                                "lesbisch",
                                "gay",
                                "homosexual",
                                "her wife",
                                "his husband",
                                "haar vrouw",
                                "zijn man",
                            }
                        ),
                        None,
                    )
                concept_match = preferred_match or concept_matches[0][1]
                if concept_match is None:
                    continue

                relation = self._relation_pattern.search(sentence)
                structured_record = self._structured_record_context(
                    sentence,
                    category,
                )
                relationship_inference = category == EntityType.SEXUAL_ORIENTATION and any(
                    value in lowered
                    for value in ("her wife", "his husband", "haar vrouw", "zijn man")
                )
                if not linked_people and not structured_record and not record_subject_reference:
                    continue
                if (
                    relation is None
                    and not structured_record
                    and not relationship_inference
                    and not record_subject_reference
                ):
                    continue

                evidence_start = sentence_start + concept_match.start()
                evidence_end = sentence_start + concept_match.end()
                evidence = Detection(
                    start=evidence_start,
                    end=evidence_end,
                    text=text[evidence_start:evidence_end],
                    entity_type=category,
                    confidence=0.90 if structured_record else 0.86,
                    source=DetectionSource.CONTEXTUAL,
                    rule=f"special_category_lexicon_v{self.schema_version}",
                    precedence=55,
                    rationale_code=(
                        "labelled_special_category_field"
                        if structured_record
                        else "person_specific_sensitive_assertion"
                    ),
                )
                detections.append(evidence)
                subject_ids = [person.id for person in linked_people]
                if (structured_record or record_subject_reference) and not subject_ids:
                    subject_ids = ["record-subject"]
                assertions.append(
                    SensitiveAssertion(
                        subject_entity_ids=subject_ids,
                        category=category,
                        full_span_start=sentence_start,
                        full_span_end=sentence_end,
                        sentence_start=sentence_start,
                        sentence_end=sentence_end,
                        evidence_spans=[
                            TextSpan(
                                start=evidence_start,
                                end=evidence_end,
                                text=text[evidence_start:evidence_end],
                            )
                        ],
                        confidence=evidence.confidence,
                        detector=self.name,
                        requires_review=True,
                        rationale_code=evidence.rationale_code
                        or "person_specific_sensitive_assertion",
                        negated=bool(NEGATION_PATTERN.search(sentence)),
                        indirect_disclosure_risk=self.assess_indirect_disclosure(
                            sentence,
                            category,
                        ),
                    )
                )

            detections.extend(self._medical_findings(text, sentence_start, sentence))

        # Only expose person candidates that participate in a contextual assertion.
        linked_ids = {
            subject_id
            for assertion in assertions
            for subject_id in assertion.subject_entity_ids
            if subject_id != "record-subject"
        } | relationship_person_ids
        detections.extend(person for person in known_people if person.id in linked_ids)
        return self._deduplicate(detections), self._deduplicate_assertions(assertions)

    @staticmethod
    def _medical_findings(
        text: str,
        sentence_start: int,
        sentence: str,
    ) -> list[Detection]:
        output: list[Detection] = []
        for pattern, entity_type, rule in (
            (CONDITION_PATTERN, EntityType.MEDICAL_CONDITION, "medical_condition_context"),
            (MEDICATION_PATTERN, EntityType.MEDICATION, "medication_context"),
            (DOSAGE_PATTERN, EntityType.DOSAGE, "dosage_context"),
        ):
            for match in pattern.finditer(sentence):
                start = sentence_start + match.start()
                end = sentence_start + match.end()
                output.append(
                    Detection(
                        start=start,
                        end=end,
                        text=text[start:end],
                        entity_type=entity_type,
                        confidence=0.88,
                        source=DetectionSource.CONTEXTUAL,
                        rule=rule,
                        precedence=50,
                        rationale_code=rule,
                    )
                )
        return output

    @staticmethod
    def assess_indirect_disclosure(
        sentence: str,
        category: EntityType,
    ) -> IndirectDisclosureRisk:
        if any(pattern.search(sentence) for pattern in INDIRECT_HIGH_PATTERNS):
            return IndirectDisclosureRisk.HIGH
        if category in {
            EntityType.GENETIC_DATA,
            EntityType.BIOMETRIC_DATA,
            EntityType.HEALTH_DATA,
            EntityType.SEXUAL_ORIENTATION,
            EntityType.TRADE_UNION_MEMBERSHIP,
            EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF,
        }:
            return IndirectDisclosureRisk.POSSIBLE
        return IndirectDisclosureRisk.SAFE

    @staticmethod
    def _structured_record_context(sentence: str, category: EntityType) -> bool:
        labels: dict[EntityType, tuple[str, ...]] = {
            EntityType.RACIAL_OR_ETHNIC_ORIGIN: ("ethnicity:", "racial origin:", "etniciteit:"),
            EntityType.POLITICAL_OPINION: (
                "political preference:",
                "political opinion:",
                "politieke voorkeur:",
            ),
            EntityType.RELIGIOUS_OR_PHILOSOPHICAL_BELIEF: (
                "religion:",
                "faith:",
                "religie:",
                "geloof:",
            ),
            EntityType.TRADE_UNION_MEMBERSHIP: ("union membership:", "trade union:", "vakbond:"),
            EntityType.GENETIC_DATA: ("genetic test:", "genome:", "dna profile", "dna-profiel"),
            EntityType.BIOMETRIC_DATA: (
                "fingerprint",
                "face template",
                "face-recognition embedding",
                "iris scan",
                "voiceprint",
            ),
            EntityType.HEALTH_DATA: ("diagnosis:", "medical history:", "diagnose:"),
            EntityType.SEX_LIFE: ("sex life:", "sexual activity", "seksleven:"),
            EntityType.SEXUAL_ORIENTATION: ("sexual orientation:", "seksuele geaardheid:"),
        }
        lowered = sentence.casefold()
        return any(label in lowered for label in labels.get(category, ()))

    @staticmethod
    def _nearest_people(
        people: list[Detection],
        before: int,
        *,
        limit: int,
    ) -> list[Detection]:
        candidates = [person for person in people if person.end <= before]
        return sorted(candidates, key=lambda person: person.end, reverse=True)[:limit]

    @staticmethod
    def _looks_like_non_person(value: str) -> bool:
        lowered = value.casefold()
        words = {
            "the",
            "article",
            "report",
            "green party",
            "labour party",
            "south asian",
            "example workers union",
            "dna profile",
            "political preference",
        }
        return lowered in words or lowered.startswith(("the ", "a "))

    @staticmethod
    def _sentences(text: str) -> list[tuple[int, int, str]]:
        output: list[tuple[int, int, str]] = []
        for match in re.finditer(r"[^\n.!?]+(?:[.!?]+|$)", text):
            raw = match.group(0)
            leading = len(raw) - len(raw.lstrip())
            sentence = raw.strip()
            if not sentence:
                continue
            start = match.start() + leading
            output.append((start, start + len(sentence), sentence))
        return output

    @staticmethod
    def _deduplicate(detections: list[Detection]) -> list[Detection]:
        unique: dict[tuple[int, int, EntityType], Detection] = {}
        for detection in detections:
            unique[(detection.start, detection.end, detection.entity_type)] = detection
        return list(unique.values())

    @staticmethod
    def _deduplicate_assertions(
        assertions: list[SensitiveAssertion],
    ) -> list[SensitiveAssertion]:
        unique: dict[tuple[int, int, EntityType], SensitiveAssertion] = {}
        for assertion in assertions:
            unique[
                (
                    assertion.full_span_start,
                    assertion.full_span_end,
                    assertion.category,
                )
            ] = assertion
        return list(unique.values())
