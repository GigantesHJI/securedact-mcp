from __future__ import annotations

import json
import re
from itertools import pairwise
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
from ..normalization import (
    NormalizedText,
    normalize_for_detection,
    requires_detection_normalization,
)
from .regex_detector import LABEL_RULES

LEXICON_PATH = Path(__file__).with_name("lexicons") / "special_categories.v1.json"

# Separators that bind a field label to its value.
_SEP_RE = r"(?:[:#=]|-)"

# Optional generic lead-in verbs that may precede a field label in a record
# (e.g. "recorded ethnicity:", "vermeld etniciteit:"). These are language-general
# phrasing patterns, not benchmark phrases.
_LEAD_VERBS_EN = (
    "recorded",
    "noted",
    "stated",
    "documented",
    "reported",
    "indicated",
    "listed",
    "specified",
    "provided",
    "notified",
    "confirmed",
    "registered",
)
_LEAD_VERBS_NL = (
    "vermeld",
    "veld",
    "opgegeven",
    "genoteerd",
    "geregistreerd",
    "vastgelegd",
    "aangegeven",
    "ingevuld",
    "genoemd",
)
LEAD_VERBS = _LEAD_VERBS_EN + _LEAD_VERBS_NL

# Non-Article-9 form headers that may follow an Article-9 value; used only to
# bound value spans (stop the value at the next field) and to reject a value
# that is itself a bare field header.
NON_SPECIAL_FIELD_HEADERS = (
    "name",
    "naam",
    "nationality",
    "nationaliteit",
    "occupation",
    "beroep",
    "employer",
    "werkgever",
)

NAME_WORD = (
    r"(?:[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ]+(?:['’.-][A-Za-zÀ-ÖØ-öø-ÿ]+)*"
    r"|[A-ZÀ-ÖØ-Þ](?:['’.-][A-Za-zÀ-ÖØ-öø-ÿ]+)+"
    r"|[A-ZÀ-ÖØ-Þ]\.)"
)
NAME_PARTICLES = r"(?:(?:de|den|der|van|von|al|el)\s+)"
NAME_PATTERN = re.compile(
    rf"\b(?:{NAME_PARTICLES}){{0,3}}{NAME_WORD}"
    rf"(?:\s+(?:{NAME_PARTICLES}){{0,3}}{NAME_WORD}){{0,3}}(?!\w)"
)
SELF_NAME_WORD = NAME_WORD
SELF_NAME_PATTERN = re.compile(
    r"(?i:\b(?:my name is|mijn naam is)\s+)"
    rf"(?P<name>(?:{NAME_PARTICLES}){{0,3}}{SELF_NAME_WORD}"
    rf"(?:\s+(?:{NAME_PARTICLES}){{0,3}}{SELF_NAME_WORD}){{0,3}})(?!\w)"
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
_STRUCTURED_FIELD_PATTERN = re.compile(
    r"(?<!\w)(?:"
    + "|".join(
        re.escape(label)
        for label in sorted(
            {label for rule in LABEL_RULES for label in rule.labels},
            key=len,
            reverse=True,
        )
    )
    + r")\s*(?::|=|#)",
    re.IGNORECASE,
)


def _load_lexicon(path: Path = LEXICON_PATH) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Special-category lexicon must be an object")
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported special-category lexicon schema")
    if not isinstance(data.get("categories"), dict):
        raise ValueError("Special-category lexicon has no categories")
    if "field_labels" in data and not isinstance(data["field_labels"], dict):
        raise ValueError("Special-category lexicon field_labels must be an object")
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
        # Field-label vocabulary: a recognised Article-9 field header (e.g.
        # "religion:", "etniciteit:") maps to the category it discloses. A bare
        # header is never itself a sensitive value; the value is the text that
        # follows the separator. This cleanly separates category-name tokens from
        # actual sensitive value concepts.
        self.field_labels: dict[str, EntityType] = {
            label.casefold(): EntityType(category)
            for label, category in (data.get("field_labels") or {}).items()
        }
        self.lead_verbs = LEAD_VERBS
        # Headers that terminate a value span (next field) or, if they are the
        # whole value, cause the field to be treated as empty.
        self._value_stop_labels: set[str] = (
            set(self.field_labels.keys())
            | {label.casefold() for rule in LABEL_RULES for label in rule.labels}
            | {header.casefold() for header in NON_SPECIAL_FIELD_HEADERS}
        )
        self._field_patterns = self._compile_field_patterns()
        self._next_field_re = re.compile(
            r"(?:"
            + "|".join(
                re.escape(label) for label in sorted(self._value_stop_labels, key=len, reverse=True)
            )
            + r")\s*"
            + _SEP_RE,
            re.IGNORECASE,
        )
        # A value continues only until the next *any* field header
        # (``Label:``/``Label =``), not just a recognised Article-9 header. Form
        # records interleave Article-9 fields with generic headers such as
        # ``Case:``/``Zaak:``/``Citizen:``; otherwise the value would run into the
        # following field (normalization also collapses the source newline that
        # used to bound it).
        # A value continues only until the next *any* single-word field header
        # (``Label:``/``Label =``), not just a recognised Article-9 header. Form
        # records interleave Article-9 fields with generic single-word headers
        # such as ``Case:``/``Zaak:``/``Citizen:``; otherwise the value would run
        # into the following field (normalization also collapses the source
        # newline that used to bound it). Multi-word known headers are covered by
        # ``_next_field_re``. The pattern is deliberately single-word so a value
        # word cannot be paired with a later colon and consumed. A hyphen is NOT a
        # boundary separator here: values such as ``Turkish-Dutch`` must keep their
        # internal hyphen (the hyphen separator only applies between a label and its
        # value in ``_SEP_RE``).
        self._value_bound_re = re.compile(
            r"\b[A-Za-zÀ-ÖØ-öø-ÿ]+(?:-[A-Za-zÀ-ÖØ-öø-ÿ]+)*\s*[:#=]",
            re.IGNORECASE,
        )
        self.relations = tuple(sorted(data["relations"], key=len, reverse=True))
        self.general_markers = tuple(
            marker.casefold() for marker in data["general_discussion_markers"]
        )
        relation_pattern = "|".join(re.escape(value) for value in self.relations)
        self._relation_pattern = re.compile(rf"\b(?:{relation_pattern})\b", re.IGNORECASE)

    def _compile_field_patterns(self) -> list[tuple[re.Pattern[str], EntityType]]:
        patterns: list[tuple[re.Pattern[str], EntityType]] = []
        for label, category in sorted(
            self.field_labels.items(), key=lambda kv: len(kv[0]), reverse=True
        ):
            pattern = re.compile(
                r"(?:(?:"
                + "|".join(re.escape(verb) for verb in self.lead_verbs)
                + r")\s+)?"
                + re.escape(label)
                + r"\s*"
                + _SEP_RE
                + r"\s*",
                re.IGNORECASE,
            )
            patterns.append((pattern, category))
        return patterns

    def detect(self, text: str) -> list[Detection]:
        detections, _ = self._analyze(text)
        return detections

    def detect_assertions(self, text: str) -> list[SensitiveAssertion]:
        _, assertions = self._analyze(text)
        return assertions

    def _analyze(self, text: str) -> tuple[list[Detection], list[SensitiveAssertion]]:
        if not requires_detection_normalization(text):
            return self._analyze_view(text)
        normalized = normalize_for_detection(text)
        detections, assertions = self._analyze_view(normalized.text)
        mapped_detections = [self._map_detection(normalized, detection) for detection in detections]
        id_map = {
            source.id: mapped.id
            for source, mapped in zip(detections, mapped_detections, strict=True)
        }
        mapped_assertions = [
            self._map_assertion(normalized, assertion, id_map) for assertion in assertions
        ]
        return mapped_detections, mapped_assertions

    def _analyze_view(self, text: str) -> tuple[list[Detection], list[SensitiveAssertion]]:
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
            end = match.end()
            if match.group(0).casefold().endswith(("'s", "\u2019s")):
                end -= 2
            person = Detection(
                start=match.start(),
                end=end,
                text=text[match.start() : end],
                entity_type=EntityType.PERSON,
                confidence=0.82,
                source=DetectionSource.CONTEXTUAL,
                rule="contextual_person_candidate",
                precedence=20,
            )
            known_people.append(person)

        # Pre-compute structured-field value spans so the per-category loop never
        # also emits a generic value-concept match that falls inside an already
        # extracted structured value (that would double-count the same disclosure).
        struct_detections, struct_assertions = self._extract_structured_fields(text)
        struct_spans = {(detection.start, detection.end) for detection in struct_detections}

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

                # A category-name token that appears in field-header position
                # (immediately followed by a value separator) is not itself the
                # sensitive value; it is a form label. The dedicated structured
                # field extraction emits the adjacent value instead, so we must
                # not also emit the bare label here (that would be the FP-A class
                # of errors: emitting "religion" while missing "Jewish").
                filtered_concepts = [
                    (concept, match)
                    for concept, match in concept_matches
                    if not self._is_field_label_position(sentence, match)
                ]
                if not filtered_concepts:
                    continue
                # Skip value concepts that are already covered by a structured-field
                # value span to avoid duplicate findings for the same disclosure.
                filtered_concepts = [
                    (concept, match)
                    for concept, match in filtered_concepts
                    if not self._span_contained_in(
                        sentence_start + match.start(),
                        sentence_start + match.end(),
                        struct_spans,
                    )
                ]
                if not filtered_concepts:
                    continue
                concept_matches = filtered_concepts

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
                explicit_subject = bool(
                    relation
                    and self._explicit_record_subject(
                        sentence,
                        relation.start(),
                    )
                )
                if (
                    not linked_people
                    and not structured_record
                    and not record_subject_reference
                    and not explicit_subject
                ):
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
                if (
                    structured_record or record_subject_reference or explicit_subject
                ) and not subject_ids:
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

        # Structured Article-9 fields were pre-computed at the start of _analyze_view;
        # merge their detections and assertions now (after the sentence loop so any
        # person-linking bookkeeping above has settled).
        detections.extend(struct_detections)
        assertions.extend(struct_assertions)

        # Only expose person candidates that participate in a contextual assertion.
        linked_ids = {
            subject_id
            for assertion in assertions
            for subject_id in assertion.subject_entity_ids
            if subject_id != "record-subject"
        } | relationship_person_ids
        detections.extend(person for person in known_people if person.id in linked_ids)
        return self._deduplicate(detections), self._deduplicate_assertions(assertions)

    def _is_field_label_position(self, sentence: str, match: re.Match[str]) -> bool:
        """True when a matched category-name token is acting as a field header.

        A header is a label immediately followed by a value separator (``:``,
        ``=``, ``#`` or ``-``). In that position the token names the field rather
        than being the sensitive value, so it must not be emitted as a finding.
        """

        token = sentence[match.start() : match.end()].casefold()
        if token not in self.field_labels:
            return False
        after = sentence[match.end() :]
        return bool(re.match(r"\s*" + _SEP_RE, after))

    @staticmethod
    def _span_contained_in(start: int, end: int, spans: set[tuple[int, int]]) -> bool:
        """True when [start, end) lies entirely within one of the given spans."""

        return any(s_start <= start and end <= s_end for s_start, s_end in spans)

    def _extract_structured_fields(
        self, text: str
    ) -> tuple[list[Detection], list[SensitiveAssertion]]:
        """Emit the value spans of recognised Article-9 field headers.

        For each ``Label<sep>Value`` (or ``Label:<newline>Value``) occurrence the
        value is extracted and emitted as the mapped category. The header token is
        never emitted. The value is bounded by the next field header, a newline,
        or trailing punctuation so a following form field is never swallowed.
        """

        detections: list[Detection] = []
        assertions: list[SensitiveAssertion] = []
        for pattern, category in self._field_patterns:
            for match in pattern.finditer(text):
                value_span = self._field_value_span(text, match.end())
                if value_span is None:
                    continue
                start, end = value_span
                value_text = text[start:end]
                detections.append(
                    Detection(
                        start=start,
                        end=end,
                        text=value_text,
                        entity_type=category,
                        confidence=0.90,
                        source=DetectionSource.CONTEXTUAL,
                        rule=f"special_category_field_value_v{self.schema_version}",
                        precedence=55,
                        rationale_code="labelled_special_category_field",
                    )
                )
                assertions.append(
                    SensitiveAssertion(
                        subject_entity_ids=["record-subject"],
                        category=category,
                        full_span_start=start,
                        full_span_end=end,
                        sentence_start=start,
                        sentence_end=end,
                        evidence_spans=[TextSpan(start=start, end=end, text=value_text)],
                        confidence=0.90,
                        detector=self.name,
                        requires_review=True,
                        rationale_code="labelled_special_category_field",
                        negated=bool(NEGATION_PATTERN.search(value_text)),
                        indirect_disclosure_risk=self.assess_indirect_disclosure(
                            value_text, category
                        ),
                    )
                )
        return detections, assertions

    def _field_value_span(self, text: str, sep_end: int) -> tuple[int, int] | None:
        """Return the (start, end) of the value following a field separator."""

        rest = text[sep_end:]
        lead = len(rest) - len(rest.lstrip())
        body = rest[lead:]
        if not body.strip():
            return None
        newline = body.find("\n")
        segment = body[:newline] if newline != -1 else body
        # Bound the value so a following form field or prose clause is never
        # swallowed. Normalization collapses the source newline, so the boundary
        # must be located explicitly: stop at the next field header (any
        # ``Label<sep>`` token) or at the first sentence terminator.
        cut = len(segment)
        bound = self._value_bound_re.search(segment)
        if bound is not None:
            cut = min(cut, bound.start())
        known = self._next_field_re.search(segment)
        if known is not None:
            cut = min(cut, known.start())
        # A whitespace-surrounded hyphen starts a new clause/bullet ("Romanian -
        # Accommodation arranged"), not an intra-value hyphen ("Turkish-Dutch"),
        # so it bounds the value too.
        dash = re.search(r"\s-", segment)
        if dash is not None:
            cut = min(cut, dash.start())
        terminator = re.search(r"[.?!]", segment)
        if terminator is not None:
            # A period glued to a single uppercase letter is an abbreviation
            # (e.g. "St.", "J."), not a sentence boundary — keep scanning.
            prefix = segment[: terminator.start()].rstrip()
            if not (len(prefix) >= 2 and prefix[-2] == " " and prefix[-1].isupper()):
                cut = min(cut, terminator.start())
        segment = segment[:cut]
        value = segment.rstrip(" \t\r\n;|.,:=-!?'\"[]")
        if not value.strip():
            return None
        # Reject a value that is itself a bare field header (e.g. an empty
        # "Religion: Nationality" sequence where Nationality carries no value).
        if value.casefold() in self._value_stop_labels:
            return None
        start = sep_end + lead
        end = start + len(value)
        if end <= start:
            return None
        return start, end

    @staticmethod
    def _map_detection(view: NormalizedText, detection: Detection) -> Detection:
        start, end = view.original_span(detection.start, detection.end)
        return Detection(
            **detection.model_dump(exclude={"id", "start", "end", "text"}),
            start=start,
            end=end,
            text=view.original[start:end],
        )

    @staticmethod
    def _map_assertion(
        view: NormalizedText,
        assertion: SensitiveAssertion,
        subject_ids: dict[str, str],
    ) -> SensitiveAssertion:
        full_start, full_end = view.original_span(
            assertion.full_span_start,
            assertion.full_span_end,
        )
        sentence_start, sentence_end = view.original_span(
            assertion.sentence_start,
            assertion.sentence_end,
        )
        evidence_spans: list[TextSpan] = []
        for evidence in assertion.evidence_spans:
            evidence_start, evidence_end = view.original_span(evidence.start, evidence.end)
            evidence_spans.append(
                TextSpan(
                    start=evidence_start,
                    end=evidence_end,
                    text=view.original[evidence_start:evidence_end],
                )
            )
        return SensitiveAssertion(
            **assertion.model_dump(
                exclude={
                    "id",
                    "subject_entity_ids",
                    "full_span_start",
                    "full_span_end",
                    "sentence_start",
                    "sentence_end",
                    "evidence_spans",
                }
            ),
            subject_entity_ids=[
                subject_ids.get(subject_id, subject_id)
                for subject_id in assertion.subject_entity_ids
            ],
            full_span_start=full_start,
            full_span_end=full_end,
            sentence_start=sentence_start,
            sentence_end=sentence_end,
            evidence_spans=evidence_spans,
        )

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
    def _explicit_record_subject(sentence: str, relation_start: int) -> bool:
        prefix = sentence[:relation_start].strip(" \t\r\n,;:|()[]{}<>\"'")
        if not prefix or len(prefix) > 80 or any(character.isdigit() for character in prefix):
            return False
        words = re.findall(r"[^\W\d_]+(?:['\u2019.-][^\W\d_]+)*", prefix, re.UNICODE)
        if not 2 <= len(words) <= 6:
            return False
        ignored_starts = {
            "a",
            "an",
            "de",
            "een",
            "het",
            "that",
            "the",
            "this",
            "those",
            "these",
        }
        return words[0].casefold() not in ignored_starts and " ".join(words) == prefix

    @staticmethod
    def _sentences(text: str) -> list[tuple[int, int, str]]:
        output: list[tuple[int, int, str]] = []
        field_starts = sorted({match.start() for match in _STRUCTURED_FIELD_PATTERN.finditer(text)})
        boundaries = sorted({0, len(text), *field_starts})
        for chunk_start, chunk_end in pairwise(boundaries):
            chunk = text[chunk_start:chunk_end]
            # A period ends a sentence only before whitespace/end. This keeps an
            # email/domain in the same assertion as the surrounding sensitive text.
            for match in re.finditer(r"[^\n!?]+?(?:[!?]+|[.]+(?=\s|$)|\n+|$)", chunk):
                raw = match.group(0)
                leading = len(raw) - len(raw.lstrip())
                sentence = raw.strip()
                if not sentence:
                    continue
                start = chunk_start + match.start() + leading
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
