# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from ..models import Detection, DetectionSource, EntityType
from ..normalization import (
    NormalizedText,
    normalize_for_detection,
    requires_detection_normalization,
)


@dataclass(frozen=True, slots=True)
class CredentialRule:
    name: str
    entity_type: EntityType
    pattern: re.Pattern[str]
    confidence: float = 1.0
    precedence: int = 110


RULES = (
    CredentialRule(
        "private_key_block",
        EntityType.PRIVATE_KEY,
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{1,8192}?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        precedence=125,
    ),
    CredentialRule(
        "github_token",
        EntityType.API_TOKEN,
        re.compile(r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{20,255}(?![A-Za-z0-9])"),
        precedence=120,
    ),
    CredentialRule(
        "aws_access_key_id",
        EntityType.ACCESS_TOKEN,
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        precedence=120,
    ),
    CredentialRule(
        "jwt",
        EntityType.ACCESS_TOKEN,
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
            r"[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
        ),
        precedence=120,
    ),
    CredentialRule(
        "database_url_credentials",
        EntityType.UNKNOWN_SECRET,
        re.compile(
            r"(?i)(?<![A-Za-z0-9])(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|"
            r"redis|amqps?)://[^\s/@:]+:[^\s/@]+@[^\s<>]+"
        ),
        precedence=120,
    ),
    CredentialRule(
        "connection_string_password",
        EntityType.PASSWORD,
        re.compile(r"(?i)\b(?:password|pwd)\s*=\s*(?P<value>[^;\s]{4,255})"),
        precedence=115,
    ),
    CredentialRule(
        "bearer_token",
        EntityType.ACCESS_TOKEN,
        re.compile(r"(?i)\bBearer[ \t]+(?P<value>[A-Za-z0-9._~+/-]{16,}={0,2})"),
        precedence=115,
    ),
    CredentialRule(
        "session_cookie",
        EntityType.SESSION_TOKEN,
        re.compile(
            r"(?im)\b(?:sessionid|session_id|connect\.sid|jsessionid)\s*[=:]\s*"
            r"[\"']?(?P<value>[A-Za-z0-9._~+/%-]{16,})"
        ),
        precedence=115,
    ),
    CredentialRule(
        "oauth_client_secret",
        EntityType.API_TOKEN,
        re.compile(
            r"(?im)\b(?:oauth[_ -]?client[_ -]?secret|client[_ -]?secret)\s*[=:]\s*"
            r"[\"']?(?P<value>[A-Za-z0-9._~+/-]{16,})"
        ),
        precedence=115,
    ),
    CredentialRule(
        "labelled_secret",
        EntityType.API_TOKEN,
        re.compile(
            r"(?im)^(?:export[ \t]+)?(?:api[_ -]?key|api[_ -]?token|secret[_ -]?key|"
            r"access[_ -]?token)\s*=\s*[\"']?(?P<value>[A-Za-z0-9._~+/-]{20,})"
        ),
        confidence=0.98,
        precedence=110,
    ),
    CredentialRule(
        "dotenv_password",
        EntityType.PASSWORD,
        re.compile(
            r"(?im)^(?:export[ \t]+)?(?:db[_ -]?password|database[_ -]?password|password)"
            r"\s*=\s*[\"']?(?P<value>[^\s\"']{8,255})"
        ),
        confidence=0.98,
        precedence=110,
    ),
)


def _entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    if not length:
        return 0.0
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


# Generic unknown-secret detection (FW-002).
#
# Conservative fallback for secret-like values that lack a recognizable vendor
# prefix or exact known format. Detection requires BOTH:
#   * a credential-ish assignment context (key -> value), and
#   * a value that looks secret (class diversity + entropy via
#     ``_plausible_generic_secret``).
# Standalone high-entropy values (UUIDs, hashes, lockfile entries, request IDs)
# are never flagged because they have no supporting secret label (FW-014).
_SECRET_ASSIGNMENT = re.compile(
    r"(?im)(?<![\w])"
    r"(?P<key>secret|secrets|access[_ -]?key|auth[_ -]?token|private[_ -]?token|"
    r"credential|credentials|api[_ -]?secret|internal[_ -]?api[_ -]?secret|"
    r"internal[_ -]?token|token|encryption[_ -]?key|signing[_ -]?key|"
    r"secret[_ -]?token|refresh[_ -]?token|x[_ -]?api[_ -]?key|server[_ -]?secret|"
    r"db[_ -]?secret|app[_ -]?secret)"
    r"[\"']?\s*[:=]\s*[\"']?"
    r"(?P<value>[A-Za-z0-9._~+/-]{16,})"
)

# Labels that are strong, direct indicators of a secret even without format
# recognition. Weaker/indirect labels still qualify but at lower confidence.
_STRONG_SECRET_LABELS = frozenset(
    {
        "secret",
        "secrets",
        "accesskey",
        "authtoken",
        "privatetoken",
        "internaltoken",
        "credential",
        "credentials",
        "apisecret",
        "internalapisecret",
        "encryptionkey",
        "signingkey",
        "serversecret",
        "dbsecret",
        "appsecret",
    }
)

# Clearly synthetic placeholder values must never be treated as secrets, even
# when paired with a secret label (FW-014 / section 8).
_PLACEHOLDER = re.compile(
    r"(?i)^(your[-_]?|example[-_]?|test[-_]?|dummy[-_]?|fake[-_]?|sample[-_]?)?"
    r"(api[-_]?key|token|secret|password|passwd|client[-_]?secret|access[-_]?key|"
    r"auth[-_]?token|changeme|replace[-_]?me|placeholder|x{6,})"
    r"([-_]?here|[0-9]{1,4})?$"
)

# Minimum value length for a generic secret. Mirrors the assignment regex and
# keeps short/ordinary identifiers out (FW-014).
_MIN_GENERIC_SECRET_LENGTH = 16


class CredentialsDetector:
    """Conservative deterministic credential detector for coding workflows."""

    name = "credentials"
    contextual = False

    def __init__(self, rules: tuple[CredentialRule, ...] = RULES) -> None:
        self.rules = rules

    def detect(self, text: str) -> list[Detection]:
        output = self._detect_view(text)
        if not requires_detection_normalization(text):
            return sorted(
                output.values(),
                key=lambda item: (item.start, item.end, item.entity_type.value),
            )
        normalized = normalize_for_detection(text)
        for detection in self._detect_view(normalized.text).values():
            mapped = self._map_to_original(normalized, detection)
            key = (mapped.start, mapped.end, mapped.entity_type)
            current = output.get(key)
            if current is None or mapped.precedence > current.precedence:
                output[key] = mapped
        return sorted(
            output.values(),
            key=lambda item: (item.start, item.end, item.entity_type.value),
        )

    def _detect_view(self, text: str) -> dict[tuple[int, int, EntityType], Detection]:
        output: dict[tuple[int, int, EntityType], Detection] = {}
        precise_spans: list[tuple[int, int]] = []
        for rule in self.rules:
            for match in rule.pattern.finditer(text):
                group = "value" if "value" in match.re.groupindex else 0
                start, end = match.span(group)
                value = text[start:end]
                if rule.name == "labelled_secret" and not self._plausible_generic_secret(value):
                    continue
                detection = Detection(
                    start=start,
                    end=end,
                    text=value,
                    entity_type=rule.entity_type,
                    confidence=rule.confidence,
                    source=DetectionSource.CREDENTIALS,
                    rule=rule.name,
                    precedence=rule.precedence,
                    rationale_code="credential_format",
                )
                key = (start, end, rule.entity_type)
                current = output.get(key)
                if current is None or detection.precedence > current.precedence:
                    output[key] = detection
                precise_spans.append((start, end))
        for detection in self._detect_unknown_secrets(text):
            if any(detection.start < e and s < detection.end for s, e in precise_spans):
                # Known precise rule already covers this span; never downgrade it.
                continue
            key = (detection.start, detection.end, detection.entity_type)
            current = output.get(key)
            if current is None or detection.precedence > current.precedence:
                output[key] = detection
        return output

    def _detect_unknown_secrets(self, text: str) -> list[Detection]:
        detections: list[Detection] = []
        for match in _SECRET_ASSIGNMENT.finditer(text):
            value = match.group("value")
            if len(value) < _MIN_GENERIC_SECRET_LENGTH:
                continue
            if not self._plausible_generic_secret(value):
                continue
            if self._is_known_benign(value) or self._is_placeholder(value):
                continue
            normalized_key = re.sub(r"[\s_-]", "", match.group("key").lower())
            confidence = 0.92 if normalized_key in _STRONG_SECRET_LABELS else 0.72
            start, end = match.span("value")
            detections.append(
                Detection(
                    start=start,
                    end=end,
                    text=value,
                    entity_type=EntityType.UNKNOWN_SECRET,
                    confidence=confidence,
                    source=DetectionSource.CREDENTIALS,
                    rule="unknown_secret",
                    precedence=100,
                    rationale_code="unknown_secret_context",
                )
            )
        return detections

    @staticmethod
    def _is_known_benign(value: str) -> bool:
        lowered = value.lower()
        if lowered.startswith(("ssh-", "pk.", "-----begin")):
            # Public keys / age keys / PEM markers are not generic secrets.
            return True
        if re.fullmatch(r"[0-9a-f]{32,}", lowered):
            # Long hex strings (SHA/checksums) are benign without a secret format.
            return True
        if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", lowered):
            return True
        return False

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        return bool(_PLACEHOLDER.fullmatch(value))

    @staticmethod
    def _map_to_original(view: NormalizedText, detection: Detection) -> Detection:
        start, end = view.original_span(detection.start, detection.end)
        return Detection(
            **detection.model_dump(exclude={"id", "start", "end", "text"}),
            start=start,
            end=end,
            text=view.original[start:end],
        )

    @staticmethod
    def _plausible_generic_secret(value: str) -> bool:
        classes = sum(
            bool(pattern.search(value))
            for pattern in (
                re.compile(r"[a-z]"),
                re.compile(r"[A-Z]"),
                re.compile(r"\d"),
                re.compile(r"[._~+/-]"),
            )
        )
        return classes >= 3 and _entropy(value) >= 3.25
