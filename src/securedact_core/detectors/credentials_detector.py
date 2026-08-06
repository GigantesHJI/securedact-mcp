# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from ..models import Detection, DetectionSource, EntityType


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


class CredentialsDetector:
    """Conservative deterministic credential detector for coding workflows."""

    name = "credentials"
    contextual = False

    def __init__(self, rules: tuple[CredentialRule, ...] = RULES) -> None:
        self.rules = rules

    def detect(self, text: str) -> list[Detection]:
        output: dict[tuple[int, int, EntityType], Detection] = {}
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
        return sorted(
            output.values(),
            key=lambda item: (item.start, item.end, item.entity_type.value),
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
