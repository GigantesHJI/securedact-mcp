from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

from ..models import Detection, DetectionSource, EntityType
from ..normalization import (
    NormalizedText,
    normalize_for_detection,
    requires_detection_normalization,
)

Validator = Callable[[str], bool]


IBAN_LENGTHS = {
    "AL": 28,
    "AD": 24,
    "AT": 20,
    "AZ": 28,
    "BH": 22,
    "BE": 16,
    "BA": 20,
    "BR": 29,
    "BG": 22,
    "CR": 22,
    "HR": 21,
    "CY": 28,
    "CZ": 24,
    "DK": 18,
    "DO": 28,
    "EE": 20,
    "FO": 18,
    "FI": 18,
    "FR": 27,
    "GE": 22,
    "DE": 22,
    "GI": 23,
    "GR": 27,
    "GL": 18,
    "GT": 28,
    "HU": 28,
    "IS": 26,
    "IE": 22,
    "IL": 23,
    "IT": 27,
    "JO": 30,
    "KZ": 20,
    "XK": 20,
    "KW": 30,
    "LV": 21,
    "LB": 28,
    "LI": 21,
    "LT": 20,
    "LU": 20,
    "MK": 19,
    "MT": 31,
    "MR": 27,
    "MU": 30,
    "MC": 27,
    "MD": 24,
    "ME": 22,
    "NL": 18,
    "NO": 15,
    "PK": 24,
    "PS": 29,
    "PL": 28,
    "PT": 25,
    "QA": 29,
    "RO": 24,
    "SM": 27,
    "SA": 24,
    "RS": 22,
    "SK": 24,
    "SI": 19,
    "ES": 24,
    "SE": 24,
    "CH": 21,
    "TL": 23,
    "TN": 24,
    "TR": 26,
    "UA": 29,
    "AE": 23,
    "GB": 22,
    "VA": 22,
}


@dataclass(frozen=True)
class RegexRule:
    name: str
    entity_type: EntityType
    pattern: re.Pattern[str]
    validator: Validator = lambda _value: True
    confidence: float = 1.0
    precedence: int = 50


@dataclass(frozen=True)
class LabelRule:
    name: str
    labels: tuple[str, ...]
    entity_type: EntityType
    value_pattern: str
    validator: Validator = lambda _value: True
    confidence: float = 0.99
    # When True, the label may be followed by a plain whitespace run ("VIN 1M8...") or a
    # connective word ("fax is 415...", "patient MRN is 558201") instead of only
    # ':'/'='/ '#'. This is intentionally restricted to structured identifier labels
    # (not free-text fields like name/diagnosis) so that relaxing the separator cannot
    # make a free-text label swallow an entire sentence.
    loose_separator: bool = False

    def compile(self) -> re.Pattern[str]:
        labels = "|".join(re.escape(label) for label in sorted(self.labels, key=len, reverse=True))
        if self.loose_separator:
            separator = r"(?::|=|#|[^\S\r\n]+(?:is|was|are|were)[^\S\r\n]+|[^\S\r\n]+)"
        else:
            separator = r"(?::|=|#)"
        return re.compile(
            rf"(?im)(?<![\w])(?P<label>{labels})[^\S\r\n]*{separator}[^\S\r\n]*"
            rf"(?P<value>{self.value_pattern})",
            re.IGNORECASE,
        )


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def luhn_valid(value: str) -> bool:
    digits = _digits(value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        number = int(char)
        if index % 2 == parity:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def iban_valid(value: str) -> bool:
    compact = re.sub(r"\s", "", value).upper()
    expected_length = IBAN_LENGTHS.get(compact[:2])
    if expected_length is None or len(compact) != expected_length:
        return False
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(ord(char) - 55) if char.isalpha() else char for char in rearranged)
    remainder = 0
    for char in numeric:
        remainder = (remainder * 10 + int(char)) % 97
    return remainder == 1


def bsn_valid(value: str) -> bool:
    digits = _digits(value)
    if len(digits) != 9 or digits == "000000000":
        return False
    weights = (9, 8, 7, 6, 5, 4, 3, 2, -1)
    return sum(int(char) * weight for char, weight in zip(digits, weights, strict=True)) % 11 == 0


def _ip(version: int) -> Validator:
    def validate(value: str) -> bool:
        try:
            return ipaddress.ip_address(value).version == version
        except ValueError:
            return False

    return validate


# North American Numbering Plan digit groupings written with separators only (no country
# prefix, no parentheses, no dots). ``415-555-2671`` and ``1-800-555-0199`` are the dominant
# written US/Canada forms; without these groupings the generic heuristic below rejects them
# because it was calibrated on EU numbers (leading ``+`` or trunk ``0``). The groupings are
# deliberately narrow so that 3-2-4 (SSN), 2-2-4 (date), 5-4 (ZIP+4) and 4-4-4-4 (card)
# shapes are not promoted to telephone numbers.
_NANP_DIGIT_GROUPS = frozenset({(3, 3, 4), (1, 3, 3, 4)})


def _phone(value: str) -> bool:
    digits = _digits(value)
    if not 7 <= len(digits) <= 15:
        return False
    stripped = value.lstrip()
    if stripped.startswith("+"):
        return True
    groups = re.findall(r"\d+", value)
    if groups and all(len(group) == 1 for group in groups):
        return False
    if tuple(len(group) for group in groups) in _NANP_DIGIT_GROUPS:
        return True
    return any(char in value for char in "(). ") or stripped.startswith("0")


def _bic(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?", value.upper()))


def _card_expiry(value: str) -> bool:
    match = re.fullmatch(r"(0[1-9]|1[0-2])/(?:\d{2}|\d{4})", value)
    return match is not None


def ssn_valid(value: str) -> bool:
    digits = _digits(value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    # Area 000, 666, and 900-999 are never assigned; group/serial 00/0000 invalid.
    if area in {"000", "666"} or area[0] == "9":
        return False
    if group == "00":
        return False
    if serial == "0000":
        return False
    return True


# ISO 3779 VIN transliteration weights and character values (I, O, Q excluded).
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)
_VIN_VALUES = {c: i for i, c in enumerate("0123456789X")}
_VIN_VALUES.update(
    {
        "A": 1,
        "B": 2,
        "C": 3,
        "D": 4,
        "E": 5,
        "F": 6,
        "G": 7,
        "H": 8,
        "J": 1,
        "K": 2,
        "L": 3,
        "M": 4,
        "N": 5,
        "P": 7,
        "R": 9,
        "S": 2,
        "T": 3,
        "U": 4,
        "V": 5,
        "W": 6,
        "X": 7,
        "Y": 8,
        "Z": 9,
    }
)


def vin_valid(value: str) -> bool:
    """Return ``True`` when ``value`` carries a valid North American VIN check digit.

    NOTE: this helper is deliberately **not** wired into ``vehicle_identifier_label``.
    ISO 3779 defines the 17-character VIN structure but does not mandate a check digit;
    the check digit at position 9 is a North American requirement (49 CFR 565.15), so
    gating detection on it would drop legitimate VINs recorded outside North America.
    It is retained as an opt-in helper for callers that know their data is North American.
    Detection therefore does not claim ISO 3779 or check-digit validation.
    """

    vin = value.upper()
    if len(vin) != 17:
        return False
    if not re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", vin):
        return False
    total = 0
    for char, weight in zip(vin, _VIN_WEIGHTS, strict=True):
        char_value = _VIN_VALUES.get(char)
        if char_value is None:
            return False
        total += char_value * weight
    check = total % 11
    expected = "X" if check == 10 else str(check)
    return vin[8] == expected


# US state identifiers used to qualify a five-digit code as a US ZIP.
_US_STATE_ABBREV = (
    "AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT "
    "NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC"
).split()
# Only USPS abbreviations are used for ZIP qualification to keep the postal format
# "(ZIP, ST)" precise; full state names are not redacted because Safe Harbor permits
# retaining state-level geography.
_US_STATE_SET = "|".join(sorted(_US_STATE_ABBREV, key=len, reverse=True))


def age_over_89(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not digits:
        return False
    age = int(digits)
    return 90 <= age <= 119


# Practical ASCII mailbox subset used for privacy detection. It deliberately
# covers common dots, underscores, hyphens, plus tags and percent/apostrophe
# forms while excluding assignment/query delimiters that commonly surround a
# labelled field or URL.
EMAIL_ATOM = r"[A-Z0-9_%+'-]"
EMAIL_LOCAL = rf"{EMAIL_ATOM}+(?:\.{EMAIL_ATOM}+)*"
EMAIL_DOMAIN_LABEL = r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
EMAIL_VALUE = rf"{EMAIL_LOCAL}@(?:{EMAIL_DOMAIN_LABEL}\.)+[A-Z]{{2,63}}"
EMAIL_PATTERN = re.compile(
    rf"(?<![\w.%+'@-])"
    rf"(?=[^@\s]{{1,64}}@){EMAIL_VALUE}"
    rf"(?![\w-]|[/\\?&#=:]|\.(?:[\w-]|\.))",
    re.IGNORECASE,
)


def _email(value: str) -> bool:
    if len(value) > 254 or value.count("@") != 1:
        return False
    local, domain = value.rsplit("@", 1)
    if not 1 <= len(local) <= 64 or local.startswith(".") or local.endswith("."):
        return False
    if ".." in local or ".." in domain or len(domain) > 253:
        return False
    labels = domain.split(".")
    return all(
        label and len(label) <= 63 and not label.startswith("-") and not label.endswith("-")
        for label in labels
    )


# An identifier value is an alphanumeric token, optionally followed by a single
# whitespace-separated token that itself contains a digit (e.g. "MBR 448821039",
# "CA 9920314"). The digit requirement in the trailing token prevents the value from
# greedily swallowing ordinary prose words (so "ACC-773102884 billed" stays bounded to
# the identifier). This keeps label-anchored detection precise.
_IDENTIFIER_TOKEN = r"[A-Z0-9][A-Z0-9._/-]*"  # noqa: S105
IDENTIFIER_VALUE = rf"{_IDENTIFIER_TOKEN}(?:\s+[A-Z0-9]*\d[A-Z0-9._/-]*)?"


def _nonempty_identifier(value: str) -> bool:
    return (
        3 <= len(value) <= 128
        and bool(re.search(r"\d", value))
        and bool(
            re.fullmatch(
                rf"{_IDENTIFIER_TOKEN}(?:\s+[A-Z0-9]*\d[A-Z0-9._/-]*)?", value, re.IGNORECASE
            )
        )
    )


DATE_VALUE = (
    r"(?:\d{1,2}\s+(?:January|February|March|April|May|June|July|August|"
    r"September|October|November|December|januari|februari|maart|april|mei|"
    r"juni|juli|augustus|september|oktober|november|december)\s+\d{4}|"
    r"\d{1,2}[-/.]\d{1,2}[-/.]\d{4}|"
    r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2})"
)
TEXT_FIELD_VALUE = r"[^\r\n;|]{2,160}"
# Labelled telephone/fax values may start with an area-code parenthesis, e.g.
# ``Fax number: (415) 555-8890``.
PHONE_LABEL_VALUE = r"(?:\+|\()?\d[\d(). -]{5,}\d"


LABEL_RULES = (
    LabelRule("name_label", ("name", "naam"), EntityType.PERSON, TEXT_FIELD_VALUE, confidence=0.95),
    LabelRule(
        "date_of_birth_label",
        ("date of birth", "DOB", "birth date", "geboortedatum"),
        EntityType.DATE_OF_BIRTH,
        DATE_VALUE,
    ),
    LabelRule(
        "address_label",
        ("address", "adres", "street address"),
        EntityType.ADDRESS,
        r"[^\r\n;|]{5,180}",
    ),
    LabelRule(
        "email_label",
        ("email", "e-mail", "e-mailadres"),
        EntityType.EMAIL,
        EMAIL_VALUE,
        _email,
    ),
    LabelRule(
        "phone_label",
        ("telephone", "phone", "telefoon", "mobiel"),
        EntityType.PHONE,
        PHONE_LABEL_VALUE,
        _phone,
    ),
    LabelRule("bsn_label", ("BSN", "burgerservicenummer"), EntityType.BSN, r"\d{9}", bsn_valid),
    LabelRule(
        "passport_label",
        ("passport", "passport number", "paspoort", "paspoortnummer"),
        EntityType.PASSPORT_NUMBER,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
    ),
    LabelRule(
        "driving_licence_label",
        (
            "driving licence",
            "driving licence number",
            "driver licence",
            "driver license",
            "rijbewijs",
            "rijbewijsnummer",
        ),
        EntityType.DRIVING_LICENCE_NUMBER,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
    ),
    LabelRule(
        "national_id_label",
        ("national ID", "ID number", "identiteitsnummer"),
        EntityType.NATIONAL_ID,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
    ),
    LabelRule(
        "customer_number_label",
        ("customer number", "customer ID", "klantnummer", "klant ID"),
        EntityType.CUSTOMER_NUMBER,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
    ),
    LabelRule(
        "case_number_label",
        ("case number", "case ID", "zaaknummer", "dossiernummer"),
        EntityType.CASE_NUMBER,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
    ),
    LabelRule(
        "employee_id_label",
        ("employee ID", "employee number", "medewerker ID", "personeelsnummer"),
        EntityType.EMPLOYEE_ID,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
    ),
    LabelRule(
        "payroll_number_label",
        ("payroll number", "payroll ID", "loonnummer", "salarisnummer"),
        EntityType.PAYROLL_NUMBER,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
    ),
    LabelRule(
        "patient_number_label",
        ("patient number", "patient no", "patient ID", "patiëntnummer", "patientnummer"),
        EntityType.PATIENT_NUMBER,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
    ),
    LabelRule(
        "medical_record_number_label",
        (
            "medical record number",
            "medical record ID",
            "medical record",
            "record number",
            "record no",
            "chart number",
            "chart no",
            "chart ID",
            "patient record number",
            "patient record no",
            "MRN",
            "medisch dossiernummer",
        ),
        EntityType.MEDICAL_RECORD_NUMBER,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
        loose_separator=True,
    ),
    LabelRule(
        "policy_number_label",
        ("policy number", "insurance policy", "polisnummer"),
        EntityType.POLICY_NUMBER,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
        loose_separator=True,
    ),
    LabelRule(
        "invoice_number_label",
        ("invoice number", "invoice ID", "factuurnummer"),
        EntityType.INVOICE_NUMBER,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
    ),
    LabelRule(
        "iban_label",
        ("IBAN",),
        EntityType.IBAN,
        r"[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}",
        iban_valid,
    ),
    LabelRule(
        "bic_swift_label",
        ("BIC", "SWIFT", "BIC/SWIFT"),
        EntityType.BIC_SWIFT,
        r"[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?",
        _bic,
    ),
    LabelRule(
        "account_reference_label",
        ("account reference", "bank account reference", "bank account ref", "rekeningreferentie"),
        EntityType.BANK_ACCOUNT_REFERENCE,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
        loose_separator=True,
    ),
    LabelRule(
        "payment_reference_label",
        ("payment reference", "payment ref", "betalingskenmerk", "betalingsreferentie"),
        EntityType.PAYMENT_REFERENCE,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
    ),
    LabelRule(
        "credit_card_label",
        ("credit card", "card number", "creditcard", "kaartnummer"),
        EntityType.CREDIT_CARD_NUMBER,
        r"(?:\d[ -]?){12,18}\d",
        luhn_valid,
    ),
    LabelRule(
        "card_expiry_label",
        ("expiry", "expiry date", "card expiry", "valid thru", "vervaldatum"),
        EntityType.CARD_EXPIRY,
        r"(?:0[1-9]|1[0-2])/(?:\d{2}|\d{4})",
        _card_expiry,
    ),
    LabelRule(
        "card_security_code_label",
        ("CVV", "CVC", "security code", "card security code", "beveiligingscode"),
        EntityType.CARD_SECURITY_CODE,
        r"\d{3,4}",
    ),
    LabelRule(
        "department_label",
        ("department", "internal department", "afdeling"),
        EntityType.DEPARTMENT,
        TEXT_FIELD_VALUE,
        confidence=0.95,
    ),
    LabelRule(
        "project_label",
        ("project", "project name", "confidential project", "projectnaam"),
        EntityType.PROJECT_NAME,
        TEXT_FIELD_VALUE,
        confidence=0.95,
    ),
    LabelRule(
        "diagnosis_label",
        ("diagnosis", "diagnose", "condition", "aandoening"),
        EntityType.MEDICAL_CONDITION,
        TEXT_FIELD_VALUE,
        confidence=0.95,
    ),
    LabelRule(
        "medication_label",
        ("medication", "medicine", "medicatie", "geneesmiddel"),
        EntityType.MEDICATION,
        TEXT_FIELD_VALUE,
        confidence=0.95,
    ),
    LabelRule(
        "dosage_label",
        ("dosage", "dose", "dosering"),
        EntityType.DOSAGE,
        TEXT_FIELD_VALUE,
        confidence=0.95,
    ),
    LabelRule(
        "health_insurer_label",
        ("health insurer", "insurer", "zorgverzekeraar"),
        EntityType.HEALTH_INSURER,
        TEXT_FIELD_VALUE,
        confidence=0.95,
    ),
    LabelRule(
        "ipv4_label", ("IPv4", "IPv4 address"), EntityType.IPV4, r"(?:\d{1,3}\.){3}\d{1,3}", _ip(4)
    ),
    LabelRule("ipv6_label", ("IPv6", "IPv6 address"), EntityType.IPV6, r"[0-9A-F:.]{2,45}", _ip(6)),
    LabelRule(
        "mac_label",
        ("MAC", "MAC address", "MAC-adres"),
        EntityType.MAC_ADDRESS,
        r"(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}|[0-9A-F]{4}(?:\.[0-9A-F]{4}){2}",
    ),
    LabelRule(
        "device_label",
        (
            "device identifier",
            "device ID",
            "apparaat-ID",
            "serial number",
            "serial no",
        ),
        EntityType.DEVICE_IDENTIFIER,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
    ),
    LabelRule(
        "session_token_label",
        ("session token", "session ID", "sessietoken", "session key"),
        EntityType.SESSION_TOKEN,
        TEXT_FIELD_VALUE,
    ),
    LabelRule(
        "api_token_label",
        ("API token", "API key", "API-token", "API-sleutel"),
        EntityType.API_TOKEN,
        TEXT_FIELD_VALUE,
    ),
    LabelRule(
        "access_token_label",
        ("access token", "bearer token", "authorization token", "toegangstoken"),
        EntityType.ACCESS_TOKEN,
        TEXT_FIELD_VALUE,
    ),
    LabelRule(
        "password_label",
        ("password", "passphrase", "wachtwoord"),
        EntityType.PASSWORD,
        r"\S{4,255}",
    ),
    LabelRule(
        "appointment_label",
        ("appointment", "appointment date", "afspraak", "afspraakdatum"),
        EntityType.APPOINTMENT,
        rf"{DATE_VALUE}(?:\s+(?:at|om)\s+(?:[01]\d|2[0-3]):[0-5]\d)?",
        confidence=0.98,
    ),
    LabelRule(
        "ssn_label",
        ("SSN", "SS", "social security number", "social security no", "social security"),
        EntityType.SSN,
        r"\d{3}[ -]?\d{2}[ -]?\d{4}",
        ssn_valid,
        loose_separator=True,
    ),
    LabelRule(
        "fax_label",
        ("fax", "fax number", "telefax", "facsimile"),
        EntityType.FAX,
        PHONE_LABEL_VALUE,
        _phone,
        loose_separator=True,
    ),
    LabelRule(
        "account_number_label",
        ("account number", "account no", "account no.", "acct", "account #"),
        EntityType.ACCOUNT_NUMBER,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
    ),
    LabelRule(
        "health_plan_beneficiary_label",
        (
            "member ID",
            "member number",
            "member no",
            "subscriber ID",
            "subscriber number",
            "beneficiary ID",
            "beneficiary number",
            "health plan ID",
            "health plan number",
            "insurance ID",
            "payer ID",
        ),
        EntityType.HEALTH_PLAN_BENEFICIARY,
        IDENTIFIER_VALUE,
        _nonempty_identifier,
    ),
    LabelRule(
        "vehicle_identifier_label",
        (
            "VIN",
            "vehicle identification number",
            "chassis number",
            "chassis no",
            "license plate",
            "licence plate",
            "plate no",
            "plate number",
        ),
        EntityType.VEHICLE_IDENTIFIER,
        r"(?:[A-HJ-NPR-Z0-9]{11,17}|[A-Z0-9][A-Z0-9_-]{2,9})",
        _nonempty_identifier,
        loose_separator=True,
    ),
    LabelRule(
        "us_zip_label",
        ("zip", "zip code", "zipcode", "postal code", "postal code"),
        EntityType.US_ZIP,
        r"\d{5}(?:-\d{4})?",
    ),
)


RULES = (
    RegexRule(
        "private_key",
        EntityType.PRIVATE_KEY,
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{1,8192}?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        precedence=95,
    ),
    RegexRule(
        "complete_dutch_address",
        EntityType.ADDRESS,
        re.compile(
            r"(?<!\w)(?:[A-ZÀ-ÖØ-Ý][\wÀ-ÖØ-öø-ÿ'’.-]+(?:\s+|$)){1,5}"
            r"\d{1,5}[A-Za-z]?(?:[-/]\d+)?\s*,?\s*"
            r"[1-9]\d{3}\s?[A-Z]{2}\s+"
            r"[A-ZÀ-ÖØ-Ý][\wÀ-ÖØ-öø-ÿ'’.-]+(?:\s+[A-ZÀ-ÖØ-Ý][\wÀ-ÖØ-öø-ÿ'’.-]+){0,3}"
            r"(?:\s*,\s*(?:Netherlands|Nederland|Belgium|België|Germany|Deutschland))?",
            re.UNICODE,
        ),
        precedence=90,
    ),
    RegexRule(
        "credit_card",
        EntityType.CREDIT_CARD_NUMBER,
        re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
        luhn_valid,
        precedence=90,
    ),
    RegexRule(
        "iban",
        EntityType.IBAN,
        re.compile(
            r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}(?![A-Z0-9])",
            re.IGNORECASE,
        ),
        iban_valid,
        precedence=90,
    ),
    RegexRule(
        "mac_address",
        EntityType.MAC_ADDRESS,
        re.compile(
            r"(?<![0-9A-F])(?:(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}|"
            r"[0-9A-F]{4}(?:\.[0-9A-F]{4}){2})(?![0-9A-F])",
            re.IGNORECASE,
        ),
        precedence=85,
    ),
    RegexRule(
        "dutch_bsn", EntityType.BSN, re.compile(r"(?<!\d)\d{9}(?!\d)"), bsn_valid, precedence=90
    ),
    RegexRule(
        "ipv6",
        EntityType.IPV6,
        re.compile(
            r"(?<![0-9A-F:.])(?:[0-9A-F]{0,4}:){2,7}"
            r"(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-F]{0,4})(?![0-9A-F:.])",
            re.IGNORECASE,
        ),
        _ip(6),
        precedence=80,
    ),
    RegexRule(
        "ipv4",
        EntityType.IPV4,
        re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
        _ip(4),
        precedence=80,
    ),
    RegexRule(
        "email",
        EntityType.EMAIL,
        EMAIL_PATTERN,
        _email,
        precedence=80,
    ),
    RegexRule(
        "dutch_postcode",
        EntityType.POSTCODE,
        re.compile(r"(?<![A-Z0-9])[1-9]\d{3}\s?[A-Z]{2}(?![A-Z0-9])", re.IGNORECASE),
        precedence=70,
    ),
    RegexRule(
        "general_date",
        EntityType.DATE,
        re.compile(DATE_VALUE, re.IGNORECASE),
        confidence=0.90,
        precedence=55,
    ),
    RegexRule(
        "time",
        EntityType.TIME,
        re.compile(
            r"(?<![A-Z0-9:])(?:[01]\d|2[0-3]):[0-5]\d(?![A-Z0-9:])",
            re.IGNORECASE,
        ),
        confidence=0.95,
        precedence=55,
    ),
    RegexRule(
        "phone",
        EntityType.PHONE,
        re.compile(r"(?<![\w-])(?:\+\s*|(?=\d))\d[\d(). -]{5,}\d(?![\w-])"),
        _phone,
        precedence=40,
    ),
    RegexRule(
        "ssn",
        EntityType.SSN,
        re.compile(r"(?<!\d)(\d{3})[ -](\d{2})[ -](\d{4})(?!\d)"),
        ssn_valid,
        precedence=85,
    ),
    RegexRule(
        "us_zip_plus4",
        EntityType.US_ZIP,
        re.compile(r"(?<!\d)\d{5}-\d{4}(?!\d)"),
        precedence=70,
    ),
    RegexRule(
        "us_zip_state",
        EntityType.US_ZIP,
        # Case-sensitive on purpose: USPS abbreviations are uppercase, and matching them
        # case-insensitively turned ordinary lowercase English words that happen to spell a
        # state code ("in", "or", "me", "hi", "ok", "de", "la", "pa") into ZIP qualifiers,
        # so any nearby five-digit value (dosages, counts, identifiers) was redacted as a
        # US ZIP under every policy.
        re.compile(
            r"(?<!\d)\d{5}(?:-\d{4})?"
            r"(?=\s*,\s*(?:" + _US_STATE_SET + r")\b)"
            r"|(?<=\b(?:" + _US_STATE_SET + r")[ -])\d{5}(?:-\d{4})?(?!\d)"
            r"|(?<=\b(?:" + _US_STATE_SET + r"), )\d{5}(?:-\d{4})?(?!\d)",
        ),
        precedence=70,
    ),
    RegexRule(
        "age_over_89",
        EntityType.AGE,
        re.compile(
            r"(?i)(?:\b(?:aged|age\s+of)\s+(9\d|1[0-1]\d)\s*(?:years?|yrs?|year-old)?\b|"
            r"\b(9\d|1[0-1]\d)[- ](?:year|yr)s?[- ]old\b)",
        ),
        age_over_89,
        confidence=0.9,
        precedence=55,
    ),
)


PREFIX_TYPES: dict[str, EntityType] = {
    "ACC": EntityType.ACCOUNT_NUMBER,
    "CUST": EntityType.CUSTOMER_NUMBER,
    "KLANT": EntityType.CUSTOMER_NUMBER,
    "CASE": EntityType.CASE_NUMBER,
    "ZAAK": EntityType.CASE_NUMBER,
    "EMP": EntityType.EMPLOYEE_ID,
    "PAYROLL": EntityType.PAYROLL_NUMBER,
    "PAY": EntityType.PAYMENT_REFERENCE,
    "PAT": EntityType.PATIENT_NUMBER,
    "MRN": EntityType.MEDICAL_RECORD_NUMBER,
    "POL": EntityType.POLICY_NUMBER,
    "INV": EntityType.INVOICE_NUMBER,
    "DEV": EntityType.DEVICE_IDENTIFIER,
    "MBR": EntityType.HEALTH_PLAN_BENEFICIARY,
    "SUB": EntityType.HEALTH_PLAN_BENEFICIARY,
    "BEN": EntityType.HEALTH_PLAN_BENEFICIARY,
    "DL": EntityType.DRIVING_LICENCE_NUMBER,
    "DV": EntityType.DRIVING_LICENCE_NUMBER,
    "UNION": EntityType.TRADE_UNION_MEMBERSHIP,
    "GEN": EntityType.GENETIC_DATA,
    "BIO": EntityType.BIOMETRIC_DATA,
    "FACE": EntityType.BIOMETRIC_DATA,
    "IRIS": EntityType.BIOMETRIC_DATA,
    "VOICE": EntityType.BIOMETRIC_DATA,
}

SENSITIVE_QUERY_KEYS = frozenset(
    {
        "account",
        "account_id",
        "account_reference",
        "api_key",
        "apikey",
        "case",
        "case_id",
        "customer",
        "customer_id",
        "email",
        "session",
        "session_id",
        "token",
        "access_token",
        "user",
        "user_id",
    }
)

URL_PATTERN = re.compile(r"\b(?:https?://|www\.)[^\s<>\[\]()]+", re.IGNORECASE)
# A prefix may be followed by a separator ('-'/'_') then the value (e.g. "MRN-558201"),
# or by a digit-led value with no separator (e.g. "MBR55210983", "ACC773102884",
# "DEV55120983"). The no-separator branch requires the value to START with a digit so
# ordinary words that merely contain a prefix (e.g. "SUBMIT", "ACCEPT", "GENETIC") are
# not misclassified as identifiers.
PREFIX_PATTERN = re.compile(
    rf"(?<![A-Z0-9])(?P<prefix>{'|'.join(sorted(PREFIX_TYPES, key=len, reverse=True))})"
    r"(?:(?:-[A-Z]{2,8})?[-_][A-Z0-9][A-Z0-9_-]{2,}"
    r"|[0-9][A-Z0-9._-]{2,})(?![A-Z0-9])",
    re.IGNORECASE,
)
RF_REFERENCE_PATTERN = re.compile(r"(?<![A-Z0-9])RF\d{8,25}(?![A-Z0-9])", re.IGNORECASE)
COMMON_SECRET_PATTERN = re.compile(
    r"(?<![A-Z0-9])(?:sk-(?:test|live)-[A-Z0-9_-]{3,}|"
    r"ghp_[A-Z0-9]{8,}|xox[baprs]-[A-Z0-9-]{8,}|"
    r"sess(?:ion)?[-_][A-Z0-9_-]{6,})(?![A-Z0-9])",
    re.IGNORECASE,
)


class RegexDetector:
    name = "regex"
    contextual = False

    def __init__(
        self,
        rules: tuple[RegexRule, ...] = RULES,
        *,
        label_rules: tuple[LabelRule, ...] = LABEL_RULES,
        prefix_types: dict[str, EntityType] | None = None,
    ) -> None:
        self.rules = rules
        self.label_rules = label_rules
        self.prefix_types = prefix_types or PREFIX_TYPES
        self._compiled_label_rules = tuple((rule, rule.compile()) for rule in label_rules)

    def detect(self, text: str) -> list[Detection]:
        results = self._detect_view(text)
        if not requires_detection_normalization(text):
            return results
        normalized = normalize_for_detection(text)
        results.extend(
            self._map_to_original(normalized, detection)
            for detection in self._detect_view(normalized.text, include_labels=False)
        )
        return self._deduplicate(results)

    def _detect_view(self, text: str, *, include_labels: bool = True) -> list[Detection]:
        results: list[Detection] = []
        if include_labels:
            results.extend(self._detect_labels(text))
        results.extend(self._detect_prefixes(text))
        results.extend(self._detect_urls(text))
        results.extend(self._detect_common_secrets(text))
        for rule, match in self._matches(text):
            start, end = match.span()
            value = match.group(0)
            if rule.name == "email" and value.startswith("'"):
                start += 1
                value = value[1:]
            if rule.name == "iban":
                value = self._trim_iban(value)
                end = start + len(value)
            if not rule.validator(value):
                continue
            results.append(
                Detection(
                    start=start,
                    end=end,
                    text=value,
                    entity_type=rule.entity_type,
                    confidence=rule.confidence,
                    source=DetectionSource.REGEX,
                    rule=rule.name,
                    precedence=rule.precedence,
                )
            )
        return self._deduplicate(results)

    @staticmethod
    def _map_to_original(view: NormalizedText, detection: Detection) -> Detection:
        start, end = view.original_span(detection.start, detection.end)
        return Detection(
            **detection.model_dump(exclude={"id", "start", "end", "text"}),
            start=start,
            end=end,
            text=view.original[start:end],
        )

    def _detect_labels(self, text: str) -> list[Detection]:
        candidates: list[tuple[Detection, int]] = []
        for rule, pattern in self._compiled_label_rules:
            for match in pattern.finditer(text):
                start, end = match.span("value")
                value = match.group("value").strip()
                leading = len(match.group("value")) - len(match.group("value").lstrip())
                start += leading
                end = start + len(value)
                if not value or not rule.validator(value):
                    continue
                candidates.append(
                    (
                        Detection(
                            start=start,
                            end=end,
                            text=text[start:end],
                            entity_type=rule.entity_type,
                            confidence=rule.confidence,
                            source=DetectionSource.LABEL,
                            rule=rule.name,
                            precedence=100,
                            rationale_code="labelled_sensitive_field",
                        ),
                        len(match.group("label")),
                    )
                )
        # A generic label can be a suffix of a more specific one (for example,
        # ``address`` in ``MAC address``).  When both capture the same value,
        # retain only the longest label so the generic rule cannot win later
        # during overlap resolution.
        longest_by_span: dict[tuple[int, int], int] = {}
        for detection, label_length in candidates:
            key = (detection.start, detection.end)
            longest_by_span[key] = max(longest_by_span.get(key, 0), label_length)
        return [
            detection
            for detection, label_length in candidates
            if label_length == longest_by_span[(detection.start, detection.end)]
        ]

    def _detect_prefixes(self, text: str) -> list[Detection]:
        output: list[Detection] = []
        for match in PREFIX_PATTERN.finditer(text):
            if not _nonempty_identifier(match.group(0)):
                continue
            prefix = match.group("prefix").upper()
            entity_type = self.prefix_types.get(prefix)
            if entity_type is None:
                continue
            output.append(
                Detection(
                    start=match.start(),
                    end=match.end(),
                    text=match.group(0),
                    entity_type=entity_type,
                    confidence=1.0,
                    source=DetectionSource.REGEX,
                    rule=f"configured_prefix:{prefix}",
                    precedence=95,
                    rationale_code="configured_identifier_prefix",
                )
            )
        for match in RF_REFERENCE_PATTERN.finditer(text):
            output.append(
                Detection(
                    start=match.start(),
                    end=match.end(),
                    text=match.group(0),
                    entity_type=EntityType.PAYMENT_REFERENCE,
                    confidence=1.0,
                    source=DetectionSource.REGEX,
                    rule="rf_payment_reference",
                    precedence=95,
                )
            )
        return output

    def _detect_common_secrets(self, text: str) -> list[Detection]:
        output: list[Detection] = []
        for match in COMMON_SECRET_PATTERN.finditer(text):
            lowered = match.group(0).lower()
            entity_type = (
                EntityType.SESSION_TOKEN
                if lowered.startswith(("sess", "session"))
                else EntityType.API_TOKEN
            )
            output.append(
                Detection(
                    start=match.start(),
                    end=match.end(),
                    text=match.group(0),
                    entity_type=entity_type,
                    confidence=1.0,
                    source=DetectionSource.REGEX,
                    rule="common_secret_prefix",
                    precedence=100,
                    rationale_code="secret_prefix",
                )
            )
        return output

    def _detect_urls(self, text: str) -> list[Detection]:
        output: list[Detection] = []
        for match in URL_PATTERN.finditer(text):
            value = match.group(0).rstrip(".,;:!?")
            end = match.start() + len(value)
            normalized = value if "://" in value else f"http://{value}"
            try:
                parsed = urlsplit(normalized)
            except ValueError:
                continue
            host = (parsed.hostname or "").lower()
            query_keys = {
                unquote(key).lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
            }
            internal = self._internal_host(host) or any(
                marker in parsed.path.lower()
                for marker in ("/case-management", "/crm/", "/portal/", "/admin/")
            )
            sensitive = bool(query_keys & SENSITIVE_QUERY_KEYS) or parsed.username is not None
            entity_type = (
                EntityType.INTERNAL_URL
                if internal
                else EntityType.SENSITIVE_URL_PARAMETER
                if sensitive
                else EntityType.URL
            )
            output.append(
                Detection(
                    start=match.start(),
                    end=end,
                    text=value,
                    entity_type=entity_type,
                    confidence=1.0 if internal or sensitive else 0.95,
                    source=DetectionSource.REGEX,
                    rule=("internal_url" if internal else "sensitive_url" if sensitive else "url"),
                    precedence=95 if internal or sensitive else 60,
                    rationale_code=(
                        "internal_url"
                        if internal
                        else "sensitive_url_parameter"
                        if sensitive
                        else None
                    ),
                )
            )
        return output

    @staticmethod
    def _internal_host(host: str) -> bool:
        if host in {"localhost", "127.0.0.1", "::1"}:
            return True
        if host.endswith((".local", ".internal", ".localhost")):
            return True
        if any(marker in host for marker in ("intranet", "corp", "internal", "portal")):
            return True
        try:
            return ipaddress.ip_address(host).is_private
        except ValueError:
            return False

    @staticmethod
    def _trim_iban(candidate: str) -> str:
        compact = re.sub(r"\s", "", candidate).upper()
        target_length = IBAN_LENGTHS.get(compact[:2])
        if target_length is None:
            return candidate
        seen = 0
        for index, char in enumerate(candidate):
            if not char.isspace():
                seen += 1
            if seen == target_length:
                return candidate[: index + 1]
        return candidate

    @staticmethod
    def _deduplicate(detections: list[Detection]) -> list[Detection]:
        output: dict[tuple[int, int, EntityType], Detection] = {}
        for item in detections:
            key = (item.start, item.end, item.entity_type)
            current = output.get(key)
            if current is None or (item.precedence, item.confidence) > (
                current.precedence,
                current.confidence,
            ):
                output[key] = item
        return list(output.values())

    def _matches(self, text: str) -> Iterator[tuple[RegexRule, re.Match[str]]]:
        for rule in self.rules:
            for match in rule.pattern.finditer(text):
                yield rule, match
