from __future__ import annotations

import json
from pathlib import Path

# Independent HIPAA Safe Harbor adversarial dataset.
# It is deliberately separate from benchmarks/hipaa/hipaa_safe_harbor.json (the 27-sample
# implementation corpus). Gold labels (gold_present) encode what SHOULD be detected under
# HIPAA Safe Harbor (45 CFR 164.514(b)(2)), independent of what the engine currently does.
# hard_negative=True cases assert that nothing in the category scope is detected (precision
# guards). adversarial=True cases probe known or suspected blind spots and are expected to
# surface as reproduced false negatives (known_missing) or false positives (known_extra);
# those are measured empirically by scripts/experimental/run_hipaa_adversarial.py, never
# silently pinned to make a number look good.

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "benchmarks" / "hipaa" / "hipaa_adversarial.json"

CASES: list[dict] = []


def add(
    cid: str,
    category: str,
    domain: str,
    text: str,
    gold_present: list[str],
    *,
    gold_absent: list[str] | None = None,
    hard_negative: bool = False,
    adversarial: bool = False,
    rationale: str = "",
) -> None:
    CASES.append(
        {
            "id": cid,
            "category": category,
            "domain": domain,
            "text": text,
            "gold_present": gold_present,
            "gold_absent": gold_absent or [],
            "hard_negative": hard_negative,
            "adversarial": adversarial,
            "rationale": rationale,
        }
    )


# --- A. Names ----------------------------------------------------------------------------
add("adv-A-001", "A", "intake", "Name: John A. Smith", ["person"],
    rationale="Labelled name field is detected deterministically.")
add("adv-A-002", "A", "intake", "Patient: Maria Gonzalez", ["person"],
    rationale="Labelled patient name detected.")
add("adv-A-003", "A", "clinical_note", "Attending physician: Jane Doe", ["person"],
    rationale="Labelled attending name detected.")
add("adv-A-004", "A", "clinical_note", "Guarantor name: William Clark", ["person"],
    rationale="Guarantor name field detected.")
add("adv-A-005", "A", "clinical_note",
    "John Smith presented with chest pain and was admitted.", ["person"],
    adversarial=True,
    rationale="Unlabelled free-text name; without the contextual model it is a reproduced FN.")
add("adv-A-006", "A", "clinical_note",
    "The patient, Mary Johnson, was discharged to home care.", ["person"],
    adversarial=True,
    rationale="Unlabelled free-text name; reproduced FN without Flair.")
add("adv-A-007", "A", "clinical_note",
    "Next of kin is Emily Carter who will coordinate follow-up.", ["person"],
    adversarial=True,
    rationale="'next of kin:' is not a name label; reproduced FN.")
add("adv-A-008", "A", "clinical_note",
    "Emergency contact on file is Olivia Bennett.", ["person"],
    adversarial=True,
    rationale="'emergency contact:' not a name label; reproduced FN.")
add("adv-A-009", "A", "hard_negative", "Smith & Wesson is the equipment manufacturer.", [],
    hard_negative=True, gold_absent=["person"],
    rationale="Organisation token; person must not be synthesised.")
add("adv-A-010", "A", "hard_negative", "the smiths moved to a new clinic location.", [],
    hard_negative=True, gold_absent=["person"],
    rationale="Lowercase plural surname is not a detected person name.")
add("adv-A-011", "A", "hard_negative", "Dr. Lee reviewed the radiology images.", [],
    hard_negative=True, gold_absent=["person"],
    rationale="'Dr. Lee' is a title+name but no name label fires; assert no false person.")
add("adv-A-012", "A", "intake", "Son of Mr. Lee was notified of the results.", ["person"],
    adversarial=True,
    rationale="'Mr. Lee' is a person reference but no name label matches; reproduced FN.")

# --- B. Geographic subdivisions smaller than a state -------------------------------------
add("adv-B-001", "B", "address", "14 Birchwood Lane, Springfield, IL 62704, United States.",
    ["address", "us_zip"], rationale="Full street address + state-qualified ZIP.")
add("adv-B-002", "B", "address", "ZIP code: 90210-1234", ["us_zip"],
    rationale="Labelled ZIP+4.")
add("adv-B-003", "B", "address", "62704, IL", ["us_zip"],
    rationale="ZIP preceded by state token.")
add("adv-B-004", "B", "address", "Boston MA 02115", ["us_zip"],
    rationale="State then ZIP with a space is a postal form.")
add("adv-B-005", "B", "address", "Reno NV 89501", ["us_zip"],
    rationale="State then ZIP with a space.")
add("adv-B-006", "B", "address", "Springfield, IL, 62704", ["us_zip"],
    rationale="Comma between state and ZIP.")
add("adv-B-007", "B", "address", "14 Birchwood Lane, Springfield, IL 62704",
    ["address", "us_zip"], rationale="Address without trailing country.")
add("adv-B-008", "B", "address", "PO Box 1234, Seattle WA 98101", ["us_zip"],
    rationale="ZIP qualified by WA.")
add("adv-B-009", "B", "address", "New York, NY 10001", ["us_zip"],
    rationale="City, state, ZIP.")
add("adv-B-010", "B", "address",
    "Street: 100 Main St, Apt 4B, Denver CO 80203", ["address", "us_zip"],
    rationale="Street address with state-qualified ZIP.")
add("adv-B-011", "B", "hard_negative", "The code 90210 was referenced without a state.", [],
    hard_negative=True, gold_absent=["us_zip"],
    rationale="Bare 5-digit value with no state is not a ZIP (no over-redaction).")
add("adv-B-012", "B", "hard_negative", "The quantity 48217 was ordered from the pharmacy.", [],
    hard_negative=True, gold_absent=["us_zip"],
    rationale="Bare 5-digit quantity must not become a ZIP.")
add("adv-B-013", "B", "hard_negative", "Cook County, IL received the referral.", [],
    hard_negative=True, gold_absent=["us_zip"],
    rationale="County + state, no ZIP; not a ZIP false positive.")
add("adv-B-014", "B", "clinical_note",
    "The patient resides in Chicago, Illinois near the lake.", ["location"],
    adversarial=True,
    rationale="City/state is a Safe Harbor geographic identifier; undetected without Flair (FN).")
add("adv-B-015", "B", "clinical_note",
    "Transferred from Los Angeles, California to a rural clinic.", ["location"],
    adversarial=True,
    rationale="City/state geographic identifier; reproduced FN without contextual model.")
add("adv-B-016", "B", "hard_negative",
    "latitude 41.8781 longitude -87.6298 plotted on the map.", [],
    hard_negative=True, gold_absent=["us_zip", "address"],
    rationale="Coordinates are not a ZIP or street address; assert no false geo detection.")

# --- C. Dates (except year) and ages over 89 ---------------------------------------------
add("adv-C-001", "C", "clinical_note",
    "The patient was admitted on 03/14/2021 and discharged 03/20/2021.", ["date"],
    rationale="Individual dates mm/dd/yyyy.")
add("adv-C-002", "C", "intake", "Date of birth: 09/30/1965", ["date_of_birth", "date"],
    rationale="Labelled DOB; the same value is also a general date.")
add("adv-C-003", "C", "clinical_note", "The 92-year-old patient recovered", ["age"],
    rationale="Age over 89 hyphenated.")
add("adv-C-004", "C", "clinical_note", "aged 105 at last visit", ["age"],
    rationale="'aged N' form.")
add("adv-C-005", "C", "clinical_note", "age of 90 years", ["age"],
    rationale="'age of N' form.")
add("adv-C-006", "C", "clinical_note", "appointment on 03/14/2021 at 14:30",
    ["date", "time"], rationale="Unlabelled date + time; appointment label needs a colon.")
add("adv-C-007", "C", "hard_negative", "storage age is 45 days for the sample", [],
    hard_negative=True, gold_absent=["age"],
    rationale="Non-individual age must not trigger age>89.")
add("adv-C-008", "C", "hard_negative", "the sample age 9 weeks is not a person", [],
    hard_negative=True, gold_absent=["age"],
    rationale="Non-individual age guard.")
add("adv-C-009", "C", "intake", "Date of birth: 1965-09-30", ["date_of_birth", "date"],
    adversarial=True,
    rationale="ISO yyyy-mm-dd DOB; detected as both date_of_birth and date.")
add("adv-C-010", "C", "intake", "DOB: 1965-09-30", ["date_of_birth", "date"],
    adversarial=True,
    rationale="DOB abbreviation + ISO date; now detected as date_of_birth and date.")
add("adv-C-011", "C", "clinical_note", "born 9/30/1965 and raised locally", ["date"],
    rationale="Unlabelled individual date; general_date catches mm/dd/yyyy.")
add("adv-C-012", "C", "clinical_note", "procedure date 12/01/2022 was uneventful", ["date"],
    rationale="Unlabelled individual date.")
add("adv-C-013", "C", "clinical_note", "the 95 yrs old donor was unsuitable", ["age"],
    adversarial=True,
    rationale="'N yrs old' (no hyphen) is not matched by the age grammar (FN).")
add("adv-C-014", "C", "hard_negative", "the 88-year-old was below the threshold", [],
    hard_negative=True, gold_absent=["age"],
    rationale="Age 88 is not over 89; must not be flagged.")
add("adv-C-015", "C", "clinical_note", "the 119-year-old centenarian was reviewed", ["age"],
    rationale="Upper bound of age grammar (119).")
add("adv-C-016", "C", "intake", "Date: 2021-03-14", ["date"],
    adversarial=True,
    rationale="Labelled ISO date is not matched by DATE_VALUE (FN).")
add("adv-C-017", "C", "clinical_note", "discharged 03/20/2021 after surgery", ["date"],
    rationale="Unlabelled discharge date.")
add("adv-C-018", "C", "hard_negative", "the meeting is scheduled on Friday", [],
    hard_negative=True, gold_absent=["date"],
    rationale="Weekday with no calendar date is not a date entity.")

# --- D. Telephone numbers ---------------------------------------------------------------
add("adv-D-001", "D", "contact", "Call 415-555-2671", ["phone"],
    rationale="Hyphen NANP form (3-3-4).")
add("adv-D-002", "D", "contact", "Phone: 415-555-2671", ["phone"],
    rationale="Labelled hyphen phone.")
add("adv-D-003", "D", "contact", "Telephone: 415-555-2671", ["phone"],
    rationale="Telephone label.")
add("adv-D-004", "D", "contact", "Call 1-800-555-0199", ["phone"],
    rationale="1-NXX-NXX-XXXX form.")
add("adv-D-005", "D", "contact", "Reach the clinic at +1 (415) 555-2671", ["phone"],
    rationale="International/parenthesised form.")
add("adv-D-006", "D", "contact", "Message 212.555.0199 for results", ["phone"],
    rationale="Dot-separated NANP.")
add("adv-D-007", "D", "contact", "tel 305-555-0123 to confirm", ["phone"],
    rationale="'tel' token preceding a hyphen number.")
add("adv-D-008", "D", "contact", "mobile 646-555-0144 available after hours", ["phone"],
    rationale="Mobile token preceding hyphen number.")
add("adv-D-009", "D", "contact", "call 415.555.2671 ext 22", ["phone"],
    rationale="Dot phone with extension text.")
add("adv-D-010", "D", "hard_negative", "the value 4155552671 is just a counter", [],
    hard_negative=True, gold_absent=["phone"],
    rationale="10-digit run with no separators is not a phone (precision guard).")
add("adv-D-011", "D", "hard_negative", "the part number 1234567 is obsolete", [],
    hard_negative=True, gold_absent=["phone"],
    rationale="7-digit run must not be a phone.")
add("adv-D-012", "D", "hard_negative", "invoice 555-01-23 is not a phone", [],
    hard_negative=True, gold_absent=["phone"],
    rationale="Short grouped digits are not a phone.")

# --- E. Fax numbers ---------------------------------------------------------------------
add("adv-E-001", "E", "contact", "Fax: +1 415-555-8890", ["fax"],
    rationale="Labelled fax with country code.")
add("adv-E-002", "E", "contact", "FAX# 415-555-8890", ["fax"],
    rationale="Fax label with hash.")
add("adv-E-003", "E", "contact", "Fax number: (415) 555-8890", ["fax"],
    rationale="Fax number with parentheses.")
add("adv-E-004", "E", "contact", "Telefax: 415-555-8890", ["fax"],
    rationale="Telefax label.")
add("adv-E-005", "E", "contact", "Facsimile: 415-555-8890", ["fax"],
    rationale="Facsimile label.")
add("adv-E-006", "E", "contact", "Fax: 415 555 8890", ["fax"],
    rationale="Space-separated fax value.")
add("adv-E-007", "E", "contact", "Our fax is 415-555-8890 for referrals.", ["fax"],
    adversarial=True,
    rationale="Fax with no colon/label syntax; generic phone catches the number but fax label "
             "does not fire (reproduced FN for fax).")
add("adv-E-008", "E", "hard_negative", "the tax form 415-55 is incomplete", [],
    hard_negative=True, gold_absent=["fax"],
    rationale="Too-short grouped digits are not a fax.")

# --- F. Email addresses ------------------------------------------------------------------
add("adv-F-001", "F", "contact", "Reach the coordinator at maria.gonzalez@example.test", ["email"],
    rationale="Bare email.")
add("adv-F-002", "F", "contact", "Email: john@example.test for scheduling", ["email"],
    rationale="Labelled email.")
add("adv-F-003", "F", "contact", "contact: a.b-c@example.test please", ["email"],
    rationale="Subdomain-style email on the allowed example.test domain.")
add("adv-F-004", "F", "contact", "support+billing@example.test handles queries", ["email"],
    rationale="Plus-tag email.")
add("adv-F-005", "F", "contact", "user_name@example.test is the inbox", ["email"],
    rationale="Underscore local part.")
add("adv-F-006", "F", "hard_negative", "page 3 of 10 in the report", [],
    hard_negative=True, gold_absent=["email"],
    rationale="No email structure.")
add("adv-F-007", "F", "hard_negative", "the local account a@b is invalid", [],
    hard_negative=True, gold_absent=["email"],
    rationale="Email needs a real TLD; a@b is rejected.")
add("adv-F-008", "F", "contact", "Write to first.last@example.test with questions", ["email"],
    rationale="Standard dotted email.")

# --- G. Social Security numbers ----------------------------------------------------------
add("adv-G-001", "G", "intake", "SSN: 123-45-6789. Please verify before enrollment.", ["ssn"],
    rationale="Labelled valid SSN.")
add("adv-G-002", "G", "intake", "Social Security Number: 789 65 4321 on file.", ["ssn"],
    rationale="Space-separated SSN.")
add("adv-G-003", "G", "intake", "SS# 789-65-4320 listed on the form.", ["ssn"],
    rationale="SS# label.")
add("adv-G-004", "G", "intake", "social security no 123456789 recorded.", ["ssn"],
    rationale="Unseparated SSN matched by the label grammar.")
add("adv-G-005", "G", "clinical_note", "The record shows 123-45-6789 as the identifier.", ["ssn"],
    rationale="Unlabelled canonical 3-2-4 is the SSN shape.")
add("adv-G-006", "G", "clinical_note", "Cross-reference 789-65-4321 in the chart.", ["ssn"],
    rationale="Unlabelled canonical SSN.")
add("adv-G-007", "G", "hard_negative", "SSN 000-12-3456 is an invalid area.", [],
    hard_negative=True, gold_absent=["ssn"], rationale="Area 000 rejected.")
add("adv-G-008", "G", "hard_negative", "SSN 666-12-3456 is unassigned.", [],
    hard_negative=True, gold_absent=["ssn"], rationale="Area 666 rejected.")
add("adv-G-009", "G", "hard_negative", "SSN 123-00-4567 has a bad group.", [],
    hard_negative=True, gold_absent=["ssn"], rationale="Group 00 rejected.")
add("adv-G-010", "G", "hard_negative", "SSN 123-45-0000 has a bad serial.", [],
    hard_negative=True, gold_absent=["ssn"], rationale="Serial 0000 rejected.")
add("adv-G-011", "G", "hard_negative", "the part code 12-3456-789 was scanned.", [],
    hard_negative=True, gold_absent=["ssn"], rationale="Wrong grouping is not an SSN.")
add("adv-G-012", "G", "hard_negative", "the serial 123-00-4567 is not an SSN.", [],
    hard_negative=True, gold_absent=["ssn"], rationale="Bad group serial rejected.")

# --- H. Medical record numbers -----------------------------------------------------------
add("adv-H-001", "H", "record", "Medical record number: MED-772019 referenced in chart.",
    ["medical_record_number"], rationale="Labelled MRN.")
add("adv-H-002", "H", "record", "MRN: MRN-558201 confirmed.", ["medical_record_number"],
    rationale="MRN label.")
add("adv-H-003", "H", "record", "medisch dossiernummer: MDN-44120 archived.",
    ["medical_record_number"], rationale="Dutch MRN label.")
add("adv-H-004", "H", "record", "Medical Record: MED772019 scanned.",
    ["medical_record_number"], rationale="MRN without hyphen in value.")
add("adv-H-005", "H", "record", "Record number: REC-552109 on file.",
    ["medical_record_number"], adversarial=True,
    rationale="'record number' is not a recognised MRN label (reproduced FN).")
add("adv-H-006", "H", "record", "Chart ID: CHART-5521 referenced.",
    ["medical_record_number"], adversarial=True,
    rationale="'chart ID' is an MRN analogue but not labelled (reproduced FN).")
add("adv-H-007", "H", "record", "patient MRN is 558201 in the system.",
    ["medical_record_number"], adversarial=True,
    rationale="MRN without colon/separator is not matched (reproduced FN).")
add("adv-H-008", "H", "hard_negative", "the term MRN alone was mentioned.", [],
    hard_negative=True, gold_absent=["medical_record_number"],
    rationale="Bare label with no value is not an MRN.")

# --- I. Health plan beneficiary numbers --------------------------------------------------
add("adv-I-001", "I", "insurance", "Member ID: MBR-448821039 on the card.",
    ["health_plan_beneficiary"], rationale="Member ID label.")
add("adv-I-002", "I", "insurance", "Subscriber ID: SUB-90012773 verified.",
    ["health_plan_beneficiary"], rationale="Subscriber ID label.")
add("adv-I-003", "I", "insurance", "Beneficiary ID: BEN-55210983 active.",
    ["health_plan_beneficiary"], rationale="Beneficiary ID label.")
add("adv-I-004", "I", "insurance", "Insurance ID: INS-552109 current.",
    ["health_plan_beneficiary"], rationale="Insurance ID label.")
add("adv-I-005", "I", "insurance", "Payer ID: PAY-552109 billed.",
    ["health_plan_beneficiary"], rationale="Payer ID label.")
add("adv-I-006", "I", "insurance", "Health plan number: HPN-552109 listed.",
    ["health_plan_beneficiary"], rationale="Health plan number label.")
add("adv-I-007", "I", "hard_negative", "member since 2020 with the plan.", [],
    hard_negative=True, gold_absent=["health_plan_beneficiary"],
    rationale="'member since' is not a beneficiary ID label.")
add("adv-I-008", "I", "record", "Patient ID: PAT-552109 cross-referenced.",
    [], hard_negative=True, gold_absent=["health_plan_beneficiary"],
    rationale="Patient ID must not be misclassified as a health-plan beneficiary.")
add("adv-I-009", "I", "insurance", "MBR55210983 is the printed number.",
    ["health_plan_beneficiary"], adversarial=True,
    rationale="MBR without hyphen/separator is not matched by label or prefix (FN).")
add("adv-I-010", "I", "insurance", "Member No: MBR 448821039 on file.",
    ["health_plan_beneficiary"], adversarial=True,
    rationale="Value containing a space is rejected by the identifier grammar (FN).")

# --- J. Account numbers ------------------------------------------------------------------
add("adv-J-001", "J", "financial", "Account No: ACC-773102884 billed this month.",
    ["account_number"], rationale="Account No label.")
add("adv-J-002", "J", "financial", "Account number: ACC-773102884 current.",
    ["account_number"], rationale="Account number label.")
add("adv-J-003", "J", "financial", "Bank account reference: BAR-55210983 noted.",
    ["bank_account_reference"], rationale="Bank account reference label.")
add("adv-J-004", "J", "financial", "Payment reference: PAYREF-552109 cleared.",
    ["payment_reference"], rationale="Payment reference label.")
add("adv-J-005", "J", "financial", "acct: 441029 settled.", ["account_number"],
    rationale="'acct' label.")
add("adv-J-006", "J", "financial", "Account #: 773102884 overdue.", ["account_number"],
    rationale="'account #' label.")
add("adv-J-007", "J", "hard_negative", "the account is closed, no number given.", [],
    hard_negative=True, gold_absent=["account_number"],
    rationale="No value; not an account number.")
add("adv-J-008", "J", "hard_negative", "reference 12345 mentioned in passing.", [],
    hard_negative=True, gold_absent=["account_number"],
    rationale="Generic number without a label is not an account number.")
add("adv-J-009", "J", "financial", "Account No ACC-773102884 was reused.",
    ["account_number"], adversarial=True,
    rationale="Account label without colon/separator is not matched (FN).")
add("adv-J-010", "J", "financial", "bank account ref BAR-55210983 pending.",
    ["bank_account_reference"], adversarial=True,
    rationale="Label without separator is not matched (FN).")
add("adv-J-011", "J", "financial", "payment ref: PAYREF 552109 posted.",
    ["payment_reference"], adversarial=True,
    rationale="Space in value rejected by grammar (FN).")
add("adv-J-012", "J", "financial", "ACC773102884 appeared on the statement.",
    ["account_number"], adversarial=True,
    rationale="ACC prefix without hyphen/separator is not matched (FN).")

# --- K. Certificate/license numbers ------------------------------------------------------
add("adv-K-001", "K", "license", "Driver license: DL-A9920314 presented.",
    ["driving_licence_number"], rationale="Driver license label.")
add("adv-K-002", "K", "license", "Driving licence number: DL-9920314 shown.",
    ["driving_licence_number"], rationale="Driving licence number label.")
add("adv-K-003", "K", "license", "Passport: P-55210983 on record.", ["passport_number"],
    rationale="Passport label.")
add("adv-K-004", "K", "license", "National ID: NID-55210983 verified.",
    ["national_id"], rationale="National ID label.")
add("adv-K-005", "K", "license", "rijbewijs: RBW-552109 valid.",
    ["driving_licence_number"], rationale="Dutch driving licence label.")
add("adv-K-006", "K", "license", "paspoortnummer: PASP-552109 valid.",
    ["passport_number"], rationale="Dutch passport label.")
add("adv-K-007", "K", "license", "ID number: IDN-55210983 recorded.",
    ["national_id"], rationale="ID number label.")
add("adv-K-008", "K", "license", "passport number: AB1234567 issued.",
    ["passport_number"], rationale="Alphanumeric passport value.")
add("adv-K-009", "K", "hard_negative", "license plate 8KGD204 is a vehicle mark.", [],
    hard_negative=True, gold_absent=["driving_licence_number", "national_id", "passport_number"],
    rationale="Licence plate is category L, not a K certificate (no false K).")
add("adv-K-010", "K", "hard_negative", "certificate of completion was issued.", [],
    hard_negative=True,
    gold_absent=["driving_licence_number", "national_id", "passport_number"],
    rationale="Occupational certificates are not enumerated (documented K gap).")
add("adv-K-011", "K", "license", "Driver licence: CA 9920314 on file.",
    ["driving_licence_number"], adversarial=True,
    rationale="Space in value rejected by identifier grammar (FN).")
add("adv-K-012", "K", "license", "Passport: AB 1234567 presented.",
    ["passport_number"], adversarial=True,
    rationale="Space in value rejected by grammar (FN).")
add("adv-K-013", "K", "license", "National ID: XY 55210983 shown.",
    ["national_id"], adversarial=True,
    rationale="Space in value rejected by grammar (FN).")
add("adv-K-014", "K", "license", "DL-A9920314 found on the form.",
    ["driving_licence_number"], rationale="DL prefix detected without a label.")

# --- L. Vehicle identifiers and serial numbers -------------------------------------------
add("adv-L-001", "L", "vehicle", "VIN: 1M8GDM9AXKP042788 recorded for the vehicle.",
    ["vehicle_identifier"], rationale="Labelled VIN.")
add("adv-L-002", "L", "vehicle", "License plate: 8KGD204 observed at scene.",
    ["vehicle_identifier"], rationale="Licence plate label.")
add("adv-L-003", "L", "vehicle",
    "Vehicle identification number: 1M8GDM9AXKP042788 logged.", ["vehicle_identifier"],
    rationale="VIN label full form.")
add("adv-L-004", "L", "vehicle", "Chassis number: CHS-55210983 stamped.",
    ["vehicle_identifier"], rationale="Chassis number label.")
add("adv-L-005", "L", "vehicle", "Plate no: 8KGD204 photographed.",
    ["vehicle_identifier"], rationale="Plate no label.")
add("adv-L-006", "L", "vehicle", "Plate number: 8KGD204 noted.",
    ["vehicle_identifier"], rationale="Plate number label.")
add("adv-L-007", "L", "hard_negative", "the word vin appeared in unrelated text.", [],
    hard_negative=True, gold_absent=["vehicle_identifier"],
    rationale="Lowercase 'vin' with no 17-char value is not a VIN.")
add("adv-L-008", "L", "vehicle", "VIN 1M8GDM9AXKP042788 on the door.",
    ["vehicle_identifier"], adversarial=True,
    rationale="VIN without colon/separator is not matched by the label rule (FN).")
add("adv-L-009", "L", "vehicle", "license plate 8KGD204 was recorded.",
    ["vehicle_identifier"], adversarial=True,
    rationale="Plate label without separator is not matched (FN).")
add("adv-L-010", "L", "vehicle", "VIN: 1M8GDM9A0KP042788 (check digit not validated).",
    ["vehicle_identifier"], adversarial=True,
    rationale="Labelled VIN is detected even with an invalid North American check digit; "
             "documented quality gap, not a detection miss.")
add("adv-L-011", "L", "hard_negative",
    "The batch token 1Z8GDM9AXKP04278Q is 17 chars with excluded letters.", [],
    hard_negative=True, gold_absent=["vehicle_identifier"],
    rationale="Excluded letters make it not a VIN; no false positive.")
add("adv-L-012", "L", "vehicle", "vin: 1m8gdm9axkp042788 lowercased.",
    ["vehicle_identifier"], rationale="Case-insensitive VIN label.")
add("adv-L-013", "L", "vehicle", "Chassis no: CHS-55210983 present.",
    ["vehicle_identifier"], rationale="Chassis no label.")
add("adv-L-014", "L", "vehicle",
    "The recovered car had 1M8GDM9AXKP042788 stamped on the dash.", ["vehicle_identifier"],
    adversarial=True,
    rationale="Unlabelled VIN is a documented gap (FN).")

# --- M. Device identifiers and serial numbers --------------------------------------------
add("adv-M-001", "M", "device", "Device identifier: DEV-55120983 implanted 2020.",
    ["device_identifier"], rationale="Labelled device identifier.")
add("adv-M-002", "M", "device", "Device ID: DEV-55120983 serialised.",
    ["device_identifier"], rationale="Device ID label.")
add("adv-M-003", "M", "device", "apparaat-ID: DEV-55120983 geactiveerd.",
    ["device_identifier"], rationale="Dutch device label.")
add("adv-M-004", "M", "device", "Device: DEV-55120983 in service.",
    ["device_identifier"], rationale="DEV prefix detected without explicit label.")
add("adv-M-005", "M", "device", "Serial No: SN-55210983 on the pump.",
    ["device_identifier"], adversarial=True,
    rationale="Serial numbers are part of Safe Harbor category M but 'serial' is not a device "
             "label; reproduced FN (M is over-claimed as FULL).")
add("adv-M-006", "M", "device", "Serial number: SN55210983 recorded.",
    ["device_identifier"], adversarial=True,
    rationale="Unprefixed serial number not detected (FN).")
add("adv-M-007", "M", "hard_negative", "the device was replaced last week.", [],
    hard_negative=True, gold_absent=["device_identifier"],
    rationale="No identifier present.")
add("adv-M-008", "M", "device", "DEV55120983 printed on the casing.",
    ["device_identifier"], adversarial=True,
    rationale="DEV prefix without hyphen/separator is not matched (FN).")

# --- N. Web URLs -------------------------------------------------------------------------
add("adv-N-001", "N", "web", "Patient summary at https://summary.example.test/patient shared.",
    ["url"], rationale="External https URL.")
add("adv-N-002", "N", "web", "Record posted at http://example.test/portal/record externally.",
    ["internal_url"], rationale="Path '/portal/' marks the URL as internal.")
add("adv-N-003", "N", "web", "Internal case at https://example.test/case-management/12.",
    ["internal_url"], rationale="Path '/case-management' marks the URL as internal.")
add("adv-N-004", "N", "web", "Login link https://example.test/login?token=abc123.",
    ["sensitive_url_parameter"], rationale="Token query parameter.")
add("adv-N-005", "N", "web", "See www.example.test/page for details.", ["url"],
    rationale="WWW URL.")
add("adv-N-006", "N", "web", "Portal https://example.test/patient?id=552109 opened.",
    ["url"], rationale="Bare 'id' query key is not in the sensitive-query set; external URL.")
add("adv-N-007", "N", "web", "Public docs at https://public.example.test/docs available.",
    ["url"], rationale="External public URL.")
add("adv-N-008", "N", "web", "Admin console https://10.0.0.5/admin reachable.",
    ["internal_url"], rationale="Private IP host + admin path.")
add("adv-N-009", "N", "hard_negative", "the string http:// was left incomplete.", [],
    hard_negative=True, gold_absent=["url"],
    rationale="No host; not a URL.")
add("adv-N-010", "N", "hard_negative", "ftp server at ftp.example.test hosts files.", [],
    hard_negative=True, gold_absent=["url"],
    rationale="FTP host without http/www is not a detected URL.")

# --- O. IP addresses ---------------------------------------------------------------------
add("adv-O-001", "O", "network", "Remote session from 203.0.113.45 logged.",
    ["ipv4"], rationale="Public IPv4.")
add("adv-O-002", "O", "network", "Tunnel endpoint 2001:db8::1 established.",
    ["ipv6"], rationale="IPv6 documentation address.")
add("adv-O-003", "O", "network", "Traffic from 198.51.100.23 and 2001:db8::2 observed.",
    ["ipv4", "ipv6"], rationale="Mixed IPv4/IPv6.")
add("adv-O-004", "O", "network", "IPv4: 192.0.2.1 configured.", ["ipv4"],
    rationale="Labelled IPv4.")
add("adv-O-005", "O", "network", "IPv6 address 2001:db8:abcd:12::1 assigned.",
    ["ipv6"], rationale="Labelled IPv6.")
add("adv-O-006", "O", "network", "Local hosts 192.168.0.1 and 10.0.0.1 contacted.",
    ["ipv4", "ipv4"], rationale="Private IPv4 pair.")
add("adv-O-007", "O", "hard_negative", "the ratio 1.2.3 is not an address.", [],
    hard_negative=True, gold_absent=["ipv4"],
    rationale="Three octets is not an IPv4.")
add("adv-O-008", "O", "hard_negative", "the value 256.1.1.1 is out of range.", [],
    hard_negative=True, gold_absent=["ipv4"],
    rationale="Invalid octet rejected by ipaddress validator (precision guard).")

# --- P. Biometric identifiers ------------------------------------------------------------
add("adv-P-001", "P", "biometric", "Fingerprint template BIO-FP-5521 stored.",
    ["biometric_data"], rationale="BIO prefix biometric.")
add("adv-P-002", "P", "biometric", "Face scan FACE-5521 enrolled.", ["biometric_data"],
    rationale="FACE prefix biometric.")
add("adv-P-003", "P", "biometric", "Iris image IRIS-5521 captured.", ["biometric_data"],
    rationale="IRIS prefix biometric.")
add("adv-P-004", "P", "biometric", "Voice print VOICE-5521 on file.", ["biometric_data"],
    rationale="VOICE prefix biometric.")
add("adv-P-005", "P", "biometric", "Genetic marker GEN-5521 sequenced.",
    ["genetic_data"], rationale="GEN prefix genetic.")
add("adv-P-006", "P", "biometric", "Biometric: BIO-FP-5521 retained.", ["biometric_data"],
    rationale="BIO prefix detected.")
add("adv-P-007", "P", "biometric", "DNA sequencing results indicate familial risk.",
    ["genetic_data"], adversarial=True,
    rationale="Textual DNA reference is genetic data but not enumerated (FN, documented P gap).")
add("adv-P-008", "P", "hard_negative", "the patient has a heart murmur.", [],
    hard_negative=True, gold_absent=["biometric_data", "genetic_data"],
    rationale="Clinical note, not a biometric/genetic identifier.")

# --- Q. Full-face photographs and comparable images (unsupported) ------------------------
add("adv-Q-001", "Q", "image_limitation",
    "Attached full-face photograph of the patient for identification.", [],
    hard_negative=True, gold_absent=["us_zip", "ssn", "vehicle_identifier"],
    rationale="Images are unsupported; text-only engine must detect nothing here.")
add("adv-Q-002", "Q", "image_limitation",
    "Scanned driver license image included in the upload.", [],
    hard_negative=True, gold_absent=["us_zip", "ssn", "vehicle_identifier"],
    rationale="Image content is out of scope for the text engine.")
add("adv-Q-003", "Q", "image_limitation",
    "Comparable image with identifiable facial features attached.", [],
    hard_negative=True, gold_absent=["us_zip", "ssn", "vehicle_identifier"],
    rationale="Unsupported category Q.")
add("adv-Q-004", "Q", "image_limitation",
    "X-ray film of the chest stored in the image archive.", [],
    hard_negative=True, gold_absent=["us_zip", "ssn", "vehicle_identifier"],
    rationale="Image unsupported; absence of a finding is expected, not compliance.")

# --- R. Any other unique identifying number, characteristic, or code ---------------------
add("adv-R-001", "R", "record", "Patient number: PAT-772019 cross-referenced.",
    ["patient_number"], rationale="Patient number label.")
add("adv-R-002", "R", "record", "Case number: CASE-551209 opened.", ["case_number"],
    rationale="Case number label.")
add("adv-R-003", "R", "hr", "Employee ID: EMP-552109 on payroll.", ["employee_id"],
    rationale="Employee ID label.")
add("adv-R-004", "R", "record", "Customer number: CUST-552109 active.", ["customer_number"],
    rationale="Customer number label.")
add("adv-R-005", "R", "hr", "Payroll number: PAYROLL-552109 current.",
    ["payroll_number"], rationale="Payroll number label.")
add("adv-R-006", "R", "financial", "Invoice number: INV-552109 sent.", ["invoice_number"],
    rationale="Invoice number label.")
add("adv-R-007", "R", "insurance", "Policy number: POL-552109 renewed.", ["policy_number"],
    rationale="Policy number label.")
add("adv-R-008", "R", "record", "Patient ID: PAT-772019 verified.", ["patient_number"],
    rationale="Patient ID label.")
add("adv-R-009", "R", "record", "Case ID: CASE-551209 indexed.", ["case_number"],
    rationale="Case ID label.")
add("adv-R-010", "R", "record", "Customer ID: CUST-552109 looked up.", ["customer_number"],
    rationale="Customer ID label.")
add("adv-R-011", "R", "hr", "Employee number: EMP-552109 filed.", ["employee_id"],
    rationale="Employee number label.")
add("adv-R-012", "R", "financial", "Invoice ID: INV-552109 paid.", ["invoice_number"],
    rationale="Invoice ID label.")
add("adv-R-013", "R", "insurance", "Policy number POL 552109 renewed.",
    ["policy_number"], adversarial=True,
    rationale="Space in value rejected by grammar though POL prefix exists (FN).")
add("adv-R-014", "R", "record", "Patient No: PAT 772019 verified.",
    ["patient_number"], adversarial=True,
    rationale="Space in value rejected by grammar (FN).")
add("adv-R-015", "R", "hard_negative", "the number 552109 alone was mentioned.", [],
    hard_negative=True,
    gold_absent=["patient_number", "case_number", "employee_id", "customer_number",
                 "payroll_number", "invoice_number", "policy_number"],
    rationale="Bare number without label/prefix is not a unique identifier.")
add("adv-R-016", "R", "hard_negative", "order case 12 of 30 was processed.", [],
    hard_negative=True, gold_absent=["case_number"],
    rationale="'case 12' without 'number'/'ID' label is not a case number.")
add("adv-R-017", "R", "record", "KLANT-552109 is the Dutch customer key.",
    ["customer_number"], rationale="KLANT prefix.")
add("adv-R-018", "R", "record", "ZAAK-552109 is the Dutch case key.", ["case_number"],
    rationale="ZAAK prefix.")
add("adv-R-019", "R", "clinical_note",
    "Relationship: spouse is listed as the emergency contact.", ["relationship"],
    adversarial=True,
    rationale="Relationship is a Safe Harbor category R type but has no detector (FN).")
add("adv-R-020", "R", "hard_negative", "the patient is clinically stable today.", [],
    hard_negative=True,
    gold_absent=["patient_number", "case_number", "employee_id", "customer_number",
                 "payroll_number", "invoice_number", "policy_number"],
    rationale="No unique identifier present.")

DOC = {
    "corpus_version": 1,
    "split": "hipaa_adversarial",
    "description": (
        "Independent HIPAA Safe Harbor adversarial evaluation (NOT the 27-sample implementation "
        "corpus). Gold labels encode what SHOULD be detected under 45 CFR 164.514(b)(2). "
        "hard_negative cases assert nothing in the category scope is detected (precision guards). "
        "adversarial cases probe blind spots and surface as reproduced known_missing/known_extra "
        "when measured by scripts/experimental/run_hipaa_adversarial.py."
    ),
    "generated_by": "scripts/experimental/build_hipaa_adversarial.py",
    "samples": CASES,
}

OUT.write_text(json.dumps(DOC, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"wrote {len(CASES)} adversarial cases to {OUT}")
