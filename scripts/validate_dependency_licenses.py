# SPDX-License-Identifier: Apache-2.0
"""Fail closed on unexpected dependency-license metadata."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TypedDict


class LicenseRecord(TypedDict):
    Name: str
    Version: str
    License: str


ALLOWED_LICENSE_MARKERS = (
    "apache",
    "bsd",
    "isc",
    "lesser general public license",
    "mit",
    "mozilla public license",
    "mpl-2.0",
    "psf",
    "public domain",
    "python software foundation",
    "unlicense",
)
FORBIDDEN_LICENSE_MARKERS = ("commercial", "proprietary", "unlicensed")
LICENSE_FILE_EXCEPTIONS = {
    ("sigstore-models", "0.0.6"): (
        "licenses/LICENSE",
        "860e3d7a86b84e6a7012c7a635fc64df475cebc6cce34dfeb73a5982ec58176c",
    )
}


def _verify_installed_exception(name: str, version: str) -> bool:
    expected = LICENSE_FILE_EXCEPTIONS.get((name.casefold(), version))
    if expected is None:
        return False
    relative_path, expected_digest = expected
    try:
        distribution = importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return False
    if distribution.version != version:
        return False
    license_file = next(
        (
            item
            for item in distribution.files or ()
            if str(item).replace("\\", "/").endswith(relative_path)
        ),
        None,
    )
    if license_file is None:
        return False
    path = Path(str(distribution.locate_file(license_file)))
    if not path.is_file():
        return False
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest == expected_digest and path.read_text(encoding="utf-8").startswith("MIT License")


def validate_records(
    records: list[LicenseRecord],
    *,
    verify_exception: Callable[[str, str], bool] = _verify_installed_exception,
) -> list[str]:
    errors: list[str] = []
    seen: dict[tuple[str, str], str] = {}
    for record in records:
        name = record["Name"].strip()
        version = record["Version"].strip()
        license_name = record["License"].strip()
        identity = (name.casefold(), version)
        if not name or not version:
            errors.append(f"dependency_license_record_invalid:{name or 'missing'}")
            continue
        lowered = license_name.casefold()
        if identity in seen:
            if seen[identity] != lowered:
                errors.append(f"dependency_license_record_conflict:{name}")
            continue
        seen[identity] = lowered
        if lowered in {"", "unknown"}:
            if not verify_exception(name, version):
                errors.append(f"dependency_license_unknown:{name}")
            continue
        if any(marker in lowered for marker in FORBIDDEN_LICENSE_MARKERS):
            errors.append(f"dependency_license_forbidden:{name}")
            continue
        if not any(marker in lowered for marker in ALLOWED_LICENSE_MARKERS):
            errors.append(f"dependency_license_unreviewed:{name}")
    return sorted(set(errors))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    arguments = parser.parse_args(argv)
    try:
        payload = json.loads(arguments.report.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("dependency_license_report_not_list")
        records: list[LicenseRecord] = []
        for record in payload:
            if (
                not isinstance(record, dict)
                or set(record) != {"Name", "Version", "License"}
                or not all(isinstance(value, str) for value in record.values())
            ):
                raise ValueError("dependency_license_record_schema_invalid")
            records.append(
                LicenseRecord(
                    Name=record["Name"],
                    Version=record["Version"],
                    License=record["License"],
                )
            )
        errors = validate_records(records)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: dependency_license_report_invalid:{type(exc).__name__}")
        return 1
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"Dependency license policy passed ({len(records)} records).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
