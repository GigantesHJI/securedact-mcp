from __future__ import annotations

from scripts.validate_dependency_licenses import LicenseRecord, validate_records


def test_known_license_families_pass() -> None:
    records = [
        LicenseRecord(Name="example-a", Version="1", License="Apache-2.0"),
        LicenseRecord(Name="example-b", Version="2", License="MIT License"),
        LicenseRecord(Name="example-c", Version="3", License="BSD-3-Clause"),
    ]
    assert validate_records(records) == []


def test_unknown_unreviewed_and_conflicting_licenses_fail_closed() -> None:
    records = [
        LicenseRecord(Name="unknown-package", Version="1", License="UNKNOWN"),
        LicenseRecord(Name="new-license", Version="1", License="MIT"),
        LicenseRecord(Name="new-license", Version="1", License="Example License"),
        LicenseRecord(Name="unreviewed", Version="1", License="Example License"),
    ]
    assert validate_records(records, verify_exception=lambda _name, _version: False) == [
        "dependency_license_record_conflict:new-license",
        "dependency_license_unknown:unknown-package",
        "dependency_license_unreviewed:unreviewed",
    ]
