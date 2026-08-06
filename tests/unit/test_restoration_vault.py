from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from securedact_core import RestorationErrorCode, RestorationSessionError, RestorationVault


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_sessions_expire_and_cleanup_erases_mapping_bytes() -> None:
    clock = Clock()
    vault = RestorationVault(ttl_seconds=5, clock=clock)
    handle = vault.store({"[EMAIL_1]": "alex@example.test"})
    assert vault.total_bytes > 0

    clock.now = 106.0
    assert vault.cleanup() == 1
    assert vault.total_bytes == 0
    with pytest.raises(RestorationSessionError) as error:
        vault.consume(handle)
    assert error.value.code == RestorationErrorCode.EXPIRED


def test_single_use_session_allows_only_one_concurrent_consumer() -> None:
    vault = RestorationVault()
    handle = vault.store({"[EMAIL_1]": "alex@example.test"})

    def consume() -> str:
        try:
            vault.consume(handle)
        except RestorationSessionError as exc:
            return exc.code.value
        return "ok"

    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(lambda _index: consume(), range(8)))

    assert outcomes.count("ok") == 1
    assert outcomes.count("restoration_session_consumed") == 7
    assert vault.total_bytes == 0


def test_capacity_mapping_limit_and_malformed_handles_fail_safely() -> None:
    vault = RestorationVault(max_sessions=1, max_total_bytes=32, max_mapping_bytes=24)
    vault.store({"[A_1]": "12345678"})
    with pytest.raises(RestorationSessionError) as capacity:
        vault.store({"[B_1]": "12345678"})
    assert capacity.value.code == RestorationErrorCode.CAPACITY

    with pytest.raises(RestorationSessionError) as oversized:
        RestorationVault(max_mapping_bytes=4).store({"[A_1]": "1234"})
    assert oversized.value.code == RestorationErrorCode.MAPPING_TOO_LARGE

    with pytest.raises(RestorationSessionError) as malformed:
        vault.consume("../not-a-handle")
    assert malformed.value.code == RestorationErrorCode.MALFORMED


def test_unknown_session_and_clear_are_rejected_without_retaining_data() -> None:
    vault = RestorationVault()
    handle = "A" * 43
    with pytest.raises(RestorationSessionError) as unknown:
        vault.consume(handle)
    assert unknown.value.code == RestorationErrorCode.UNKNOWN

    vault.store({"[EMAIL_1]": "alex@example.test"})
    vault.clear()
    assert vault.session_count == 0
    assert vault.total_bytes == 0
