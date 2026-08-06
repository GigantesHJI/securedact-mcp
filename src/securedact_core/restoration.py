# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256

RESTORATION_HANDLE_BYTES = 32
RESTORATION_HANDLE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


class RestorationErrorCode(StrEnum):
    MALFORMED = "restoration_session_malformed"
    UNKNOWN = "restoration_session_unknown"
    EXPIRED = "restoration_session_expired"
    CONSUMED = "restoration_session_consumed"
    CAPACITY = "restoration_vault_capacity_exceeded"
    MAPPING_TOO_LARGE = "restoration_mapping_too_large"


class RestorationSessionError(ValueError):
    def __init__(self, code: RestorationErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


@dataclass(slots=True)
class _Session:
    mapping: dict[str, str]
    expires_at: float
    size: int
    single_use: bool


@dataclass(slots=True)
class _Tombstone:
    code: RestorationErrorCode
    expires_at: float


class RestorationVault:
    """Bounded in-memory storage for opaque, expiring restoration sessions."""

    def __init__(
        self,
        *,
        ttl_seconds: float = 900.0,
        max_sessions: int = 256,
        max_total_bytes: int = 4 * 1024 * 1024,
        max_mapping_bytes: int = 1024 * 1024,
        clock: Callable[[], float] = time.monotonic,
        token_factory: Callable[[int], str] = secrets.token_urlsafe,
    ) -> None:
        if ttl_seconds <= 0 or min(max_sessions, max_total_bytes, max_mapping_bytes) <= 0:
            raise ValueError("restoration vault limits must be positive")
        self.ttl_seconds = ttl_seconds
        self.max_sessions = max_sessions
        self.max_total_bytes = max_total_bytes
        self.max_mapping_bytes = max_mapping_bytes
        self._clock = clock
        self._token_factory = token_factory
        self._sessions: dict[str, _Session] = {}
        self._tombstones: dict[bytes, _Tombstone] = {}
        self._total_bytes = 0
        self._lock = threading.RLock()

    @property
    def session_count(self) -> int:
        with self._lock:
            self._cleanup_locked(self._clock())
            return len(self._sessions)

    @property
    def total_bytes(self) -> int:
        with self._lock:
            self._cleanup_locked(self._clock())
            return self._total_bytes

    def store(self, mapping: Mapping[str, str], *, single_use: bool = True) -> str:
        copied = dict(mapping)
        if any(
            not isinstance(key, str) or not key or not isinstance(value, str)
            for key, value in copied.items()
        ):
            raise ValueError("restoration mappings must contain non-empty string keys and values")
        size = sum(
            len(key.encode("utf-8")) + len(value.encode("utf-8")) for key, value in copied.items()
        )
        if size > self.max_mapping_bytes:
            raise RestorationSessionError(RestorationErrorCode.MAPPING_TOO_LARGE)
        now = self._clock()
        with self._lock:
            self._cleanup_locked(now)
            if (
                len(self._sessions) >= self.max_sessions
                or self._total_bytes + size > self.max_total_bytes
            ):
                raise RestorationSessionError(RestorationErrorCode.CAPACITY)
            for _attempt in range(8):
                handle = self._token_factory(RESTORATION_HANDLE_BYTES)
                if (
                    RESTORATION_HANDLE_PATTERN.fullmatch(handle)
                    and handle not in self._sessions
                    and self._handle_digest(handle) not in self._tombstones
                ):
                    break
            else:
                raise RestorationSessionError(RestorationErrorCode.CAPACITY)
            self._sessions[handle] = _Session(
                mapping=copied,
                expires_at=now + self.ttl_seconds,
                size=size,
                single_use=single_use,
            )
            self._total_bytes += size
            return handle

    def consume(self, handle: str) -> dict[str, str]:
        if not RESTORATION_HANDLE_PATTERN.fullmatch(handle):
            raise RestorationSessionError(RestorationErrorCode.MALFORMED)
        now = self._clock()
        digest = self._handle_digest(handle)
        with self._lock:
            self._cleanup_locked(now)
            tombstone = self._tombstones.get(digest)
            if tombstone is not None:
                raise RestorationSessionError(tombstone.code)
            session = self._sessions.get(handle)
            if session is None:
                raise RestorationSessionError(RestorationErrorCode.UNKNOWN)
            if session.expires_at <= now:
                self._erase_locked(handle, session)
                self._tombstones[digest] = _Tombstone(
                    RestorationErrorCode.EXPIRED,
                    now + self.ttl_seconds,
                )
                raise RestorationSessionError(RestorationErrorCode.EXPIRED)
            result = dict(session.mapping)
            if session.single_use:
                self._erase_locked(handle, session)
                self._tombstones[digest] = _Tombstone(
                    RestorationErrorCode.CONSUMED,
                    now + self.ttl_seconds,
                )
            return result

    def cleanup(self) -> int:
        with self._lock:
            before = len(self._sessions)
            self._cleanup_locked(self._clock())
            return before - len(self._sessions)

    def clear(self) -> None:
        with self._lock:
            for session in self._sessions.values():
                session.mapping.clear()
            self._sessions.clear()
            self._tombstones.clear()
            self._total_bytes = 0

    def _cleanup_locked(self, now: float) -> None:
        for handle, session in list(self._sessions.items()):
            if session.expires_at <= now:
                self._erase_locked(handle, session)
                self._tombstones[self._handle_digest(handle)] = _Tombstone(
                    RestorationErrorCode.EXPIRED,
                    now + self.ttl_seconds,
                )
        for digest, tombstone in list(self._tombstones.items()):
            if tombstone.expires_at <= now:
                del self._tombstones[digest]

    def _erase_locked(self, handle: str, session: _Session) -> None:
        self._sessions.pop(handle, None)
        self._total_bytes = max(0, self._total_bytes - session.size)
        session.mapping.clear()

    @staticmethod
    def _handle_digest(handle: str) -> bytes:
        return sha256(handle.encode("ascii")).digest()
