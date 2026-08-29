# SPDX-License-Identifier: Apache-2.0
"""Cross-process single-instance guard for the managed agent (AGENT-018).

Prevents two agent loops (a manual ``agent run`` plus the background service, or
two service instances) from polling the same control-plane queue at once, which
would double-claim jobs and corrupt local state. Uses an OS advisory lock on a
lock file so it is released automatically if the process crashes.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl


@contextmanager
def agent_instance_lock(lock_path: Path) -> Iterator[bool]:
    """Context manager yielding ``True`` if the lock was acquired, else ``False``.

    The lock is held for the ``with`` block and released (or dropped on process
    exit) automatically. A non-blocking acquire means a second concurrent agent
    loop observes ``False`` and must exit rather than spawning a duplicate loop.
    """

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(lock_path, "a+")  # lifetime managed by the contextmanager
    acquired = False
    try:
        if sys.platform == "win32":
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                acquired = True
            except OSError:
                acquired = False
        else:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError:
                acquired = False
        yield acquired
    finally:
        try:
            if sys.platform == "win32":
                if acquired:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        handle.close()
