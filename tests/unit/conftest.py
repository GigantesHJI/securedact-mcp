from __future__ import annotations

import pytest

from securedact_enforced import gemini_hook


@pytest.fixture(autouse=True)
def _stub_runtime_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep unit tests hermetic: do not spawn real enforcement daemons.

    The prompt/model hooks lazily start the local runtime when ``SessionStart``
    left no live daemon. Unit tests mock inspection outcomes directly and must
    not pay for (or be destabilized by) spawning a detached daemon process. The
    real-host regression test overrides ``ensure_runtime`` to exercise the real
    start path.
    """

    monkeypatch.setattr(gemini_hook, "ensure_runtime", lambda *args, **kwargs: None)
    monkeypatch.setattr(gemini_hook, "start_runtime", lambda *args, **kwargs: None)
