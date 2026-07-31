from __future__ import annotations

from typing import Protocol

from ..models import Detection


class Detector(Protocol):
    name: str
    contextual: bool

    def detect(self, text: str) -> list[Detection]: ...
