"""Provider-safe messages shared by local enforcement hook front ends."""

from __future__ import annotations

PROMPT_BLOCK = "SecuRedact detected protected information. The prompt was not sent."
REVIEW_BLOCK = "SecuRedact requires local human review before this content can be sent."
FAIL_CLOSED = "SecuRedact could not validate this protected path, so it was not sent."
TOOL_BLOCK = "SecuRedact blocked this outbound action because it contains protected information."


def prompt_block(reason: str) -> dict[str, object]:
    """Build the documented Claude prompt-block response without input text."""

    return {"decision": "block", "reason": reason, "suppressOriginalPrompt": True}
