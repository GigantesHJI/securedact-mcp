"""Provider-safe messages shared by local enforcement hook front ends."""

from __future__ import annotations

PROMPT_BLOCK = "SecuRedact detected protected information. The prompt was not sent."
REVIEW_BLOCK = "SecuRedact requires local human review before this content can be sent."
FAIL_CLOSED = "SecuRedact could not validate this protected path, so it was not sent."
TOOL_BLOCK = "SecuRedact blocked this outbound action because it contains protected information."

# FW-020 result-inspection messages. These never contain raw sensitive content;
# they explain why a model-bound tool result was sanitized or hidden.
RESULT_BLOCKED = "SecuRedact replaced this tool result because it contained protected information."
RESULT_OVERSIZE = (
    "SecuRedact blocked this tool result because it exceeded the configured inspection limit."
)

# FW-030 egress messages. These explain why an outbound network write was blocked
# or held for approval without echoing any request body, header, or credential.
EGRESS_BLOCKED = (
    "SecuRedact blocked this outbound network request because it contains protected information."
)
EGRESS_OVERSIZE = (
    "SecuRedact blocked this outbound network request because it exceeded the inspection limit."
)
EGRESS_APPROVAL = (
    "SecuRedact requires local approval before this outbound network request can proceed."
)


def prompt_block(reason: str) -> dict[str, object]:
    """Build the documented Claude prompt-block response without input text."""

    return {"decision": "block", "reason": reason, "suppressOriginalPrompt": True}
