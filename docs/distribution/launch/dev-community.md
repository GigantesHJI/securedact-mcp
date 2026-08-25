# DEV Community — Article Outline

> Outline (not a finished marketing article). Angle: a concrete, technical
> story about putting a privacy firewall in front of AI agents.

## Suggested title options

1. Your AI agent can read your files and secrets — here's how we're putting a privacy firewall in front of it
2. Local-first privacy for AI agents: detecting PII and secrets before they leave your machine
3. Building a fail-closed privacy layer for MCP agents (with runnable examples)

## Intro

AI agents are no longer just chatting — they read files, call tools, and send
prompts to external models. That convenience quietly exposes PII, API keys, and
local documents. This post walks through how SecuRedact puts a local privacy
firewall in front of that flow.

## Threat scenario

A benign-looking task — "summarize this lead" — pulls in an email, an IBAN, and
a stray API key from context. Without a check, all three reach the external
model. (Use only synthetic examples; never real data.)

## Architecture

- `User/Agent → SecuRedact → AI Model / Tool / File / Network`
- Local detection: deterministic credential/identifier detectors + optional
  local NER.
- Policy engine applies versioned profiles (`strict_external_ai`, `gdpr`).
- Residual validation before approval; minimal responses by default.

## Filesystem protection example

Show `securedact_read_file` defending against traversal/symlinks and blocking
protected paths (`.env`, SSH keys) before any content is read.

## Secret detection example

Show a synthetic `.env` block being detected and blocked under
`strict_external_ai` (no sanitized output returned).

## Egress / network protection example

Show outbound tool calls classified as internal/external/unknown, and how
policy can require approval or block egress.

## MCP integration

The `prepare_for_external_ai` tool returns `status` + `sanitized_text`; the
host must use only the approved output. Enforced hooks for Claude Code and
Gemini CLI run the same decision before a prompt, model call, or tool action.

## Local-first privacy model

No network listener by default, no telemetry, no provider calls, fail-closed
when required detection is unavailable.

## Open-source link

- Repo: https://github.com/GigantesHJI/securedact-mcp
- Docs: https://github.com/GigantesHJI/securedact-mcp/tree/main/docs
- Synthetic demos: `docs/distribution/security-demo.md`

## Limitations

Detection is not a guarantee; MCP mode requires the host to actually invoke the
tool; GDPR behavior is detection, not legal certification.

## Invitation

Try the runnable demos, open issues with synthetic test cases, and tell us
which host integrations you need next.
