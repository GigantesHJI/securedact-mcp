# SecuRedact Enforced

SecuRedact Enforced protects configured provider lifecycle paths. It is distinct
from MCP mode: MCP mode gives an agent a SecuRedact tool it may call; enforced
mode invokes local SecuRedact from a provider hook before the configured action
proceeds.

The enforcement decision is made by the packaged `securedact_core` engine held
in one warmed per-session local runtime. Claude Code prompt/tool hooks and
Gemini CLI lifecycle hooks ask that same warmed runtime over an authenticated
loopback protocol; they never rebuild SecuRedact per call. No MCP round-trip is
involved, so an instruction such as "ignore the privacy tool" does not decide
whether the check runs.

## Shipped integrations

Two provider integrations ship in this release. There is no Codex enforced
plugin; Codex is configured in MCP mode only (see
[`docs/codex.md`](codex.md) and `integrations/codex/`).

### Claude Code

`SessionStart` and `SessionEnd` manage the per-session warmed runtime.
`UserPromptSubmit` checks submitted prompt text. Claude can block a prompt but
cannot replace it, so a prompt that needs sanitization is blocked rather than
transparently rewritten. `review_required`, a policy block, malformed prompt
input, a model/runtime failure, and an internal error all block the prompt
without echoing its protected values.

`PreToolUse` checks selected outbound tool inputs. Its matcher is exactly
`^(mcp__.*|WebFetch|WebSearch)$`, so it intercepts remote MCP tools plus Claude
Code `WebFetch` and `WebSearch` only. Local file tools and shell commands are
left unchanged by this matcher. Sanitizable inputs are rewritten using Claude's
official `updatedInput` mechanism; review-required, blocked, malformed
protected, and failed checks deny the tool call.

### Gemini CLI

`SessionStart` and `SessionEnd` manage the per-session warmed runtime.
`BeforeAgent` checks the user's text turn. `BeforeModel` may rewrite the
model-bound request with the signed sanitized text and injects opaque
pseudonym-token guidance so the model treats tokens such as `[EMAIL_1]` as
semantic labels rather than resolvable values. `BeforeTool` intercepts tool
calls.

The Gemini `BeforeTool` matcher is
`^(mcp_.*|.*(http|web|search|fetch|request|api|connect).*)$`. Because it matches
tool *names*, a local tool whose name contains one of those substrings
(`http`, `web`, `search`, `fetch`, `request`, `api`, `connect`) is classified as
outbound and checked (or denied) like an external tool. This is broader than
Claude Code's matcher and is intentional: Gemini tool names do not carry an
`mcp__` marker, so the substring list is the practical signal for outbound
tools.

## Boundary and failure behavior

This is not a claim that every exfiltration route is stopped. It does not
necessarily protect arbitrary subprocess or network traffic, browser extensions,
manual commands, applications that do not load the plugin, provider paths that
bypass documented hooks, or Claude Code `@` file references inserted before a
tool call.

## Evidence

Claude Code documents the lifecycle order, its prompt-block response, and
`updatedInput` for `PreToolUse` in its [Hooks
reference](https://code.claude.com/docs/en/hooks). Gemini CLI documents
`SessionStart`, `BeforeAgent`, `BeforeModel`, `BeforeTool`, and `SessionEnd`
hook events and structured JSON responses in its official CLI hooks
documentation.

| Provider | Evidence level | Current result |
| --- | --- | --- |
| Claude Code | CONFIG VALIDATED; UNIT TESTED | Manifest and hook JSON validate locally; actual host load pending. |
| Gemini CLI | CONFIG VALIDATED; UNIT TESTED | Manifest and hook JSON validate locally; actual host load pending. |

## Runtime distribution and guided onboarding

The Claude and Gemini hook artifacts needed by `securedact-mcp setup` are
included as package resources in the wheel. Setup supplies those resources to
the providers' official plugin/extension commands, so a repository checkout is
not required. Provider configuration remains separate from the installed
Python runtime and local models.

The integrations never download packages or models while a hook is running.
`setup` delegates contextual installation and verification to SecuRedact's
existing explicit, consented model flow. It does not bypass Claude/Gemini trust,
write provider credentials, or invoke their hosted models.