# SecuRedact Enforced

SecuRedact Enforced protects configured provider lifecycle paths. It is distinct
from MCP mode: MCP mode gives an agent a SecuRedact tool it may call; enforced
mode invokes local SecuRedact from a provider hook before the configured action
proceeds.

The hooks call the packaged `securedact_core` public API directly. They do not
use an MCP round-trip, so an instruction such as "ignore the privacy tool" does
not decide whether the check runs.

## Boundary and failure behavior

`UserPromptSubmit` checks submitted prompt text. Both current providers can
block a prompt but cannot replace it, so a prompt that needs sanitization is
blocked rather than transparently rewritten. `review_required`, a policy block,
malformed prompt input, a model/runtime failure, and an internal error all block
the prompt without echoing its protected values.

`PreToolUse` checks selected outbound tool inputs. The included configurations
cover remote MCP tools for Codex and Claude Code, plus Claude Code `WebFetch`
and `WebSearch`. Sanitizable inputs are rewritten using each provider's official
`updatedInput` mechanism; review-required, blocked, malformed protected, and
failed checks deny the tool call. Local file tools and shell commands are left
unchanged by these plugins.

This is not a claim that every exfiltration route is stopped. It does not
necessarily protect arbitrary subprocess or network traffic, browser extensions,
manual commands, applications that do not load the plugin, provider paths that
bypass documented hooks, Codex hosted tools that do not traverse local hooks, or
Claude Code `@` file references inserted before a tool call.

## Evidence

Codex documents deterministic `UserPromptSubmit` and `PreToolUse` command hooks,
prompt blocking, and `updatedInput` for supported tool inputs in its [Hooks
documentation](https://learn.chatgpt.com/docs/hooks). Claude Code documents the
same lifecycle order, its prompt-block response, and `updatedInput` for
`PreToolUse` in its [Hooks reference](https://code.claude.com/docs/en/hooks).

| Provider | Evidence level | Current result |
| --- | --- | --- |
| Codex | CONFIG VALIDATED; UNIT TESTED | Manifest and hook JSON validate locally; actual host load pending. |
| Claude Code | CONFIG VALIDATED; UNIT TESTED | Manifest and hook JSON validate locally; actual host load pending. |

## Runtime distribution assessment

Both plugin directories are self-contained hook artifacts but intentionally do
not download code or models. Today each requires a separately installed
SecuRedact Python runtime (including the required local model) and `python` on
`PATH`; Codex uses `python` on Windows. The current provider plugin formats can
run packaged scripts, but do not themselves establish a safe Python runtime or
model bootstrap contract. A future one-click install can bundle a signed native
runtime or depend on a signed SecuRedact package; model downloads must remain an
explicit, consented SecuRedact setup step.
