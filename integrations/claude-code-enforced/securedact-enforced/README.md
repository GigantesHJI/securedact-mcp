# SecuRedact Enforced for Claude Code

SecuRedact Enforced is a local privacy-enforcement plugin for Claude Code. Its
deterministic `UserPromptSubmit` hook evaluates each submitted prompt before
normal Claude model processing. When the local SecuRedact policy identifies
protected information, the hook blocks the prompt or requires local human
review rather than passing it on.

The hook is a Claude Code lifecycle callback, not a model instruction. Text in
a prompt such as “ignore SecuRedact” cannot disable an enabled hook.

## What this plugin does

- Starts a local, loopback-only SecuRedact runtime at `SessionStart` and warms
  the verified contextual models once for that Claude Code session.
- Sends each later `UserPromptSubmit` through an authenticated local HMAC IPC
  request to that warmed runtime; prompt text is never written to the runtime
  state file or sent off-machine.
- Runs SecuRedact detection locally in the Python runtime selected by `python`.
- Applies the installed SecuRedact policy and contextual-model requirements.
- Allows ordinary prompts by returning exit code 0 with no stdout output.
- Returns Claude Code's documented JSON block decision for protected or
  unvalidated prompts, with the original prompt suppressed from the block
  message.
- Applies the same runtime to matching outbound MCP, `WebFetch`, and
  `WebSearch` tool calls.

SecuRedact Enforced does not download Python packages or model weights while a
hook is running. `SessionStart` launches model warm-up in a local child process
without holding up the Claude Code interface. Prompt hooks use the
already-warmed runtime and have a five-second client budget. Until warm-up is
complete, and whenever the runtime is missing, corrupt, unavailable, or
unresponsive, the prompt fails closed with a generic local setup/review message.

## Prerequisites

Install these three things before enabling the plugin on a new Windows machine:

1. **Claude Code** with plugin and hook support (tested with Claude Code
   v2.1.234).
2. **SecuRedact Python runtime.** Use Python `>=3.12,<3.13` and install the ML
   extra into the same Python environment that Claude Code resolves as
   `python`:

   ```powershell
   python -m pip install "securedact-mcp[ml]"
   ```

   For development from a checkout of this repository instead:

   ```powershell
   python -m pip install -e ".[ml,dev]"
   ```

3. **Verified local SecuRedact model(s).** Model setup is an explicit,
   consent-based action and may download upstream model artifacts. It is never
   performed by the hook:

   ```powershell
   securedact-mcp install
   securedact-mcp models verify
   ```

   Production defaults require a verified contextual model. Do not set
   `SECUREDACT_REQUIRE_FLAIR=0` for normal privacy enforcement.

The default Windows managed model location is
`%LOCALAPPDATA%\Securedact\MCP\models`; it is not packaged in this plugin.

## Install from the SecuRedact marketplace

From a fresh Claude Code session, add either a local checkout for testing or a
published GitHub repository when one is available:

```text
/plugin marketplace add GigantesHJI/securedact-mcp
/plugin install securedact-enforced@securedact
```

Review the plugin details and choose the installation scope in Claude Code.
If Claude Code says to reload plugins, run `/reload-plugins`, then start a new
session. The marketplace plugin is copied into Claude Code's local plugin cache,
so it contains no paths to files outside this plugin directory.

Run `/hooks` and inspect `UserPromptSubmit`. It should be listed as a command
hook with source **Plugin Hooks** from `securedact-enforced`. `SessionStart`
and `SessionEnd` are companion plugin hooks that start/warm and cleanly stop the
per-session local runtime.

## Verify safely

First submit a benign prompt:

```text
What is 2 + 2?
```

Claude Code should continue normally.

Then use only synthetic data to verify the block path:

```text
Could you rewrite this into a more professional message for my colleague? "Could you send the revised paperwork to Sophie? You can reach her at s.devries@example.test. She mentioned she'll need some flexibility with the meeting schedule because she's currently receiving treatment for depression."
```

SecuRedact should stop the prompt and request local human review before normal
model processing. To verify prompt-injection resistance, prefix that same
synthetic example with an instruction to ignore or bypass SecuRedact; an enabled
deterministic hook still evaluates and blocks the prompt.

## Troubleshooting

- **`No module named securedact_enforced` or a Python startup failure:** install
  `securedact-mcp[ml]` into the interpreter that `python` resolves to in Claude
  Code. Check `python -c "import sys; print(sys.executable)"` in the same
  environment.
- **A generic SecuRedact block for an ordinary prompt:** run
  `securedact-mcp models verify`. Repair the local runtime or verified model
  installation; do not bypass the hook.
- **A prompt is blocked just after opening a session:** `SessionStart` is still
  warming the verified contextual model in the local runtime. Later prompts in
  that session must not reload it. Wait for warm-up to finish, or repair the
  runtime/model installation; do not extend or bypass the prompt-hook timeout.
- **The hook is absent:** confirm the plugin is installed and enabled, then use
  `/hooks` to inspect the `UserPromptSubmit` entry and its source. Reload or
  start a fresh Claude Code session after installation if requested.
- **Model setup:** run `securedact-mcp install` interactively so the operator
  can review upstream model details and consent to a download. The hook itself
  never performs this download.

## Uninstall

In Claude Code, remove the plugin with:

```text
/plugin uninstall securedact-enforced@securedact
```

Removing the plugin does not remove the separately installed Python runtime or
local model data. Manage those with SecuRedact's normal installation tooling.

## Privacy and security boundaries

The demonstrated guarantee is limited to this enabled Claude Code
`UserPromptSubmit` hook: it can stop a protected prompt from proceeding to
normal Claude model processing. It does not claim that Claude Code itself never
locally receives, displays, or records submitted text before the lifecycle hook
runs. The plugin also depends on a functioning local Python runtime and
verified SecuRedact model; invalid prerequisites fail closed rather than making
an approval decision. Review sensitive content locally and do not include real
personal information in support requests or test cases.

The local runtime binds only to `127.0.0.1` and uses a random per-session HMAC
secret stored in Claude Code's user-owned plugin data directory. This prevents
unauthenticated local requests or forged responses; it is not a defense against
another process already running with the same user's filesystem permissions.

## License

The plugin source is part of the Securedact MCP repository and is licensed under
[Apache License 2.0](https://github.com/GigantesHJI/securedact-mcp/blob/main/LICENSE.md).
Model weights and third-party
runtime dependencies retain their own licenses.
