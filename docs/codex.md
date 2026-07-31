# Codex Setup

## Install first

Create a Python 3.12 virtual environment and install Securedact MCP. See
[Installation](installation.md).

For the secure production path, install the ML dependencies and complete guided
model setup before configuring Codex:

```powershell
python -m pip install "securedact-mcp[ml]"
securedact-mcp install
securedact-mcp models verify
```

## Windows configuration

Codex supports local `stdio` MCP servers in `~/.codex/config.toml` or a
project-scoped `.codex/config.toml`. Copy
[`examples/codex-config.toml`](../examples/codex-config.toml), replace
`<USERNAME>`, and verify both absolute paths.

```toml
[mcp_servers.securedact]
command = 'C:\Users\<USERNAME>\Desktop\securedact-mcp\.venv\Scripts\python.exe'
args = ["-m", "securedact_mcp"]
cwd = 'C:\Users\<USERNAME>\Desktop\securedact-mcp'
enabled = true
required = true
startup_timeout_sec = 30
tool_timeout_sec = 60
```

Use an absolute interpreter path so Codex launches the reviewed virtual
environment rather than an unrelated Python installation.

## Required server behavior

`required = true` makes Codex startup or resume fail if the enabled MCP server
cannot initialize. It does **not** guarantee that every prompt is automatically
routed through `analyze_text` or `redact_text`.

## Verify tools

1. Run `codex mcp list`.
2. Start Codex and use `/mcp`.
3. Confirm exactly:
   - `analyze_text`
   - `redact_text`
   - `restore_text`
   - `create_safe_copy`
4. Test `redact_text` with `alex.example@example.test`.
5. Confirm `status` is `ok` and use only `sanitized_text`.

If the selected contextual model is missing or corrupt, the tool result fails
closed and provides the matching `securedact-mcp install --language ...`
command. Do not add a reduced-coverage override merely to suppress that error.

## Recommended secure workflow

Add durable project guidance requiring the agent to:

```text
1. Call analyze_text on content before downstream AI use.
2. Stop for review or block outcomes.
3. Call redact_text with the approved policy.
4. Continue only when status is exactly "ok".
5. Use only sanitized_text downstream.
6. Keep entities and mapping local.
7. Never call restore_text before provider-bound use.
```

Workflow instructions reduce host misuse risk but should be tested; they are not
equivalent to a transparent network interceptor.

## Official reference

See the
[official Codex MCP documentation](https://developers.openai.com/codex/mcp/)
and
[configuration reference](https://developers.openai.com/codex/config-reference/).
Client options can change, so verify current documentation when deploying.
