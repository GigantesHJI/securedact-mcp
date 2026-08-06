# Codex setup

Use the maintained sample and workflow in
[`integrations/codex`](../integrations/codex/README.md). Replace every absolute
path placeholder with the reviewed Python environment and repository location.

Set the server as required where appropriate, but do not confuse successful MCP
startup with prompt interception. Project instructions must require
`prepare_for_external_ai`, stop on every non-`ok` result, and forward only
`sanitized_text`. The expected tool set contains five operations, including the
recommended high-level tool.

Install and verify the selected local contextual model before using sensitive
input:

```powershell
securedact-mcp install
securedact-mcp models verify
securedact-mcp diagnostics runtime
```

Compatibility statements and their evidence level are tracked in
[Compatibility](compatibility.md). Client behavior can change; verify current
Codex MCP documentation when deploying.
