# Windsurf setup

Use the maintained configuration, safe workflow, synthetic expected response,
and troubleshooting notes in
[`integrations/windsurf`](../integrations/windsurf/README.md). Replace the
absolute Python-path placeholder, restart Windsurf, and confirm all five tools
are listed.

Workspace rules must call `prepare_for_external_ai`, stop on every non-`ok`
status, and pass only `sanitized_text` downstream. An enabled MCP server does
not guarantee automatic prompt routing. See [Compatibility](compatibility.md)
for the tested evidence level and limitations.
