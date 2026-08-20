# SecuRedact Enforced for Claude Code

The plugin artifact is in `securedact-enforced/`. It contains a Claude Code
plugin manifest, deterministic hook configuration, and supplemental skill.
Install the SecuRedact runtime and its local model first; no dependency or model
is downloaded by the plugin.

Normal PyPI users can run `securedact-mcp setup`; it supplies the packaged copy
of this plugin to Claude's official marketplace and plugin commands. For
development, run `claude plugin validate --strict securedact-enforced`, then
install the directory or expose it through a Claude Code marketplace. Ensure
`python -m securedact_enforced.provider_hook` succeeds in the
same user environment and use `/hooks` to confirm the pre-tool-use registration.
See
[`docs/enforced.md`](../../docs/enforced.md) for scope and limitations.
