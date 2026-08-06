# Versioning and compatibility

Package releases use semantic versioning. Public JSON includes
`schema_version: "1"`; additive optional fields can remain compatible, while a
removed field or changed meaning requires a schema-version and migration
decision.

After 1.0, removing or renaming a public Python symbol, MCP tool, parameter,
status, reason-code meaning, response mode, policy semantic, or restoration
contract is a major change. Before 1.0, such changes still require prominent
changelog and upgrade notes. A security fix may intentionally disable unsafe
legacy behavior sooner; the release notes must say so.

Tool registration order is not an API. Stable tool names, schemas, status
values, safe reason codes, and minimal response privacy properties are APIs.
Detector internals, merge helpers, managed-model storage layout, and lifecycle
implementation are not public unless exported and documented in
[Public API](public-api.md).

Deprecations must identify the replacement and earliest removal release. The
current direct mapping and legacy redaction response are deprecated in favor of
opaque restoration sessions and minimal preparation responses.
