# Upgrade and migration

## Safe upgrade

1. Read the changelog and release notes, especially schema, policy, model, and
   security sections.
2. Verify checksums, keyless signature, provenance attestation, and repository
   identity before installing.
3. Install into a new virtual environment from the reviewed release artifact;
   do not overwrite the known-good environment.
4. Run `securedact-mcp models verify` and `securedact-mcp diagnostics runtime`.
5. Run the installed MCP smoke test and the host's synthetic routing test.
6. Switch the host's absolute command path only after all checks pass. Retain
   the old environment until the observation window ends.

## Current migration

Use `prepare_for_external_ai` instead of chaining lower-level tools. Expect
minimal responses by default. If restoration is necessary, request
`restore_capable` and pass the returned opaque session to `restore_text` once.
Do not parse or store direct mappings. `redact_text` legacy mode and
`restore_text` direct mappings are transitional trusted-local paths and may be
removed under the versioning policy.

Local policy files are strictly validated; unsafe exposure flags, duplicate
names, unsupported schema versions, symlinks/reparse points, and invalid
residual behavior now block public preparation rather than being ignored.
