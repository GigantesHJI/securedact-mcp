# Rollback and post-release checks

## Observation

After publishing, verify the release page from an unauthenticated session,
download every artifact, recheck checksums/signature/provenance, install the
wheel cleanly on a supported Python/OS combination, and run the MCP smoke test.
Watch private security reports and public issue channels without requesting real
user data.

## Roll back an installation

Point the MCP host back to the retained, verified previous virtual environment
and restart the host. Restoration sessions are process-local and intentionally
cannot migrate; outstanding handles become invalid. Re-run model verification
and a synthetic routing test. Never downgrade by copying package files into an
environment in place.

## Withdraw a bad release

Git tags and published artifacts are immutable evidence. Do not silently replace
or force-move them. Mark the GitHub release as affected/withdrawn, stop
recommending it, publish the impact and safe version, and issue a new patch
release from a reviewed fix. If exposure is security-sensitive, follow
[Vulnerability releases](vulnerability-releases.md) and coordinate disclosure.

If signature or provenance verification fails, treat the release as a supply-
chain incident even when functional tests pass.
