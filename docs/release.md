# Release overview

Securedact releases are immutable GitHub artifacts, not PyPI publications. Only
an annotated `v<version>` tag whose version matches package metadata and a dated
changelog section can start the release workflow. The tag must point at a clean,
reviewed commit.

The workflow recreates the frozen lock environment, runs every quality/privacy
gate, builds once, inspects archives, installs the wheel into a clean
environment, performs an exact MCP protocol smoke test, creates an SBOM and
checksums, and uploads the build as a workflow artifact. A separate least-
privilege publish job keylessly signs the same bytes, produces GitHub build
provenance, and attaches artifacts to the GitHub release. It never rebuilds and
never publishes to PyPI.

Use the step-by-step [Releasing runbook](releasing.md). Related controls:

- [Versioning and compatibility](versioning.md)
- [Upgrade and migration](upgrading.md)
- [Rollback](rollback.md)
- [Vulnerability releases](vulnerability-releases.md)
- [Supply chain](supply-chain.md)
- [Release notes template](release-notes-template.md)

No public release is ready while the NOTICE copyright-holder placeholder,
interim security-address confirmation, or upstream model-weight license review
remains unresolved.
