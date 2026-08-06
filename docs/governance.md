# Governance and maintainer operations

Securedact MCP is maintainer-led. Maintainers are responsible for repository
triage, review quality, the fail-closed privacy boundary, compatibility evidence,
dependency stewardship, releases, and coordinated vulnerability handling.

Security-sensitive changes should receive two knowledgeable reviews when the
maintainer pool permits it. A reviewer should be independent from the author for
release, policy, restoration-vault, detector-stack, residual-validation, model
registry, workflow, and dependency-lock changes.

The project follows semantic versioning. Stable public APIs and serialized schema
versions are changed deliberately; breaking changes require an upgrade guide,
changelog entry, compatibility test, and major-version change after `1.0.0`.
Deprecations normally remain for at least one minor release unless retaining the
old behavior would expose sensitive data.

## GitHub settings checklist

Repository files cannot prove the following administrative settings are enabled.
Before public release, a repository administrator should verify:

- pull requests, approvals, conversation resolution, and required checks;
- stale-approval dismissal and CODEOWNERS review for sensitive files;
- blocked force pushes, branch deletion, and narrowly restricted bypass;
- signed commits where operationally appropriate and signed release tags;
- private vulnerability reporting, dependency graph, Dependabot alerts, and
  secret scanning;
- no release secrets are exposed to workflows from forks;
- protected environments and reviewer approval for release publication.

Record the verification date and administrator in the private release record.
Do not mark an unchecked control as enabled in public documentation.
