# Supply-chain controls

## Dependencies and lock

`uv.lock` is the reviewed resolution source for CI and releases. Jobs use
`uv sync --frozen`; an uncommitted resolution is a release failure. Dependency
updates require a lock diff, upstream/repository/provenance and license review,
test/evaluation gates, `pip-audit`, and regenerated license/SBOM evidence.

## GitHub Actions

Third-party actions are pinned to full commit SHAs with a nearby release tag
comment. Dependabot proposes updates. Reviewers must inspect the upstream tag,
commit ownership/diff, permissions, release notes, and workflow behavior before
accepting a new SHA. Actions receive job-scoped least privilege; untrusted pull
requests never receive publish permissions.

## Artifacts, signing, and provenance

The tag workflow builds once and transfers exact bytes to the publish job.
Archives are inspected for forbidden content and clean-installed before release.
CycloneDX SBOMs and SHA-256 checksums accompany distributions. Sigstore keyless
signing uses GitHub OIDC, and GitHub artifact attestation records build
provenance. Consumers must validate repository/workflow identity as well as the
cryptographic result.

## Models

Model downloads are separate, explicit, and consent-gated. Only registry-
allowlisted official repositories and immutable revisions are accepted. Exact
component sizes/hashes, local manifests, offline load tests, and atomic
activation protect runtime selection. Model IDs, revisions, hashes, upstream
terms, and unresolved weight-license questions are reviewed independently from
Python package licensing. Checkpoints never enter package artifacts or CI.

## Secret and key rotation

Gitleaks scans source history/worktrees; tests use obvious synthetic values.
There is no long-lived Sigstore key. Repository, environment, package, model,
host, or integration credentials must be narrowly scoped and rotated when a
maintainer leaves, exposure is suspected, permissions change, or the provider's
rotation interval is reached. Remove old credentials before adding replacements,
review access/audit logs, rerun scans, and document the incident privately.

## Release blockers

Unreviewed lock/action/model changes, audit failures, prohibited or unexpected
licenses, missing SBOM/checksum/signature/provenance, moving model revisions,
unresolved release placeholders, or any secret/user-data/artifact leak block a
release.
