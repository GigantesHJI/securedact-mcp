# Releasing runbook

## Prepare

1. Work from a release branch and review all changes; do not release a dirty
   worktree.
2. Resolve every release-blocking placeholder and confirm the private security
   contact is monitored.
3. Update the version in `pyproject.toml` and
   `src/securedact_mcp/__init__.py`.
4. Move changelog entries from `Unreleased` to `## [X.Y.Z] - YYYY-MM-DD` and
   write migration/security notes using the release-notes template.
5. Review dependency/license changes, upstream model identities, immutable
   revisions, sizes, hashes, and model-weight terms.
6. Update `uv.lock` intentionally and review its diff.

## Verify

Run the complete sequence in [Testing](testing.md), plus:

```powershell
uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file build\runtime-requirements.txt
uv run pip-audit --strict --requirement build\runtime-requirements.txt
uv run pip-licenses --format=json --output-file=build\licenses.json
uv run cyclonedx-py environment --output-file build\sbom.cdx.json
uv run python scripts\release_metadata.py validate
```

Inspect the wheel and source archive for models, caches, secrets, user data,
logs, safe copies, mappings, databases, provider code, desktop/web code, local
paths, and unexpected binaries. Perform an isolated installed-wheel MCP smoke
test. Compare deterministic quality/performance reports with the committed
baseline; never substitute mocked-Flair results for a real-model claim.

## Tag and publish

1. Merge the approved release commit under branch protection.
2. Create an annotated tag: `git tag -a vX.Y.Z -m "Securedact X.Y.Z"`.
3. Push only that tag and monitor the tag-only release workflow.
4. Confirm the protected `pypi` environment approved the expected repository,
   tag, and workflow, and that PyPI Trusted Publishing used GitHub OIDC without
   an API token or stored PyPI credential.
5. Confirm all attached hashes match the build artifact, Sigstore verification
   succeeds, the GitHub attestation identifies the expected repository/workflow,
   the PyPI files match the validated distributions, and the SBOM contains no
   checkpoint.
6. Publish the completed release notes and update the compatibility matrix only
   for hosts actually tested.
7. Install the exact released version from public PyPI in a clean Python 3.12
   environment and repeat the CLI and MCP protocol smoke tests.
8. Follow the post-release checks in [Rollback](rollback.md).

The workflow deliberately rejects lightweight tags, mismatched versions,
missing dated changelog entries, dirty inputs, gate failures, and prohibited
artifact contents.
