# Release Process

## Current status

The standalone package and release automation are present. No release should be
published until the complete validation sequence passes and the interim license,
upstream model terms, security contact, and compatibility claims receive owner
review.

The workflow never publishes to PyPI.

## Maintainer checklist

1. Create a release branch; do not work directly on `main`.
2. Update the version in `pyproject.toml` and `src/securedact_mcp/__init__.py`.
3. Move relevant changelog entries from `Unreleased` to the version/date.
4. Run repository, format, lint, type, unit, integration, and privacy checks.
5. Build with `python -m build`.
6. Run `python -m twine check dist/*`.
7. Inspect wheel and source-distribution contents.
8. Confirm no models, logs, mappings, safe copies, secrets, local databases,
   archives, desktop code, provider code, or user data are included.
9. Confirm the English/Dutch repository IDs, revisions, sizes, and hashes against
   official Hugging Face metadata; moving revisions are release blockers.
10. Recheck upstream model-weight licensing. A citation is not permission.
11. Install the wheel into a clean Python 3.12 environment.
12. Verify import, CLI parsing, console entry point, MCP initialization, and tool
    registration without downloading real weights.
13. Verify with MCP Inspector and supported client versions.
14. Tag the reviewed commit and create a GitHub release.
15. Let the release workflow attach artifacts; do not publish to PyPI.

## Artifact policy

Allowed:

- Python source;
- lexicon JSON required by the contextual detector;
- package metadata;
- license and documentation.

Forbidden:

- model checkpoints or model-pack archives;
- Hugging Face caches, snapshots, blobs, or staging directories;
- logs, mappings, safe copies, SQLite data, environment files, or credentials;
- desktop/Tauri, website, API gateway, or provider implementations;
- PyInstaller output.

## Versioning

Use semantic versioning. A breaking change to a tool name, input schema, output
status, mapping behavior, safe-copy boundary, or privacy guarantee requires a
major-version decision and explicit migration notes.

## GitHub metadata

Recommended description:

> Local-first privacy MCP server that analyzes, reviews, and redacts sensitive
> data before AI workflows process it.

Suggested topics: `mcp`, `model-context-protocol`, `privacy`, `pii`, `gdpr`,
`data-redaction`, `ai-security`, `local-first`, `codex`, `cursor`, `windsurf`.
