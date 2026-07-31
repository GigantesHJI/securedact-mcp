# Changelog

All notable changes to this repository will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
No versioned server release has been published yet.

## [Unreleased]

### Added

- Standalone Python package for the tested Securedact MCP adapter and local
  provider-independent privacy engine.
- Four MCP tools: `analyze_text`, `redact_text`, `restore_text`, and
  `create_safe_copy`.
- Python 3.12 metadata and `securedact-mcp` console entry point.
- Versioned synthetic privacy corpus and unit/integration coverage.
- Product, security, privacy, threat-model, client, testing, and release docs.
- Repository validation, CI, release workflow, and community health files.
- Guided `securedact-mcp install` setup for English, Dutch, both, or no
  contextual model, with explicit interactive/non-interactive consent.
- Versioned model registry pinning the official `flair/ner-english-large` and
  `flair/ner-dutch-large` repositories to immutable commits and exact checkpoint
  metadata.
- Direct official downloads through `huggingface_hub`, managed OS data paths,
  local SHA-256 manifests, offline Flair load tests, and atomic activation.
- `securedact-mcp models` list, status, verify, path, update, and remove commands.
- Local conservative English/Dutch runtime routing and an optional Windows
  bootstrap installer.
- Safe `securedact-mcp models diagnose` output for managed configuration,
  integrity, detector readiness, and final failure-code inspection.

### Security

- Explicit MCP host-invocation limitation and approved-output workflow.
- Safe-copy basename, extension, configured-root, and no-overwrite controls.
- Input-size limit and fail-closed required-model behavior.
- Local models, mappings, safe copies, logs, credentials, and build artifacts
  excluded from version control and release artifacts.
- Consent, allowlisted-source, immutable-revision, integrity, staging, rollback,
  fail-closed runtime, and no-model-artifact release gates.
- Managed multilingual startup now loads each enabled Flair detector exactly
  once, reports ready only when all children are ready, and returns a stable
  non-sensitive failure code when any enabled model fails to load.
- Managed model configuration now takes precedence over inherited legacy model
  variables, and CLI/runtime discovery shares one model-store resolver and
  active-configuration loader.
