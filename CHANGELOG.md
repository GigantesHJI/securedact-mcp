# Changelog

All notable changes to this repository will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version 0.1.0 was an unpublished release attempt. Version 0.1.1 is the first
public server release.

## [Unreleased]

## [0.2.1] - 2026-08-20

### Added

- Official MCP Registry readiness: root-level `server.json` declaring the
  `securedact-mcp` PyPI package with stdio transport, plus the PyPI ownership
  marker (`mcp-name`) in the README. No MCP tool, privacy, detection,
  restoration, enforcement, or policy semantics changed.
- Repository and release validation now cross-check the registry metadata
  (`server.json` name/version) and the README ownership marker against the
  package version so they cannot drift.

### Changed

- Claude Code enforced `PreToolUse` now asks the warmed per-session SecuRedact
  runtime over the authenticated loopback protocol instead of building a model
  runtime per outbound tool call; it fails closed while that runtime is
  unavailable or warming.
- Aligned enforced-mode documentation, packaging, and tests with the shipped
  Claude Code and Gemini CLI integrations. Removed the unshipped Codex enforced
  plugin claims, dead Codex-only CLI/provider paths, and stale generated Codex
  artifacts. Documented the Gemini `BeforeAgent`/`BeforeModel`/`BeforeTool`
  behavior, model-bound rewriting, and the broader `BeforeTool` matcher.
- Bumped the Claude Code enforced plugin and marketplace artifact version from
  `0.2.0` to `0.2.1` because the shipped hook resources changed. The Gemini
  extension stays at `0.2.0` because its shipped behavior and resources are
  unchanged.

## [0.2.0] - 2026-08-19

### Added

- `securedact-mcp setup` as a unified guided onboarding command for package,
  Python, ML dependency, contextual-model, Claude Code, and Gemini CLI
  readiness.
- Host detection, targeted `--host` selection, deterministic
  `--non-interactive` inspection, idempotent provider setup, and final readiness
  reporting.
- Install-safe Claude and Gemini integration resources in the wheel, with
  clean-wheel setup smoke coverage that does not require a source checkout.

### Changed

- Guided onboarding reuses the existing model installer, upstream-terms prompt,
  managed configuration, and offline verifier rather than adding another
  downloader or consent system.
- Claude and Gemini onboarding uses their official plugin/extension management
  commands and preserves provider trust prompts and unrelated configuration.
- No privacy policy, detection, pseudonymisation, review/block, restoration,
  provider enforcement, authenticated runtime, HMAC, or MCP semantics changed.

## [0.1.1] - 2026-08-19

### Added

- First public PyPI release, including the previously prepared MCP server,
  explicit local model installation, Claude and Gemini enforced integrations,
  confidence-aware pseudonymisation, the automatic pseudonymisation toggle,
  request-local PERSON alias preservation, and fail-closed local enforcement.

### Fixed

- Corrected the Linux cold-start budget in the process-level Claude runtime
  fixture. Production runtime and privacy behavior are unchanged.

## [0.1.0] - 2026-08-19

### Added

- Standalone Python package for the tested Securedact MCP adapter and local
  provider-independent privacy engine.
- Five MCP tools, including the recommended minimal-by-default
  `prepare_for_external_ai` operation plus lower-level analysis, redaction,
  restoration, and restricted safe-copy operations.
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
  component-level SHA-256 manifests, isolated offline Flair load tests, and
  atomic activation.
- `securedact-mcp models` list, status, verify, diagnose, path, update, repair,
  and remove commands.
- Pinned `FacebookAI/xlm-roberta-large` tokenizer/configuration runtime assets
  required by both serialized Flair checkpoints, stored in a shared managed
  Hugging Face cache rather than an ambient user cache.
- Local conservative English/Dutch runtime routing and an optional Windows
  bootstrap installer.
- Safe `securedact-mcp models diagnose` output for managed configuration,
  integrity, detector readiness, and final failure-code inspection.
- `securedact-mcp diagnostics runtime` for sanitized protocol, deterministic,
  per-language contextual, and full-engine readiness.
- A versioned Dutch MCP person/email regression fixture, 75+ positive and 50+
  negative email cases, bounded property tests, and a real stdio cold-start test.
- A strict provider-neutral public Python API with typed request/result schemas,
  dependency injection, serialized model inference, stable error codes, and
  explicit compatibility boundaries.
- Response modes for minimal output, raw-free review metadata, process-gated
  debug details, and opaque restore-capable sessions.
- A bounded, thread-safe, in-memory restoration vault with random 256-bit
  handles, expiry, single-use semantics, replay detection, and erasure.
- Required `strict_external_ai`, `gdpr`, `identifiers_only`, and
  `review_all_contextual` profiles plus strict local JSON/YAML policy loading,
  thresholds, versioning, duplicate rejection, digests, and fail-closed unsafe
  configuration handling.
- A separate deterministic credential/secret detector and stable order-
  independent overlap/conflict resolution.
- A manifest-validated synthetic EN/NL evaluation corpus spanning development,
  validation, release-gate, adversarial, and negative splits; identifiers,
  credentials, GDPR Article 9 categories, prose, forms, Markdown, JSON/YAML-like
  content, logs, tables, and multilingual ambiguity.
- A `securedact-eval` CLI for exact/relaxed one-to-one quality metrics,
  grouped/micro/macro/weighted reports, deterministic bootstrap confidence
  intervals, performance measurements, environment metadata, and regression
  gates. Mocked contextual inference is distinguished from real-model results.
- Copyable Codex, Cursor, and Windsurf integration packages with expected tool
  discovery, safe workflow rules, troubleshooting, limitations, and honest
  compatibility evidence.
- A committed `uv.lock`, frozen CI/release environments, pinned GitHub Actions,
  Dependabot, CodeQL, Gitleaks, dependency/license audit, clean artifact
  inspection, CycloneDX SBOM, keyless Sigstore signing, GitHub build provenance,
  release metadata/checksum scripts, and clean installed-wheel MCP smoke test.
- Apache License 2.0 licensing, NOTICE and third-party/model licensing guidance,
  governance, DCO contribution rules, CODEOWNERS, branch-protection checklist,
  product-boundary ADR, public API/policy/restoration/conflict/evaluation docs,
  and release, upgrade, rollback, vulnerability, versioning, and supply-chain
  runbooks.
- A fail-closed dependency-license policy with a hash-pinned reviewed exception
  for missing machine-readable metadata, plus exact runtime-requirement audits.

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
- Setup, verification, diagnostics, and MCP startup now share one offline cache
  environment. Fresh-process verification prevents unrelated global caches from
  making an incomplete installation appear ready.
- MCP initialize and `tools/list` no longer wait for Flair deserialization.
  Enabled models load once after the standard initialized notification; calls
  during loading fail closed with `contextual_model_initializing` and are not
  queued or replayed.
- The production engine now enforces its deterministic regex and contextual-rule
  layers before reporting ready. Missing layers return
  `privacy_detector_stack_incomplete`.
- Fixed the email terminal-boundary rule that rejected canonical addresses before
  sentence punctuation such as `emma@example.com.`. The practical detector now
  rejects malformed/URL suffixes without returning partial email spans.
- Normal safe responses no longer expose raw findings or placeholder mappings;
  blocked and review-required responses never include sanitized output.
- `strict_external_ai` blocks detected credentials and special-category data,
  and all approved high-level results undergo residual validation.
- Safe-copy responses no longer expose absolute paths and use the same safe
  high-level preparation contract.
- Direct caller-supplied restoration mappings and raw legacy redaction responses
  now require explicit trusted compatibility modes and carry deprecation codes.
- Explicit English/Dutch high-level requests now select the matching configured
  contextual model instead of being treated as automatic-language input.
- Updated the frozen `cryptography` dependency to 50.0.0 after the vulnerability
  audit identified four advisories affecting the prior resolution.
