# Changelog

All notable changes to this repository will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version 0.1.0 was an unpublished release attempt. Version 0.1.1 is the first
public server release.

## [Unreleased]

### Added

- Enterprise Connectors foundation (Batch 1): platform-neutral connector contracts
  in `securedact_core/connectors/` (ARCH-001/002/003, CONN-001):
  - `ConnectorResource`, `ResourceKind`, `ConnectorCapability`, `ConnectorIdentity`,
    `ScanContext`, `NormalizedContent` (contracts).
  - `ScanRequest`, `ScanResult`, `ScanStatus`, `ScanSeverity`, `ScanError`,
    `ScanFinding` (privacy-safe result model — no raw detected values).
  - `ConnectorScanner` base orchestration: normalize → `SecuredactEngine.prepare` →
    translate to `ScanResult`, with size-limit and unsupported-format handling that
    never reports a false success.
  - Connector audit event types (`CONNECTOR_*`) added to the core `AuditEventType`.
  - Identifier validation that rejects path-traversal / unsafe characters so platform
    identifiers can never become SSRF targets.
- Microsoft-specific code is isolated from the core engine: no `msal`/`msgraph`
  import is pulled in by `securedact_core` or the MCP server (verified by tests).

## [0.4.1] - 2026-08-24

### Fixed

- Gemini `FILE_READ`/`FILE_WRITE` paths are canonicalized against the active workspace
  before firewall evaluation.
- Safe relative/absolute in-workspace paths now work correctly.
- Traversal/outside-root paths fail closed.
- Windows-style separators are normalized before canonicalization so traversal protection
  behaves consistently on Windows and POSIX/Linux.
- UNC, URL, null-byte and uncanonicalizable paths remain fail-closed.
- Added cross-platform regression coverage.

## [0.4.0] - 2026-08-24

### Added

- Optional external Article 9 ML layer (Bardsai `eu-pii-anonimization-multilang-v2-preview`)
  as a complementary semantic detector for GDPR special-category data. It is OFF by
  default and enabled per deployment with `SECUREDACT_ARTICLE9_ML_ENABLED=1`. Design:
  - New `DetectionSource.ML_ARTICLE9` and a merge priority slot between CONTEXTUAL (2)
    and FLAIR (3) so a precise regex/contextual boundary still wins while the ML span
    is recorded as supporting provenance.
  - `BardsaiArticle9Detector` (`src/securedact_core/detectors/bardsai_detector.py`)
    implements the `Detector` protocol. Heavy ML imports (`torch`/`transformers`) stay
    lazy, weights load offline (`local_files_only=True`), and a missing model degrades
    gracefully (engine warning, no crash).
  - Category-aware routing: ADDITIVE (UNION/FALLBACK) for the FULL Bardsai covered label
    set — racial/ethnic origin, religion, sexual orientation, health, political opinion,
    biometric_data, and trade_union_membership. This matches the frozen A9-SOTA-001
    `bard` component, which actually emitted biometric_data (16×) and
    trade_union_membership (1–2×); the earlier tests asserting those two labels were
    *suppressed* were superseded by the frozen 0.4.0 architecture and updated to assert
    additive surfacing. genetic_data and sex_life are absent (no label in the checkpoint).
    Every emission is a special category, so the engine routes it to REVIEW — never
    auto-redaction.
  - Pinned registration (revision `8e0b19766bb0dd4916d096b4f540dd46c138c760`) lives in a
    separate `article9_ml_registry.py` module so the Flair `model_registry.py` keeps its
    exactly-three-revisions invariant required by the repository validator.
  - Privacy-suite and unit tests cover REVIEW bias, category suppression, merge
    provenance, non-Article-9 label leakage, and graceful model-unavailable degradation.

- Agent Privacy Firewall performance guards (FW-041): consolidated the inspection
  size cap into a single source of truth `MAX_INSPECTION_TEXT_CHARS` (1,000,000)
  reused by the text APIs and the safe-read path, so the two limits cannot drift.
  Added a reproducible performance baseline (`scripts/benchmark_firewall.py`) and a
  structural regression suite (`tests/unit/test_firewall_performance.py`) covering
  cheap-deterministic-before-contextual ordering, oversize rejection before
  detectors, path-block termination before content scanning, binary rejection
  before the privacy engine, approved-text digest reuse, and isolated audit
  emission. No async/queue/cache/telemetry architecture was added.
- Agent Privacy Firewall backward-compatibility and security regression suite
  (FW-042): a dedicated contract (`tests/unit/test_firewall_backward_compat.py`)
  proving the firewall is strictly additive — the original five MCP tools keep
  their contract, legacy policies without a `firewall` section still load, explicit
  firewall disable restores legacy host behavior without disabling the privacy
  engine, entity/detector behavior is unchanged, and the core security invariants
  (`Read(".env")`/`credentials.json`/`id_rsa` BLOCK; `src/app.py` ALLOW; UNKNOWN
  tools inspected; safe-read/symlink/traversal blocks; protected-path `ALLOW`
  rejected as `INVARIANT_VIOLATION`; audit never serializes raw secrets/PII) hold
  for both Claude and Gemini.

- Agent Privacy Firewall: `securedact_read_file` MCP tool (FW-011) that safely
  reads a local file, blocks protected paths before access, defends against path
  traversal / symlink / UNC / case / rename tricks (FW-012), and returns only
  sanitized text. Binary and oversized files are rejected in the text-only MVP
  (FW-013). The firewall policy layer (`FirewallPolicy`), tool classification
  (`classify_tool`), and enforced-hook matchers were added to support this.
- Agent Privacy Firewall enforcement foundation (FW-001) and configuration
  integration (FW-003): Claude `PreToolUse` and Gemini `BeforeTool` hooks now
  build a `ToolContext`, evaluate the firewall, and map the decision to a host
  permission outcome via the centralized `firewall_decision_outcome`. Firewall
  policy is loaded from the existing JSON/YAML policy mechanism with fail-closed
  invariants; `SECUREDACT_FIREWALL_ENABLED=0` disables it. `WARN` /
  `REQUIRE_APPROVAL` are intentionally modeled as `FirewallDecision` fields rather
  than new `PrivacyAction` members.
- Agent Privacy Firewall: an `UNKNOWN` tool classification no longer silently
  allows the tool; it is content-inspected (fail-closed when the runtime is
  unavailable) so unrecognized tools cannot bypass enforcement.

- Agent Privacy Firewall: tool-result sanitization (FW-020). Claude `PostToolUse`
  and Gemini `AfterTool` hooks now inspect the model-bound result of protected
  tools (native `Read`/`Write`/`Edit`/`MultiEdit`/`NotebookEdit`/`Bash`/`Grep`/
  `Glob`, `mcp__*`, `WebFetch`/`WebSearch`) and run it through the warmed-runtime
  inspector. Claude replaces the result with the sanitized payload via
  `updatedToolOutput`, preserving structured shapes (e.g. Bash stdout/stderr,
  MCP content blocks). Gemini cannot replace results, so it hides a sensitive
  result (deny with a safe reason) rather than delivering it. Oversize results
  and inspector failures fail closed without exposing raw PII/secrets. Tool-result
  inspection honors `MAX_TOOL_RESULT_CHARS` and respects the firewall enable
  switch, reusing the FW-033 audit events for metadata-only logging.

- Agent Privacy Firewall: privacy-preserving audit events (FW-033). A new
  `securedact_core/audit.py` module defines an immutable, metadata-only
  `AuditEvent` model (`FILE_BLOCKED`, `SECRET_DETECTED`, `PII_REDACTED`,
  `TOOL_BLOCKED`, `APPROVAL_REQUIRED`) with a no-op default sink and a
  capturing sink for tests. Safe-read and the Claude/Gemini enforced hooks
  emit these events for blocked paths, detected secrets, redacted PII, denied
  tools, and approval-required decisions. Serialization allowlists metadata
  keys and rejects raw sensitive values, and audit failure can never weaken
  an enforcement decision. Persistent local audit-log storage/rotation is a
  separate opt-in item (FW-044) and is intentionally not implemented here.

- Agent Privacy Firewall: egress protection for outbound network tools (FW-030).
  `classify_tool` now reliably assigns `ToolOperation.NETWORK_WRITE` to HTTP
  `POST`/`PUT`/`PATCH`, webhooks, browser submit/navigation with payload,
  uploads, email/send/MCP network tools, and `git push`-like operations, while
  `NETWORK_READ` (GET/search/`WebFetch`) is never treated as a write. A
  normalized destination is extracted and scoped `internal`/`external`/`unknown`
  (loopback, private ranges, and an explicit allowlist are internal; an absent
  destination is never trusted). The Claude `PreToolUse` (`_inspect_egress`) and
  Gemini `BeforeTool` (`_apply_egress_inspection`) paths reuse the warmed privacy
  engine to recursively scan the outbound payload (headers, body, `json`, form
  fields) and enforce `BLOCK`/`REDACT`/`REQUIRE_APPROVAL`. Known and
  `UNKNOWN_SECRET` credentials are blocked; PII/special-category data follows the
  policy-driven `REDACT` action. Oversize payloads and scanner/client failures
  fail closed (deny), never raw-allow. The destination key is excluded from
  content scanning because it is metadata, not outbound content. Shell-based
  exfiltration (`Bash("curl ...")`) is intentionally not labeled network egress;
  no cross-tool taint tracking is performed (FW-031 is separate).

- Agent Privacy Firewall: approval workflow for egress (FW-032). The existing
  `requires_approval`/`REVIEW_REQUIRED` mapping is now exercised by the egress
  path: Claude returns `permissionDecision: deny` (user override) and Gemini
  returns `decision: deny` with a reason — no fake interactive approval protocol.
  The opt-in `FirewallPolicy.egress_external_require_approval` flag upgrades an
  external/unknown `NETWORK_WRITE` whose payload was merely redacted (PII) into a
  `REQUIRE_APPROVAL` decision. Every approval-required egress emits an
  `APPROVAL_REQUIRED` audit event, and every blocked egress emits the first
  legitimate `EGRESS_BLOCKED` event (metadata-only, no raw body/header/credential).

## [0.3.0] - 2026-08-21

### Added

- Improved structured GDPR Article 9 detection. Structured field-value detection
  now correctly extracts the sensitive value instead of the field label.
- Claude Code marketplace preparation and Gemini CLI gallery/discovery
  preparation added since v0.2.1 (root-level `gemini-extension.json` and
  `hooks/hooks.json`, plus the Claude marketplace manifest).

### Changed

- Structured Article 9 misses reduced from 94 to 0 on the benchmark.
- Exact Article 9 F1 improved from 20.29% to 31.30%; exact precision from
  57.94% to 73.90%; exact recall from 12.30% to 19.85%.
- English and Dutch exact F1 each improved by roughly 11 percentage points.
- No increase in the hard-negative false-positive rate.
- Aligned the Gemini extension artifact `version` to `0.3.0` across the
  repository-root, `integrations/`, and wheel `setup_assets/gemini` copies; the
  three copies are byte-identical and a unit test enforces that parity.

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
