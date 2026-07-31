# Threat Model

## Scope

This threat model covers the local Securedact MCP server, its `stdio` protocol
boundary, privacy engine, caller-managed mappings, consent-based model setup,
runtime model loading, and safe-copy output.

## Assets

- raw prompts and content;
- detected spans and classifications;
- placeholder mappings;
- sanitized output and safe copies;
- policy configuration;
- local model files;
- host configuration and process environment;
- credentials that may appear in input.

## Trust boundaries

1. User to MCP host.
2. MCP host to Securedact over `stdio`.
3. MCP request validation to the local privacy engine.
4. Privacy decision to approved sanitized output.
5. Safe-copy handler to the local filesystem.
6. Host-controlled sanitized output to a downstream workflow.
7. Dependency and model supply chain to local execution.
8. Guided installer to the official Hugging Face HTTPS service.

## Threats and controls

### Host bypass or misuse

The host may omit a tool call, ignore review/block status, forward findings or a
mapping, restore content too early, or send the raw prompt separately.

Controls:

- explicit structured `ok`, `review_required`, and `blocked` outcomes;
- `sanitized_text` only on successful redaction;
- required-server startup where supported;
- client workflow guidance and synthetic integration tests;
- explicit warning that MCP is not universal interception.

Residual risk: host behavior is outside the server's enforcement boundary.

### Protocol corruption and diagnostic leakage

Anything written to stdout can corrupt `stdio`. Diagnostics may expose content.

Controls:

- no application prompt logging;
- stdout integrity tests;
- provider-independent local tools;
- documentation requiring stderr-only sanitized diagnostics.

Never add logging of raw prompts, findings, mappings, keys, safe-copy content, or
AI responses.

### Provider-bound payload leakage

The host may select the wrong field or send a pre-audit value.

Controls:

- residual validation inside `redact_text`;
- fail-closed status on review, policy, model, and residual failures;
- one documented approved field: `sanitized_text`;
- no provider package or provider call in this repository.

### Safe-copy filesystem escape

An attacker may use absolute paths, traversal, Windows drive prefixes, alternate
separators, unsupported extensions, or overwrite.

Controls:

- content input rather than arbitrary source-file reads;
- configured output root;
- `.txt` and `.md` basename allowlist;
- explicit rejection of `/`, `\`, `:`, `.` and `..`;
- resolved target-parent equality check;
- exclusive file creation;
- traversal, extension, root, and overwrite tests.

Residual risk: operating-system compromise, filesystem races outside the process
trust boundary, and a maliciously configured root.

### Placeholder mapping disclosure

Mappings reveal original values.

Controls:

- no server-side mapping persistence;
- mappings returned only to the local MCP caller;
- unknown placeholders preserved;
- no mapping logging.

Residual risk: the host owns mapping isolation, retention, and access control.
There is no server-side session isolation or encrypted mapping vault.

### Residual or indirect disclosure

Partial spans, transformed values, unsupported formats, or remaining context may
still disclose sensitive information.

Controls:

- deterministic precedence and non-overlapping replacement;
- exact, normalized, partial, deterministic, URL-decoded, and placeholder checks;
- special-category assertions and indirect-risk review;
- fail closed for critical residuals;
- adversarial and negative-control corpus.

No residual scanner can guarantee universal semantic privacy.

### Unsupported files and active content

Images, archives, executables, macros, PDFs, encrypted files, and malformed
encodings are not parsed.

Controls:

- safe-copy accepts text content only;
- only `.txt` and `.md` output names are allowed;
- no file execution, archive extraction, document rendering, or unrestricted
  read tool.

### Denial of service

Large input or expensive inference may exhaust resources.

Controls:

- character limit defaulting to 1,000,000 and clamped to that maximum;
- installer file-count, exact expected-size, disk-space, timeout, and bounded
  retry limits;
- bounded deterministic patterns and synthetic fuzz tests.

Residual risk: inference has no per-tool cancellation deadline inside the server;
the MCP host should enforce tool timeouts.

### Model availability and integrity

A required model may be absent, corrupt, incompatible, or replaced.

Controls:

- an allowlisted repository ID and immutable commit for English and Dutch;
- exact required-file layout, pinned size/hash, local manifest, path,
  compatibility, and SHA-256 validation;
- random staging, offline Flair load smoke test, atomic activation, and safe
  cleanup/rollback on failure;
- offline local loading;
- load once at startup;
- fail-closed redaction when required contextual coverage is unavailable;
- explicit environment switch for reduced-coverage mode.

The runtime server never downloads. Corrupt non-secret configuration is rebuilt
only from verified models; it never silently becomes a reduced-protection
configuration. When both languages are installed, uncertain language triggers
conservative contextual analysis rather than a skip.

### Dependency and supply-chain compromise

Python packages, actions, build tools, or model artifacts may be compromised.

Controls:

- constrained Python dependencies and separate optional ML extra;
- CI secret scanning and artifact inspection;
- no model checkpoints in source distributions or wheels;
- release build and clean-install smoke test;
- model integrity checks;
- direct use of `huggingface_hub` without Git, Git Xet, the Hugging Face CLI,
  shell installers, arbitrary URLs, or required credentials;
- displayed upstream licensing uncertainty and separate citation information.

Supported checkpoints use PyTorch serialization. Loading a compromised
checkpoint is a potential code-execution boundary. Official provenance and an
exact pinned digest reduce substitution risk but do not establish that upstream
content is harmless. The upstream model cards currently omit a clear separate
model-weight license identifier; citations are not license grants.

Before a public production release, pin GitHub Actions to reviewed commit hashes
and adopt a reproducible dependency-resolution policy.

## Out of scope

- compromised operating system, Python runtime, or MCP host;
- local administrator or malicious hardware;
- deliberate user copying of raw input to a provider;
- provider-side behavior after approved content leaves the local boundary.

## Security test gates

The suite covers startup, exact tool registration, malformed requests, stdout
integrity, traversal, unsupported extensions, repeated and unknown placeholders,
review/block outcomes, residual behavior, registry immutability, consent,
mocked downloads, local integrity, activation rollback, multilingual routing,
model failure, artifact exclusion, corpus evaluation, and an end-to-end `stdio`
session.
