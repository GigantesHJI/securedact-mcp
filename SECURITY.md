# Security Policy

## Supported versions

No Securedact MCP server version has been released from this repository. The
current `0.1.0` package is an unreleased alpha pending repository review.

Once releases begin, this section will list supported versions and security
update policy.

## Reporting a vulnerability

Do not open a public GitHub issue for a suspected vulnerability, privacy bypass,
credential exposure, or accidental inclusion of real data.

Report privately to:

`security@securedact.com`

This is an interim role address. The repository owner must confirm that it is
actively monitored before public release. Do not replace it with a personal
address.

Include:

- affected version or commit;
- operating system and MCP host;
- concise reproduction steps using synthetic values;
- observed and expected privacy behavior;
- potential impact;
- whether any real data may have been exposed.

Do not attach raw prompts, personal data, API keys, mappings, safe copies, model
files, or customer logs. Coordinate a secure transfer method if sensitive
evidence is essential.

We aim to acknowledge a valid report within five business days and coordinate
remediation and disclosure timing. This target is not a service-level agreement.

## Security model

Securedact MCP is intended to run locally as a process started by an MCP host
over `stdio`.

Implemented properties:

- local analysis, policy evaluation, redaction, audit, and restoration;
- no provider calls from audit-only tools;
- no network listener by default;
- fail-closed behavior when required detection capability is unavailable;
- exact residual validation before output is marked approved;
- restricted safe-copy directories and supported file types;
- minimal-by-default responses and bounded, single-use in-memory restoration sessions;
- no telemetry;
- no shell execution or unrestricted filesystem access.
- consent-based model setup restricted to three official Hugging Face repository
  IDs (two checkpoints and one shared transformer dependency) and immutable
  registry revisions;
- exact per-component size/hash validation, local manifests, isolated offline
  load testing, staging, atomic activation, and failure cleanup.

Implemented properties are covered by the synthetic test suite. They remain
subject to the limitations in this policy and do not constitute a universal
detection guarantee.

## MCP boundary

MCP does not transparently intercept every prompt. The host or agent workflow
must invoke Securedact and use only the approved sanitized output. Marking a
server as required can enforce successful initialization where supported, but
does not prove that every prompt was routed through a tool.

The host, its configuration, and any downstream provider remain separate trust
boundaries.

## Protocol and logging

For local `stdio`:

- stdout is reserved exclusively for MCP protocol messages;
- safe operational diagnostics go to stderr;
- no raw input or content-derived strings may appear in diagnostics;
- no prompts, detected PII, placeholder mappings, API keys, safe-copy content,
  or AI responses may be logged;
- errors must use stable codes and sanitized descriptions.

Protocol initialization is not a privacy-ready signal. The server completes the
standard handshake before checkpoint deserialization, then starts one
synchronized background load after `notifications/initialized`. While any
required language is validating or loading, privacy-dependent calls return the
stable `contextual_model_initializing` block. The input is not queued, persisted,
or replayed. A load, manifest, dependency, integrity, or storage failure retains
its specific safe failure code and never enables regex-only fallback.

CI and release tests must include sensitive canaries and stdout-capture checks.

## Safe-copy security

`create_safe_copy`:

- accepts content strings rather than arbitrary source-file paths;
- allows only `.txt` and `.md` output basenames;
- rejects separators, drive prefixes, traversal, unsupported names, and
  oversized content;
- resolve canonical paths and reject traversal;
- write only inside configured local output roots;
- use exclusive creation and never overwrite;
- never expose unrestricted read or write access.

## Placeholder and restoration security

Mappings reconnect placeholders to original sensitive values and are held only
when `restore_capable` is explicitly requested:

- minimal, review, and debug preparation do not create a restoration session;
- the bounded in-memory vault uses cryptographically random opaque handles;
- sessions expire after 15 minutes by default and are consumed once;
- capacity and mapped-byte limits prevent unbounded retention;
- mappings are erased on consume, expiry, cleanup, close, or process exit;
- mappings and handles are never logged or returned together;
- malformed, unknown, expired, and replayed handles fail with safe codes.

The deprecated direct-mapping MCP route requires
`trusted_local_review: true`. Anyone able to restore a session can recover its
values, so the host must still protect handles and restored output. The vault is
not encrypted persistent storage and does not survive process termination.

## Residual leakage and model availability

Residual validation lowers risk but cannot guarantee detection of every semantic,
encoded, transformed, or indirect disclosure. The exact proposed sanitized
payload must be checked.

If a policy requires a local statistical model and that model is absent,
incompatible, or fails integrity validation, approval must fail closed. A weaker
fallback must never be selected silently.

Full readiness also requires the production deterministic detector invariant:
the validated regex, credentials, and contextual-rule detectors must all be present.
An incomplete stack returns `privacy_detector_stack_incomplete`, even if Flair
loaded successfully. This prevents a runtime-construction regression from
silently dropping canonical email and identifier coverage.

The MCP server does not download during startup. The separate human-facing setup
command downloads only after consent. With both English and Dutch installed,
language selection is local and uncertain input is handled conservatively rather
than skipping contextual analysis.

## Dependency and supply-chain security

- Keep runtime dependencies minimal and constrained.
- Separate developer, benchmark, security, and optional ML dependencies.
- Use the committed lock with frozen resolution in CI and release jobs.
- Verify model origin, license, version, and integrity.
- Allow model downloads only from registry-approved official Hugging Face
  repositories at immutable commits; never accept arbitrary repository IDs or
  URLs.
- Treat PyTorch/Flair checkpoint deserialization as a supply-chain execution
  boundary. Pinned hashes and official provenance reduce risk but do not prove a
  checkpoint is benign.
- Keep Hugging Face credentials out of setup output. Public supported models are
  fetched without requesting or passing an authentication token.
- Do not accept successful loading through an ambient Hugging Face cache as
  installation proof. The verifier starts a clean child process, disables user
  site imports, and points all cache variables at Securedact-managed storage.
- Keep GitHub Actions pinned to reviewed full commit SHAs.
- Scan commits and release artifacts for secrets and unexpected files; audit
  dependencies/licenses and attach SBOM, checksums, keyless signature, and
  build provenance.
- Do not commit or publish model checkpoints, logs, mappings, databases, safe
  copies, environment files, credential exports, or user data.

Securedact does not redistribute the supported model weights. The upstream model
cards currently provide citations but no clear separate model-weight license
identifier. A citation is not license permission; maintainers must review terms
before release and users must review the displayed upstream notice before
download.

## Model storage and rollback

Model staging, active versions, rollback data, configuration, and integrity
manifests live in a user-owned OS application-data directory, never in the Git
repository or Python environment. Custom paths are restricted. Incomplete or
unexpected snapshots, links, executable extras, hash mismatches, and failed
Flair loads are not activated. On setup failure, only the failed staging tree is
removed and prior active configuration remains unchanged.

If the active configuration is corrupt, Securedact reconstructs it only from
verified installed models. Otherwise it fails closed and gives repair guidance.

Both supported checkpoints require the pinned tokenizer/configuration files from
`FacebookAI/xlm-roberta-large`. These files live in a shared managed cache and
are recorded individually in each dependent model manifest. Repair validates an
existing checkpoint before downloading only missing dependencies. Component and
manifest activation is rollback-safe; one language cannot remove a shared
component still required by the other.

## Denial of service

The implementation bounds text length, installer file count, expected total
download size, retries, metadata timeouts, and minimum free disk space. It does
not parse user-supplied archives or arbitrary files. Large supported model
downloads and local inference can still consume disk, bandwidth, memory, CPU,
and time. MCP hosts should enforce startup and per-tool timeouts because local
model inference has no internal request deadline.

## More detail

See [Threat model](docs/threat-model.md) and
[Privacy model](docs/privacy-model.md).
