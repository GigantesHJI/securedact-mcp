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
- caller-supplied mappings with no server-side persistence;
- no telemetry;
- no shell execution or unrestricted filesystem access.
- consent-based model setup restricted to two official Hugging Face repository
  IDs and immutable registry revisions;
- exact model size/hash validation, local manifests, offline load testing,
  staging, atomic activation, and failure cleanup.

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

Mappings reconnect placeholders to original sensitive values and must be treated
as secrets:

- `redact_text` returns the mapping to the local caller;
- the server does not retain a mapping vault or restoration session;
- `restore_text` uses only the mapping supplied on that call;
- unknown placeholders remain unchanged;
- mappings must remain out of logs and external payloads.

The host is responsible for access control, isolation, expiry, and secure
destruction of mappings. This is a material current limitation.

## Residual leakage and model availability

Residual validation lowers risk but cannot guarantee detection of every semantic,
encoded, transformed, or indirect disclosure. The exact proposed sanitized
payload must be checked.

If a policy requires a local statistical model and that model is absent,
incompatible, or fails integrity validation, approval must fail closed. A weaker
fallback must never be selected silently.

The MCP server does not download during startup. The separate human-facing setup
command downloads only after consent. With both English and Dutch installed,
language selection is local and uncertain input is handled conservatively rather
than skipping contextual analysis.

## Dependency and supply-chain security

- Keep runtime dependencies minimal and constrained.
- Separate developer and optional ML dependencies.
- Review lock or reproducible-resolution strategy before release.
- Verify model origin, license, version, and integrity.
- Allow model downloads only from registry-approved official Hugging Face
  repositories at immutable commits; never accept arbitrary repository IDs or
  URLs.
- Treat PyTorch/Flair checkpoint deserialization as a supply-chain execution
  boundary. Pinned hashes and official provenance reduce risk but do not prove a
  checkpoint is benign.
- Keep Hugging Face credentials out of setup output. Public supported models are
  fetched without requesting or passing an authentication token.
- Pin GitHub Actions to reviewed revisions for production release.
- Scan commits and release artifacts for secrets and unexpected files.
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
