# Changelog

All notable changes to this repository will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version 0.1.0 was an unpublished release attempt. Version 0.1.1 is the first
public server release.

## [Unreleased]

### Added

- **First-class Google Workspace onboarding for the managed agent.** `securedact-mcp
  setup` now provisions the Google connector dependencies into the machine-owned
  runtime (installing `securedact-mcp[google]==<running version>` plus a fail-closed
  post-install import check), authorizes Google **locally on the machine** against the
  machine data root (`C:\ProgramData\Securedact`), and creates the machine-local
  connector binding through the existing shipped binding mechanism. The OAuth token is
  written only to the machine vault; it is never sent to the control plane and never
  placed on the command line, in the environment, or in logs. A valid machine token is
  reused idempotently; a user-profile token is never silently migrated. Google is only
  required when it is actually configured, so a fresh install without Google does not
  pull the Google extra. `securedact-mcp agent service upgrade --google` re-provisions
  the Google extra while preserving registration, token, and bindings.

- **Machine-runtime Google OAuth authorization and SecuRedact-managed OAuth app.**
  Google authorization now executes *inside* the machine-owned runtime (via the
  `runtime_bootstrap google-auth --loopback` subcommand), so a missing
  `google_auth_oauthlib` in the setup CLI's interpreter can no longer break onboarding
  and the same Google code the scheduled agent uses is what authorizes. The default
  production path uses a **SecuRedact-managed** Google OAuth application
  (`SECUREDACT_GOOGLE_MANAGED_CLIENT_ID`); normal customers never create their own
  Google Cloud project. Bring-your-own (BYO) Google Cloud OAuth is now an explicit
  advanced/enterprise option (`--google-byo` / `SECUREDACT_GOOGLE_BYO`), not the
  default onboarding experience. A missing runtime dependency, or a managed-app
  authorization that does not complete, fails closed (no machine binding, agent not
  reported ready) rather than falling back to a manual copy/paste flow or prompting
  the customer for OAuth credentials.

### Fixed

- **Google OAuth no longer fails with `No module named 'google_auth_oauthlib'`
  on a clean laptop.** The deps-readiness probe validated the machine-owned
  runtime, but the OAuth step executed in the setup CLI's interpreter (which may
  lack the `google` extra), so a missing `google_auth_oauthlib` surfaced as a
  `Could not start Google authorization` error and then prompted the customer to
  paste an OAuth client secret. Google authorization now runs *inside* the
  machine-owned runtime (which always carries the Google extra), and a missing
  runtime dependency fails closed instead of asking for credentials.

- **Managed-agent UAC elevation hand-off now continues setup in the same RC
  environment.** The elevated re-launch uses `sys.executable` plus the
  `-m securedact_mcp.cli` module form with the working directory preserved, so it
  can never resolve a globally installed `securedact-mcp` on PATH. The re-launched
  child resumes the managed-agent onboarding exactly once (via the
  `SECUREDACT_AGENT_ELEVATED` resume marker) and treats a declined/denied UAC
  prompt as a safe stop rather than a fake-success hand-off. No registration token
  or credential is ever placed in argv, the environment, logs, or a temporary
  command file.

- **Fixed the elevated child silently exiting before resuming setup.** `cli.py`
  lacked a `if __name__ == "__main__": raise SystemExit(main())` guard, so
  `python -m securedact_mcp.cli setup --agent --agent-elevated` (the exact command
  the UAC hand-off launches) merely imported the module and returned exit code 0.
  Windows created the elevated child successfully, but it died instantly and no
  setup continuation ever ran. Added the guard so the child now reaches the Managed
  Agent flow. `_shell_execute_runas` also logs sanitized diagnostics (executable
  basename, argument count, cwd, exit/error code only) on hand-off failure for
  safe observability without exposing any secret or environment content.

- **Managed-agent registration now writes to the machine root, not the user
  profile.** `install_windows_service` registers directly under the authoritative
  machine data root (`C:\ProgramData\Securedact`), so the SYSTEM-run scheduled task
  finds its registration and heart-beats Online. An existing user-profile
  `agent.json` is never treated as a machine registration, and an existing valid
  machine registration is reused idempotently without consuming a new token.

- **Package import no longer eagerly pulls in `mcp`.** `securedact_mcp` previously
  imported `create_server` from `.server` at package-import time, which transitively
  imported `mcp`. On CPython 3.12 that import re-execs the process via
  `sys._base_executable`, so the managed-agent CLI and the Task Scheduler launcher
  (`securedact_agent_loop.py`, driven by `python -m securedact_mcp.agent.cli run`)
  started under the base interpreter instead of the machine-owned runtime. `create_server`
  is now exposed lazily through a module `__getattr__`; importing `securedact_mcp` or
  `securedact_mcp.agent.cli` leaves `mcp` out of `sys.modules`, while `create_server()`
  still works when the MCP server is actually started.

- **DEV baseline no longer re-applies the LocalSystem identity.** In
  `SECUREDACT_AGENT_SERVICE_DEV_BASELINE=1` mode `install_windows_service`
  keeps the LocalSystem identity that `win32serviceutil.InstallService` already
  creates and skips `configure_account()` / `ChangeServiceConfig` entirely, so the
  real-Windows WinError 1057 ("The account name is invalid or does not exist, or
  the password is invalid...") from a LocalSystem → LocalSystem reconfiguration
  no longer blocks the baseline. Production is unchanged: it still performs the
  LocalSystem → `NT SERVICE\SecuredactAgent` transition, verifies the vSA SID,
  and applies the ACL/integrity gates. Baseline failures can no longer report
  "failed to apply least-privilege service identity".

- **DEV baseline service now reaches `SERVICE_RUNNING` (no WinError 1053).** The
  SCM-hosted `pythonservice.exe` process has a `sys.path` that does **not** include
  the installing Python's `site-packages` or the project `src`, so it could not
  `import securedact_mcp` and the service never entered `SvcDoRun` — SCM timed out
  with WinError 1053 ("did not respond ... in a timely fashion"). The service
  environment now exports `PYTHONPATH` (computed from the installing interpreter:
  the `securedact_mcp` package root plus every `site-packages` on `sys.path`), which
  CPython reads at startup, so the SCM host can import the agent. `SvcDoRun` reports
  `SERVICE_RUNNING` *before* any agent/network/model work, so startup can never block
  the SCM timeout. This is minimal startup-path wiring only — no ACL/vSA hardening and
  no identity change (baseline stays LocalSystem).

- **Temporary DEV-baseline startup diagnostics.** When
  `SECUREDACT_AGENT_SERVICE_DEV_BASELINE=1`, `service_windows` writes scrubbed,
  secret-free startup diagnostics (process start, imported module/class,
  `sys.executable`, sanitized `sys.path`, `cwd`, `SvCDoRun` entry, `SERVICE_RUNNING`,
  agent-loop start, and exception type/safe message) to
  `C:\ProgramData\Securedact\logs\service-bootstrap.log` (falling back to the agent
  data dir, then `TEMP`, so they are never silently lost). No tokens, credentials,
  OAuth material, lease secrets, document content, or secret env values are ever
  written. This is a temporary debugging aid to be removed before production.

- **Two-phase SCM/ACL lifecycle reconciled; install no longer requires the vSA SID
  before the service exists.** Phase 1 (pre-SCM) runs the strict security gate and
  bootstraps the data dir *without* resolving `NT SERVICE\SecuredactAgent` (which is
  `ERROR_NONE_MAPPED` / 1332 until the SCM service is created), so `validate_install_security`
  and `_assert_not_user_writable` are called without `service_account` there. Phase 1 also
  deterministically `icacls /reset`s the data dir first, stripping any stale explicit ACE
  (including a leftover `S-1-5-80-…` vSA ACE from a prior, since-removed install) before
  re-granting only SYSTEM/Administrators (F) + installing user (RX). Only Phase 3 — after the
  SCM service is created, its logon identity transitioned to the vSA, and the exact SID
  resolved — applies the vSA ACLs and re-runs `validate_install_security(service_account=…)`,
  which now trusts the vSA by its resolved canonical SID. No `S-1-5-80-*` prefix is trusted
  generically and the fail-closed gate is preserved.

- **Phase-3 `writable_data_dir` false positive on the hardened data dir fixed (vSA SID
  resolved deterministically).** The service-aware final gate trusted the vSA only via
  `LookupAccountName`, which can be flaky/unavailable on some hosts even after SCM
  creation, so the on-disk vSA ACE (`S-1-5-80-…`) was sometimes still flagged as an
  untrusted writer. The configured service identity is now also resolved to its exact
  SID **deterministically** from the (uppercased) service name via the virtual-service-
  account SID algorithm (SHA-1 of the UTF-16LE name → `S-1-5-80-<5 subauth>`), which is
  identical to the SID Windows assigns to the on-disk ACE and needs no `LookupAccountName`
  round-trip. `trusted_write_sids` trusts the union of the LookupAccountName result and
  the deterministic SID (both the exact identity, never an `S-1-5-80-*` prefix), so the
  Phase-3 `validate_install_security(service_account=…)` / `_assert_not_user_writable`
  now clear the data dir on real Windows. Diagnostics now tag every issue with
  `phase=phase1_code_path_integrity` / `phase3_final_integrity` and the offending writer
  SID (`untrusted=…`), and a real-Windows-gated test exercises the actual
  `enumerate_aces_windows` provider against a temp dir whose DACL carries the vSA's real
  SID. Rollback, vSA identity, token ordering, and least-privilege ACLs are preserved.

- **Install security gate false-flagged the vSA (`NT SERVICE\SecuredactAgent`) as an
  untrusted writer on the hardened ProgramData data dir.** The trusted-writer set was
  pinned to `S-1-5-18` (SYSTEM) and `S-1-5-32-544` (Administrators) only, so the vSA's
  legitimately-granted Full control (applied by `build_service_account_principals`) was
  treated as a world-write risk, producing a spurious `writable_data_dir` failure. The
  configured service identity is now resolved to its exact SID via `LookupAccountName`
  and trusted by that canonical SID — friendly-name and raw-SID ACEs of the same identity
  collapse to one trusted principal. No SID *prefix* (e.g. any `S-1-5-80-*`) is trusted
  generically, so an unrelated service SID with Full control is still rejected. The
  strict code-path gate (interpreter/package/site-packages) remains SYSTEM/Administrators
  only unless the caller explicitly names `service_account`. Added regression tests for
  the vSA in both representations, an unrelated vSA SID, the real ACL, and Users/Everyone
  and installing-user-full failure modes.

- **Machine runtime missing `securedact_mcp.agent` (`ModuleNotFoundError` on
  `python -m securedact_mcp.agent.runtime_bootstrap`).** The secure machine
  runtime was provisioned from the published `securedact-mcp==<running_version>`
  distribution, but the published wheel predates / diverges from the managed-agent
  code actually running the setup wizard, so it lacked the `agent` package. Added
  a fail-closed runtime-source strategy: released mode pins the **exact** published
  distribution; dev/local-validation mode (`SECUREDACT_RUNTIME_DEV_WHEEL=1`, opt-in)
  builds and installs a **controlled local wheel** from the current checkout.
  `provision_machine_runtime` now verifies the installed runtime can actually import
  `securedact_mcp.agent.runtime_bootstrap` and fails closed (never silently leaving a
  stale runtime) if it cannot. Local wheels are validated to be a local `*.whl` file
  and to contain the agent bootstrap, blocking arbitrary URL/source-path injection.

- **Dev/local-validation runtime accepted a stale same-version checkout
  (`SECUREDACT_RUNTIME_DEV_WHEEL=1` fast path).** `provision_machine_runtime(dev_local=True)`
  treated any existing runtime whose `securedact_mcp.agent.runtime_bootstrap` imported as
  fresh. Two checkout revisions can both report `securedact-mcp==0.4.2`, so a dev runtime
  built from revision A silently survived a switch to revision B (e.g. a changed
  `service_windows.py`). The bootstrap import is no longer a freshness signal in dev mode:
  a trusted content digest of the current checkout is stored in the runtime and compared
  on every rerun; a mismatch deterministically rebuilds the controlled local wheel and
  force-reinstalls it (replacing the stale same-version dist-info). Released mode is
  unchanged (still idempotent, no `--force-reinstall`), and `--force-reinstall` stays
  scoped to the validated local wheel. All ACL/service/token security invariants are preserved.

- **Real-Windows managed-agent service install failed on `SERVICE_CONFIG_FAILURE_ACTIONS`.**
  `WinSCMController._set_failure_actions()` passed `win32service.ChangeServiceConfig2`
  a bare `list` of `(delay_ms, action_type)` tuples (swapped order) instead of the
  `dict` pywin32 requires: `{"ResetPeriod": int, "RebootMsg": str, "Command": str,
  "Actions": [(SC_ACTION_RESTART, delay_ms), ...]}`. Now built via
  `_build_failure_actions()` — a dictionary, correct key casing/types, and
  `(win32service.SC_ACTION_RESTART, 1000)` 2-tuples for 3 restart attempts with a
  1s delay and a 1-day reset period, no reboot and no recovery command. Fail-closed
  rollback on failure-action config failure is preserved (partial LocalSystem service
  removed, token unconsumed); the service still does not start until vSA identity, SID
   resolution, final ACLs, and security validation succeed.

- **Real-Windows `ChangeServiceConfig` LocalSystem -> `NT SERVICE\SecuredactAgent`
  failed with WinError 1057 (`ERROR_INVALID_PASSWORD`).** `WinSCMController._set_service_account()`
  passed an empty-string password for the virtual service account. Per Microsoft SCM
  semantics, a virtual service account (`NT SERVICE\<ServiceName>`) requires
  `lpPassword == NULL` (pywin32 `None`); only built-in accounts (LocalSystem/LocalService/
  NetworkService) use an empty string. Passing `""` for a vSA is rejected with 1057. The
  password is now selected by `_service_account_password()` (`None` for vSA/managed
  accounts, `""` for built-ins). The vSA remains the least-privilege logon identity (it is
  the per-service SID `NT SERVICE\SecuredactAgent` itself, so no `SERVICE_CONFIG_SERVICE_SID_INFO`
  change is needed to use that SID in the runtime/data ACLs). No fallback to LocalSystem;
  ACLs/service/token fail-closed ordering and rollback on any 1057/other failure are preserved.


### Fixed

- **Real-Windows empty-DACL runtime defect (`WinError 5` on `CreateProcess`).**
  A single `icacls <tree> /inheritance:r /T /grant:r ...(OI)(CI)...` left existing
  *leaf files* (e.g. `runtime\Scripts\python.exe`) with an EMPTY, deny-all DACL,
  because Windows drops an ACE that carries container/object-inherit flags on a
  non-container object. This broke the bootstrap launch and failed closed. The
  runtime and data-dir hardening now use a deterministic **two-pass** scheme:
  pass 1 (`/inheritance:r /T /grant:r ...(OI)(CI)...`) sets container-propagation
  ACEs; pass 2 (`/T /grant ...`, flag-less, append) gives every existing file a
  directly-effective, executable ACE while preserving the `(OI)(CI)` propagation
  ACE on directories. Added `deploy.verify_runtime_tree_acl`, a fail-closed
  post-hardening check of the *real* effective ACLs (catches an empty-DACL file
  and a too-permissive data-dir parent that still carries inherited `Users` write
  rights) run before any registration token is consumed or the service starts.
  `deploy.provision_machine_runtime`, `deploy.upgrade_runtime`, and the
  `install_windows_service` Phase-3 flow now verify the tree end-to-end.
- **Real-Windows `icacls` exit 1332 during `securedact-mcp setup --agent`.** The
  installer hardened the runtime/data ACL with the virtual-service-account ACE
  (`NT SERVICE\SecuredactAgent`) *before* the SCM service existed, so the
  per-service SID was unresolvable (`ERROR_NONE_MAPPED` / icacls 1332). Reworked
  `install_windows_service` into a secure two-phase sequence: Phase 1 hardens the
  runtime/data dir with only SYSTEM/Administrators/installing-user (no vSA);
  Phase 2 installs the service (not started) and verifies the vSA now resolves;
  Phase 3 applies the vSA ACE to the runtime (RX) and data dir (full on its own
  store) and re-runs full validation; Phase 4 registers the one-time token and
  starts the service. A failed install after SCM creation rolls back (stops and
  removes) the incomplete service without weakening ACLs or touching credentials.
  `deploy.provision_machine_runtime` now hardens the runtime without the vSA
  initially (`include_service_acl`) and adds it only once the service exists.

### Added

- Managed-agent first real production Google Workspace end-to-end local scan
  flow. A claimed `google_workspace` job is executed entirely on the local
  agent: it resolves the local Google connector binding (integration id ->
  local profile), fetches Google Drive content through the customer's locally
  stored OAuth token, scans it with `securedact_core`, and submits only bounded
  safe summary metadata (categories, counts, severity, review flag) to the
  control plane. Verified with a fake Google transport + fake control plane and
  regression tests for PII-exfiltration and OAuth-token-exfiltration
  (`tests/unit/test_managed_agent_google_e2e.py`).
- Secure Windows deployment path for the Managed Agent: `securedact-mcp setup`
  provisions a dedicated, admin/SYSTEM-owned machine runtime under
  `C:\ProgramData\Securedact\runtime` and installs/starts the service from it, so
  the service never executes user-writable `pipx`/`uv tool` Python. Added
  `securedact-mcp setup --agent` (idempotent rerun) and
  `securedact-mcp agent service upgrade` (state-preserving, admin-initiated). The
  registration token is delivered over stdin, never echoed or persisted.
- Folder/drive aggregate scans now surface per-category `category_counts` in the
  safe result; `resources_scanned` reflects the real number of Drive items
  inspected. The injected-transport seam in `GoogleConnectorClient` enables
  record/replay smoke runs without the Google SDK.
- Hardened safe-result guard: a defense-in-depth forbidden-substring scan rejects
  any leaked PII value, OAuth token, or content key before submission. A missing
  optional Google connector now maps to the safe `connector_unavailable` code
  instead of leaking `ModuleNotFoundError`.
- Managed-agent persistent **Windows background service** (AGENT-018). The agent
  can run as a native Windows Service (`SecuredactAgent`) via pywin32: it starts
  automatically on boot, runs with no console window, auto-restarts on failure,
  and stops gracefully. `securedact-mcp agent service install|start|stop|status|
  uninstall|logs` manage it; `agent register --token ... --install-service`
  registers and installs in one step. It runs under a **least-privilege virtual
  service account** (`NT SERVICE\SecuredactAgent`) by default, with all state under
  a machine-wide, ACL-hardened (fail-closed) `C:\ProgramData\Securedact` directory
  and a single-instance lock that prevents duplicate agent loops. An install-time
  integrity gate refuses to install when the code paths it would execute as a
  privileged identity are writable by a non-admin principal (the `pipx`/`uv tool`
  user-writable venv class).


### Security

- Windows managed-agent service security release gate addressed: default identity is
  now a virtual service account (least privilege); the installing user is granted
  READ ONLY (not write) on `ProgramData\Securedact`, preventing credential-vault /
  Fernet-key / OAuth-vault / binding replacement and escalation; ProgramData ACL
  hardening fails closed; an install-time code-path integrity preflight blocks
  user-writable interpreter/package/site-packages/pywin32 paths; the service
  environment sets `PYTHONNOUSERSITE=1` to block user-site/DLL hijacking; the
  control-plane job schema fails closed on unknown platform/target-type; and the
  log scrubber now redacts Google OAuth tokens (`ya29.`/`1//`) and token
  assignments. See `docs/managed-agent.md` and
  `tests/unit/test_agent_service_security.py`.
### Added

- HIPAA Safe Harbor independent adversarial validation: a 202-case dataset
  (`benchmarks/hipaa/hipaa_adversarial.json`), a measurement runner
  (`scripts/experimental/build_hipaa_adversarial.py`,
  `scripts/experimental/run_hipaa_adversarial.py`), and focused regression tests
  (`tests/unit/test_hipaa_adversarial_regressions.py`, 47 passed + 4 xfailed gap
  pins). Final metrics: precision 1.000, recall 0.909, F1 0.952, 0 false positives.
  Results documented in `docs/hipaa-safe-harbor-gap-analysis.md` §14.
- HIPAA Safe Harbor profile module (`securedact_core/hipaa.py`) and public API
  (`SecuredactEngine.hipaa_safe_harbor`) mapping the 18 Safe Harbor identifiers
  (A–R, plus unsupported Q) to internal entity types with an explicit
  supported/partial/unsupported state model and a residual-scan audit pass. The
  `HIPAA_SAFE_HARBOR_POLICY` is registered as a built-in policy. The module is a
  mechanical de-identification aid only and carries no compliance-certification
  language (see `docs/hipaa-safe-harbor-profile.md`).
- Optional HIPAA contextual Flair ensemble (`securedact_core/detectors/
  hipaa_flair_detector.py`): a PERSON-only gate for Safe Harbor category A
  (Names), lazy-loaded, locally resolved, and explicitly rejecting all
  non-PERSON Flair labels (no geography/structured identifiers). Enabled via
  `hipaa_safe_harbor(..., contextual_ner=True)`; deterministic behavior and
  existing contextual rules are unchanged when it is off. Missing-model behavior
  degrades gracefully to deterministic and is surfaced in the result metadata.

### Changed

- `regex_detector.py`: `DATE_VALUE` now accepts ISO `yyyy-mm-dd`/`yyyy/mm/dd` dates;
  `date_of_birth_label` recognizes the `DOB` abbreviation; `ssn_label` recognizes the
  `SS#` label; `device_label` recognizes `serial number`/`serial no`; `ACC` prefix
  maps to `ACCOUNT_NUMBER` (was `BANK_ACCOUNT_REFERENCE`) to stop a double
  classification.
- `hipaa.py`: category **H (Medical record number) downgraded FULL → PARTIAL** because
  adversarial recall was 0.43 (only standard MRN labels/prefixes detected; synonyms and
  separator-less forms missed). Category M keeps FULL with an explicit serial-number
  limitation note.

- `regex_detector.py` (HIPAA false-negative closure, precision preserved): added a
  `loose_separator` option to `LabelRule` so structured identifier labels (ssn, fax,
  medical_record_number, vehicle, account_reference, policy_number) also fire on a plain
  whitespace or a connective word (`fax is …`, `patient MRN is …`); the option is **not**
  enabled for free-text labels (name/diagnosis/etc.) to avoid over-capturing prose.
  `IDENTIFIER_VALUE` now accepts one space-separated, digit-bearing token so internal-space
  values (`MBR 448821039`, `CA 9920314`) are caught. The prefix rule accepts a digit-led
  value with no separator (`MBR55210983`, `ACC773102884`, `DEV55120983`) while still
  requiring the value to start with a digit to avoid `SUBMIT`/`ACCEPT`/`GENETIC` false
  positives. MRN label synonyms (`medical record`, `record number`, `chart ID`,
  `patient record number`) and aliases `patient no` / `bank account ref` / `payment ref`
  were added. Net effect on the 202-case adversarial set: recall 0.794 → 0.909, F1
  0.885 → 0.952, **0 false positives retained**; 4 of 8 xfailed gap pins are now passing
  regression tests (ssn-no-separator, fax-no-colon, vin-no-colon, dev-prefix-no-separator),
  leaving 4 documented gaps (A names, B geography, P DNA text, R relationship).

- MCP tool-definition quality: every registered tool now exposes a detailed,
  agent-facing description (purpose, when to use, when to use another tool,
  security/side-effect behavior, and returned result) and every parameter carries
  a non-empty JSON Schema `description`. Tool names, parameter names, required/
  optional status, defaults, response structures, and security semantics are
  unchanged. Adds regression tests in `tests/unit/test_mcp_tool_definition_quality.py`.

- Compliance control catalog (COMP-001): declarative `SEC-XXX-###` control catalog
  in `securedact_core/compliance/catalog.py` mapping existing technical controls to
  GDPR, EU AI Act, NIS2, ISO/IEC 27001, SOC 2, DORA, PCI DSS, NEN 7510, and BIO2,
  with a CI anti-drift integrity check (`validate_catalog_integrity`).
- Compliance evidence fields (COMP-002): additive, default-empty `control_ids` and
  `policy_digest` on `FirewallDecision` and `AuditEvent`; firewall decisions carry a
  stable policy digest and rule-attributed control ids, propagated into emitted
  audit events. No enforcement or schema behavior changed for legacy callers.
- Compliance documentation (COMP-003): `docs/compliance/` with a mandatory
  `limitations.md` stating SecuRedact does not establish organizational compliance,
  plus `README.md`, `control-catalog.md`, and `compliance-matrix.md`.

- M365-110 OneDrive resource browser (core-side, transport-agnostic): new isolated
  `securedact_core/connectors/microsoft/` package implementing OneDrive browsing
  (drive -> folders -> files, `parentReference` breadcrumb, file/folder distinction,
  bounded pagination, and selection -> existing scan pipeline). It consumes Microsoft
  Graph v1.0 REST JSON through an injected `GraphTransport` (no Microsoft SDK import in
  core), reuses `ConnectorResource`/`ConnectorScanner`, keeps the read-only `Files.Read`
  scope, and enforces server-side token resolution + tenant isolation. Automated tests
  use a mocked Graph transport. Real-tenant E2E verification is still required (see
  `docs/enterprise-connectors-roadmap.md` §62).

- GWS-110 Google Workspace / Drive read-only connector: new isolated
  `securedact_core/connectors/google/` package (transport-agnostic browser; no Google
  SDK import in core) plus a control-plane facade in
  `securedact_mcp/connectors/google/` (OAuth, transport, encrypted token storage, and
  the `securedact-mcp google auth|status|list|scan` CLI). It browses and scans My Drive,
  Shared Drives, Google Docs/Sheets/Slides (exported to text via the read-only scope),
  and ordinary text files through the existing `ConnectorScanner` /
  `SecuredactEngine.prepare` pipeline. The connector is opt-in and disabled unless
  `SECUREDACT_GOOGLE_ENABLED=1`; it requests only `drive.readonly` and fails closed on
  any write scope. Tokens are stored encrypted at rest (Fernet) with a separate key
  file and never logged. Google SDK dependencies are an optional extra imported
  lazily, so existing installs are unaffected. Gmail, Calendar, Google Chat, and
  domain-wide delegation remain out-of-scope later milestones.

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

### Fixed

- Cross-platform runtime startup hardening (no behavior change to enforcement or
  fail-closed guarantees):
  - Runtime state now lives under a per-user directory on every platform
    (`%LOCALAPPDATA%` on Windows, `~/Library/Application Support` on macOS,
    `~/.local/state` honoring `XDG_STATE_HOME` on Linux) instead of the shared
    system temp directory, so the session secret cannot be pre-created or
    symlinked by another local account.
  - `ensure_runtime` / `start_runtime` now bound the *whole* call (lock acquire +
    health probe + model warm-up) to a single deadline derived from the host hook
    budget, so a prompt-hook stage can never outlive its budget and be killed
    mid-check.
  - A still-warming start is reused (waited for) rather than duplicated: a child
    daemon claims the warming marker with its own pid, and a second start waits for
    that live child instead of spawning a competing daemon; a stale state or dead
    warming marker is recovered by a fresh start.
- Gemini hook prompt-stage runtime start budget is now derived from the 20s host
  hook budget (reserving headroom) rather than a fixed 5s, keeping the real
  runtime lifecycle contract separate from the hermetic hook logic.

## [0.4.2] - 2026-08-24

Patch release. It fixes local Gemini CLI enforcement so a benign prompt is no longer
fail-closed as a "protected path" failure, and it keeps every deny path intact. No
policy, detection, or firewall behavior changed.

### Fixed

- Gemini `BeforeAgent`/`BeforeModel` now lazily ensure the local enforcement runtime
  is ready instead of relying solely on `SessionStart`.
- Prompt-stage runtime failures now use a path-neutral fail-closed message.
- Glob/Grep/discovery operations with no concrete file target are no longer rejected
  as invalid protected paths.
- Concrete `FILE_READ`/`FILE_WRITE` operations still canonicalize against the active
  workspace before firewall evaluation.
- Safe workspace reads allowed; `.env`/traversal/UNC/URL/null-byte cases remain
  fail-closed.
- Added installed-runtime/real-host regression coverage.
- `gemini-extension.json` now tracks the package version across the root,
  `integrations/`, and `setup_assets/` copies.

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
