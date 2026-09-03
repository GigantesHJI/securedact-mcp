# SecuRedact Managed Agent

The managed agent is a **local-first** daemon that runs on a customer's own
machine. It pulls scan jobs from the SecuRedact control plane, performs the
actual content retrieval and detection **locally**, and reports back only
bounded, privacy-safe summary metadata.

> Google document content is retrieved and scanned on the machine running the
> SecuRedact managed agent. The managed-agent job protocol sends only bounded
> scan summary metadata to the SecuRedact control plane.

## Architecture

```
SecuRedact.com
    creates / queues managed scan job
        │  (job descriptor: platform, integration_id, target_type, target_ref,
        │   pinned CP-200 policy snapshot, one-time lease secret)
        ▼
local securedact-mcp managed agent
    authenticates (agent credential + Ed25519 entitlement)
        ▼
agent claims job (lease secret + generation)
        ▼
resolves LOCAL connector binding (integration_id -> local profile)
        ▼
Platform content fetched LOCALLY via the customer's local OAuth token
        ▼
securedact_core scans LOCALLY (real detection pipeline)
        ▼
safe summary reducer (categories / counts / severity / review flag)
        ▼
ONLY safe summary metadata
        ▼
SecuRedact.com job result endpoint
```

Raw customer content — Google Docs/Sheets/Slides text, Microsoft 365/SharePoint/OneDrive
content, local connector responses, and `securedact_core` findings — **never** leaves
the machine. The control plane may receive only: job id, agent id, schedule id,
platform/target metadata, policy id/version/digest, status, severity, categories,
counts, `review_required`, `policy_decision`, `supported_action`, bounded warning
codes, safe error code, `resources_scanned`, `duration_ms`, and safe aggregate
metadata.

It must **never** receive: document text, redacted text, matched text, snippets,
context, names, email addresses, phone numbers, IBAN values, OAuth access
tokens, OAuth refresh tokens, `Authorization` headers, the agent credential,
the lease secret inside the result object, or platform API raw error bodies.

## Registration (production flow)

1. In the web dashboard / admin console, create an **agent registration token**
   (`srr_...`).
2. On the local PC:

   ```powershell
   securedact-mcp agent register --token <REGISTRATION_TOKEN> `
       --control-plane-url https://www.securedact.com
   ```

3. The agent stores its issued `sra_...` credential in OS-protected local storage
   (never in clear text, never printed).
4. The agent activates its entitlement (see below). Its heartbeat then appears
   in the control plane.

Do **not** use a hardcoded agent credential. Registration is the only path that
produces a credential.

## Entitlement (production flow)

```
agent credential
  -> POST /v1/entitlements/activate
  -> signed Ed25519 token (JWKS verified locally)
  -> local verification + cache
  -> refresh before refresh_after
```

The agent refreshes its entitlement automatically inside the run loop. If the
production signing key is not configured yet, **do not** enable dev/ephemeral
signing in production — the agent will report the exact missing environment or
config step instead of bypassing verification.

## Google local OAuth

The target architecture is: **the local agent owns the Google credentials.**
SecuRedact.com does **not** supply Google OAuth credentials to the agent. The
control-plane `integration_id` is used strictly as a binding/reference
identifier; the actual OAuth token lives in the local Google credential store
(encrypted at rest).

```powershell
# Authenticate the local Google connector (read-only drive scope).
securedact-mcp google auth

# Check the local Google status / auth state.
securedact-mcp google status
```

The connector requests only `drive.readonly`. Any write/expanded scope in
configuration fails closed. The OAuth token is refreshed locally when required;
it is never sent to the control plane.

## Microsoft 365 local setup

> **Microsoft support ships in the base `securedact-mcp` package.** The
> Microsoft connector package (`securedact_mcp.connectors.microsoft`,
> `securedact_core.connectors.microsoft`) has no third-party dependencies that
> are not already required by the core, so it is installed with the base wheel.
> There is no separate `[microsoft]` pip extra and none is required.

Microsoft content stays on the machine. Microsoft Graph resource identifiers
(stable `driveId` / `folderId` / `siteId` / `driveItemId`) stay on the machine.
The control plane receives only **opaque** `target_ref` values and bounded
aggregate result metadata. See
[Microsoft 365 target descriptor](#microsoft-365-target-descriptor).

### Normal managed setup (recommended)

The SecuRedact-managed Microsoft Entra public-client application is used by
default. Normal customers do **not** need to create an Entra app, provide a
client ID, client secret, or tenant ID.

```powershell
# 1) Enable the connector in this shell session.
$env:SECUREDACT_MICROSOFT_ENABLED = "1"

# 2) Authorize locally (browser opens the Microsoft consent screen; the
#    loopback OAuth receiver captures the redirect and exchanges the code
#    locally with PKCE). No client ID, tenant ID, or secret is required.
securedact-mcp microsoft auth
#   -> opens browser; after consent, the encrypted token is stored under
#      %ProgramData%\Securedact\microsoft\token.json.enc

# 3) Verify the local connector is enabled and has a token vault ready.
securedact-mcp microsoft status
```

Configuration is machine-local (encrypted at rest under
`<machine root>\microsoft\token.json.enc`, paired with a sibling Fernet
key, chmod 0600). The token never leaves the machine; no Graph URL, filename, or
PII is written to stdout.

> **Why no `[microsoft]` extra?** `securedact_mcp.connectors.microsoft` and
> `securedact_core.connectors.microsoft` use only `urllib` / `cryptography` /
> `requests` / `msal`, which are already required by the core. The Microsoft
> connector is therefore always available on the managed agent.

### BYO (bring-your-own) Microsoft Entra app (advanced/enterprise)

If you operate your own Microsoft Entra application instead of the SecuRedact
managed app, pass `--microsoft-byo` during setup or run the standalone command:

```powershell
securedact-mcp microsoft setup --byo
#   -> Microsoft Entra client (application) id: <paste your client id>
#   -> Microsoft Entra tenant id (press Enter for 'common'): <tenant>
#   -> Microsoft Entra client secret (Enter to skip for public-client / PKCE): <Enter or secret>
```

In BYO mode, a client secret is **not required** for the public-client / PKCE
flow (the same PKCE protection applies). A secret is only needed if you
registered a confidential-client app, which is rare for the managed-agent
Desktop use case.

> **Why no `[microsoft]` extra?** `securedact_mcp.connectors.microsoft` and
> `securedact_core.connectors.microsoft` use only `urllib` / `cryptography` /
> `requests` / `msal`, which are already required by the core. The Microsoft
> connector is therefore always available on the managed agent.

## Connector binding

A connector binding records that a control-plane integration has been bound
locally so the agent may use the customer's locally-stored OAuth token. The
binding stores only non-secret metadata (integration id, platform, local
profile, display name). The OAuth token itself stays in the platform's credential
store.

```powershell
# Google Workspace
securedact-mcp agent connector bind google_workspace `
    --integration-id <CONTROL_PLANE_INTEGRATION_ID> `
    --profile default

# Microsoft 365
securedact-mcp agent connector bind microsoft365 `
    --integration-id <CONTROL_PLANE_INTEGRATION_ID> `
    --profile default
```

The ``--platform`` argument's choices are derived from the canonical
``SUPPORTED_BINDING_PLATFORMS`` constant (``google_workspace`` and
``microsoft365``). Future providers cannot drift from this list — they are
added by extending the constant and nothing else.

Binding must not contain OAuth tokens. List bindings with
`securedact-mcp agent connectors list`.

Binding must not contain OAuth tokens. List bindings with
`securedact-mcp agent connectors list`.

> **Advanced escape hatch.** The manual `--integration-id` / `agent connector bind google`
> flow is an *advanced* path. Normal customers should **not** need to paste an opaque
> integration ID: the setup wizard auto-resolves the correct integration for the machine's
> tenant once the tenant-scoped eligible-integrations endpoint ships (see
> [Roadmap: tenant-scoped eligible integration discovery](#roadmap-tenant-scoped-eligible-integration-discovery)).
> Only use manual binding when an operator must pin a specific integration that the
> automatic resolution does not surface (e.g. a non-default or pre-provisioned integration).

## Control-plane target descriptor

The claimed job supplies a target descriptor. The agent maps it cleanly to
local platform connector calls:

### Google Workspace

| `target_type`        | Local action                                    |
|----------------------|-------------------------------------------------|
| `integration`        | scan the whole bound integration (My Drive)     |
| `drive`              | scan a Drive / Shared Drive root                |
| `folder`             | scan a single Drive folder recursively          |
| `resource`           | scan a single file (full category detail)       |
| `resource_collection`| scan a single file (full category detail)       |
| anything else        | fails closed (`unsupported_target`)             |

### Microsoft 365

| `target_type`        | Local action                                    |
|----------------------|-------------------------------------------------|
| `integration`        | scan the whole bound integration (My Drive via `drive_id="me"`) |
| `drive`              | scan a registered SharePoint drive              |
| `folder`             | scan a single registered Drive folder recursively |
| `site`               | scan a single registered Drive folder recursively (alias of `folder` for SharePoint) |
| `resource`           | scan a single registered Drive file (full category detail) |
| `resource_collection`| scan a single registered Drive file (full category detail) |
| anything else        | fails closed (`unsupported_target`)             |

#### Opaque `target_ref` (the documented Microsoft 365 workflow)

For Microsoft 365, **`target_ref` is an opaque token** of the form
``mtgt_<version>_<random>`` (e.g. ``mtgt_1_aBcDeF…``). It is **not** a raw
Microsoft Graph identifier.

* The opaque token is generated locally by
  `securedact-mcp microsoft targets add` and stored encrypted in the
  **machine-local target registry**.
* The control plane only ever sees the opaque token.
* The local agent resolves the opaque token back to the raw
  ``driveId``/``folderId``/``siteId`` only inside the local scan, so the
  Graph identifier never crosses the control-plane privacy boundary.
* The agent rejects lookup under the wrong ``integration_id`` (fail-closed
  cross-integration isolation).
* The registry is encrypted at rest using Fernet under the machine data
  root; writes are atomic and chmod 0600.

The mapping is local-only. HMAC fingerprints in the result envelope are
intentionally **non-reversible** and complement the opaque registry; the
registry provides the reversible lookup the agent needs, and the fingerprint
provides the privacy-safe identity the control plane sees.

> **Removing a target:** `securedact-mcp microsoft targets remove --target-id <mtgt_...>`
> deletes the local mapping. The control plane cannot remove a target it does
> not know the opaque id of.

#### Legacy raw composite form (deprecated, not for new schedules)

> **Deprecated.** The previous contract accepted raw composite `target_ref`
> strings (e.g. `driveId:folderId`). This is **rejected by default** in
> version 0.5+ of the managed agent to keep raw Microsoft Graph identifiers
> out of the control-plane privacy boundary. Existing schedules that still
> send raw composite strings will fail closed at claim time with
> `unsupported_target`. New schedules MUST use opaque `mtgt_…` tokens
> registered locally via `securedact-mcp microsoft targets add`.

If accepting legacy raw composite identifiers is temporarily required for an
existing customer migration, the agent will only honor it when the
``target_ref`` matches the form ``<driveId>:<folderId>`` AND the deployment
explicitly re-enables the legacy path. New deployments must not enable the
legacy path.

#### Local target discovery (the operator workflow)

```powershell
# List OneDrive roots, the OneDrive children of a drive, or SharePoint sites:
securedact-mcp microsoft list --drive-id <ONE_DRIVE_ID>

# Register a folder by name (bounded local walk; no Graph /search needed):
securedact-mcp microsoft targets add `
    --integration-id <CONTROL_PLANE_INTEGRATION_ID> `
    --drive-id <ONE_DRIVE_ID> `
    --folder-name "SecuRedact-Smoke-Test" `
    --label "SecuRedact-Smoke-Test"
# -> { "target_id": "mtgt_1_...", "kind": "one_drive_folder", ... }
# The CLI echoes ONLY the opaque target_id + label; raw driveId/folderId stay
# in the encrypted local registry.

# Or register a folder whose raw driveItem id was obtained locally:
securedact-mcp microsoft targets add `
    --integration-id <CONTROL_PLANE_INTEGRATION_ID> `
    --drive-id <ONE_DRIVE_ID> `
    --folder-id <FOLDER_ITEM_ID> `
    --label "SecuRedact-Smoke-Test"

# List registered targets:
securedact-mcp microsoft targets list
# -> { "targets": [{ "target_id": "mtgt_1_...", "kind": "one_drive_folder",
#                    "label": "SecuRedact-Smoke-Test", ... }, ...] }

# Register a SharePoint drive target (no folder):
securedact-mcp microsoft targets add `
    --integration-id <CONTROL_PLANE_INTEGRATION_ID> `
    --site-id <SITE_ID> `
    --drive-id <SITE_DRIVE_ID> `
    --label "Team Documents"
```

After registration, the only thing the control plane needs to schedule that
folder is the opaque ``target_id``. Schedule the scan through the dashboard
with:

```text
platform          = "microsoft365"
integration_id    = <CONTROL_PLANE_INTEGRATION_ID>
target_type       = "folder"
target_ref        = "mtgt_1_..."
```

The control plane does not need to know the driveId, folderId, siteId, or
filename.

## Agent run loop

```powershell
securedact-mcp agent status
securedact-mcp agent run
```

`agent run` polls for jobs continuously. It:

- sends a heartbeat at a bounded interval,
- ensures the entitlement stays valid (refreshes before expiry),
- claims a job (handling `204` = no work as a normal idle),
- executes the local scan,
- renews the job lease while a long scan is in progress (heartbeat callback),
- stops further processing if the job is cancelled,
- backs off with bounded delay on transient control-plane errors,
- handles Ctrl+C cleanly (no tight loop, no crash loop).

Lease renewal runs while the local scan executes, so long folder/drive scans do
not silently lose their lease. If the job heartbeat reports cancellation, the
agent stops further managed processing (it does **not** submit success after
cancellation, and never deletes local Google data or credentials).

## Windows background service (AGENT-018)

For a hands-off customer experience the agent can run as a **native Windows
Service** instead of a foreground PowerShell window. The service:

- starts **automatically on Windows boot** (no console window, no login needed),
- **polls continuously** and **heartbeats** on the same loop as `agent run`,
- **auto-restarts** on crash (3 attempts, 1s apart),
- stops **gracefully** on `service stop` (completes the current heartbeat/backoff
  then exits),
- holds a **single-instance lock** so a manual `agent run` cannot start a second,
  conflicting loop.

The dashboard "Online" state is derived from heartbeat timestamps exactly as for
foreground mode — the persistent service heartbeat makes the UI show Online
without any web-app change.

### Service identity and security model

The service runs under a least-privilege virtual service account (`NT SERVICE\SecuredactAgent`) by default (LocalSystem is only an explicit fallback). All agent state — `agent.json`, the encrypted
agent-credential vault, the encrypted Google OAuth token vault, and the job state
— lives under a single machine-wide directory, by default
`C:\ProgramData\Securedact` (override with `SECUREDACT_APP_DATA_DIR`). On install
that directory is **ACL-hardened (fail-closed)** so only `SYSTEM`, `Administrators`,
and the service account can read/write it, while the **installing user gets READ
ONLY** (enough for local diagnostics, but not enough to replace the credential
vault, Fernet key, OAuth vault, or bindings). Standard users cannot read or write
it. The least-privilege identity was chosen deliberately:

- **No secret is ever placed on the service command line or in service metadata.**
  The data directory reaches the service process via its dedicated service
  `Environment` registry key and the machine-wide `SECUREDACT_APP_DATA_DIR`
  variable. The registration token, agent credential, OAuth token, lease secret,
  and entitlement JWT stay in OS-protected local storage.
- Credentials stored under a single user's profile/keyring would be **unavailable to
  the service account**, so the machine-wide `ProgramData` root (shared by both
  interactive `agent`/`google` commands and the service) is used instead.

### Install via the unified setup wizard (recommended)

The recommended path is the unified wizard, which keeps every module optional and
selectable and provisions a *secure machine-owned runtime* for the service:

```powershell
securedact-mcp install      # optional: contextual models
securedact-mcp setup        # Models -> Upstream Terms -> Plugins -> Managed Agent
```

During `setup`, the Managed Agent step:

1. explains what the background agent does,
2. asks whether to install it,
3. tells you where to obtain the one-time registration token
   (Dashboard -> Local Agents -> Add agent),
4. prompts for the token (typed, never echoed, never persisted),
5. provisions a dedicated, admin/SYSTEM-owned Python runtime under
   `C:\ProgramData\Securedact\runtime`,
6. registers the machine,
7. installs + starts the Windows service,
8. verifies the heartbeat, and
9. reports **Online**.

The advanced `agent register` / `agent service install` / `agent service start` /
`agent run` commands remain available for debugging.

Run an **elevated (Administrator)** PowerShell for the Managed Agent step:

```powershell
# One-time: install the package (per the installation doc), then register AND
# install the background service in a single step.
securedact-mcp agent register --token <REGISTRATION_TOKEN> --install-service

# (Optional) equivalent explicit two-step form:
securedact-mcp agent register --token <REGISTRATION_TOKEN>
securedact-mcp agent service install

# Ensure the local Google connector is authorized (also writes to ProgramData):
securedact-mcp google auth
```

`agent register --install-service` (and `agent service install`):

1. creates `C:\ProgramData\Securedact` and hardens its ACL,
2. persists `SECUREDACT_APP_DATA_DIR` machine-wide so interactive `agent`/`google`
   commands and the service share the exact same location,
3. registers the agent (if a token is supplied),
4. installs the `SecuredactAgent` service (virtual service account
   `NT SERVICE\SecuredactAgent`, auto-start, restart-on-failure),
5. starts it.

After this, **no PowerShell window is needed** — the dashboard shows Online and
scans execute.

### Install integrity gate (privilege-escalation defense)

Before installing, the service refuses to proceed unless the **code it will execute
as a privileged identity is trustworthy**: the Python interpreter, the
`securedact_mcp` package, its `site-packages`, and the pywin32 directory must not be
writable by any non-admin / non-SYSTEM principal. If they are — which is exactly what
**`pipx install`** and **`uv tool install`** produce, because they place the
interpreter and `site-packages` under the installing user's profile — the install is
aborted (fail-closed) rather than granting that user code execution as the service
identity.

Safe pilot deployment:

```powershell
# Admin-elevated shell; install into an admin-owned, non-user-writable venv:
python -m venv C:\ProgramData\Securedact\venv
C:\ProgramData\Securedact\venv\Scripts\pip install securedact-mcp
C:\ProgramData\Securedact\venv\Scripts\securedact-mcp agent register --token <TOKEN> --install-service
```

The service environment also sets `PYTHONNOUSERSITE=1` so a normal user cannot plant a
user-site package, `sitecustomize.py`, `.pth` file, or DLL that the service would
import. ProgramData ACL hardening is **fail-closed**: if `icacls` cannot apply the
restricted ACL, the install aborts instead of leaving a world-writable store.

### Secure machine runtime (pilot)

The service must never load Python/package code from a user-writable path. `pipx
install` and `uv tool install` place the interpreter and `site-packages` under the
installing user's profile, which that user can write — running them as a service is a
local privilege-escalation, and the install gate refuses it (fail-closed).

The pilot secure model is **Approach A — a dedicated machine-owned Python
environment**:

* **Runtime path:** `C:\ProgramData\Securedact\runtime` (a full venv created by an
  Administrator). The service `ImagePath` therefore points at
  `C:\ProgramData\Securedact\runtime\Scripts\pythonservice.exe`, *not* a user profile.
* **Who can write it:** only `SYSTEM` and `Administrators` (via `icacls`
  `/inheritance:r`). The service account `NT SERVICE\SecuredactAgent` and the
  installing user get **read + execute only**.
* **What it contains:** the exact pinned `securedact-mcp` package plus its
  dependencies (including `pywin32`), installed from the configured package index
  pinned to the installed version (or a controlled local wheel) — no arbitrary
  download.
* **Validation:** `validate_install_security()` re-checks the runtime's interpreter,
  package, `site-packages`, and `pywin32` paths after provisioning and fails closed if
  any remain user-writable.
* **State separation:** the data dir (`C:\ProgramData\Securedact`) is hardened
  separately; runtime re-provisioning never touches `agent.json`, the credential
  vault, the OAuth vault, or bindings, so upgrades preserve registration and Google
  auth.

### Service management commands

```powershell
securedact-mcp agent service status    # installed? running/stopped?
securedact-mcp agent service start     # start the background service
securedact-mcp agent service stop      # graceful stop
securedact-mcp agent service logs      # show the scrubbed service log path + tail
securedact-mcp agent service uninstall # stop + remove the service
```

`agent run` remains available as the **foreground/debug** mode. By default it
acquires the single-instance lock and refuses to start while the service is
running; pass `--no-lock` only when deliberately debugging a second loop.

### Startup / restart behavior

- **Boot:** `SERVICE_AUTO_START` brings the agent up before any user logs in.
- **Crash:** `ChangeServiceConfig2` failure actions restart the process
  (3 attempts, 1s apart); the loop reconnects after transient network loss and
  uses the existing offline entitlement grace.
- **No lost jobs:** a job whose lease expires while the service is down is
  re-claimed by the control plane (the agent never submits a false success and
  never deletes local data).
- **No duplicates:** the OS advisory lock file prevents two loops.

### Logging / diagnostics

Service diagnostics are written (rotating, scrubbed) to
`C:\ProgramData\Securedact\logs\agent-service.log`. Every line is passed through
the secret scrubber, so it can contain only: service start/stop, heartbeat
connectivity state, job id (claimed/completed/failed), `safe_error_code`,
agent version, and non-secret errors. It **never** contains document text, PII,
OAuth tokens, the agent credential, the registration token, lease secrets, or the
entitlement JWT. Inspect with `securedact-mcp agent service logs`.

### Upgrade procedure

```powershell
# Secure, admin-initiated runtime upgrade (preserves all agent state):
securedact-mcp agent service upgrade
# or re-run the dedicated wizard step:
securedact-mcp setup --agent
# Registration, credentials, OAuth vault, and bindings under ProgramData are preserved.
```

The `agent service upgrade` flow (also reached via `setup --agent`) is the secure
replacement for the old `uv tool upgrade` + service reinstall cycle. It is
**admin-initiated**: it stops the service, re-provisions the machine-owned runtime
(admin/SYSTEM-owned, never user-writable) with the same pinned package version,
re-validates the code-path ACLs, and restarts the service. Because the agent
state (agent.json, credential vault, OAuth vault, bindings) lives in the separate
`ProgramData\Securedact` data dir, it is never touched — so no re-registration and
no Google re-auth are required unless a credential itself is invalid. No arbitrary
URL/download or unsigned auto-update is used; the source is the same configured
package index pinned to the installed version (or a controlled local wheel).

### Credential implications

Because the service runs as a virtual service account against `ProgramData\Securedact`,
the agent credential vault and the Google OAuth token vault are machine-scoped, not
user-scoped. Any local administrator (or the service account) can read them (by
design); standard, non-admin users cannot. The installing user retains READ ONLY
and cannot replace them. Do **not** point `SECUREDACT_APP_DATA_DIR` at a location
under a single user's profile if you also run the service — the service account
would not be able to read the credentials.

### Uninstall

```powershell
securedact-mcp agent service uninstall     # stops + removes the service
# Optionally remove the machine runtime and/or data dir (admin):
# Remove-Item -Recurse -Force 'C:\ProgramData\Securedact\runtime'
# Remove-Item -Recurse -Force 'C:\ProgramData\Securedact'   # also deletes credentials/bindings
```

Uninstalling the service only removes the SCM registration and stops the process; it
does **not** delete `agent.json`, the credential vault, the OAuth vault, or the
connector bindings. Remove the `ProgramData\Securedact` tree only when you intend to
fully decommission the agent on that machine (this also destroys stored credentials
and Google bindings, which then require re-registration and Google re-auth).

### Troubleshooting

- **Dashboard shows Offline after boot** — the service may have failed to start.
  Run `securedact-mcp agent service status` and `securedact-mcp agent service logs`.
- **`agent not registered; cannot start service`** — registration did not complete
  under `ProgramData`. Re-run `securedact-mcp agent register --token ... --install-service`
  from an elevated shell.
- **`another Securedact agent loop is already running`** — a manual `agent run` (or a
  second service instance) holds the lock. Stop it, or run `agent run --no-lock` only
  for debugging.
- **Google job fails safe (`connector_unavailable`/`auth_required`)** — the Google
  token was written to a different data dir. Ensure `SECUREDACT_APP_DATA_DIR` matches
  and re-run `securedact-mcp google auth` from an elevated shell.

### macOS / Linux

The background service is **Windows-only**. On other platforms use
`securedact-mcp agent run` in the foreground, or wrap it with your platform's
native service manager (launchd / systemd). Equivalent lifecycle is future work.

## Result schema (control plane)

The reduced job result is allowlisted. Fields:

```json
{
  "status": "succeeded | failed",
  "severity": "none | low | medium | high",
  "categories": ["email", "iban", "phone", "..."],
  "counts": { "email": 1, "iban": 1, "phone": 1 },
  "review_required": true,
  "policy_decision": "allow | review | redact | block",
  "supported_action": "none | review | redact | block",
  "warnings": ["resource_not_found"],
  "safe_error_code": null,
  "resources_scanned": 1,
  "duration_ms": 42,
  "policy_version_id": "pv-...",
  "policy_digest": "sha256..."
}
```

`categories`/`counts` carry only bounded per-category counts — never values. A
second defense-in-depth guard scans the serialized result for forbidden
substrings (PII values, token names, content keys) and rejects anything leaked.

Only these safe error codes may appear: `connector_unavailable`,
`resource_not_found`, `auth_required`, `policy_invalid`,
`engine_unavailable_local`, `temporary_network_error`,
`agent_execution_error`, `unsupported_target`, `cancelled`, `lease_invalid`,
`result_invalid`, `internal_error`.

**Schema ownership.** `securedact_mcp.agent.reducer` is the single source of
truth for this envelope — it defines the allowlisted fields, the closed category
vocabulary, the safe error codes, and the bounded counts, and it enforces the
contract at `reduce_scan_results` / `validate_safe_result`. This section is
descriptive only; the agent (not the control plane) validates every payload, and
the protocol is intentionally unchanged (no new fields or category labels may be
introduced here).

## Offline behavior

- Entitlement activation requires the control plane at least once; afterwards a
  cached, locally-verified token is used until `refresh_after`.
- Registration requires the control plane.
- The platform scan itself requires only the local credential and the platform's
  API (Google Drive API or Microsoft Graph API, over TLS). The control plane is
  not involved in detection.

## Troubleshooting

- **`No valid Google authorization found`** — run `securedact-mcp google auth`.
- **`No valid Microsoft authorization found`** — run `securedact-mcp microsoft auth`.
- **`google provider unavailable`** — the optional Google connector package is
  not installed. Install the `google` extra (`pip install "securedact-mcp[google]"`
  via uv) and re-run. The base agent continues to run and other job types are
  unaffected; a Google job then fails safely with `connector_unavailable`
  (never a `ModuleNotFoundError` leak).
- **`microsoft provider unavailable`** — the optional Microsoft connector package is
  not installed. Install the `microsoft` extra (`pip install "securedact-mcp[microsoft]"`
  via uv) and re-run. The base agent continues to run and other job types are
  unaffected; a Microsoft job then fails safely with `connector_unavailable`
  (never a `ModuleNotFoundError` leak).
- **`policy_invalid`** — the claimed policy snapshot is not implemented by the
  local core. The job is reported safe-failed; no content is sent.
- **`auth_required`** — the local platform token is missing/revoked. Re-run
  `securedact-mcp google auth` or `securedact-mcp microsoft auth`.

## Missing connector errors

If a platform connector is unavailable, the base agent still runs, claim of a
job for that platform fails safely (result `connector_unavailable` or
`unsupported_target`), and no `ModuleNotFoundError` is leaked to the control
plane or logs.

## Reauthorization

```powershell
securedact-mcp google auth
```

Refresh tokens are stored encrypted; on expiry the connector refreshes locally.
If refresh is rejected/revoked, re-run `google auth`.

## Revocation

Revoking the agent in the control plane causes the run loop to stop on the next
heartbeat (it detects the `agent_revoked` response and exits cleanly). Local
Google credentials can be revoked with `securedact-mcp google` revocation (best
effort remote revoke + local token deletion); the agent never deletes local
Google data.

## Roadmap: tenant-scoped eligible integration discovery

**TODO (dashboard/webapp, not implemented in this task):** Implement tenant-scoped
eligible integration discovery for registered managed agents.

The managed-agent registration already establishes the machine's SecuRedact agent
identity / tenant relationship. The setup wizard must eventually use that identity
to resolve *which* Google Workspace integration the machine should bind, instead of
asking the operator to copy an opaque integration ID. The internal resolver
(`securedact_mcp.agent.google_setup.resolve_google_integration`) already accepts an
injected `ControlPlaneIntegrationSource`; this endpoint is the thing it will call.

### Endpoint purpose

Given the registered managed agent, return the list of Google Workspace
integrations the agent's tenant is eligible to bind on this machine. The setup
wizard then auto-selects when exactly one is eligible, presents a human-readable
choice when several are, and tells the operator to create one in the dashboard when
none are.

### Security requirements

- **Authenticated** with the existing managed-agent credential (`Bearer <sra_...>`).
- **Tenant-scoped**: the agent must only ever see its own tenant's integrations; it
  must never be able to enumerate another tenant's integrations (fail closed on a
  cross-tenant request).
- Only **safe metadata** is returned: integration id, platform, and a
  human-readable display name.
- **Never** returns a Google OAuth token, a Google client secret, Drive content, or
  any customer PII.
- Disabled / stale integrations are filtered appropriately before being returned.

### Conceptual response

```json
{
  "integrations": [
    { "id": "...", "platform": "google_workspace", "display_name": "My Workspace" }
  ]
}
```

### 0 / 1 / many behavior

- **0 eligible integrations** → setup reports: "No Google Workspace integration
  exists in your SecuRedact account. Create one in the dashboard first."
- **Exactly 1 eligible** → selected automatically (no operator choice required).
- **>1 eligible** → interactive human-readable selection, e.g.:

  ```
  Which Google Workspace integration should this computer use?
  1. Company Workspace
  2. Test Workspace
  ```

The internal id stays hidden/internal in every case.

### Preferred future UX (scoped registration token)

Even better: the dashboard's "Add local agent" flow for a specific Google Workspace
integration can issue a one-time registration token *already scoped to that
integration*. The setup wizard then knows the intended integration immediately and
skips discovery entirely. This scoped-token architecture is the preferred long-term
direction but is **not** implemented in this task — the resolver only consumes it
once the control plane exposes it.

## Managed Google OAuth — product configuration vs. customer secrets

Normal customers connect to Google Workspace through a Google OAuth application
**that SecuRedact owns and operates** (the "managed" Google Desktop / Installed
application). The customer experience is:

```
pip install securedact-mcp
securedact-mcp setup
→ Connect Google Workspace? yes
→ browser opens Google
→ approve Drive read-only
→ local token/binding
→ Online
```

No customer needs a Google Cloud project, an OAuth client id prompt, an OAuth client
secret prompt, or any machine environment variable for Google.

### Source of truth (packaged managed config)

The managed Google OAuth client id and Desktop client secret ship **in the package**
as open-source product configuration:

- module: `src/securedact_mcp/connectors/google/managed_config.py`
- `MANAGED_GOOGLE_CLIENT_ID` — public (a Google Desktop/Installed client id).
- `MANAGED_GOOGLE_CLIENT_SECRET` — published as product configuration; it is
  **SecuRedact-managed application configuration, not a customer secret and not a
  customer OAuth token**.
- structured view: `packaged_managed_google_config()` → `ManagedGoogleConfig`.

These values are shipped in both the wheel and the sdist, so a fresh
`pip install securedact-mcp` resolves them with no environment configuration.

### Resolution precedence (normal vs. override)

1. explicit DEV/OPS override environment variables
   `SECUREDACT_GOOGLE_MANAGED_CLIENT_ID` / `SECUREDACT_GOOGLE_MANAGED_CLIENT_SECRET`
   (used for CI injection, enterprise repackaging, or local development);
2. the packaged default in `managed_config.py`;
3. fail closed only when both are absent.

So:

- a released wheel works out of the box (no env vars required);
- development/testing can override without modifying source;
- CI can inject synthetic values;
- a future enterprise build can override safely.

### What stays local (customer secrets)

The actual customer OAuth **access token and refresh token remain local and
encrypted** under the machine data root (`<machine root>/google/token.json.enc`). The
managed app client secret never travels on argv, into the environment of the scheduled
task (unless explicitly overridden), into logs, or to the control plane. Customer Drive
content and PII stay on the machine.

### BYO (bring-your-own / advanced / enterprise)

`securedact-mcp setup --agent --google yes --google-byo` opts into a customer/admin
supplied Google Cloud OAuth application. BYO uses the customer's own client id/secret
(explicitly provided) and **ignores the packaged managed config** unless an override is
also set. BYO credentials may require encrypted local persistence as part of that
advanced flow.

### Rotating / changing the managed OAuth app for a future release

To ship a new SecuRedact-managed Google OAuth app, update `MANAGED_GOOGLE_CLIENT_ID`
and `MANAGED_GOOGLE_CLIENT_SECRET` in
`src/securedact_mcp/connectors/google/managed_config.py` (and the corresponding
`MANAGED_GOOGLE_*` endpoint/project constants if they change), then release a new
wheel. Existing customers keep their local OAuth tokens/bindings; only the app
identity used for new authorizations changes. Do **not** place the managed app
credentials in Task Scheduler argv or machine environment variables as a substitute
for packaging them in the wheel.
