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
resolves LOCAL Google connector binding (integration_id -> local profile)
        ▼
Google content fetched LOCALLY via the customer's local OAuth token
        ▼
securedact_core scans LOCALLY (real detection pipeline)
        ▼
safe summary reducer (categories / counts / severity / review flag)
        ▼
ONLY safe summary metadata
        ▼
SecuRedact.com job result endpoint
```

Raw customer content — Google Docs/Sheets/Slides text, local connector responses,
and `securedact_core` findings — **never** leaves the machine. The control plane
may receive only: job id, agent id, schedule id, platform/target metadata,
policy id/version/digest, status, severity, categories, counts,
`review_required`, `policy_decision`, `supported_action`, bounded warning codes,
safe error code, `resources_scanned`, `duration_ms`, and safe aggregate metadata.

It must **never** receive: document text, redacted text, matched text, snippets,
context, names, email addresses, phone numbers, IBAN values, OAuth access
tokens, OAuth refresh tokens, `Authorization` headers, the agent credential,
the lease secret inside the result object, or Google API raw error bodies.

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

## Connector binding

A connector binding records that a control-plane integration has been bound
locally so the agent may use the customer's locally-stored OAuth token. The
binding stores only non-secret metadata (integration id, platform, local
profile, display name). The OAuth token itself stays in the Google credential
store.

```powershell
securedact-mcp agent connector bind google `
    --integration-id <CONTROL_PLANE_INTEGRATION_ID> `
    --profile default
```

Binding must not contain OAuth tokens. List bindings with
`securedact-mcp agent connectors list`.

## Control-plane target descriptor

The claimed job supplies a target descriptor. The agent maps it cleanly to
local Google connector calls:

| `target_type`        | Local action                                    |
|----------------------|-------------------------------------------------|
| `integration`        | scan the whole bound integration (My Drive)     |
| `drive`              | scan a Drive / Shared Drive root                |
| `folder`             | scan a single Drive folder recursively          |
| `resource`           | scan a single file (full category detail)       |
| `resource_collection`| scan a single file (full category detail)       |
| anything else        | fails closed (`unsupported_target`)             |

Unknown target types fail closed; the agent never guesses.

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
- The Google scan itself requires only the local credential and Google's API
  (over TLS). The control plane is not involved in detection.

## Troubleshooting

- **`No valid Google authorization found`** — run `securedact-mcp google auth`.
- **`google provider unavailable`** — the optional Google connector package is
  not installed. Install the `google` extra (`pip install "securedact-mcp[google]"`
  via uv) and re-run. The base agent continues to run and other job types are
  unaffected; a Google job then fails safely with `connector_unavailable`
  (never a `ModuleNotFoundError` leak).
- **`policy_invalid`** — the claimed policy snapshot is not implemented by the
  local core. The job is reported safe-failed; no content is sent.
- **`auth_required`** — the local Google token is missing/revoked. Re-run
  `securedact-mcp google auth`.

## Missing connector errors

If the Google connector is unavailable, the base agent still runs, claim of a
Google job fails safely (result `connector_unavailable` or `unsupported_target`),
and no `ModuleNotFoundError` is leaked to the control plane or logs.

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
