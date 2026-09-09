# Customer-Facing Installer / Bootstrap Contract

This document defines the **exact** contract the dashboard
(`SecuRedactedApp.py`) must implement so the customer-facing Windows
installer can install and register the SecuRedact managed agent without
the customer ever opening PowerShell.

The customer journey is:

```
Business entitlement active
  → Dashboard: "Install SecuRedact"
  → dashboard generates srr_* token + bootstrap config
  → browser downloads installer EXE
  → user double-clicks the EXE
  → Windows UAC prompt
  → installer provisions the machine runtime
  → installer installs pinned securedact-mcp
  → installer installs required Flair model(s)
  → installer registers the agent with srr_* token
  → scheduled task created and started
  → installer reports bounded result to the dashboard
  → dashboard shows "Agent ● Online"
```

The customer does **not** copy/paste a token, does **not** open
PowerShell, and does **not** touch a terminal.

## 1. Bootstrap endpoint (control plane → dashboard)

The dashboard must call a control-plane endpoint that returns the bounded
bootstrap config. The existing control-plane endpoint that issues
`srr_*` registration tokens is reused — no new endpoint is required, but
the *response shape* must conform to this schema.

### Request

```
POST /api/agents/registration-token
Content-Type: application/json
Authorization: Bearer <dashboard session JWT>

{
  "organization_id": "org_...",
  "machine_label": "Patrick's laptop"   // optional, dashboard-friendly name
}
```

### Response (success, 200)

```json
{
  "registration_token": "srr_<id>_<secret>",
  "control_plane_url": "https://www.securedact.com",
  "expires_at": "2026-09-07T12:00:00Z",
  "recommended_version": "0.6.0",
  "installer_url": "https://www.securedact.com/download/SecuRedactInstaller-0.6.0.exe"
}
```

### Schema (single source of truth)

```json
{
  "schema": "securedact.bootstrap.v1",
  "required_fields": [
    "control_plane_url",
    "registration_token",
    "recommended_version",
    "expires_at"
  ],
  "optional_fields": ["installer_url", "models"],
  "rejected_fields": "any field not listed above",
  "registration_token_shape": "srr_<id>_<secret>",
  "recommended_version_shape": "PEP 440 pin (e.g. '0.6.0'); 'latest' rejected",
  "expires_at_shape": "ISO 8601 UTC with trailing 'Z'",
  "models_allow_list": [
    "flair/ner-english-large",
    "flair/ner-dutch-large"
  ]
}
```

Run `securedact-mcp installer describe-contract` from any install of the
package to print this contract programmatically.

### Hard rules

* `registration_token` MUST be single-use, short-lived (default TTL
  15 min), and hash-stored server-side.
* `recommended_version` MUST be an exact PEP 440 pin (e.g. `0.6.0`).
  `latest` and `*` are rejected by the installer (fail-closed).
* `expires_at` MUST be in the future at the moment the installer starts.
  Expired tokens fail closed with a bounded user-readable error.
* `control_plane_url` MUST be HTTPS unless `localhost`/`127.0.0.1`
  (developer override).
* The `srr_*` token MUST NOT be returned in any other endpoint
  response, log line, or browser history that survives the install.

## 2. Bootstrap config file (dashboard → installer)

The dashboard packages the bootstrap config in a JSON file that the
downloaded installer reads. Two delivery options are supported:

### Option A: sidecar JSON (preferred for v0.6.0)

The dashboard's download endpoint serves a **zip** containing:

* `SecuRedactInstaller-0.6.0.exe` — the signed installer
* `securedact-bootstrap.json` — the bootstrap config above
* `README.txt` — "Double-click SecuRedactInstaller-0.6.0.exe"

The installer auto-discovers `securedact-bootstrap.json` next to its
own EXE.

### Option B: embedded config (smaller, but couples the EXE to the token)

The dashboard serves a per-customer EXE with the bootstrap config
embedded in a sidecar resource. The installer reads the sidecar first,
then falls back to the sidecar JSON. v0.6.0 ships Option A; Option B is
a follow-up once the PyInstaller packaging step is wired.

### Anti-rules

* The token MUST NOT appear in the URL query string (it would land in
  browser history, web-server access logs, and CDN logs).
* The token MUST NOT be embedded in a long-lived secret store on the
  customer's machine.
* The dashboard MUST NOT execute anything on the control-plane side in
  response to a download click — the bootstrap config is the only thing
  the customer needs.

## 3. Dashboard readiness polling contract

The installer writes a **bounded, privacy-safe** result envelope to
`stdout` (and to a per-install log under
`C:\ProgramData\Securedact\installer-logs\`). The dashboard's "Return
to Dashboard" button can:

* `GET /api/agents?machine=<id>` — list agents for the current org
* The agent row's `last_heartbeat_at` + `status` fields reflect the
  installer's outcome:
  * `status="online"`, `last_heartbeat_at` within 60 s → `Agent ● Online`
  * `status="registered"`, no heartbeat yet → `Installing…`
  * agent not present → install failed; show the bounded `error_code`
    from the result envelope (see §4)

The control plane's authoritative readiness signal is:

1. Agent row exists in the dashboard's `/api/agents` list.
2. `last_heartbeat_at` is within the last 60 seconds.
3. `health="healthy"` (no degraded flag from the heartbeat).

No WebSocket is required.

## 4. Installer result envelope (zero secrets)

The installer emits (to stdout and to the dashboard) the following
bounded JSON:

```json
{
  "success": true,
  "steps": [
    {"name": "validate-token",      "state": "ok"},
    {"name": "pin-version",         "state": "ok", "message": "securedact-mcp==0.6.0"},
    {"name": "install-runtime",     "state": "ok", "message": "runtime=... python=..."},
    {"name": "install-models",      "state": "ok", "message": "flair/ner-english-large"},
    {"name": "register-agent",      "state": "ok", "message": "agent_id='agent_...'"},
    {"name": "verify-version",      "state": "ok", "message": "runtime reports 0.6.0"},
    {"name": "verify-heartbeat",    "state": "ok", "message": "agent online"}
  ],
  "agent_id": "agent_...",
  "control_plane_url": "https://www.securedact.com",
  "installed_version": "0.6.0",
  "runtime_path": "C:\\ProgramData\\Securedact\\runtime",
  "error_code": null,
  "error_message": null
}
```

`error_code` is one of:

| code | meaning |
|---|---|
| `bootstrap_token_missing` | the bootstrap config was missing the `srr_*` token |
| `bootstrap_version_invalid` | `recommended_version` is not an exact X.Y.Z pin (e.g. `latest`) |
| `bootstrap_config_invalid` | the JSON is malformed, expired, or has unknown fields |
| `runtime_provision_failed` | venv create / pip install / ACL hardening failed |
| `model_install_failed` | a model in the allow-list failed to install or verify |
| `agent_registration_failed` | the control plane rejected the `srr_*` token |
| `version_mismatch` | the installed runtime reports a different version than the pin |
| `heartbeat_failed` | no first heartbeat within the timeout (default 30 s) |

The dashboard MUST display the bounded `error_code` + `error_message`
verbatim — never the raw stack trace or any secret material.

## 5. Reinstall / upgrade behavior

The dashboard's "Repair" / "Reinstall" / "Upgrade" buttons re-issue a
fresh `srr_*` token only when needed:

* **Healthy existing agent** (heartbeat < 60 s old): the installer
  detects this on the machine and **does not consume** a new token. The
  user gets a "Already installed" success.
* **Stale / missing agent**: the dashboard issues a new `srr_*` token
  and the installer consumes it normally.
* **Upgrade from 0.5.0 to 0.6.0**: the installer re-uses the existing
  registration and only replaces the runtime code (no new token
  consumed, no OAuth re-auth triggered, no `connector-bindings.json`
  reset).

## 6. Security checklist for the dashboard

- [ ] `POST /api/agents/registration-token` response shape matches §1
- [ ] `srr_*` token TTL ≤ 15 minutes
- [ ] Token is single-use; consumed status is hash-stored server-side
- [ ] Token is **never** logged, **never** placed in URLs, **never**
      persisted client-side
- [ ] Download endpoint does not require auth beyond the dashboard
      session (the token in the bootstrap config is the proof)
- [ ] "Return to Dashboard" polls `/api/agents` and waits for
      `last_heartbeat_at` within 60 s + `health="healthy"`
- [ ] "Repair" button only re-issues a new `srr_*` token when the
      dashboard cannot find a healthy agent for the current machine
