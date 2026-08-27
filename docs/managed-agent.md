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
