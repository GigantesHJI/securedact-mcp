# Enterprise Connectors — Batch 1 Implementation (Microsoft 365 read-only scan)

This document covers the **first approved batch** of the Enterprise Connectors
roadmap: contracts + control-plane skeleton + a read-only Microsoft 365 scan
(findings only), with correct tenant isolation. It is read-only: no write-back, no
background scanning, no inventory, no Copilot/Teams/Outlook integration.

> Read the approved roadmap first: [`enterprise-connectors-roadmap.md`](./enterprise-connectors-roadmap.md).
> The canonical model and security requirements live there.

## Implemented roadmap IDs

`ARCH-001`, `ARCH-002`, `ARCH-003`, `CTRL-001`, `CTRL-002`, `CTRL-003`,
`ARCH-004`, `ARCH-005`, `CONN-001`, `CONN-002`, `M365-102`, `M365-103`,
`M365-105`, plus `CTRL-005` (Integrations dashboard, required by the integration
foundation).

## Architecture

```
SecuRedactedApp.py (control plane)
      |
      | control plane
      v
Organization / Integration / TenantConnection mapping (server-side)
      |
      v
SecuRedact service boundary (canonical API or in-process engine)
      |
      v
Connector orchestration (routes/connectors.py)
      |
      v
Microsoft Graph adapter (services/connectors/microsoft_graph.py)
      |
      v
Normalized ConnectorResource
      |
      v
SecuRedact Core (SecuredactEngine.prepare)  <-- never imports Microsoft SDKs
      |
      v
ScanResult (privacy-safe)
```

Microsoft-specific code lives in `SecuRedactedApp.py/services/connectors/` and
`spfx/securedact-sharepoint/`. The core detection engine is never exposed
directly over the network and has **no** Microsoft dependency.

## Core connector contracts (ARCH-001/002/003, CONN-001)

`securedact_core/connectors/`:
- `contracts.py` — `ConnectorResource`, `ResourceKind`, `ConnectorCapability`,
  `ConnectorIdentity`, `ScanContext`, `NormalizedContent`, plus
  `validate_resource_identifier` (rejects `..`/spaces/unsafe chars).
- `scan.py` — `ScanRequest`, `ScanResult`, `ScanStatus`, `ScanSeverity`,
  `ScanError`, `ScanFinding`. No raw detected values.
- `base.py` — `ConnectorScanner.scan(...)`: retrieve+extract (done by the
  platform connector) → `prepare` → translate → emit connector audit events.
  Never reports a false success (size limits, unsupported formats, engine
  failures become structured errors).

## Control plane (CTRL-001/002/003, ARCH-004/005, M365-102, CTRL-005)

`models.py`: `Organization`, `OrganizationMembership`, `Integration`,
`TenantConnection`, `OAuthState`. Existing `User` accounts are untouched and a
personal organization is created lazily on first Integrations access.

`services/connectors/`:
- `config.py` — reads Entra config from env; documents the **least-privilege,
  read-only, delegated** scopes.
- `validation.py` — Graph identifier validation (SSRF prevention).
- `token_store.py` — Fernet-encrypted token storage. **Fails closed** when no key
  is configured in production; never stores plaintext; never logs tokens.
- `oauth_state.py` — server-generated, single-use, TTL-bound OAuth `state`
  bound to `(user, org)`.
- `microsoft_graph.py` — isolated Graph adapter; endpoints built internally from
  validated identifiers; injectable HTTP sender for testing.
- `orchestrator.py` — `scan_microsoft_resource(...)`: server-side membership
  check → integration ownership check → validated tenant connection → encrypted
  token resolution + refresh + tenant cross-check → Graph retrieval → safe
  extraction → engine boundary → `ConnectorScanResult`.
- `engine_boundary.py` — `EngineBoundary` (default: canonical API client).
- `audit.py` — metadata-only connector audit emission (no PII/secrets).

`routes/connectors.py` (blueprint `connectors`, prefix `/dashboard`):
- `GET  /dashboard/integrations` — Integrations dashboard (CTRL-005).
- `POST /dashboard/integrations/microsoft/connect` — start Entra OAuth.
- `GET  /dashboard/integrations/microsoft/callback` — code exchange + tenant map.
- `GET  /dashboard/integrations/microsoft/status` — connection health.
- `POST /dashboard/integrations/<id>/disconnect` — revoke + delete.
- `POST /dashboard/api/scan` — read-only scan (authn + org membership + integration ownership + tenant mapping enforced).

`spfx/securedact-sharepoint/` — thin ListView Command Set that resolves the
selected item's driveItem identity and calls `/dashboard/api/scan`; it contains
**no detector logic and no secrets** and renders only safe summaries.

## Microsoft Entra app setup

1. In **Entra ID > App registrations**, create a new app (e.g. `SecuRedact
   Connectors`).
2. Under **Authentication > Platforms**, add a **Web** redirect URI exactly
   equal to `SECUREDACT_M365_REDIRECT_URI` (default
   `https://localhost/dashboard/integrations/microsoft/callback`).
3. Under **Certificates & secrets**, create a **client secret**; copy it to
   `MICROSOFT_ENTRA_CLIENT_SECRET`.
4. Copy the **Application (client) ID** to `MICROSOFT_ENTRA_CLIENT_ID`.
5. Set `MICROSOFT_ENTRA_TENANT_ID` to your tenant id, or `common` for
   multi-tenant.
6. Under **API permissions**, add the delegated permissions below and **Grant
   admin consent** only if your tenant requires it for `Sites.Read.All`.

## Graph permissions (actually requested — read-only)

| Permission | Type | Why | Admin consent |
|---|---|---|---|
| `User.Read` | Delegated | Identify caller + tenant id | No |
| `Files.Read` | Delegated | Download the user-selected file | No |
| `Sites.Read.All` | Delegated | Resolve the site/library of the selected item | **Depends on tenant** (not universal) |
| `offline_access` | Delegated | Refresh token for the panel/session | No |

**NOT requested:** `Files.ReadWrite`, `Files.ReadWrite.All`, `Sites.ReadWrite.All`,
and the legacy `Files.Read.Selected` / `Files.ReadWrite.Selected` file-handler
scopes (these must not be used to call Graph directly).

## Environment variables (web app `.env`)

```
MICROSOFT_ENTRA_CLIENT_ID=...
MICROSOFT_ENTRA_CLIENT_SECRET=...
MICROSOFT_ENTRA_TENANT_ID=common
SECUREDACT_M365_REDIRECT_URI=https://localhost/dashboard/integrations/microsoft/callback
SECUREDACT_CONNECTOR_ENCRYPTION_KEY=<32-byte url-safe base64 Fernet key>
SECUREDACT_OAUTH_STATE_TTL_SECONDS=600
SECUREDACT_CONNECTOR_MAX_DOWNLOAD_BYTES=20971520
SECUREDACT_CONNECTOR_HTTP_TIMEOUT_SECONDS=30
SECUREDACT_CONNECTOR_MAX_SCAN_CHARS=1000000
```

Generate the encryption key:

```bash
python -c "import cryptography.fernet; print(cryptography.fernet.Fernet.generate_key().decode())"
```

In **production**, omitting `SECUREDACT_CONNECTOR_ENCRYPTION_KEY` makes token
storage fail closed (no plaintext fallback). In **development**, an ephemeral key
is generated with a warning; never use that mode in production.

## Database migration

New tables (`organizations`, `organization_memberships`, `integrations`,
`tenant_connections`, `oauth_states`) are additive and do not alter existing
`users`/`api_keys`. Apply explicitly with:

```bash
psql "$DATABASE_URL" -f migrations/add_enterprise_connectors.sql
```

Rollback (drops only the new tables) is documented at the bottom of that file.
`db.create_all()` at app startup also creates them idempotently for dev/fresh
installs.

## Running tests

### Core (this repo)

```bash
uv run python -m pytest tests/unit/test_connector_contracts.py -q
```

Covers contract serialization, `ResourceKind`, capability declaration, scan
request/result, invalid resource identity, platform-independent imports (no
Microsoft import), extraction, mapping, and no-false-success.

### Web app (SecuRedactedApp.py)

```bash
pip install -r requirements.txt
pytest tests/test_enterprise_connectors.py
```

Requires the web app venv (Flask, Flask-Login, Flask-SQLAlchemy, cryptography,
requests). Tests use SQLite + a mocked Graph sender + a fake engine boundary; no
real Microsoft tenant is contacted. Covers the mandatory tenant-isolation matrix
(§21), OAuth state (§24), Graph responses (§23), and token storage.

## Test tenant setup (manual E2E, M365-106)

1. Create a Microsoft 365 developer tenant with a test user.
2. Register the Entra app as above; set the env vars; run the web app.
3. As the test user, open **Integrations → Connect Microsoft 365**, complete
   consent, confirm status shows **Connected** with the correct tenant id.
4. In SharePoint/OneDrive, select a text file (`.txt`/`.md`/`.csv`/`.json`/`.html`),
   run **Scan with SecuRedact** (SPFx) or the dashboard scan form, and confirm
   findings (categories/counts/severity) are returned with no raw PII.
5. Confirm an unsupported format returns `unsupported_format` and no redacted copy
   is created (write-back is out of scope).

## Known limitations (Batch 1)

- **Supported extraction:** text-like formats only (txt/md/csv/json/html). Office
  (DOCX/XLSX/PPTX) and PDF extraction are deferred (CONN-003).
- **No write-back** (M365-104), no redacted SharePoint copy.
- **No background scanning** (M365-200), no delta/crawl.
- **No inventory dashboard** (M365-300).
- **No** GitHub, Google, Atlassian, Salesforce, ServiceNow, Box, Slack, Teams,
  Outlook, or Copilot integrations.
- Microsoft dependencies (`msal`/`msgraph-sdk`) are optional/isolated and never
  imported by `securedact_core` or the MCP server.
- The web app invokes the engine through the canonical API boundary by default;
  in-process `securedact_core` usage is supported via the injected `EngineBoundary`.
