# SecuRedact Enterprise Connector Architecture & Microsoft 365 Integration — Roadmap

> **Status:** Planning / Architecture. This document is the authoritative description of the approved Enterprise Connectors roadmap. It was produced during planning and is preserved here with the corrections noted in the "Corrections applied" section below.
>
> **Save target:** `securedact-mcp/docs/enterprise-connectors-roadmap.md` (this file).
>
> **Batch 1 implementation status** is tracked separately in `docs/enterprise-connectors-batch1.md`.

---

## Corrections applied (preserve-and-correct pass)

1. **Microsoft Selected permissions.** The legacy delegated scopes `Files.Read.Selected` and `Files.ReadWrite.Selected` are **not** preferred for direct Microsoft Graph access. Per current Microsoft Graph documentation these are file-handler scopes intended for Office Add-ins / Office 365 file handlers and must not be used to call Microsoft Graph directly. Where granular selected-resource access is discussed, the current Selected permissions model is `Sites.Selected`, `Lists.SelectedOperations.Selected`, `ListItems.SelectedOperations.Selected`, and `Files.SelectedOperations.Selected`. These Selected scopes require **both** admin/user consent **and** an explicit resource permission assignment (e.g., adding the app to the site/list/item with the specific role). Selected-resource provisioning is **out of scope for Batch 1** and is not implemented. The read-only batch requests only delegated `User.Read`, `Files.Read`, `Sites.Read.All`, and `offline_access`.
2. **`Sites.Read.All` consent.** The permissions matrix now distinguishes **delegated** `Sites.Read.All` from **application** `Sites.Read.All`. Delegated `Sites.Read.All` does **not** universally require admin consent; whether admin consent is required depends on the tenant's permission policy. It is incorrect to state that delegated `Sites.Read.All` always requires admin consent. Application `Sites.Read.All` (used for background scanning in M365-200) does require admin consent and is not used in this batch.
3. **CTRL-005 priority.** `CTRL-005` (Dashboard Integrations area + health) appeared under both P0 and P1 in an earlier planning summary. Resolved from the roadmap content (§48) to **P1**, listed once. Batch 1 additionally delivers the Integrations dashboard surface because the integration-foundation requirement (§19 of the implementation brief) needs it.

---

## 1. Executive Summary

SecuRedact is evolving from per-host AI/privacy integrations into a **privacy firewall between sensitive organizational data and AI/automated systems**. The existing web application (`SecuRedactedApp.py`) already owns accounts, authentication (including Google SSO), Stripe billing/licensing, and an authenticated dashboard, and it already proxies redaction to a canonical SecuRedact API. The core engine (`securedact_core`) already owns detection, policy, redaction, residual validation, the audit-event abstraction, and the firewall — all text-based and provider-neutral.

The recommended architecture keeps `SecuRedactedApp.py` as the **control plane** (accounts, organizations, Microsoft Entra OAuth, integration configuration, tenant→organization mapping, policy administration, findings/audit presentation, integration health) and keeps `securedact_core` as the **security/data plane** (detection, policy, redaction, audit). Enterprise platforms connect through **reusable connector boundaries**: a capability-oriented connector model that feeds normalized content into the existing `SecuredactEngine.prepare(text=...)` API. Microsoft 365 / SharePoint / OneDrive is the first production connector, delivered as M365-102 (user-triggered selected-file scan) — read-only in Batch 1. The connector *contracts* live in core (pydantic, no platform SDK); platform-specific code (Microsoft Graph, OAuth) lives in an isolated, optional package so existing MCP/Claude/Gemini installs are never forced to pull Microsoft dependencies.

---

## 2. Current Repository Landscape

| Repository | Path | Role (confirmed) |
|---|---|---|
| Core / MCP | `Desktop/securedact/securedact-mcp` | `securedact_core` engine + `securedact_mcp` server + `securedact_eval`. Local, offline, text-based privacy engine. No web UI, no HTTP API, no model weights in package. |
| Web app | `Desktop/securedact/SecuRedactedApp.py` | Flask 2.2 monolith (Python 3.10), Postgres, Flask-Login, Google SSO, Stripe billing, dashboard. Proxies `/redact` to canonical SecuRedact API. |

Both repos compile/run independently. The web app is the existing integration/control-plane surface; per its own `AGENTS.md`, "Note significant logic moves there." Concurrent/unrelated work observed:
- Core: untracked `AGENTS.md`, `scripts/a9_*`, `src/securedact_eval/experimental/` — **unrelated**, do not touch.
- Web: modified `templates/download.html`, `templates/self_host_api.html` — **unrelated marketing/install pages**, do not touch.

---

## 3. Current SecuRedact Architecture (core)

- **Public API** (`securedact_core/api.py`): `SecuredactEngine.prepare(RedactionRequest) -> PrepareResult`, `restore(...)`, `read_file(...)`. `prepare` is text-only (`RedactionRequest.text`, max `DEFAULT_MAX_TEXT_CHARS = 1_000_000`). Result carries `status` (`ok`/`review_required`/`blocked`), `outcome`, `policy`, `policy_version`, `policy_digest`, `counts`, `action_counts`, `sanitized_text` (only when approved), optional `findings`/`restoration_session`.
- **Detection** (`detectors/`): deterministic `RegexDetector`, `CredentialsDetector` (passwords, API keys, tokens, OAuth, JWT, DB URLs, dotenv); contextual `ContextualPrivacyDetector`; `GlinerDetector`; `FlairDetector`; optional `BardsaiArticle9Detector` (Article 9 special categories → REVIEW only). PII + GDPR + Article 9 (`SPECIAL_CATEGORY_TYPES` → `REVIEW`/`BLOCK`) + secrets all present.
- **Policy** (`policies.py`, `policy_loader.py`): `Policy` is a frozen pydantic model, **serializable** (yaml/json), has `digest`, supports `category_actions`, `replacement_mode`, `block_on_unreviewed`, `firewall`. `PolicyRegistry` + `load_policy_registry_from_environment()` load custom policies from a directory. Built-ins include `strict_external_ai` (credentials + special-category BLOCK; the right default for external/AI contexts).
- **Firewall** (`firewall.py`): `FirewallPolicy`/`ToolContext`/`FirewallDecision(action, requires_approval, reason)`. Additive layer; `MAX_INSPECTION_TEXT_CHARS = 1_000_000` single source of truth; practical tool-result cap 200 KB.
- **Audit** (`audit.py`): privacy-preserving `AuditEvent` (typed fields + allowlisted scalar `metadata`; never serializes raw PII/secrets/tokens/mappings). `set_audit_sink` is process-wide; emission is fail-safe (never weakens enforcement). Event types: `FILE_BLOCKED`, `SECRET_DETECTED`, `PII_REDACTED`, `TOOL_BLOCKED`, `APPROVAL_REQUIRED`, `FILE_READ`, `EGRESS_BLOCKED`, `POLICY_OVERRIDE`, plus connector events `CONNECTOR_RESOURCE_ACCESSED`, `CONNECTOR_SCAN_STARTED`, `CONNECTOR_SCAN_COMPLETED`, `CONNECTOR_FINDING`, `CONNECTOR_POLICY_BLOCKED`, `CONNECTOR_REDACTION_CREATED`, `CONNECTOR_WRITE_COMPLETED`, `CONNECTOR_PERMISSION_DENIED`, `CONNECTOR_ERROR`.
- **Safe read** (`safe_read.py`): `read_file_safely` is **local-path, text-only** — blocks binary (`binary_file_unsupported`), enforces traversal/symlink/UNC defenses, size cap. **No format-preserving redaction for DOCX/XLSX/PPTX/PDF.**
- **MCP server** (`securedact_mcp/server.py`): registers the high-level `prepare_for_external_ai`, `analyze_text`, `redact_text`, `restore_text`, `create_safe_copy`. `create_safe_copy` supports **only `.txt`/`.md`** basenames. **New connector logic must NOT add Microsoft tools to this server** (repo-boundary validator expects a fixed MCP tool set; keep the MCP surface stable).

---

## 4. Current `SecuRedactedApp.py` Architecture (control plane candidate)

- **Auth**: Flask-Login sessions; `User` model (`email`, `password` (bcrypt), `otp_secret` (TOTP 2FA), `api_key`, `email_verified`, `verification_token`, `reset_token`, `terms_accepted`). `APIKey` model (`user_id`, `key`).
- **SSO**: `routes/sso.py` already implements **Google OAuth** via `flask_dance` (openid + email/profile). This is the direct precedent for Microsoft Entra OAuth.
- **Billing/licensing**: Stripe (`/create-checkout-session`, `/create_payment_intent`, `/activate`) + `license_server.py` standalone. Plans: Personal/Professional/Free.
- **Dashboard**: `routes/dashboard.py` is minimal (renders `dashboard.html` with the user's `api_key`). Room to add an **Integrations** area.
- **Canonical API proxy**: `services/securedact_api_client.py` `post_redact(text, entities, machine_id)` → `SECUREDACT_API_BASE_URL` (Bearer `SECUREDACT_API_TOKEN`), primary→backup failover, 8s timeout. **This is the existing SecuRedact service boundary**; connectors should reuse the same engine path (in-process via `securedact_core`, or via this API).
- **DB**: Flask-SQLAlchemy `users`/`api_keys` tables; some endpoints also use raw `psycopg2` against `api_licenses`. Inconsistent access — new integration tables should use the SQLAlchemy models layer consistently.
- **Gaps (confirmed absent)**: no `Organization`/`Workspace` model, no `Integration`/`Tenant` model, no findings store, no audit table, no policy-admin UI, no connector-scoped credentials store, no `Microsoft`/`Entra` code.

---

## 5. Confirmed Reusable Functionality

| Capability | Where | Reuse for connectors |
|---|---|---|
| PII / GDPR / Article 9 detection | `securedact_core` detectors | Scan extracted content via `prepare` |
| Secret/credential detection | `CredentialsDetector` | Same |
| Policy evaluation + serialization | `Policy` / `PolicyRegistry` | Org policies = serialized `Policy` objects |
| Redaction + residual validation | `prepare` | Produce `sanitized_text` |
| Approval-required decisions | `PrepareStatus.REVIEW_REQUIRED` | Surface in SPFx/dashboard |
| Audit events (privacy-preserving) | `audit.py` | Emit connector events via same sink |
| Size/perf guards | `MAX_INSPECTION_TEXT_CHARS`, firewall | Reuse for inbound content |
| Safe defaults / fail-closed | engine + firewall | Inherit |
| Accounts + Google SSO + Stripe | web app | Extend to orgs + Entra; reuse billing |
| Canonical redaction API | `securedact_api_client` | Connector backend calls engine through this boundary |

---

## 6. Architectural Gaps

1. No organization/workspace/tenant model in the web app.
2. No canonical resource model that is not "a local file."
3. No connector contract layer (capabilities, normalized content, result translation).
4. No integration/tenant credential store with encryption + rotation.
5. No policy-admin surface that emits a serializable `Policy` per org.
6. No findings/audit persistence (core audit is in-memory sink only; web app has none).
7. No format-preserving redaction for Office/PDF (only `.txt`/`.md` safe copies).
8. No service/API boundary scoped to "organization + connector + external resource."
9. MCP server must stay frozen — connector entry points must live elsewhere (web app blueprint + SPFx).

---

## 7. Control Plane vs Security/Data Plane

**Control plane — owns `SecuRedactedApp.py` (extend):**
- User accounts, 2FA, sessions.
- Organization / Workspace model + membership + roles (owner, admin, connector_admin, member).
- Integration configuration UI (Microsoft 365, later GitHub/Google…).
- Microsoft Entra OAuth initiation + callback + consent state + `state` CSRF token.
- Tenant → Organization mapping store (encrypted token store).
- Policy administration (edit/serialize a `Policy`; version + digest).
- Findings summary + audit presentation (read-only views).
- Integration health / connection status.
- Billing/licensing (exists).

**Security/data plane — owns `securedact_core` (+ a SecuRedact Service boundary):**
- Resource content retrieval (per-connector; NOT in core).
- Text normalization / extraction (connector-provided; core consumes text).
- Detection, policy evaluation, redaction, residual validation (`SecuredactEngine.prepare`).
- Firewall decisioning (reuse).
- Audit event generation (reuse sink; add connector event types).
- Safe handling of sensitive content (memory-only; no raw PII/secrets in logs).

**Ownership rule:** anything that *touches sensitive content or makes a privacy decision* lives in core/the service. Anything that *configures access or presents results* lives in the web app. Microsoft/Graph code lives in an isolated optional package, never in `securedact_core` or the MCP server.

---

## 8. Account / Organization / Tenant Model

Evolve the web app (smallest safe change):
- Add `Organization` (id, name, slug, created_at, subscription_tier).
- `OrganizationMembership` (user_id, org_id, role ∈ {owner, admin, connector_admin, member}).
- `User` gains optional personal-organization membership (lazy-created on first Integrations access) so existing accounts are not orphaned.
- `Integration` (org_id, platform=`microsoft365`, status, configured_scopes, created_by, created_at).
- `TenantConnection` (integration_id, platform_tenant_id (Entra tenant GUID), display_name, encrypted_token_blob, token_kind ∈ {delegated, application}, connected_by, connected_at, last_health_at).
- One org MAY connect multiple external tenants; one tenant maps to exactly one org (enforced uniquely). Personal/developer users remain supported (org optional).
- Migration: additive tables; existing `User` rows keep working (no column added to `users`; membership is via the `organization_memberships` table). See `migrations/add_enterprise_connectors.sql`.

---

## 9. Proposed Connector Architecture

- **Contracts in core** (`securedact_core/connectors/`): pure pydantic, zero platform imports. Defines `ConnectorResource`, `ResourceKind`, `ConnectorCapability`, `ScanRequest`, `ScanResult`, `NormalizedContent`, `ConnectorIdentity`. Lets core unit tests validate mapping without any Microsoft dependency.
- **Platform code in isolated package** (`SecuRedactedApp.py/services/connectors/`): Microsoft Graph client, Entra OAuth, SPFx config discovery. Heavy SDKs (`msal`, `msgraph-sdk`) are **optional/isolated**; never imported by core or MCP.
- **Execution flow:** connector retrieves resource → extracts/normalizes text + metadata → builds `ScanRequest(resource=ConnectorResource, text=normalized)` → calls `SecuredactEngine.prepare` (or the canonical API) → translates `PrepareResult` to `ScanResult` → (optional) writes sanitized copy back via connector → emits audit events.
- Keep connector *orchestration* in the web app (`integrations`/`connectors` blueprint) so org/tenant/auth are enforced in one place.

---

## 10. Canonical Resource Model (not "File")

```python
class ResourceKind(str, Enum):
    FILE = "file"
    DOCUMENT = "document"
    MESSAGE = "message"
    RECORD = "record"
    ISSUE = "issue"
    PAGE = "page"
    COMMENT = "comment"
    ATTACHMENT = "attachment"
    REPO_CONTENT = "repo_content"


class ConnectorResource(BaseModel):
    resource_id: str  # platform-native id (driveItem id, issue key, record id)
    platform: str  # "microsoft365"
    resource_kind: ResourceKind
    org_id: str
    tenant_id: str  # SecuRedact org + platform tenant (isolation keys)
    parent_id: str | None  # container/library/issue/thread
    name: str
    mime_type: str | None
    size_bytes: int | None
    external_url: str | None
    sensitivity_context: dict = {}  # connector hints, never raw content
    content_ref: str | None = None  # opaque handle to retrieved bytes (connector-owned)
    extracted_text: str | None = None  # normalized content for the engine
    metadata: dict = {}
```

Rationale: GitHub (REPO_CONTENT/COMMENT), Slack (MESSAGE), Jira (ISSUE/COMMENT), Confluence (PAGE), Salesforce/ServiceNow (RECORD), Box (FILE/DOCUMENT) all map without forcing a file abstraction.

---

## 11. Connector Capability Model

Capability-oriented, not one monolithic interface. `ConnectorCapability` = {READ, WRITE, LIST, WATCH, METADATA, PERMISSIONS, QUARANTINE, UI_ACTIONS, ANNOTATIONS, CHECKS}. Each connector declares the subset it implements; the control plane discovers capabilities to render UI (e.g., WRITE hidden if unsupported).

Common operations (connector-owned where platform-specific):
- `get_resource(ref) -> ConnectorResource`
- `list_resources(container, filters) -> list[ConnectorResource]`
- `read_resource(resource) -> NormalizedContent` (text extraction)
- `write_resource(resource, content)` (generic write)
- `write_sanitized_copy(original, sanitized_text, kind) -> ref` (M365-100 write-back — **deferred to M365-104, not in Batch 1**)
- `watch_changes(subscription)` (M365-200 — deferred)
- `get_permissions(resource)`, `get_metadata`, `apply_metadata` (M365-300 — deferred)
- `quarantine(resource)` (future enforcement)
- `emit_platform_notification(result)` (PR/Checks/SPFx toast)

Operations that genuinely belong in the **common SecuRedact layer**: `ScanRequest`/`ScanResult` translation and `prepare` invocation. Connectors must NOT implement meaningless operations to satisfy an interface — unimplemented capability ⇒ absent from the declared set.

**Batch 1 Microsoft capability set:** `{READ, SCAN}`. `WRITE`, `WATCH`, `QUARANTINE` are intentionally **not** implemented or advertised in this batch.

---

## 11a. Microsoft Selected permissions model (corrected)

The legacy delegated scopes `Files.Read.Selected` and `Files.ReadWrite.Selected` are **Office 365 file-handler scopes** and are **not** used to call Microsoft Graph directly. Do not prefer them for direct Graph access.

The current Selected permissions model is:
- `Sites.Selected`
- `Lists.SelectedOperations.Selected`
- `ListItems.SelectedOperations.Selected`
- `Files.SelectedOperations.Selected`

These Selected scopes require **both** consent **and** an explicit resource permission assignment (the app must be granted the specific role on the specific site/list/item, typically via the Graph `permissions` API or the admin center). They are **not** a drop-in replacement for `Files.Read`/`Sites.Read.All`, and Selected-resource provisioning is **out of scope for Batch 1** — it is not implemented.

---

## 12. Service / API Boundary

New `SecuRedactedApp.py` blueprint `connectors` (authenticated via Flask-Login session + org context):
- `POST /dashboard/integrations/microsoft/connect` — start Entra OAuth (generate+store `state`, redirect to Microsoft).
- `GET /dashboard/integrations/microsoft/callback` — exchange code, validate `state`, store encrypted tokens, link tenant→org.
- `GET /dashboard/integrations/microsoft/status` — connection health.
- `POST /dashboard/integrations/<id>/disconnect` — revoke + delete tokens.
- `POST /dashboard/api/scan` — body `{resource_ref, policy?}` → org+tenant authz → connector `read_resource` → `prepare` → `ScanResult` (+ audit). Returns findings metadata only (no raw PII).

Security boundary: every request is attributed to `(user, org, integration, tenant)`. The engine is invoked **server-side**; `securedact_core` is never exposed directly over the network. SPFx calls only these endpoints (never Graph for scanning). File transfer: JSON with `extracted_text` (or streamed base64 for binaries in M365-200 only). Request size ≤ `MAX_INSPECTION_TEXT_CHARS`. Idempotency: `client_resource_version` + `scan_id` correlation; replay protected by short-lived `state` and nonce on webhooks.

---

## 13. Microsoft 365 Architecture (M365-102, read-only Batch 1)

Scope (Batch 1): SharePoint document library + OneDrive, user-selected file, "Scan with SecuRedact," **read-only findings only**.
- **SPFx** ListView Command Set (tenant-deployed via App Catalog) adds a "SecuRedact" button to the command bar/context menu.
- On selection, SPFx resolves the selected item's driveItem identity and calls the web app `/dashboard/api/scan` (passing the `driveItem` id + site/drive id). The web app resolves the Entra token for that org/tenant, calls Microsoft Graph `driveItem` content, normalizes, runs `prepare`, returns `ScanResult`.
- User views safe findings (risk, PII count, Article 9 categories, secrets, policy decision, confidence). **No redacted copy / write-back in Batch 1.**
- Audit events emitted. Action belongs to the correct org + Microsoft tenant.

---

## 14. Microsoft Onboarding Flow

```
Dashboard > Integrations > Microsoft 365 > Connect
  -> web app generates OAuth state (cryptographically random, stored server-side, TTL ~10 min)
  -> redirect to Entra authorize (client_id = SecuRedact Entra app, redirect_uri = web app /callback,
     scope = User.Read Files.Read Sites.Read.All offline_access, response_type=code, state=...,
     prompt=consent)
  -> Microsoft redirects to /callback?code&state
  -> web app validates state (CSRF), exchanges code for tokens, verifies tenant id from token response
  -> stores encrypted tokens (see §17), maps tenant_id -> current org
  -> Integration active
```
OAuth `state` generated + stored server-side (not in cookie alone); callback validates against stored value. Tenant ID taken from the verified token response `tenant` claim (server-issued, not browser input). `Files.Read.Selected` is **not** requested (see §11a).

---

## 15. Microsoft Authentication Model

- **Delegated** permissions for M365-102 (user acts on their own selected file). **Admin consent** may be required for delegated `Sites.Read.All` in *some* tenants, but it is **not universal** — see corrected §16. For user-owned files, `Files.Read` and `User.Read` are typically user-consented.
- **Refresh tokens**: required (offline access) to act after the panel session; stored encrypted (see §17); rotation handled by refresh flow; revocation on disconnect.
- **Application permissions**: deferred to M365-200 (background scanning); not needed for user-triggered M365-102.
- Token storage: encrypted at rest (Fernet with key from `SECUREDACT_CONNECTOR_ENCRYPTION_KEY`, or cloud KMS). Never in logs. Rotation + expiry tracked; `/status` reports health.
- Reauth: when access token expired, silent-acquire via refresh; if refresh fails, surface "Reconnect" in dashboard.

---

## 16. Microsoft Permissions Matrix (Batch 1 — read-only)

| Permission | Type | MVP feature | Admin consent | Narrower alt | Risk if compromised |
|---|---|---|---|---|---|
| `User.Read` | Delegated | Identify caller + tenant id | No | — | Identity only; low |
| `Files.Read` | Delegated | Download selected SharePoint/OneDrive file | No | `Files.Read.Selected`/**`Sites.Selected`** exist but are **not used here** (see §11a) | Read user files; medium — scope to selected |
| `Sites.Read.All` | **Delegated** | Resolve library/site for selected item | **Depends on tenant** — **not universal** (some tenants require admin consent, many do not) | `Sites.Selected` (requires explicit resource assignment; **out of scope for Batch 1**) | Read all sites the user can access; prefer `Sites.Selected` when available |
| `Sites.Read.All` | **Application** | Background scanning (M365-200) | **Yes** | `Sites.Selected` | Broad; deferred, not in Batch 1 |
| `offline_access` | Delegated | Refresh token for panel action | No | — | Long-lived access; encrypt + rotate |

**Not requested in Batch 1 (read-only):** `Files.ReadWrite`, `Files.ReadWrite.All`, `Sites.ReadWrite.All`, and the legacy `Files.Read.Selected`/`Files.ReadWrite.Selected` file-handler scopes.

Least privilege (corrected): this batch uses delegated `User.Read` + `Files.Read` + `Sites.Read.All` + `offline_access`. The legacy `*.Selected` file-handler scopes are explicitly **not** used for direct Graph calls. `Sites.Selected` is the viable selected model but requires an explicit resource permission assignment and is deferred (not implemented in Batch 1).

---

## 17. Microsoft Tenant Mapping & Isolation

- `TenantConnection.platform_tenant_id` (Entra `tid`) uniquely mapped to one `org_id` (DB unique constraint).
- Every Graph call is scoped by the org's `TenantConnection`; the web app selects the token by `(org_id, tenant_id)` from the request context — never from client-supplied tenant.
- Enforcement: a scan request for `org=A` cannot resolve `tenant=B`'s token; cross-tenant token use is rejected (403). Findings/audit rows carry `org_id`+`tenant_id`; queries are org-scoped.
- Tokens encrypted; key in env/KMS; decryption only server-side in the connector execution path.

---

## 18. SPFx Architecture

- **SharePoint Framework (SPFx)** ListView Command Set, `supportedFileTypes` (all for reporting; write-back only for supported — write-back deferred).
- Fluent UI side panel/dialog shows Before-scan (selected file, supported/unsupported), During-scan (progress, cancel, timeout/error), Findings (overall risk, PII count, Article 9, secrets, policy decision, confidence — **no raw sensitive values**), Actions (for Batch 1: view findings only; redacted copy deferred), Errors (permission denied, unsupported, oversized, corrupted, SecuRedact unavailable, Graph fail, auth expired, policy fail).
- SPFx uses the **host** session to call the web app backend (not Graph directly for scanning). CSRF/CORS: backend allows only the SPFx app domain with credentials; all state-changing calls require the user session.
- Thin: **no detection logic in the browser.** SPFx only renders results and triggers backend calls.

---

## 19. Content / Privacy Boundary (data flow)

1. User selects file in SharePoint → SPFx → web app `/dashboard/api/scan`.
2. Web app resolves Entra token, calls Graph `driveItem` content → bytes held **in memory only** (temp file only if extraction requires it, in a private dir, deleted after request).
3. Connector extracts/normalizes text (text/markdown/csv/json/html only in Batch 1; Office/PDF extraction is CONN-003, deferred).
4. `SecuredactEngine.prepare(text=normalized, policy=org_policy)` → `PrepareResult` (or the canonical API boundary).
5. Sanitized text + findings metadata returned to SPFx; **raw sensitive values never leave the service in UI/logs** (consistent with `audit.py` allowlist).
6. Audit events emitted (connector event types) with `org_id`+`tenant_id`, no raw PII/secrets.
- Deployment modes (SaaS / EU / self-hosted / zero-retention) stay possible because the engine is invoked server-side and content is memory-only; no architectural lock-in to a single hosting model.

---

## 20. File-Format Strategy

Three distinct capabilities, evaluated against current code:
- **A. Content extraction** — connector-owned. TXT/MD/CSV/JSON/HTML: trivial. DOCX/XLSX/PPTX: via optional `python-docx`/`openpyxl`/`python-pptx` (text only). PDF: text via optional `pypdf` (no OCR). **Batch 1 implements text/markdown/csv/json/html only** (these are safely extractable with existing dependencies); Office/PDF extraction is CONN-003 (deferred).
- **B. Detection** — works on any extracted text via `prepare`.
- **C. Format-preserving redaction** — **only `.txt`/`.md` today** (`create_safe_copy`). Write-back/format-preserving redaction is M365-104 (deferred).

**Batch 1 rule (M365-102):** detection + reporting for text-like extractable formats; **unsupported formats → "scan only unavailable / unsupported"** with a clear UX note. No redacted copy in Batch 1.

---

## 21. M365-102 MVP Definition (Batch 1)

**In scope (read-only):** connect Entra tenant→org; SPFx command; selected-file Graph retrieval; existing `prepare` detection; structured findings; safe unsupported-format handling; audit; docs; tests.
**Out of scope:** write-back (M365-104), tenant crawling, Teams, Outlook, Copilot interception, Purview replacement, dashboard redesign beyond Integrations, Google/GitHub/Salesforce/ServiceNow/Atlassian/Box/Slack, billing, ML changes, Office/PDF extraction (CONN-003).

---

## 22. M365-200 Automated Scanning (plan only)

Graph **change notifications** + **delta queries** on `driveItem`s; subscriptions with renewal; initial index + incremental. Webhook validation (client-state/`validationToken`), replay protection (nonce + dedup), retries/backoff, duplicates, moved/renamed/deleted handling, subscription expiry renewal, throttling. Uses **application** permissions (admin-consented). Fail-closed: missed events → periodic delta reconciliation, not silent skip.

---

## 23. M365-300 Privacy Inventory / Dashboard (plan only)

Dashboard table: resource id, platform, location, last scanned, risk, finding counts, categories, policy version, detector/model version, remediation state. **Metadata only — no raw PII/secrets.** SharePoint sensitivity columns are optional display only; do **not** write PII into SharePoint metadata. Results primarily in SecuRedact dashboard.

---

## 24. M365-400 Copilot / AI Direction (classification)

| Capability | Classification |
|---|---|
| User-triggered SharePoint/OneDrive scan | **SUPPORTED NOW** (M365-102, read-only) |
| Background repo scanning (Graph delta) | **POST-PROCESSING** (M365-200) |
| Findings written to SharePoint columns | **ADVISORY ONLY** (M365-300) |
| Block Copilot from reading a file | **NOT CURRENTLY ENFORCEABLE** (no supported Microsoft mechanism; only sensitivity labels/purview can) |
| Intercept Outlook mail pre-send | **NOT CURRENTLY ENFORCEABLE** |
| Intercept Teams messages | **NOT CURRENTLY ENFORCEABLE** |
| Copilot connector governance | **ADVISORY ONLY** |

Do not claim SecuRedact can intercept Copilot/Office traffic without a current Microsoft-supported mechanism.

---

## 25. GitHub — Second Reference Connector (validation only)

Future GH-100: GitHub App (installation per org/repo), webhook validation (HMAC), push/PR events, changed-file scan, **Checks API** (pass/fail + annotations), required checks, policy blocking, dashboard association. Capability set {READ, LIST, WATCH, CHECKS, ANNOTATIONS, UI_ACTIONS} fits the model with **no file-only assumption** (REPO_CONTENT/COMMENT). Confirms the abstraction is not Microsoft-specific. No GitHub code in this roadmap.

---

## 26–31. Cross-Platform Validation (architecture only)

- **Google Workspace** (Drive/Docs/Sheets/Gmail/Chat): resource model = DOCUMENT/FILE/MESSAGE; OAuth 2.0 + Workspace domain; change via Drive API watch; native UI = Drive add-on. Fits.
- **Atlassian** (Jira/Confluence): ISSUE/PAGE/COMMENT/ATTACHMENT; OAuth 2.0 (3LO) or Connect; webhooks; write via REST. Fits.
- **Salesforce** (CRM objects/records/attachments): **RECORD** kind added — proves the model is not file-only. Fits with `ResourceKind.RECORD`.
- **ServiceNow** (ITSM/HR/security/knowledge): RECORD/PAGE/ATTACHMENT; REST + event hooks. Fits.
- **Box** (enterprise docs/metadata/events): FILE/DOCUMENT; Box API + events. Office model generalizes. Fits.
- **Slack** (messages/threads/channels/files): **MESSAGE** kind — proves conversational resources supported. Fits.

None require changing the canonical model; only `ResourceKind` extensions. No implementation.

---

## 32. Canonical Model Must Support More Than Files

Confirmed by §26–31: `ResourceKind` (FILE/DOCUMENT/MESSAGE/RECORD/ISSUE/PAGE/COMMENT/ATTACHMENT/REPO_CONTENT) is required. Security processing operates on `extracted_text` + contextual metadata; the platform-specific container is connector-owned.

---

## 33. Dashboard as Integration Control Plane

Add an **Integrations** area to `SecuRedactedApp.py` (alongside Overview/Findings/Policies/Audit/Team/Billing/Settings). Integrations page lists Microsoft 365 (tenant, status, scopes, last activity, Configure/Disconnect) and unconnected GitHub/Google (Connect buttons). Built on the existing `dashboard.html`/Flask-Login; no second account system.

---

## 34. Policy Architecture

- Existing `Policy` is serializable and reusable — org policies = a `Policy` row/JSON keyed by `org_id`, with `policy_version`+`policy_digest` (inherit core `digest`).
- Platform overrides: an org may select a built-in (`strict_external_ai` default for external/AI context) or a custom serialized policy; no parallel SaaS policy engine.
- Invalid policy config → reject at save (reuse `Policy` validation + `policy_loader` invariants); cache digest to detect stale; never silently downgrade to a less-safe policy.

---

## 35. Deployment Model

- **Community/dev:** local service + dev tenant + manual SPFx install.
- **Hosted:** securedact.com dashboard + org account + Entra OAuth + hosted connector backend + centralized policies (reuse existing web app + canonical API).
- **Enterprise/self-hosted:** customer Entra app + private network + EU/on-prem + isolated control plane; engine invoked in-process (no external API). Architecture keeps this possible (server-side engine, memory-only content, encrypted tokens).
M365-102 ships hosted; self-host is a config, not a code fork.

---

## 36. Installation / Onboarding

1. Log in / create SecuRedact account. 2. Personal organization is created automatically. 3. Connect Microsoft 365 (user consent; admin consent only if the tenant requires it for `Sites.Read.All`). 4. Install SPFx via App Catalog (tenant-wide). 5. Command appears. 6. Dashboard shows health.

---

## 37. Enterprise Security Requirements

Least privilege (§16, corrected), tenant isolation (§17), authn/z (Entra + session), encrypted token storage + rotation + revocation, zero-retention (memory-only), sensitive logging prohibition (reuse `audit.py` allowlist), auditability (connector events), rate limits (Graph + engine), DoS (size caps), malicious/zip-bomb/oversized/unsupported (size guards + binary rejection), filename/path attacks (validate `driveItem` id, not names), content-type spoofing (verify by Graph metadata, treat as untrusted), SSRF (Graph only, no arbitrary URLs), webhook forgery (HMAC + `validationToken`), replay (nonce+dedup), CSRF (`state`), open redirect (fixed redirect_uri), compromised credentials (revoke + reauth), supply-chain (pin Graph SDK, hash-lock), tenant-mapping mistakes (unique constraint + server-side token resolution). **Threat model for M365-102** below.

---

## 38. Failure Model

- **Interactive user scan:** fail-**open-to-safe** UX — if SecuRedact unavailable/Graph fails/token expired/unsupported/oversized/corrupted/extraction fails/timeout/policy error → show error, **do not write anything**, do not silently send raw content anywhere. Blocked `prepare` result → show "cannot proceed" (fail-closed on content).
- **Background/enforcement (M365-200+):** fail-**closed** — missing scan ⇒ flag/quarantine, never assume clean.
- Distinguish clearly; M365-102 is interactive and must never auto-exfiltrate or auto-write on error.

---

## 39. Audit & Observability

Reuse `audit.py` sink; connector event types (see §3). Security audit = these (with `org_id`, `tenant_id`, `integration_id`, `platform_resource_id`, `policy_version`, `detector_version`, `scan_duration`, correlation id). Operational logs separate. Dashboard = summaries. **Never log raw PII/secrets** (enforced by allowlist).

---

## 40. API Security

User sessions (Flask-Login) for dashboard; SPFx uses the signed-in user session + same-site/CORS-scoped calls. Connector identity = `(org_id, integration_id, tenant_id)` resolved server-side. Token expiry enforced. API scopes per capability. CSRF via `state` for OAuth + Flask CSRF for forms. Replay via short TTL + nonce. Every external-resource request attributable to org+connector (§17).

---

## 41. Testing Strategy

- **Contract unit (core):** `ConnectorResource` mapping, `ResourceKind`, capabilities, normalized content, policy context, tenant/org context, `ScanResult` translation.
- **Microsoft unit:** Graph metadata→`driveItem` mapping, id/site/item validation, MIME handling, filename validation, tenant mapping, `ScanResult` mapping (mocked Graph).
- **Integration:** mocked Graph — auth boundaries, download, scan, write-back, permission denial, rate limit, retries, token expiry, malformed responses, oversized.
- **Dashboard:** connect flow, `state` validation, tenant association, org authz, disconnect, health, cross-tenant prevention.
- **SPFx:** command visibility, selection, unsupported format, API failure, results render, cancel, wrong tenant/config.
- **Security:** tenant isolation, permission escalation, OAuth callback forgery, `state` mismatch, malicious metadata/filename, spoofed content-type, oversized, webhook forgery, replay, unsafe logging.
- **E2E:** real M365 test tenant (selected file → scan → findings). Existing tests in both repos must stay green.

---

## 42. Repository / Package Ownership

- `securedact_core/connectors/` — **contracts only** (pydantic, no SDK). Owned by core repo.
- `SecuRedactedApp.py/services/connectors/` — Microsoft/Graph/OAuth code (isolated; `msal`/`msgraph-sdk` optional). 
- `SecuRedactedApp.py` — control plane + connector orchestration blueprint + dashboard Integrations + encrypted token store.
- `spfx/securedact-sharepoint/` — separate TypeScript package, fully isolated from Python packaging.
- Rationale: keeps Microsoft deps out of core/MCP; monorepo-free; smallest maintainable surface.

---

## 43. Dependency Strategy

- Microsoft SDKs (`msal`, `msgraph-sdk`, optional Office/PDF extractors) are **optional extras** and live in `services/connectors/`. Never imported by `securedact_core`/`securedact_mcp`.
- Core detection imports never require Microsoft packages.
- SPFx deps entirely separate (npm).
- Existing MCP/Claude/Gemini installs remain lightweight; `pip install securedact-mcp` does not pull Graph.

---

## 44. Backward Compatibility

- MCP tool set unchanged (do not add Microsoft tools).
- Claude/Gemini integrations unchanged (host-side).
- Firewall + policy loader invariants unchanged.
- CLI unchanged.
- Public Python API (`SecuredactEngine.prepare`) unchanged; connectors are callers, not modifiers.
- Web login/dashboard unchanged for existing users (additive org tables + lazy personal org).

---

## 45. Performance

Graph latency + download + extraction + detector latency + (write-back). Reuse `MAX_INSPECTION_TEXT_CHARS`. MVP is synchronous request/response (user wait acceptable); no queue/worker in M365-102. Concurrency: one engine per process (reuse; serializers inference). Define MVP SLO: scan < ~15s for ≤200KB text; document explicitly, no premature distributed infra.

---

## 46. M365-102 MVP Scope (narrow, shippable) — see §21.

---

## 47. M365-102 Definition of Done

Mandatory gates:
1. Org → Microsoft tenant connection with verified tenant id (from token response).
2. Tenant isolation enforced (cross-tenant rejected).
3. Clean Entra consent flow (user consent; admin consent only if the tenant requires it).
4. Least-privilege Graph permissions (corrected §16; no legacy `*.Selected` file-handler scopes, no write scopes).
5. SPFx command visible + correctly identifies selected `driveItem`.
6. Content retrieved via Graph + run through `prepare` (or canonical API boundary).
7. Structured findings returned (no raw PII in UI).
8. Unsupported file handled safely (scan-only / unsupported).
9. Meaningful audit events (no raw sensitive data logged).
10. Security + dashboard + SPFx + integration tests green.
11. E2E against a real test tenant.
12. No regressions in MCP/Claude/Gemini/dashboard.

A successful API call alone ≠ done.

---

## 48. Roadmap IDs & Priorities

Scheme: `ARCH` (architecture/contracts), `CTRL` (control plane/web app), `CONN` (connector contracts/core), `M365-1xx` (Microsoft milestones), `GH-1xx`, `GWS/ATL/SF/SN/BOX/SLACK-1xx` (validation only).

| ID | Title | Pri | Milestone | Status | Owner |
|---|---|---|---|---|---|
| ARCH-001 | Canonical resource model (`ConnectorResource`/`ResourceKind`) | P0 | Now | PLAN | core |
| ARCH-002 | Connector capability + operation contracts | P0 | Now | PLAN | core |
| ARCH-003 | Connector result/audit event model | P0 | Now | PLAN | core |
| ARCH-004 | Service/API boundary spec (`connectors` blueprint) | P0 | Now | PLAN | web |
| ARCH-005 | Tenant isolation enforcement pattern | P0 | Now | PLAN | web |
| CTRL-001 | Organization/Workspace + membership/roles | P0 | Now | PLAN | web |
| CTRL-002 | Integration + TenantConnection tables (encrypted tokens) | P0 | Now | PLAN | web |
| CTRL-003 | Entra OAuth connect/callback/`state`/consent | P0 | Now | PLAN | web |
| CTRL-004 | Policy admin (serialize `Policy` per org) | P1 | Now | PLAN | web |
| CTRL-005 | Dashboard Integrations area + health | **P1** | Now | PLAN | web |
| CTRL-006 | Findings + audit presentation (metadata only) | P1 | M365-300 | PLAN | web |
| CONN-001 | Core connector base (retrieve→normalize→`prepare`→translate) | P0 | Now | PLAN | core |
| CONN-002 | Microsoft Graph client (isolated extra) | P0 | M365-102 | PLAN | web/conn |
| CONN-003 | Office/PDF text extraction (isolated extra) | P1 | M365-102 | PLAN | conn |
| CONN-004 | Redacted-copy writer (supported formats) | P1 | M365-102 | PLAN | conn |
| M365-101 | SPFx ListView Command Set + Fluent panel | P0 | M365-102 | PLAN | spfx |
| M365-102 | Selected-file Graph retrieval + `prepare` scan | P0 | M365-102 | PLAN | conn/web |
| M365-103 | Findings UI (risk/PII/A9/secrets/decision) | P0 | M365-102 | PLAN | spfx |
| M365-104 | Sanitized copy write-back (supported formats) | P1 | M365-102 | PLAN | conn |
| M365-105 | Audit events + tenant isolation tests | P0 | M365-102 | PLAN | core/web |
| M365-106 | E2E real-tenant validation | P0 | M365-102 | PLAN | qa |
| M365-201 | Graph change notifications + delta (background) | P2 | M365-200 | PLAN | conn |
| M365-301 | Privacy inventory dashboard (metadata) | P2 | M365-300 | PLAN | web |
| M365-401 | Copilot/Teams/Outlook advisory (docs only) | P3 | M365-400 | SPEC | docs |
| GH-101 | GitHub App + Checks capability validation | P2 | GH | PLAN | conn |
| GWS-101 | Google Workspace capability validation | P3 | — | PLAN | docs |
| ATL-101 | Atlassian capability validation | P3 | — | PLAN | docs |
| SF-101 | Salesforce RECORD-kind validation | P3 | — | PLAN | docs |
| SN-101 | ServiceNow RECORD-kind validation | P3 | — | PLAN | docs |
| BOX-101 | Box document-model validation | P3 | — | PLAN | docs |
| SLACK-101 | Slack MESSAGE-kind validation | P3 | — | PLAN | docs |

Every item: objective, rationale, dependencies, likely modules/files, acceptance criteria, tests, security considerations, risk — captured above per section.

---

## 49. Recommended Implementation Order

1. ARCH-001/002/003 (contracts in core) — validates abstraction.
2. CTRL-001/002/005 (org model + token store + isolation) — control plane.
3. CONN-001 (core connector base) + ARCH-004 (API boundary).
4. CTRL-003 (Entra OAuth) + CONN-002 (Graph client).
5. M365-102 (scan) + M365-103 (findings UI).
6. M365-101 (SPFx command).
7. CONN-003/004 + M365-104 (redacted copy).
8. M365-105/106 (audit + E2E).
9. GH-101 (validate/refine abstraction).
10. M365-201/301 (background + inventory).
Rationale: contracts + control plane first de-risk the Microsoft-specific work; GitHub validates generality before further platforms.

---

## 50. (This document is the deliverable.)

---

## 51. Explicit Non-Goals

- No production Microsoft SDKs/Graph calls in the planning step.
- No detector/model/policy-engine changes.
- No second account/dashboard/licensing system.
- No GitHub/Google/Atlassian/Salesforce/ServiceNow/Box/Slack implementation.
- No format-preserving redaction for PDF/images.
- No Copilot/Office traffic interception claims.
- No parallel policy engine; no broad tenant-wide Graph permissions without justification.

---

## 52. Open Questions (resolved where possible)

1. Hosted vs self-hosted default for M365-102 (recommend hosted; self-host config-only).
2. `Sites.Selected` vs `Sites.Read.All` availability — resolved: Batch 1 uses delegated `Sites.Read.All`; `Sites.Selected` viable but requires explicit resource assignment and is deferred (see §11a).
3. Redacted-copy for DOCX: in-MVP additive (`python-docx` text replace) or post-MVP? → deferred to M365-104 (not in Batch 1).
4. Where should encrypted token keys live (env `Fernet` vs cloud KMS) per deployment? → env `SECUREDACT_CONNECTOR_ENCRYPTION_KEY` (Fernet) in Batch 1; KMS pluggable later.
5. Should org policies be editable in UI (CTRL-004) in M365-102 or deferred to M365-300? → deferred (CTRL-004 not in Batch 1).
6. Does the existing canonical API (`securedact_api_client`) become the connector backend, or run engine in-process in the web app? → Recommend in-process for self-host; API for hosted — same `Policy`/`prepare` path. Both options are supported via the injected engine boundary.

---

## 53. Recommended First Implementation Batch (this task)

Smallest sensible shippable slice — contracts + control-plane skeleton + Microsoft read-only scan, no write-back:

- **ARCH-001** canonical resource model (core).
- **ARCH-002** capability/operation contracts (core).
- **ARCH-003** connector result + audit event model (core).
- **CTRL-001** Organization + membership/roles (web).
- **CTRL-002** Integration + TenantConnection (encrypted tokens) (web).
- **CTRL-003** Entra OAuth connect/callback/`state`/consent (web).
- **ARCH-004** `connectors` blueprint + `/api/scan` boundary (web).
- **ARCH-005** tenant isolation enforcement (web).
- **CONN-001** core connector base: retrieve→normalize→`prepare`→translate (core).
- **CONN-002** Microsoft Graph client (isolated extra) (web/conn).
- **M365-102** selected-file Graph retrieval + `prepare` scan (web/conn).
- **M365-103** SPFx findings UI (spfx).
- **M365-105** audit events + tenant-isolation + security tests (core/web).
- **CTRL-005** (Dashboard Integrations area) — included in Batch 1 as the required user-facing integration surface (roadmap priority P1, listed once).

This batch delivers a read-only Microsoft 365 scan (findings only) end-to-end with correct tenant isolation and no regressions, leaving write-back (M365-104), background scanning (M365-200), and inventory (M365-300) as clean follow-ups.
