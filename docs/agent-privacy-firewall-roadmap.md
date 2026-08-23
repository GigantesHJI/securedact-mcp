# SecuRedact Agent Privacy Firewall — Roadmap

> Package version: **0.3.0**
> Status: documentation-only, implementation-ready roadmap. No code is implemented here.
> Companion to `docs/security-quality-roadmap.md`.
> This document is **not** a vulnerability admission. It is a plan to extend
> SecuRedact from prompt/content protection into a broader local privacy and DLP
> firewall for AI agents.

---

## 1. Current capability inventory (from repository inspection)

Classification: `EXISTS` / `PARTIAL` / `MISSING`.

| Capability | State | Evidence |
| --- | --- | --- |
| MCP server architecture (5 tools) | **EXISTS** | `src/securedact_mcp/server.py` `create_server` |
| MCP tools: `prepare_for_external_ai`, `analyze_text`, `redact_text`, `restore_text`, `create_safe_copy` | **EXISTS** | `server.py:450-689` |
| Redaction pipeline (`prepare`/`redact` + residual validation) | **EXISTS** | `src/securedact_core/engine.py`, `api.py` |
| Detectors: regex, contextual (Flair), credentials | **EXISTS** | `src/securedact_core/detectors/{regex,contextual,credentials,flair}_detector.py` |
| PII detection (email, phone, address, BSN, IBAN, IP, etc.) | **EXISTS** | `models.EntityType` (`models.py:10-90`), `regex_detector.py` |
| GDPR Article 9 / special-category detection | **EXISTS** | `taxonomy.SPECIAL_CATEGORY_TYPES`, `special_categories.v1.json` lexicon (`contextual_detector.py:24`) |
| Secret detection — known formats | **EXISTS** | `credentials_detector.py:RULES` (private key, GitHub, AWS, JWT, DB URL, password, bearer, session cookie, OAuth, labelled secret, dotenv password) |
| Secret detection — generic / unknown high-entropy secrets | **MISSING** | `UNKNOWN_SECRET` is only used by `database_url_credentials`; no standalone entropy+context secret detector. `_plausible_generic_secret` only gates `labelled_secret`. |
| Policy engine — content-based (entity type → action) | **EXISTS** | `policies.py:Policy`, `PolicyRegistry`, `BUILT_IN_POLICIES` |
| Policy engine — context inputs (path, tool, op, network) | **MISSING** | `Policy` has no `tool_name`/`mcp_server`/`operation`/`path`/`destination` fields; actions limited to `ALLOW/REVIEW/REDACT/BLOCK`. |
| Policy actions `WARN` / `REQUIRE_APPROVAL` | **MISSING** | `PrivacyAction` is `ALLOW/REVIEW/REDACT/BLOCK` only (`models.py`, used in `policies.py`). |
| Configuration (policy files + env overrides + safe defaults) | **PARTIAL** | `policy_loader.py:LocalPolicyLoader`, `SECUREDACT_POLICY_DIR`, `SECUREDACT_AUTOMATIC_PSEUDONYMIZATION`; no firewall config namespace. |
| File handling — write sanitized **output** | **EXISTS** | `create_safe_copy` writes to `SECUREDACT_SAFE_COPY_DIR` (`server.py:653-689`). |
| File handling — **read** / protect source files | **MISSING** | No file-read capability anywhere in `securedact_core`; only model/policy I/O (`model_management.py`, `policy_loader.py`). |
| Resource handling (MCP resources) | **MISSING** | No `list_resources`/`read_resource` in `server.py`. |
| Tool-call handling — inspect outbound **tool input** | **PARTIAL** | `securedact_enforced/provider_hook.py` (Claude `PreToolUse`, matcher `mcp__*|WebFetch|WebSearch`), `gemini_hook.py` `BeforeTool` (`mcp_*|http|web|...`). Only Claude + Gemini. |
| Tool-call handling — sanitize **tool result/response** | **PARTIAL** | Gemini `BeforeModel` rewrites model-bound text (`gemini_hook.py:299-340`); Claude `PreToolUse` does **not** rewrite arbitrary tool results. No `PostToolUse` result sanitization. |
| Egress / agent-chain reasoning (read→network taint) | **MISSING** | No cross-tool session taint; enforcement is per-event. |
| Tests | **EXISTS** | `tests/unit`, `tests/privacy`, `tests/integration`, `tests/evaluation`. |
| Integrations — Claude + Gemini enforced hooks | **EXISTS** | `integrations/claude-code-enforced/.../hooks.json`, `integrations/gemini-enforced/.../hooks.json`. |
| Integrations — Codex / Cursor / Windsurf | **PARTIAL** | MCP-only: `integrations/codex/config.toml`, `cursor/mcp.json`, `windsurf/mcp_config.json`. No enforced hook wrapping. |
| CLI / server entrypoints | **EXISTS** | `cli.py` (`install`/`setup`/`models`/`diagnostics`), `server.main`. |
| Documentation | **EXISTS** | `SECURITY.md`, `docs/threat-model.md`, `docs/privacy-model.md`. |

**Key architectural finding:** the firewall's enforcement spine **already exists**
as `src/securedact_enforced/`. It runs a per-session, warmed, HMAC-authenticated
loopback daemon (`claude_runtime._RuntimeServer`) and exposes
`PrivacyEnforcer.inspect_text` / `inspect_payload` (`adapter.py`) that recursively
sanitize text leaves. Claude (`provider_hook.handle_event`) and Gemini
(`gemini_hook.handle_event`) invoke it from host hooks. This is the realistic
foundation; the firewall is an *extension* of this hook/enforcement model plus
explicit safe tools and an extended policy engine — **not** a transparent proxy.

---

## 2. Threat model

The agent may have tools beyond SecuRedact:

```text
Agent
  ├── SecuRedact MCP (explicit tools + enforced hooks)
  ├── Filesystem MCP
  ├── Shell / Terminal
  ├── Coding-agent file tools
  ├── Database tools
  ├── Browser tools
  ├── HTTP / network tools
  └── Other MCP servers
```

SecuRedact's visibility is limited to (a) text explicitly passed to its tools and
(b) tool/event inputs routed through a registered host hook (Claude/Gemini today).
Anything a tool returns, or any tool not matched by the hook matcher, is **outside**
SecuRedact's view unless the host supports result rewriting.

Threats to address:

- **Sensitive files:** `.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`,
  `credentials.json`, `service-account*.json`, `~/.ssh/*`, `~/.aws/*`,
  `~/.config/*`, browser profiles, password stores. Avoid blanket-blocking broad
  directories; use precise path/name/extension policy.
- **Secrets:** passwords, API keys, access tokens, OAuth secrets, bearer tokens,
  JWTs, private keys, cloud credentials, DB credentials, connection strings,
  GitHub/GitLab/OpenAI/Anthropic/Google credentials. Avoid vendor-prefix-only
  matching; use format + entropy + context.
- **Personal information:** reuse existing PII detection (names, addresses, email,
  phone, BSN, IBAN, IP, identifiers, health/special-category per `SPECIAL_CATEGORY_TYPES`).
- **Agent attacks:** prompt injection, indirect prompt injection, malicious repo
  instructions, malicious documents, secret harvesting, credential discovery, data
  exfiltration, tool chaining. Especially:

```text
read sensitive file
        ↓
agent obtains secret
        ↓
HTTP / browser / network tool
        ↓
external destination
```

SecuRedact can raise the cost of these attacks (block prohibited reads, sanitize
tool inputs, block/redact detected secrets), but **cannot** guarantee prevention
when the exfiltration path is a tool it neither inspects nor controls.

---

## 3. Target architecture

### Realistic flow

```text
                    AI Agent
                       │
                       ▼
              SecuRedact Enforcement Layer
        (host hooks: Claude PreToolUse / Gemini BeforeTool+BeforeModel)
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   Explicit safe    Tool-input       Tool-result
   tools            inspection        inspection*
   (read_file)      (hooks)          (PostToolUse*)
        │              │              │
        └──────────────┼──────────────┘
                       ▼
              Sensitive Data Scan
         (reuse credentials/regex/contextual detectors)
                       │
              ┌────────┼────────┐
              ▼        ▼        ▼
           ALLOW    REDACT    BLOCK
         (WARN / REQUIRE_APPROVAL as softer defaults)
```

`*` = tool-result inspection requires host support for result rewriting
(Gemini `BeforeModel` yes; Claude arbitrary-tool result rewriting limited — see
Security Boundaries).

### What SecuRedact can enforce itself vs. what requires external support

| Mechanism | Enforced by SecuRedact? | Requires |
| --- | --- | --- |
| Sanitize text passed to `prepare_for_external_ai` | Yes | — |
| Block prohibited **tool calls** by input inspection (path/op) | Yes, for matched tools | Host hook (Claude/Gemini today) |
| Sanitize **tool input** before it runs | Yes (Gemini `BeforeTool`/`BeforeModel`; Claude `PreToolUse` updatedInput) | Host hook |
| Sanitize **tool result** content | Partial (model text in Gemini; no general Claude PostToolUse rewrite) | Host result-rewrite support |
| Read a file and return sanitized content | Yes, via NEW explicit `securedact_read_file` tool | Additive MCP tool |
| Block read of a prohibited path | Yes, at tool-call boundary | Host hook or explicit tool |
| Reason about read→network **chains** | No (best-effort heuristic only) | Session/OS-level taint (out of scope for MVP) |
| Transparently intercept arbitrary FS/shell access | **No** | Proxy/gateway/OS sandbox/container |

**Do not claim** SecuRedact transparently intercepts every filesystem/shell
operation. The enforceable surface is: explicit SecuRedact tools + host-routed
hook events. Everything else is advisory.

---

## 4. Policy engine extension

Extend (do **not** replace) `policies.Policy` (`src/securedact_core/policies.py`)
with an optional firewall layer. Keep content-based `category_actions` intact.

Proposed policy inputs (match conditions):

- `path`, `filename`, `extension`, `mime/content_type`
- `detected_entity` (`EntityType`), `detected_secret_type`
- `confidence`, `source` (detector)
- `tool_name`, `mcp_server`, `operation` (`read`/`write`/`send`/`query`/...)
- `source`/`destination`/`network_destination`
- `sensitivity_level`

Proposed actions (add to `PrivacyAction`): `ALLOW`, `REDACT`, `BLOCK`,
**`WARN`**, **`REQUIRE_APPROVAL`**.

Evaluation order per inspected item/event:

1. Firewall context rules (path/tool/op/destination) → `BLOCK`/`WARN`/`REQUIRE_APPROVAL`/`REDACT`/`ALLOW`.
2. Fall back to existing content-based `category_actions` → `REDACT`/`BLOCK`/`REVIEW`.

Sensible defaults (avoid breaking coding agents):

| Data | Default |
| --- | --- |
| Normal source code | ALLOW |
| Person names | REDACT |
| Email/phone/address | REDACT |
| BSN | REDACT |
| Health/special-category | REDACT |
| Credit-card data | BLOCK |
| Password | BLOCK |
| API token | BLOCK |
| Private key | BLOCK |
| `.env` | BLOCK |
| `.ssh/*` | BLOCK |
| Unknown high-confidence secret | BLOCK |
| Ambiguous sensitive op | WARN / REQUIRE_APPROVAL |

Reuse `policy_loader._validate_invariants` (`policy_loader.py:135-149`) to keep
fail-closed invariants (protected types never `ALLOW`; residual validation on;
`expose_raw_values`/`expose_mapping` off).

---

## 5. File protection

### Safe file read (new explicit tool)

```text
securedact_read_file(path)
      ↓
Path policy (BLOCK .env, .ssh, *.pem, ...)
      ↓
Resolve (no traversal / symlink escape / UNC abuse / case tricks)
      ↓
Read locally (size + type limits)
      ↓
SecuRedact scan (reuse prepare/scan_residual)
      ↓
REDACT sensitive info
      ↓
Return sanitized content
```

Placement: add `securedact_read_file` to `server.py` `create_server` (additive,
like `create_safe_copy`). It reuses `SecuredactEngine.prepare` /
`privacy_engine.scan_residual` and the existing `DEFAULT_MAX_TEXT_CHARS` /
`SECUREDACT_MAX_TEXT_CHARS` controls.

Considerations:

- **Text types:** source, JSON, YAML, CSV, Markdown, logs, config — scan in full.
- **Binary / PDFs / docs:** MVP scans text extracts only; binary/PDF deferred
  (FW-013). Block-or-skip non-text by MIME/signature, never silently pass through
  sensitive plaintext inside a mislabeled file.
- **Very large files:** enforce a configurable max scan size; fail closed or skip
  with a `WARN` rather than scanning unbounded.
- **Symlinks / traversal / UNC / alt notation / case / renamed `.env`:** resolve
  canonical absolute path; reject escape outside allowed roots; compare resolved
  name+extension against policy (case-insensitive); treat renamed secret files
  via content scan (secrets detected regardless of filename).
- **Base64-encoded secrets:** the credentials detector's normalization path
  already handles encoded variants (`credentials_detector.detect` +
  `normalize_for_detection`); reuse it. Do not over-engineer speculative bypass
  detection beyond what the detector already covers.

---

## 6. Tool-response protection

Strategies compared:

1. **Explicit SecuRedact safe tools** (e.g. `securedact_read_file`) — realistic,
   MVP-friendly, fully under our control. **Recommended primary mechanism.**
2. **MCP proxy/gateway** — would transparently wrap other MCP servers, but is a
   large new component, not present in the repo, and many hosts have no gateway
   concept. **Later / advanced (FW-021, speculative).**
3. **Wrappers around other MCP servers** — per-server safe adapters; realistic but
   high maintenance. **Later (FW-022).**
4. **Host-specific hooks (PostToolUse)** — already partially used; extend to
   sanitize results of protected tools where the host allows result rewriting
   (Gemini yes; Claude limited). **Primary near-term (FW-020).**
5. **Combinations** — explicit tools + hook input/output inspection is the
   pragmatic MVP; proxy/gateway is a future option.

Tradeoff: explicit tools are guaranteed and testable but require the agent to use
them; hooks cover more automatically but are host-dependent and limited by what
the host exposes (input vs. result rewriting).

---

## 7. Secret detection

Current: `CredentialsDetector` (`credentials_detector.py`) has strong **known-format**
rules and a `_plausible_generic_secret` entropy+class heuristic gating labelled
secrets. Gap: **no detector for unknown high-entropy secrets** presented without a
recognizable label/format.

Proposed dedicated secret capability (reuse, don't duplicate):

- **Combine:** regex/format rules (existing `RULES`) + entropy
  (`_entropy`) + known credential formats + contextual indicators
  (assignment/keyword near high-entropy token) + PEM/private-key markers
  (existing) + URI credential detection (existing `database_url_credentials`) +
  structured config parsing (dotenv/yaml/json key→value, existing patterns
  extended).
- **Confidence levels:** `high` (known format / labelled+entropy), `medium`
  (high-entropy value near credential-ish key), `low` (standalone high-entropy in
  a non-secret context).
- **Default actions:** `high` → `BLOCK`; `medium` → `BLOCK` or `REQUIRE_APPROVAL`;
  `low` → `WARN` (never auto-block a random UUID/hash/lockfile entry).
- **False positives:** a random high-entropy identifier (UUID, hash, package
  lockfile entry, public key, example/test credential, documentation) **must not**
  become a blocked credential without supporting context. Gate on key/label/format
  or on being inside a recognized secret container.

New `UNKNOWN_SECRET` detection should run as an *additional* conservative rule, not
replace the precise ones, to keep FP low.

---

## 8. Egress protection

Prevent `Sensitive read → external transmission`.

```text
READ_SENSITIVE  (file/tool returns secret/PII)
      ↓  (session taint, advanced)
NETWORK_WRITE   (HTTP/browser/email/upload/git/MCP-net tool)
      ↓
BLOCK / REQUIRE_APPROVAL
```

Enforcement reality:

- **Feasible MVP:** inspect *inputs* of network tools (HTTP request bodies, browser
  submit payloads, upload args, `git push` URLs, webhook targets) for secrets/PII
  using the same detectors, and `BLOCK`/`REDACT`/`REQUIRE_APPROVAL`. This reuses
  the existing tool-input inspection path (Claude `PreToolUse` /
  Gemini `BeforeTool`) extended to network-tool matchers (FW-030).
- **Later / advanced:** true cross-tool taint (READ_SENSITIVE → NETWORK_WRITE)
  requires session-scoped state associating extracted sensitive values with
  subsequent sends. Hard, speculative (FW-031).
- **Host-level only:** actual byte-level network interception requires OS
  sandboxing / egress firewall / container — outside SecuRedact's scope (Security
  Boundaries).

Network destinations: classify `network_destination` (internal vs. external,
allowlist) as a policy input; external send of high-sensitivity → `BLOCK`/
`REQUIRE_APPROVAL`.

---

## 9. Auditability

Privacy-preserving local-only security log. Event types: `FILE_BLOCKED`,
`SECRET_DETECTED`, `PII_REDACTED`, `TOOL_BLOCKED`, `EGRESS_BLOCKED`,
`APPROVAL_REQUESTED`, `POLICY_OVERRIDE`, plus existing hook receipts
(`write_hook_receipt` in `claude_runtime.py`).

Never log raw secrets/values. Store metadata only:

```json
{
  "event": "SECRET_DETECTED",
  "type": "api_key",
  "action": "BLOCK",
  "source": ".env",
  "secret_value": "<never stored>",
  "entity_span_length": 24,
  "policy": "strict_external_ai",
  "tool_name": "mcp__filesystem__read_file",
  "session_digest": "<hash>"
}
```

Reuse the existing `write_hook_receipt` pattern; add a structured audit sink,
opt-in and local-only, with rotation (FW-033/FW-044).

---

## 10. Developer usability

Fit the **existing** config system (`policies.py` + `policy_loader.py` +
`SECUREDACT_POLICY_DIR` + env overrides). Add a firewall subsection to policy
files rather than a parallel config:

```yaml
securedact:
  protection:
    pii: redact
    secrets: block
  filesystem:
    protect_sensitive_files: true
  network:
    protect_egress: true
```

Concretely: extend `Policy` with `firewall: FirewallPolicy | None`
(`policies.py`), load via `LocalPolicyLoader` (JSON/YAML already supported,
`policy_loader.py:118-119`), keep `SECUREDACT_*` env overrides where they map
cleanly. Sensible secure defaults: secrets `block`, PII `redact`, sensitive files
`block`, egress `require_approval` for external high-sensitivity.

---

## 11. Compatibility

| Host | Today | Firewall path |
| --- | --- | --- |
| Claude Code | Enforced hook (`PreToolUse`/`UserPromptSubmit`), matcher `mcp__*|WebFetch|WebSearch` | Extend matcher + add `PostToolUse` result inspection; best host fit |
| Gemini CLI | Enforced hook (`BeforeAgent`/`BeforeModel`/`BeforeTool`) | Already rewrites model text; extend `BeforeTool` matchers + result path |
| Codex | MCP-only (`config.toml`) | Add enforced wrapper config later (FW-040); MVP = explicit tools only |
| Cursor / Windsurf | MCP-only (`mcp.json`/`mcp_config.json`) | Same as Codex |
| Generic MCP clients | MCP tools | Explicit `securedact_read_file` etc.; no transparent interception |
| Local / IDE agents | depends on host | Host hook or explicit tools |

Prefer standards-based MCP functionality. Host-specific hook integration is
**required** only where we want automatic (not opt-in) enforcement — Claude/Gemini
today; others need new adapters (FW-040).

---

## 12. Backward compatibility

- Existing MCP tools (`prepare_for_external_ai`, etc.) unchanged; `securedact_read_file`
  is additive.
- Existing `Policy` content actions unchanged; firewall layer is additive
  (`firewall: None` ⇒ legacy behavior).
- New `PrivacyAction` values (`WARN`, `REQUIRE_APPROVAL`) are additive enum members;
  legacy policies never emit them.
- CLI `install`/`setup`/`models`/`diagnostics` unchanged; setup gains firewall
  prompts later (FW-003) but non-interactively no-ops.
- Integrations: add hook matchers/PostToolUse; do not remove MCP configs.
- Tests: add a backward-compat suite asserting legacy policy + tool behavior
  (FW-042). Breaking changes require explicit justification.

---

## 13. Performance

- **Max scan size** per file/tool result (reuse `SECUREDACT_MAX_TEXT_CHARS`,
  add firewall-specific cap).
- **Fast secret detection before expensive ML:** run `CredentialsDetector` +
  regex first; only invoke contextual/Flair when needed (engine already orders
  deterministic detectors; preserve that).
- **Caching:** reuse the daemon's approved-text digest cache
  (`claude_runtime._approved_text_digests`) for tool-result repetition.
- **File-type filtering:** skip binary/non-text early.
- **Configurable protection levels:** `off` / `secrets_only` / `full` to keep
  normal coding-agent usage fast.
- Security must not make coding agents painfully slow; hook timeouts already
  exist (`provider_hook` 30s, `gemini_hook` 2–18s) and fail closed.

---

## 14. Testing strategy

Unit + integration for:

**Files**
- `.env` → `BLOCK`
- SSH private key (`id_rsa`) → `BLOCK`
- Normal source code → `ALLOW`
- JSON with credentials → `BLOCK`/`REDACT`
- Document with PII → `REDACT`
- Harmless high-entropy IDs (UUID/hash) → `ALLOW` (no false block)

**Attacks**
- Path traversal (`../../.env`) → blocked/normalized
- Symlink bypass → resolved & blocked
- Renamed secret file (`config.bak` containing secrets) → caught by content scan
- Base64-encoded credential → detected via normalization
- Prompt-injection attempting to extract a secret → blocked/fail-closed
- Tool response containing credentials → sanitized where host allows
- read → network exfiltration attempt → `BLOCK`/`REQUIRE_APPROVAL` (input-based)

**False positives**
- UUIDs, hashes, package lockfiles, test fixtures, public keys, example
  credentials, documentation → not blocked.

Reuse existing `tests/privacy` (property/fuzz), `tests/unit`,
`tests/integration` (stdio subprocess), and `securedact_eval` corpus patterns.

---

## 15. Roadmap structure

IDs use the `FW-###` namespace (consistent numbered style with the existing
`ROAD-###` security-quality roadmap). Phases follow repository evidence: the
enforcement spine exists (P0 extends it), then file/secret protection (P1), then
tool-response firewall (P2), then egress/chain (P3), then ecosystem/hardening
(P4).

### P0 — Security foundation

#### FW-001 — Firewall decision/enforcement foundation
- **priority:** P0
- **status:** implemented
- **problem:** `Policy` (`policies.py`) is content-only; no path/tool/op/
  network inputs and no interactive enforcement outcome.
- **security impact:** Without context inputs, file/tool/egress policy is
  impossible; without a provider-neutral enforcement outcome, file/tool decisions
  cannot be turned into host permission results.
- **current repository state:** `FirewallPolicy`, `FirewallRule`, `ToolContext`,
  `ToolOperation`, `classify_tool`, `evaluate_firewall`, and `FirewallDecision`
  exist in `src/securedact_core/firewall.py`; `Policy.firewall` (optional
  `FirewallPolicy`) is wired in `policies.py`; `policy_loader._validate_invariants`
  rejects firewall policies that would `ALLOW` a protected path
  (`INVARIANT_VIOLATION`). Production hooks `provider_hook.handle_event`
  (Claude `PreToolUse`) and `gemini_hook.handle_event` (`BeforeTool`) build a
  `ToolContext`, evaluate the firewall, and map the `FirewallDecision` to a host
  outcome via the centralized `firewall_decision_outcome` in `adapter.py`.
- **design decision — `WARN` / `REQUIRE_APPROVAL` are NOT added to
  `PrivacyAction`:** interaction requirements are carried on `FirewallDecision`
  (`requires_approval`, `warning`, `reason`) rather than forced into the data
  action enum. `firewall_decision_outcome` maps `BLOCK` → `BLOCKED`,
  `requires_approval`/`REVIEW` → `REVIEW_REQUIRED` (host-deny the user can
  override), else `ALLOW`. `PrivacyAction` stays `ALLOW/REVIEW/REDACT/BLOCK`; no
  enum members were added. This is the smallest auditable change and preserves
  backward compatibility.
- **unknown-tool handling:** classification that yields `UNKNOWN` no longer skips
  enforcement. Both hooks route `UNKNOWN` through content inspection (fail-closed
  when the runtime is unavailable) so an unrecognized tool is never silently
  allowed merely because the classifier did not recognize the operation.
- **files/modules:** `src/securedact_core/firewall.py`,
  `src/securedact_core/policies.py`, `src/securedact_core/policy_loader.py`,
  `src/securedact_core/__init__.py`, `src/securedact_enforced/adapter.py`,
  `src/securedact_enforced/provider_hook.py`, `src/securedact_enforced/gemini_hook.py`.
- **dependencies:** none
- **tests required:** policy unit tests for context rules + invariants
  (`test_firewall_policy.py`); production-path tests in `test_enforced_hooks.py`
  and `test_gemini_enforced.py` (block `.env`/`.ssh`/`credentials.json`, allow
  `src/app.py`, disable preserves legacy, unknown-tool inspected,
  `requires_approval` → deny).
- **acceptance criteria:** A firewall rule keyed on `path`/`.env` blocks at the
  tool-call boundary before execution; `requires_approval` yields a host deny;
  blocked/allowed outcomes demonstrated through the real provider event handlers,
  not only helper functions; legacy policies and disabled-firewall behavior
  unchanged. All met.
- **complexity:** L
- **MVP required:** yes
- **speculative:** no

#### FW-002 — Generic / unknown-secret detector
- **priority:** P0
- **status:** implemented
- **problem:** No detection for high-entropy secrets lacking a known format/label.
- **security impact:** Unknown secrets (e.g. unlabeled tokens) can leak.
- **current repository state (pre-implementation):** `UNKNOWN_SECRET` only used
  by DB-URL rule; `_plausible_generic_secret` gates labelled secrets only.
- **implementation:** Added a conservative fallback rule in
  `src/securedact_core/detectors/credentials_detector.py` (`_SECRET_ASSIGNMENT`
  regex + `_detect_unknown_secrets`, emitted as `UNKNOWN_SECRET`,
  `rule="unknown_secret"`, `precedence=100`). It runs **after** the precise
  `RULES`; any span already covered by a precise credential rule is skipped so
  known formats are never downgraded (detection-ordering invariant from §12).
  `UNKNOWN_SECRET` was already wired into `CategoryGroup.CREDENTIALS`
  (`taxonomy.py`) with default action `BLOCK`, so policy mapping needed no change.
- **detection strategy (signals combined — never entropy alone):**
  1. **Context label** — a credential-ish assignment key (e.g. `secret`,
     `access_key`, `auth_token`, `private_token`, `credential`, `api_secret`,
     `internal_api_secret`, `internal_token`, `token`, `encryption_key`,
     `signing_key`, `secret_token`, `refresh_token`, `x_api_key`,
     `server/db/app_secret`). A single reusable keyword set is used; labels
     already covered by precise rules (`api_key`, `api_token`, `secret_key`,
     `access_token`, `client_secret`, `password`, …) are intentionally excluded
     to avoid duplication/downgrade.
  2. **Assignment/container context** — `KEY=value`, `KEY: value`, `"KEY": "value"`
     (JSON), `KEY: value` (YAML/TOML), `KEY = "value"` (dotenv/INI/source). A
     leading `\b`-style `(?<![\w])` boundary keeps `mytoken`/`csrftoken` out.
  3. **Plausible-secret value gate** — reuses `_plausible_generic_secret`
     (≥3 character classes among lower/upper/digit/`._~+/-`, entropy ≥ 3.25) plus
     a minimum length of 16 (`_MIN_GENERIC_SECRET_LENGTH`, mirrored by the value
     regex). This is what excludes UUIDs, hex/SHA hashes, and short identifiers.
  4. **Confidence** — `0.92` for strong labels (`_STRONG_SECRET_LABELS`),
     `0.72` for weaker/indirect labels. Both clear the default policy threshold
     (0.30) and strict (0.15); `low`-confidence inputs (no label, or value fails
     the gate) are **not emitted at all** — they stay `ALLOW`.
- **dependencies:** none
- **tests required:** high-entropy labelled→detect; UUID/hash/lockfile→no block;
  base64 secret→detect.
- **tests added:** `tests/unit/test_credentials_detector.py`
  (`test_unknown_secret_context_detected`, `test_benign_high_entropy_not_flagged_as_unknown_secret`,
  `test_placeholder_values_not_flagged`, `test_lockfile_style_entries_not_flagged`,
  `test_mixed_content_only_secret_flagged`, `test_unknown_secret_blocks_through_engine_pipeline`,
  `test_known_labelled_secret_not_downgraded`) and integration in
  `tests/unit/test_safe_read_file.py`
  (`test_safe_read_catches_unknown_secret_via_content_scan`,
  `test_safe_read_allows_benign_config`).
- **acceptance criteria:** Unknown secret with supporting context detected at
  `high`/`medium`; benign high-entropy identifiers stay `ALLOW`. **Met.**
- **complexity:** M
- **MVP required:** yes
- **speculative:** no

#### FW-003 — Firewall configuration schema (reuse policy files + env)
- **priority:** P0
- **status:** implemented
- **problem:** No firewall config namespace; setup cannot express
  `pii: redact` / `secrets: block` / `filesystem` / `network`.
- **security impact:** Users cannot enable/configure the firewall coherently.
- **current repository state:** `Policy.firewall` (optional `FirewallPolicy`) is
  loaded from the existing JSON/YAML policy mechanism (`policy_loader.py`);
  `LocalPolicyLoader._validate_invariants` runs `validate_firewall_policy` and
  raises `INVARIANT_VIOLATION` on any firewall rule that would `ALLOW` a
  protected path. `load_firewall_policy_from_environment()` returns the first
  loaded policy's `firewall`, falling back to the single authoritative built-in
  `default_firewall_policy()` (`firewall.py`). `SECUREDACT_FIREWALL_ENABLED=0`
  disables the firewall (returns `None`); any other value keeps the default-on
  behavior, which a policy file can refine.
- **precedence (verified):** built-in `default_firewall_policy()` → policy file
  `firewall` section → `SECUREDACT_FIREWALL_ENABLED=0` explicit disable override.
  The firewall is on by default wherever the enforced integration is installed; a
  user policy file can extend/replace the rule set but cannot weaken the
  mandatory protected-path invariants.
- **no parallel config system:** the firewall reuses `Policy` + the existing
  `SECUREDACT_POLICY_DIR` loader and env overrides; there is exactly one
  authoritative default (`default_firewall_policy`), not duplicated per component.
- **setup/CLI:** interactive firewall setup prompts are intentionally deferred;
  noninteractive `cli.setup` is unchanged (no-op for the firewall). Configuration
  is fully available via built-in defaults, policy files, and the env switch.
- **files/modules:** `src/securedact_core/policies.py`,
  `src/securedact_core/policy_loader.py`, `src/securedact_core/firewall.py`,
  `src/securedact_mcp/cli.py`.
- **dependencies:** FW-001
- **tests required:** load firewall policy from JSON (allow + reject weakening);
  env disable; default-when-no-config (`test_firewall_policy.py`).
- **acceptance criteria:** A policy file containing a `firewall` section loads and
  is used by the hooks; a policy that would `ALLOW` a protected path fails with
  `INVARIANT_VIOLATION`; defaults are secure and on by default; legacy behavior
  preserved when disabled. All met.
- **complexity:** M
- **MVP required:** yes
- **speculative:** no

#### FW-004 — Enforced fail-closed contract & non-goals documentation
- **priority:** P0
- **problem:** Enforcement depends on host hook behavior; limits must be explicit.
- **security impact:** Prevents over-claiming protection.
- **current repository state:** `provider_hook`/`gemini_hook` fail closed; no
  consolidated contract.
- **proposed implementation:** Document enforcement contract + non-goals
  (Security Boundaries); add invariant that any unknown/missing hook event fails
  closed (already true in `provider_hook.handle_event`).
- **files/modules:** `docs/`, `provider_hook.py`, `gemini_hook.py`.
- **dependencies:** none
- **tests required:** hook unit tests asserting fail-closed on malformed/unknown.
- **acceptance criteria:** Docs present; tests cover fail-closed paths.
- **complexity:** S
- **MVP required:** yes
- **speculative:** no

### P1 — Sensitive file + secret protection

#### FW-010 — Sensitive file path/extension policy
- **priority:** P1
- **problem:** No path/filename/extension based blocking.
- **security impact:** Prohibited files can be read/processed.
- **current repository state:** MISSING (no file policy).
- **proposed implementation:** Firewall context rules over `path`/`filename`/
  `extension` (`.env`, `.ssh/*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`,
  `credentials.json`, `service-account*.json`); precise, not broad-dir blanket.
- **files/modules:** `policies.py` (FirewallPolicy), `enforced/*` hook matchers,
  `server.py` (read tool).
- **dependencies:** FW-001
- **tests required:** `.env` blocked; `src/app.py` allowed; `id_rsa` blocked.
- **acceptance criteria:** Prohibited paths blocked at tool-call boundary.
- **complexity:** M
- **MVP required:** yes
- **speculative:** no

#### FW-011 — `securedact_read_file` safe-read tool
- **priority:** P1
- **problem:** SecuRedact cannot read and sanitize a file for the agent.
- **security impact:** Agent must pipe raw file text through `prepare_for_external_ai`
  manually; easy to forget.
- **current repository state:** MISSING (no read capability).
- **proposed implementation:** Additive MCP tool in `server.py`: path policy →
  resolve → read (size limits) → `prepare`/`scan_residual` → return sanitized.
- **files/modules:** `src/securedact_mcp/server.py`, `src/securedact_core/engine.py`.
- **dependencies:** FW-001, FW-010
- **tests required:** read+redact PII file; blocked `.env`; oversized → safe fail.
- **acceptance criteria:** Returns sanitized content; blocks prohibited paths.
- **complexity:** L
- **MVP required:** yes
- **speculative:** no

#### FW-012 — Path traversal / symlink / UNC / case / rename defenses
- **priority:** P1
- **problem:** Bypass attempts against the read tool / path policy.
- **security impact:** Escaping allowed roots or hiding prohibited files.
- **current repository state:** MISSING for user files (`create_safe_copy` has
  basic resolve; not for reads).
- **proposed implementation:** Canonical absolute resolve; reject symlink/UNG
  escape outside roots; case-insensitive name+ext compare; content scan catches
  renamed secret files.
- **files/modules:** `server.py` (read tool), `policies.py`.
- **dependencies:** FW-011
- **tests required:** `../../.env`, symlink to secret, `SECRET.BAK`, UNC path.
- **acceptance criteria:** All bypass attempts blocked/normalized; content still
  scanned.
- **complexity:** M
- **MVP required:** yes
- **speculative:** no

#### FW-013 — File content-type / size / binary handling
- **priority:** P1
- **problem:** Binary/PDF/very-large files need defined behavior.
- **security impact:** Scanning unbounded or mis-typed files risks FP/slowness or
  missed plaintext.
- **current repository state:** MISSING.
- **proposed implementation:** MIME/signature sniff; skip/block binary; size cap;
  text extracts only for MVP; PDF/doc deferred.
- **files/modules:** `server.py`, `detectors/*`.
- **dependencies:** FW-011
- **tests required:** large file safe-fail; binary skipped; csv/json scanned.
- **acceptance criteria:** Defined, safe behavior for each class.
- **complexity:** M
- **MVP required:** partial (text focus; binary deferred)
- **speculative:** no

#### FW-014 — Known-secret hardening + false-positive tuning
- **priority:** P1
- **status:** implemented
- **problem:** Lockfiles, public keys, example creds, docs must not false-block.
- **security impact:** Over-blocking harms usability and erodes trust.
- **current repository state (pre-implementation):** PARTIAL (good precise
  rules; FP tuning not formalized for the new generic detector).
- **implementation:** FP protection is built into the FW-002 generic detector
  (`credentials_detector.py`) rather than via broad path/name allowlists:
  - **Class-diversity gate** — `_plausible_generic_secret` requires ≥3 of
    {lower, upper, digit, `._~+/-`}. Pure-hex UUIDs/SHA/git-SHAs (≤2 classes)
    are excluded structurally, not by listing paths.
  - **Known-benign guard** (`_is_known_benign`) — skips values starting with
    `ssh-`/`pk.`/`-----BEGIN` (public/age/PEM markers) and any ≥32-char hex or
    RFC-4122 UUID; public keys are therefore never treated as the generic
    secret, while existing precise `private_key_block` (PRIVATE_KEY) detection is
    untouched.
  - **Placeholder guard** (`_is_placeholder`) — suppresses clearly synthetic
    values (`your-api-key-here`, `YOUR_TOKEN_HERE`, `example-secret`, `changeme`,
    `replace-me`, `xxxxxxxx`, …). Only obviously-fake values are suppressed;
    realistic secrets copied into docs are still detectable.
  - **No broad allowlists** — no `if "test" in path` or `if README` bypasses;
    suppression is purely structural/value-based.
  - **Precise rules preserved** — `private_key_block`, `github_token`,
    `aws_access_key_id`, `jwt`, DB-URL, bearer, session cookie, oauth, labelled
    secret, dotenv password keep their exact patterns/precedence and are never
    weakened or downgraded to `UNKNOWN_SECRET`.
- **dependencies:** FW-002
- **tests required:** package-lock entry allowed; real AWS key blocked; example
  credential in docs allowed.
- **tests added:** `tests/unit/test_credentials_detector.py`
  (`test_benign_high_entropy_not_flagged_as_unknown_secret`,
  `test_placeholder_values_not_flagged`, `test_lockfile_style_entries_not_flagged`,
  `test_mixed_content_only_secret_flagged`,
  `test_known_labelled_secret_not_downgraded`) plus the benign safe-read case in
  `tests/unit/test_safe_read_file.py`.
- **acceptance criteria:** No false block on benign high-entropy/known-benign.
  **Met** — UUID, SHA-256, git SHA, `sha512-` integrity, `API_KEY=your-api-key-here`,
  `TOKEN=<token>`, public SSH key, random `request_id`/`trace_id`, lockfile
  entries, and `DB_HOST` are all left unflagged by the generic rule, while the
  precise AWS key rule continues to block.
- **complexity:** M
- **MVP required:** yes
- **speculative:** no

### P2 — Tool-response privacy firewall

#### FW-020 — PostToolUse result sanitization (Claude + Gemini)
- **priority:** P2
- **problem:** Tool **results** (e.g. filesystem read output) are not sanitized.
- **security impact:** Sensitive content returned by tools reaches the agent.
- **current repository state:** PARTIAL (Gemini `BeforeModel` rewrites model text;
  Claude `PreToolUse` does not rewrite arbitrary tool results).
- **proposed implementation:** Add `PostToolUse` (Claude) / extend `BeforeTool`
  result path (Gemini) to run `inspect_payload` on results of protected tools;
  redact where host allows; block otherwise.
- **files/modules:** `provider_hook.py`, `gemini_hook.py`, `adapter.py`.
- **dependencies:** FW-001
- **tests required:** filesystem read result with secrets → redacted/blocked where
  host supports.
- **acceptance criteria:** Results sanitized for supported hosts; fail-closed
  otherwise.
- **complexity:** L
- **MVP required:** no
- **speculative:** no

#### FW-021 — Optional MCP proxy/gateway
- **priority:** P2
- **problem:** Transparent wrapping of other MCP servers would broaden coverage.
- **security impact:** Potential universal interception; large surface.
- **current repository state:** MISSING; no proxy infra.
- **proposed implementation:** Optional gateway that proxies other MCP servers and
  inspects input/output. **Defer**; host hooks + explicit tools cover MVP.
- **files/modules:** new `securedact_gateway` (later).
- **dependencies:** FW-020
- **tests required:** proxy sanitizes proxied server I/O.
- **acceptance criteria:** Defined only when scoped; not MVP.
- **complexity:** XL
- **MVP required:** no
- **speculative:** yes

#### FW-022 — Explicit safe wrappers around other MCP servers
- **priority:** P2
- **problem:** Non-SecuRedact MCP servers return unsanitized data.
- **security impact:** Leakage from those servers.
- **current repository state:** MISSING.
- **proposed implementation:** Per-server safe-adapter config that routes a
  server's output through `inspect_payload`.
- **files/modules:** `enforced/*`, config.
- **dependencies:** FW-020
- **tests required:** wrapped server output sanitized.
- **acceptance criteria:** Configurable wrappers sanitize.
- **complexity:** L
- **MVP required:** no
- **speculative:** no

#### FW-023 — Expand protected-tool matchers
- **priority:** P2
- **problem:** Filesystem/shell/db/browser tools not in hook matchers.
- **security impact:** Those tools' inputs bypass inspection.
- **current repository state:** PARTIAL (Claude `mcp__*|WebFetch|WebSearch`;
  Gemini `mcp_*|http|web|...`).
- **proposed implementation:** Extend matcher regexes in `integrations/*/hooks.json`
  and `is_protected_outbound_tool` / `_is_external_tool` to include filesystem,
  shell, db, browser tool namespaces; gate by policy.
- **files/modules:** `provider_hook.py`, `gemini_hook.py`, `integrations/*`.
- **dependencies:** FW-001, FW-010
- **tests required:** filesystem/shell tool input inspected.
- **acceptance criteria:** Protected matchers cover common exfil/secret tools.
- **complexity:** M
- **MVP required:** no
- **speculative:** no

### P3 — Egress and agent-chain protection

#### FW-030 — Egress detection for network tools
- **priority:** P3
- **status:** implemented
- **problem:** Secrets/PII sent via HTTP/browser/email/upload/git/webhook.
- **security impact:** Exfiltration of already-accessed sensitive data.
- **current repository state:** `src/securedact_core/firewall.py` classifies
  outbound network operations, extracts/normalizes a destination, and scopes it
  internal/external/unknown; `src/securedact_enforced/provider_hook.py`
  (`_inspect_egress`) and `src/securedact_enforced/gemini_hook.py`
  (`_apply_egress_inspection`) reuse the warmed privacy engine to scan the
  outbound payload and enforce `BLOCK`/`REDACT`/`REQUIRE_APPROVAL`.
- **implementation:**
  * **Classification:** `ToolOperation.NETWORK_WRITE` is reliably assigned to
    HTTP `POST`/`PUT`/`PATCH`, webhooks, browser submit/navigation with a
    payload, uploads, email/send/MCP network tools, and `git push`-like
    operations whose input exposes a `remote`/`repository` destination. A
    structured `method` field (e.g. `POST`) pins direction without guessing.
    `NETWORK_READ` (GET/search/`WebFetch`) is never treated as a write.
    Provider aliases live in the classification maps in `firewall.py`, not in
    policy code.
  * **Destination extraction:** `normalize_destination` returns a host-only
    value (strips path/query/fragment/credentials) for URLs, `git@host:repo`,
    `user@host` and bare hosts; `classify_destination_scope` returns
    `internal` (loopback, private ranges, `*.local`/`.internal`/`.corp`, or an
    explicit allowlist), `external`, or `unknown` (absent → never trusted).
  * **Outbound payload scanning:** the warmed engine recursively inspects
    strings, dict/list payloads, headers, body, `json`, and form fields; the
    destination key itself is excluded from content scanning (it is metadata)
    via `egress_scan_payload`. Known and `UNKNOWN_SECRET` credentials are
    blocked; PII/special-category data follows policy-driven `REDACT`.
  * **Internal vs external:** deterministic only — allowlisted domains/hosts,
    loopback/private; everything else is `external`/`unknown`. No network
    discovery.
  * **Fail-closed:** oversize (`recursive_text_length` > `MAX_TOOL_RESULT_CHARS`)
    and scanner/client errors deny (Claude `permissionDecision: deny`; Gemini
    `decision: deny`) rather than allow. Clean, trivially-inspectable payloads
    are not blocked.
  * **No taint tracking:** only sensitive content present in the outbound tool
    input itself is protected (FW-031 remains separate).
  * **Unsupported shell-based exfiltration:** `Bash("curl ...")` is classified
    `SHELL_EXEC` and is not silently labeled a network egress; fragile shell
    parsing is intentionally avoided.
- **files/modules:** `src/securedact_core/firewall.py`,
  `src/securedact_enforced/provider_hook.py`,
  `src/securedact_enforced/gemini_hook.py`, `tests/unit/test_firewall_egress.py`.
- **dependencies:** FW-023
- **tests required:** HTTP POST with token → blocked; internal host allowed;
  GET/search not treated as write; oversize/scanner failure fail closed.
- **acceptance criteria:** Network sends of secrets/PII blocked/approved;
  external/unknown destinations not silently trusted.
- **complexity:** L
- **MVP required:** no
- **speculative:** no

#### FW-031 — Cross-tool taint tracking (READ_SENSITIVE → NETWORK_WRITE)
- **priority:** P3
- **problem:** No reasoning that a value read earlier is now being sent.
- **security impact:** Chained exfiltration undetected.
- **current repository state:** MISSING (per-event only).
- **proposed implementation:** Session-scoped taint store associating extracted
  sensitive spans with subsequent network ops; best-effort, conservative.
- **files/modules:** `enforced/*` session state.
- **dependencies:** FW-030
- **tests required:** read secret → network send flagged.
- **acceptance criteria:** Demonstrated chain detection; no false positives on
  unrelated flows.
- **complexity:** XL
- **MVP required:** no
- **speculative:** yes

#### FW-032 — Approval workflow / REQUIRE_APPROVAL
- **priority:** P3
- **status:** implemented
- **problem:** Ambiguous sensitive ops need human-in-the-loop, not hard block.
- **security impact:** Usability vs. safety balance.
- **current repository state:** `requires_approval=True` on `FirewallRule`
  (mapped to `EnforcementOutcome.REVIEW_REQUIRED`) and the egress policy flag
  `egress_external_require_approval` already exist; both route through the
  provider host primitives — no fake interactive approval protocol was invented.
- **implementation:**
  * **Claude (`PreToolUse`):** a `REVIEW_REQUIRED` decision is returned as
    `permissionDecision: deny` with a `permissionDecisionReason` (the user can
    then override/handle the tool call out-of-band). Documented exactly as
    deny-with-reason + user override.
  * **Gemini (`BeforeTool`):** a `REVIEW_REQUIRED` decision is returned as
    `decision: deny` with a `reason` (Gemini offers no richer handshake).
  * **Audit:** every approval-required egress decision emits an
    `APPROVAL_REQUIRED` metadata-only event (FW-033); a blocked egress also emits
    the first legitimate `EGRESS_BLOCKED` event.
  * **Egress upgrade:** when `egress_external_require_approval=True`, an external
    or unknown `NETWORK_WRITE` whose payload was merely redacted (PII) is
    upgraded to `REQUIRE_APPROVAL` instead of sending the redacted payload. It
    is opt-in (default off) so the default stays policy-driven by the content
    engine.
- **files/modules:** `src/securedact_core/firewall.py`, `adapter.py`,
  `src/securedact_enforced/provider_hook.py`,
  `src/securedact_enforced/gemini_hook.py`.
- **dependencies:** FW-001
- **tests required:** ambiguous op → approval requested; denied → blocked;
  `APPROVAL_REQUIRED` audit event emitted; no fake interactive protocol claimed.
- **acceptance criteria:** Approval path works on supported hosts (deny +
  user override), and is documented accurately.
- **complexity:** M
- **MVP required:** no
- **speculative:** no

#### FW-033 — Privacy-preserving audit log events
- **priority:** P3 (but MVP-required for accountability)
- **status:** implemented (FW-033 only; persistent logs remain FW-044)
- **problem:** No structured security audit of firewall actions.
- **security impact:** Incidents undetectable post-hoc; no accountability.
- **current repository state:** `src/securedact_core/audit.py` provides a small,
  centralized, metadata-only audit-event model (`AuditEvent`, `AuditEventType`,
  `emit_audit_event`). Event *generation* is always available; the default sink
  is a no-op (no persistent storage), and tests inject a capturing
  `AuditSinkCollector` via `capture_audit_events`. `AuditEvent` serialization
  (`to_safe_dict`) allowlists metadata keys, drops non-scalar values, and rejects
  raw-value key fragments, so a secret/PII value cannot be serialized by
  accident. Events are wired into `SecuredactEngine.read_file` (`FILE_BLOCKED`,
  `SECRET_DETECTED`, `PII_REDACTED`) and the Claude/Gemini enforced hooks
  (`TOOL_BLOCKED`, `APPROVAL_REQUIRED`). `EGRESS_BLOCKED` is now emitted by the
  FW-030 egress enforcement path (the first legitimate emitter); `POLICY_OVERRIDE`
  remains reserved for FW-044 and is not emitted here. Audit emission is wrapped
  so a failure can never turn a BLOCK into an ALLOW.
- **configuration:** security-event generation is always on; persistent local
  storage/rotation is a separate opt-in concern (FW-044) and is **not**
  implemented here. The default sink performs no disk/network writes.
- **files/modules:** `src/securedact_core/audit.py`, `src/securedact_core/api.py`
  (`read_file`), `src/securedact_enforced/provider_hook.py`,
  `src/securedact_enforced/gemini_hook.py`.
- **dependencies:** FW-001
- **tests required:** events emitted with metadata only; no secret value logged
  (see `tests/unit/test_audit_events.py`).
- **acceptance criteria:** Audit entries contain no raw sensitive content; all
  10 quality-gate conditions in the implementation brief are met.
- **complexity:** M
- **MVP required:** yes
- **speculative:** no

### P4 — Ecosystem integration and hardening

#### FW-040 — Codex / Cursor / Windsurf enforced hook adapters
- **priority:** P4
- **problem:** Those hosts are MCP-only today; no automatic enforcement.
- **security impact:** Agent can ignore SecuRedact there.
- **current repository state:** PARTIAL (MCP configs only).
- **proposed implementation:** Add enforced wrappers where hosts support hooks;
  otherwise document explicit-tool-only mode.
- **files/modules:** `integrations/codex`, `integrations/cursor`,
  `integrations/windsurf`, `enforced/*`.
- **estimated complexity:** L; **MVP required:** no; **speculative:** no

#### FW-041 — Performance guards (scan size, fast-secret-first, caching)
- **priority:** P4 (MVP-required for usability)
- **status:** implemented
- **problem:** Scanning every tool result can be slow.
- **security impact:** Slowness encourages disabling protection.
- **current repository state (pre-implementation):** PARTIAL (max text chars; approved-text digest cache in `claude_runtime`).
- **implementation:** Guards are *verified and consolidated*, not expanded into heavy
  architecture. The single source of truth `MAX_INSPECTION_TEXT_CHARS = 1_000_000`
  (`firewall.py`) is reused by the text APIs (`DEFAULT_MAX_TEXT_CHARS`) and the
  safe-read path (`DEFAULT_READ_MAX_BYTES`), replacing two parallel magic
  constants so the caps cannot drift. All scan paths are bounded:
  * MCP boundary `_validate_text` / `SECUREDACT_MAX_TEXT_CHARS` (clamped to the cap);
  * `RedactionRequest` pydantic `max_length` rejects oversize input **before** any
    detector runs;
  * safe-read checks byte size (`stat`) before reading content and sniffs NUL bytes
    for binary before the privacy engine;
  * the firewall evaluates the resolved path **before** content scanning, so a
    `Read(".env")` block never reaches Flair/detectors;
  * the daemon's approved-text digest cache (`_approved_text_digests`, sha256 only,
    never raw text) skips re-scanning identical approved content.
  Detector ordering is already cheap-first (`credentials` → `regex` →
  `contextual_rules`); it was preserved and covered by a regression test rather
  than rewritten. Audit emission is metadata-only with a no-op default sink and is
  fail-safe, so it adds negligible, isolated overhead.
- **measured baseline (deterministic stack only — no Flair; `scripts/benchmark_firewall.py`):**
  small clean ≈ 15 ms (0.9 KB), small sensitive ≈ 2 ms (0.2 KB), medium ≈ 95 ms
  (≈12 KB), near-limit ≈ 16 s (200 KB, heavy email repetition). The hard ceiling
  is the 1 MB cap; inputs above it are rejected before any detector runs.
- **known performance limitations:** the deterministic detector stack is the
  dominant cost and is super-linear on large, match-heavy text (a 200 KB
  email-heavy payload approaches the Gemini 18 s hook budget). This bounds the
  *cost* FW-020 must assume per tool result, but no detector optimization was
  performed (out of scope; semantics must not be weakened). The 1 MB cap is the
  only hard ceiling; hosts with tighter latency budgets should set
  `SECUREDACT_MAX_TEXT_CHARS` / `SECUREDACT_READ_MAX_BYTES` lower.
- **files/modules:** `src/securedact_core/firewall.py`, `src/securedact_core/api.py`,
  `src/securedact_core/safe_read.py`, `src/securedact_enforced/claude_runtime.py`,
  `tests/unit/test_firewall_performance.py`, `scripts/benchmark_firewall.py`.
- **dependencies:** none
- **tests required:** perf tests within budget; fast-secret-first ordering.
- **tests added:** `tests/unit/test_firewall_performance.py`
  (`test_detector_ordering_is_cheap_before_contextual`,
  `test_oversize_text_rejected_before_privacy_analysis`,
  `test_safe_read_byte_size_checked_before_content_scan`,
  `test_safe_read_binary_skips_privacy_engine`,
  `test_claude_blocked_path_does_not_invoke_content_inspection`,
  `test_gemini_blocked_path_does_not_invoke_content_inspection`,
  `test_approved_text_digest_reuse_avoids_rescan`,
  `test_audit_emission_is_isolated_and_cheap`).
- **acceptance criteria:** Normal usage within latency budget. **Met** — all size
  guards confirmed, blocked paths terminate before content scanning, binary/oversize
  paths avoid expensive processing, detector ordering verified, digest caching safe,
  and a reproducible baseline exists. No strict ms latency target was invented; the
  recorded baseline reflects the deterministic stack and is bounded by the 1 MB cap.
- **complexity:** M
- **MVP required:** yes
- **speculative:** no

#### FW-042 — Backward compatibility tests + deprecation policy
- **priority:** P4 (MVP-required)
- **status:** implemented
- **problem:** Additive changes can still regress legacy behavior.
- **security impact:** Users lose existing functionality unexpectedly.
- **current repository state (pre-implementation):** EXISTS (broad tests) but no
  firewall-specific BC suite.
- **implementation:** Added a dedicated regression contract
  `tests/unit/test_firewall_backward_compat.py` that consolidates the firewall's
  additivity guarantees and security invariants in one auditable place, on top of
  the existing feature suites. It proves:
  * **MCP contract preserved** — the original five tools keep their exact
    request/response behavior; `securedact_read_file` is additive; the registry
    contains exactly the six tools;
  * **legacy policy compatibility** — a policy file without a `firewall` section
    still loads and redacts; `default_firewall_policy` follows the documented
    block/allow contract; explicit `SECUREDACT_FIREWALL_ENABLED=0` disables the
    firewall (legacy host behavior) while the privacy engine itself stays on;
  * **entity/detector compatibility** — EMAIL/PHONE/IBAN/IPv4/BSN, known
    credentials, and `UNKNOWN_SECRET` are still detected by the unchanged
    deterministic stack; the `contextual_rules` detector remains wired;
  * **firewall security invariants** — `Read(".env")`/`Read("credentials.json")`/
    `Read("id_rsa")`/`Read(".ssh/id_rsa")` BLOCK, `Read("src/app.py")` ALLOW,
    UNKNOWN tools are content-inspected (never silently allowed), safe-read blocks
    protected/traversal/symlink paths and sanitizes PII / blocks unknown secrets,
    and an attempt to `ALLOW` a protected path raises `INVARIANT_VIOLATION`;
  * **audit no-leak** — security events never serialize raw secrets/PII;
  * **provider hook contracts** — Claude (`permissionDecision` allow/deny) and Gemini
    (`decision` allow/deny) keep their documented schema, including modified-input
    shape for sanitized nested payloads;
  * **firewall-disabled compatibility** — `SECUREDACT_FIREWALL_ENABLED=0` restores
    legacy host behavior but does not disable SecuRedact's privacy engine.
- **files/modules:** `tests/unit/test_firewall_backward_compat.py`.
- **dependencies:** none
- **tests required:** legacy tool/policy behavior unchanged.
- **tests added:** `tests/unit/test_firewall_backward_compat.py`
  (`test_exact_tool_registry_includes_additive_read_file`,
  `test_original_five_tools_keep_contract`,
  `test_securedact_read_file_blocks_protected_and_sanitizes_normal`,
  `test_legacy_policy_without_firewall_section_loads`,
  `test_firewall_defaults_follow_documented_contract`,
  `test_deterministic_detectors_still_find_core_entities`,
  `test_known_credential_and_unknown_secret_still_detected`,
  `test_contextual_detector_remains_wired_unchanged`,
  `test_claude_hook_blocks_protected_reads`,
  `test_claude_hook_allows_normal_read`,
  `test_claude_unknown_tool_is_inspected_not_silently_allowed`,
  `test_gemini_hook_blocks_protected_reads`,
  `test_gemini_hook_allows_normal_read`,
  `test_gemini_unknown_tool_is_inspected_not_silently_allowed`,
  `test_safe_read_blocks_protected_and_traversal_and_symlink`,
  `test_safe_read_sanitizes_normal_pii_and_blocks_unknown_secret`,
  `test_policy_allow_of_protected_path_is_rejected`,
  `test_policy_loaded_allow_of_protected_path_is_invariant_violation`,
  `test_audit_security_events_never_serialize_raw_secrets`,
  `test_firewall_disabled_keeps_legacy_host_behavior_but_privacy_still_works`).
- **acceptance criteria:** BC suite green on every firewall PR. **Met** — the suite
  is green and covers the contracts above; combined with `tests/unit` (803 passed),
  `tests/privacy` + `tests/evaluation` (69 passed), and `tests/integration` (8 passed).
- **deprecation policy:** No breaking change to the five original MCP tools or to
  `PrivacyAction` was made; the firewall is strictly additive. A policy that would
  `ALLOW` a protected path is rejected at load time (`INVARIANT_VIOLATION`). Any
  future deprecation requires explicit justification and a dedicated BC test.
- **complexity:** S
- **MVP required:** yes
- **speculative:** no
- **MVP required:** yes
- **speculative:** no

#### FW-043 — Prompt-injection detection heuristics
- **priority:** P4
- **problem:** Malicious instructions试图 harvest secrets.
- **security impact:** Indirect injection can coerce exfiltration.
- **current repository state:** MISSING.
- **proposed implementation:** Heuristics in prompt/text inspection (instructional
  patterns toward secret recovery); conservative, non-blocking `WARN`.
- **files/modules:** `enforced/*`, `detectors/*`.
- **dependencies:** FW-001
- **tests required:** injection attempt → WARN; benign → no flag.
- **acceptance criteria:** Detected without harming normal prompts.
- **complexity:** L
- **MVP required:** no
- **speculative:** yes

#### FW-044 — Local-only optional audit log storage + rotation
- **priority:** P4
- **problem:** Audit sink needs safe storage.
- **security impact:** Audit log itself can leak if mishandled.
- **current repository state:** MISSING (only stdout receipts).
- **proposed implementation:** Rotated, permission-restricted local log;
  opt-in; no raw values.
- **files/modules:** new `audit.py`.
- **dependencies:** FW-033
- **tests required:** rotation; permissions; no secret content.
- **acceptance criteria:** Safe local audit lifecycle.
- **complexity:** M
- **MVP required:** no
- **speculative:** no

---

## 16. MVP definition

**Smallest useful release legitimately called "SecuRedact Agent Privacy Firewall":**

### What the MVP protects
- Explicit SecuRedact tool usage remains (backward compatible).
- **Claude + Gemini enforced hooks** continue to sanitize prompts and outbound
  tool **inputs** (existing), extended by the firewall policy layer (FW-001).
- **Sensitive file path policy** blocks reads of `.env`, `.ssh/*`, `*.pem`,
  `*.key`, `*.p12`, `*.pfx`, `credentials.json`, `service-account*.json`
  (FW-010).
- **`securedact_read_file`** reads a file locally, applies path/symlink/traversal
  defenses, and returns **sanitized** content (FW-011, FW-012).
- **Generic/unknown secret detection** blocks unlabeled high-entropy secrets with
  supporting context, without false-blocking UUIDs/hashes (FW-002, FW-014).
- **Configurable firewall policy** via existing policy files + secure defaults
  (FW-003).
- **Privacy-preserving audit events** (FW-033).
- **Performance guards** so normal coding stays fast (FW-041), and **backward-
  compat** guarantees (FW-042).

### What the MVP does NOT protect
- **Tool *results* from non-protected tools are not sanitized** (no general
  PostToolUse rewriting in MVP; Gemini model-text only). A filesystem read of a
  non-prohibited-but-sensitive file returns raw content to the agent unless that
  host supports result rewriting.
- **Separate Filesystem MCP / shell / browser / database servers not matched by
  the hook matcher** bypass input inspection.
- **Any direct OS/shell access outside the MCP/hook layer** is invisible to
  SecuRedact.
- **Read→network exfiltration chains** are not detected (no taint tracking; FW-031
  deferred).
- **Codex / Cursor / Windsurf** get explicit tools only, no automatic enforced
  hook interception (FW-040 deferred).
- **Binary/PDF document internals** are not deep-scanned (FW-013 text-only MVP).

---

## 17. Security Boundaries and Non-Goals

SecuRedact **cannot** protect against:

- An agent with unrestricted OS access or shell commands that bypass the MCP/hook
  layer.
- Malicious or compromised software running outside SecuRedact.
- Direct filesystem access not routed through SecuRedact (separate Filesystem MCP
  server, OS APIs, other tools).
- Tool **results** the host does not let SecuRedact rewrite (most Claude tool
  results; arbitrary-tool result rewriting is host-limited).
- True byte-level network interception — that requires OS sandboxing, an egress
  firewall, or containerization, which are out of SecuRedact's scope.
- Transparent interception of *every* agent tool call on hosts without a hook/
  gateway mechanism.

SecuRedact is a **local, fail-closed, hook-and-tool-based privacy/DLP layer**, not
a network firewall or OS sandbox. It raises the cost and reduces the likelihood of
leakage; it does not provide a hard guarantee when the exfiltration path is
outside its enforced surface.

---

## 18. Final recommendation

1. **Recommended architecture:** Extend the existing `securedact_enforced` hook +
   daemon spine (`provider_hook.py`, `gemini_hook.py`, `claude_runtime.py`,
   `adapter.py`) with (a) an additive firewall policy layer on `Policy`
   (`FW-001`/`FW-003`), (b) an explicit `securedact_read_file` safe tool
   (`FW-011`/`FW-012`), (c) a generic secret detector (`FW-002`), (d) network-tool
   input inspection (`FW-023`/`FW-030`), and (e) privacy-preserving audit
   (`FW-033`). Prefer explicit tools + host hooks over a proxy/gateway.

2. **Recommended MVP:** FW-001, FW-002, FW-003, FW-004, FW-010, FW-011, FW-012,
   FW-013 (text), FW-014, FW-033, FW-041, FW-042.

3. **First 5 implementation tasks in exact order:**
   1. **FW-001** — extend policy engine (context inputs + `WARN`/`REQUIRE_APPROVAL`).
   2. **FW-003** — firewall config schema reusing policy files + env.
   3. **FW-002** — generic/unknown-secret detector (FP-safe).
   4. **FW-010** — sensitive file path/extension policy.
   5. **FW-011** — `securedact_read_file` safe-read tool (with FW-012 defenses
      landing alongside it).

4. **Major technical risks:** host hook capability variance (Claude vs Gemini vs
   others); performance of scanning every tool result; false positives from
   aggressive secret detection; complexity of result rewriting where hosts limit
   it.

5. **Major security risks:** over-claiming protection for tool *results* and
   out-of-band exfiltration; secret-detector false negatives on novel formats;
   policy misconfiguration weakening invariants (mitigated by
   `policy_loader._validate_invariants`).

6. **Functionality that should explicitly wait:** MCP proxy/gateway (FW-021),
   cross-tool taint tracking (FW-031), Codex/Cursor/Windsurf enforced hooks
   (FW-040), prompt-injection heuristics (FW-043), deep binary/PDF scanning
   (FW-013 full), local audit storage/rotation (FW-044). These are valuable but
   larger, host-dependent, or speculative; they should not block the MVP.

7. **Estimated path from current SecuRedact → Agent Privacy Firewall:** The
   current architecture **provides a realistic foundation**. The enforcement
   daemon, recursive payload inspection, fail-closed hooks, and rich
   detectors/PII/special-category coverage already exist (`securedact_enforced/*`,
   `detectors/*`, `taxonomy.SPECIAL_CATEGORY_TYPES`, `credentials_detector.RULES`).
   Substantial architectural change is **not** required; the work is largely
   *additive*: extend `Policy`, add one MCP tool, add a secret rule, broaden hook
   matchers, and add audit. The biggest gaps are the **missing file-read
   capability**, the **missing context/tool/network policy inputs**, and the
   **absence of result sanitization for arbitrary tools** — all addressable
   without re-architecting the core engine.

---

## Appendix — roadmap IDs created

`FW-001` … `FW-044` (P0: 001–004; P1: 010–014; P2: 020–023; P3: 030–033;
P4: 040–044).

## Reports

1. **File created/updated:** `docs/agent-privacy-firewall-roadmap.md`.
2. **Roadmap IDs created:** FW-001, FW-002, FW-003, FW-004, FW-010, FW-011,
   FW-012, FW-013, FW-014, FW-020, FW-021, FW-022, FW-023, FW-030, FW-031, FW-032,
   FW-033, FW-040, FW-041, FW-042, FW-043, FW-044.
3. **Proposed MVP scope:** explicit tools + Claude/Gemini enforced hooks extended
   by a firewall policy layer; sensitive-file path blocking; `securedact_read_file`
   with traversal/symlink defenses; generic secret detection; firewall config;
   audit events; performance + backward-compat guards. Does **not** sanitize
   arbitrary tool results, intercept out-of-band OS/shell access, detect
   read→network chains, or auto-enforce on Codex/Cursor/Windsurf.
4. **Five highest-priority items:** FW-001, FW-003, FW-002, FW-010, FW-011
   (with FW-012 alongside).
5. **Important security limitation discovered:** SecuRedact's enforcement is
   **hook/tool-input based, not a transparent proxy**. It can block a prohibited
   *read* (e.g. `.env`) at the tool-call boundary, but it **cannot sanitize the
   content returned by a tool** unless the host supports result rewriting (Gemini
   `BeforeModel` for model text only; Claude `PreToolUse` does not rewrite
   arbitrary tool results). Consequently, a filesystem read of a
   non-prohibited-but-sensitive file (e.g. `config.yaml` with credentials) is **not
   blocked by path and its returned content is not sanitized** in the MVP. Any
   separate Filesystem MCP / shell / browser / database server, or direct OS
   access, is outside SecuRedact's view unless matched by the hook matcher. This
   must be stated plainly in Security Boundaries and must not be over-claimed.
