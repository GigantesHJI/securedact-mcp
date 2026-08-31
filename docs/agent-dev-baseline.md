# Managed Agent — DEV-ONLY Windows Service Baseline

> **NOT PRODUCTION SECURE.** This mode exists only to prove the basic Windows
> service lifecycle before the custom hardening is layered on. It must never be
> used outside local debugging. The hardened production implementation
> (`NT SERVICE\SecuredactAgent`, ProgramData/runtime ACLs, code-path integrity
> gate, vSA SID validation) is intact and unchanged; this is a separate, opt-in
> branch selected by an environment variable.

## What the baseline mode is

Setting `SECUREDACT_AGENT_SERVICE_DEV_BASELINE=1` before installing the service
temporarily bypasses **only** the custom Windows hardening that has been blocking
service startup:

- custom ProgramData (`C:\ProgramData\Securedact`) DACL replacement;
- runtime-tree ACL hardening (`runtime/` under ProgramData);
- the service code-path integrity gate (`validate_install_security`);
- vSA-specific ACL/SID validation (the `NT SERVICE\SecuredactAgent` SID lookup
  that fails with icacls 1332 / `ERROR_NONE_MAPPED` before SCM registration);
- other pre-start ACL assertions (`_require_runtime_launchable`,
  `_assert_not_user_writable`, `verify_runtime_tree_acl`).

It installs under the **simplest viable Windows service identity: `LocalSystem`**
(no per-account ACLs, no SID resolution). This is *not* least-privilege and is
*not* a supported production configuration — it is a known-working reference point
so the functional defects can be separated from the hardening defects.

## What is NEVER bypassed (application / protocol security)

Baseline mode does **not** weaken any of the following:

- no registration token / agent credential / OAuth token is ever placed in
  `argv`, the service environment, or logs;
- the registration token remains **one-time** (consumed in-memory only);
- no arbitrary job command is executed — jobs run through the normal local scan
  reducer/executor;
- Google content stays local (only derived safe results leave the host);
- the result allowlist / privacy reducer stays active;
- TLS and control-plane authentication stay required.

## Exact install / run command (real Windows host, elevated PowerShell)

```powershell
# From an elevated (Administrator) PowerShell prompt.
$env:SECUREDACT_AGENT_SERVICE_DEV_BASELINE = "1"

securedact-mcp agent service install `
  --token <srr_one_time_registration_token> `
  --control-plane-url https://your-securedact-control-plane
```

Notes:

- The flag must be exactly `"1"`. Any other value (`"true"`, `"yes"`, `"0"`,
  empty) leaves the hardened production path active — it cannot be flipped on by
  accident.
- `agent register --install-service ...` with the same env var also works.
- The service is installed `AUTO_START` under `LocalSystem`, so it starts on boot.
- Confirm the result includes `"dev_baseline": true` and a `"warning"` field; if
  those are absent the production path ran instead.

## How to verify

### 1. Service is RUNNING

```powershell
securedact-mcp agent service status
# -> { "installed": true, "state": "running", "account": "LocalSystem", "dev_baseline": true }
# or directly:
Get-Service SecuredactAgent
```

### 2. Dashboard shows Online with PowerShell closed

- Close the PowerShell window that ran the install (this proves no console/child
  keeps the agent alive — it is a real SCM service).
- In the SecuRedact dashboard, the agent must show **Online** (heartbeat
  succeeds). If you reopen an elevated PowerShell later, status still reports
  `running`.

### 3. Managed Google scan succeeds

- From the dashboard, queue a managed Google Workspace scan job for this agent.
- The agent must claim the job, run the local scan, and submit the **safe**
  (reduced/allowlisted) result. Verify the dashboard shows the scan completed and
  that no raw Google content left the host.

### 4. Service returns after reboot

```powershell
Restart-Computer
# After reboot:
Get-Service SecuredactAgent   # -> Status: Running
# Dashboard still shows Online; a new heartbeat succeeds.
```

If the service is `Running` after a reboot with no manual intervention, the
lifecycle is proven: setup → install → start → heartbeat → Online → claim job →
local scan → submit safe result → survive terminal close/reboot.

## Stop here

Once the baseline proves the lifecycle on the real Windows host, **stop**. Do not
re-add hardening automatically. Re-enable the production hardening by removing the
env var (and reinstalling) before any non-debug use:

```powershell
Remove-Item Env:SECUREDACT_AGENT_SERVICE_DEV_BASELINE
securedact-mcp agent service uninstall
# ...then run the normal production setup (securedact-mcp setup --agent)
```

## Automated guard tests

`tests/unit/test_agent_service_dev_baseline.py` proves:

- the flag is active **only** for the literal value `"1"` (parametrized over
  `"0"`, `"true"`, `"yes"`, `"on"`, `"2"`, `" 1"`, `"1 "`, empty, unset);
- in baseline mode no `icacls` hardening runs, the vSA SID is never resolved, and
  the service installs+starts under `LocalSystem`;
- with the flag **off**, the production path still hardens ACLs, still resolves
  the vSA SID, still uses the vSA identity, and still fails closed when no ACL
  provider is available;
- the one-time registration token is never leaked to argv/env/logs even in
  baseline mode.
