# CI troubleshooting and GitHub Actions availability

The first step of every job emits `SECUREDACT_CI_STEPS_STARTED=1`. It contains no context or secrets.
Use it with the failure location, not as a success signal.

## Decision tree

1. **Is the startup marker absent and the log stops at “Prepare all required actions”, “Getting
   action download info”, or “Failed to resolve action download info”?** Repository scripts never
   started. A `503 Service Unavailable` or download-info timeout is normally a GitHub action-resolution
   infrastructure failure. Check [GitHub Status](https://www.githubstatus.com/), wait for recovery,
   and rerun the failed job or whole workflow. An in-step retry, `continue-on-error`, pytest retry,
   or dependency cache cannot catch this pre-step failure.
2. **Is the marker present and a package index, approved dataset, vulnerability database, or release
   call timed out or returned 429/5xx?** This is a dependency-network failure. The repository's retry
   helper uses at most three attempts, exponential backoff with jitter, per-attempt and overall
   timeouts, and preserves the final failure. It does not retry authentication, permissions, hash,
   licence, or test failures.
3. **Is the marker present and lint, typing, pytest, privacy evaluation, build, metadata, licence, or
   benchmark logic failed?** This is a repository/test failure. Reproduce it with the local command
   below and fix the cause; rerunning without a change is not a remedy.
4. **Does an action repository/SHA not exist, the organization block an action, a private action lack
   access, YAML fail to parse, or permissions fail?** This is configuration. Validate
   `.github/actions-lock.yml`, inspect repository/organization Actions policy, and make a reviewed
   settings or code change. Do not dismiss it as transient.

## Audit result and remaining settings checks

All direct action repositories were public, active, under the expected owner, and reachable at the
recorded commits on 2026-08-06. The reviewed releases are checkout v6.1.0, setup-python v6.3.0,
upload-artifact v7.0.1, download-artifact v8.0.1, CodeQL v4, Gitleaks v3.0.0, Sigstore Python v3.0.1,
and attest-build-provenance v4. Composite inspection also found and recorded upload-artifact v4.6.2,
softprops/action-gh-release v2.3.2, and actions/attest v4.1.1. The inventory records exact SHAs and
review notes. No repository rename, archive, privacy change, or owner change was found. No historical
run timestamp was available to correlate the previously observed 503/timeouts with a specific Status
incident, so those failures are classified as consistent with transient service failure—not proven
repository defects.

Repository code cannot determine whether organization Actions policy currently blocks a third-party
action. An administrator must confirm that `gitleaks/gitleaks-action`,
`sigstore/gh-action-sigstore-python`, and their recorded nested actions are permitted. A policy block
is configuration, not an outage.

## Safe reruns

Use the run page's **Re-run failed jobs** or **Re-run all jobs** control; no source-only commit is
needed. For additional GitHub runner diagnostics, select **Enable debug logging** when rerunning if
your repository permissions expose it. Keep the same trusted revision. There is no self-triggering or
automatic recursive rerun: confidently classifying a pre-step failure would require elevated log/API
processing, and the small convenience does not justify broader write permissions or loop risk.

An action-free diagnostic workflow was not added. A job with only `run:` steps could prove that a
runner started, but it could not securely validate private repository code without implementing
token-bearing checkout. That adds credential-handling and revision-selection risk while validating
less than the official checkout action.

## Workflow isolation, caching, and images

Essential pull-request CI resolves only official checkout and Python-setup actions. Security,
CodeQL, scheduled synthetic benchmark, pre-provisioned model benchmark, and release/signing actions
are separate failure domains. `ubuntu-24.04` and `windows-2025` reduce image drift; they do not prevent
GitHub service outages. Non-release concurrency cancels obsolete runs for the same ref. Release runs
are never cancelled in progress.

Ordinary dependency caches may reduce package-index traffic, but this repository does not add a cache
action to mandatory CI because that would add another pre-step action dependency. Never cache
restricted/customer/private-holdout data, mappings, credentials, or raw sensitive reports. GitHub
controls pinned action downloads; an ordinary dependency cache does not fix their resolution.

## Local parity and branch protection

After a locked sync, the primary network-free verification command is:

```powershell
uv run python scripts\verify.py
```

It validates repository/data/workflow boundaries, the smoke manifest, formatting, lint, types, tests,
privacy/evaluator behavior, smoke scoring, package build, metadata, and distribution contents. Local
success helps work continue during an outage but does not replace required GitHub checks.

If required checks are blocked by an Actions incident, confirm and record the incident, wait for
recovery, and rerun. Do not treat missing action downloads as passed tests or casually weaken branch
protection. Any emergency bypass must follow repository governance, be narrowly authorized, and be
recorded for later review.
