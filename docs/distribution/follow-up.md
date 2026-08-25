# Distribution Follow-up (out of scope for this milestone)

Issues discovered during the distribution-readiness pass that are **outside** the
marketplace/packaging scope (per the mission's scope discipline). Listed here so
they are not lost; fixing them is a separate decision.

## 1. Stale SECURITY.md supported-versions text — FIXED

`SECURITY.md` previously claimed "No Securedact MCP server version has been
released … current `0.1.0` package is an unreleased alpha." That was inaccurate
(the project is at released `0.4.2` and `CHANGELOG.md` records public `0.1.1+`
releases). Updated in this milestone to reflect the real release status. This was
a trust-signal correction, not a behavior change.

## 2. Deterministic secret detection gaps

The deterministic stack does **not** flag some common secret shapes:

- AWS-style keys (`AKIA1234567890ABCD`) are not detected by the deterministic
  credentials detector.
- `OPENAI_API_KEY=sk-proj-...` style assignments are not detected (only certain
  `api_key=`/`client_secret=`/`password:` shapes are).

These are detection-quality issues, not marketplace blockers. If broader secret
coverage is desired, file a detector-improvement issue with synthetic
corpus cases. (Note: the contextual model may cover some of these; not verified
here.)

## 3. Person/entity (PER) names not caught deterministically

`prepare(..., policy="gdpr")` with `SECUREDACT_REQUIRE_FLAIR=0` redacts emails
and IBANs but leaves names like "Jane Example" unchanged. Names require the
contextual NER model. This is expected and documented, but marketplace copy
should avoid implying deterministic name detection. (Current copy already
attributes name detection to the optional contextual model.)

## 4. Commercial vs open-source scope clarity

The website (`securedact.com`) markets a separate commercial desktop application
and paid plans. The repository's open-source scope is the `securedact-mcp`
package, MCP server, and enforced hooks. Marketplace listings in this milestone
intentionally describe only the open-source repository. Consider adding a short
"open-source vs commercial" note in the README to prevent visitor confusion, if
desired.

## 5. README first paragraph + badges

The README was improved with a product tagline, a "Why SecuRedact" section, and
PyPI/Python/License badges. Confirm the PyPI badges resolve (the package must be
published at `pypi.org/project/securedact-mcp/` — the website claims it is, but
verify before relying on the badges).

## 6. MCP Registry ownership verification

Publishing to the official MCP Registry (`mcp-publisher publish`) requires GitHub
OAuth ownership of `GigantesHJI` and a PyPI package whose version matches
`server.json` (`0.4.2`). Verify both before the maintainer runs the publish
command.
