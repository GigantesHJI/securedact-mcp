# Reddit — Launch Packages

> Research current subreddit rules before posting. Self-promotion is often
> restricted; prefer genuine participation and staggered posts. Do not cross-post
> spam. Each community below lists a caveat.

## General rules

- Read each subreddit's sidebar / wiki before posting.
- Use "self" text posts with substance, not bare links.
- Disclose that you are the author/maintainer (transparency).
- Lead with the technical problem and the solution; keep marketing minimal.
- Stagger posts over days/weeks; engage in comments.
- Never post real secrets, PII, or local paths (use synthetic examples).

## 1. r/ModelContextProtocol (MCP)

- **Why it fits:** directly on-topic for an MCP server.
- **Caveat:** check self-promotion/shill rules; some MCP communities welcome
  project shares in dedicated threads.
- **Suggested title:** "SecuRedact: a local-first privacy/firewall MCP server (PII, secrets, filesystem, egress)"
- **Angle:** what it does, the fail-closed design, and a request for which
  detectors/hosts matter. Link repo + `docs/distribution/security-demo.md`.

## 2. r/LocalLLaMA

- **Why it fits:** local-first, privacy, running models locally.
- **Caveat:** leans toward local models/weights; frame as local privacy
  infrastructure, not a hosted product.
- **Suggested title:** "Local-first privacy layer for agents: detecting PII/secrets before they leave your machine"
- **Angle:** emphasize no telemetry, local processing, and the deterministic
  detector stack.

## 3. r/AI_Agents

- **Why it fits:** audience runs agents on sensitive data.
- **Caveat:** can be promotion-heavy; contribute value first.
- **Suggested title:** "Putting a privacy firewall in front of AI agents (open-source, local-first)"
- **Angle:** threat scenario + architecture + runnable synthetic demo.

## 4. r/cybersecurity / r/netsec

- **Why it fits:** secret detection, data-loss prevention, egress control.
- **Caveat:** strict; often requires research/technical depth, no low-effort
  promo.
- **Suggested title:** "How we built a fail-closed local privacy layer for AI agents (detectors, policies, residual validation)"
- **Angle:** focus on the security design (fail-closed, minimal responses,
  firewall protected-path blocking), not the product.

## 5. r/privacy

- **Why it fits:** data protection, local-first.
- **Caveat:** skeptical of "privacy" claims; be precise, cite limitations.
- **Suggested title:** "Local-first approach to reducing PII/exposure in AI agent workflows"
- **Angle:** how local processing reduces exposure; explicitly state it is not a
  compliance guarantee.

## 6. r/selfhosted

- **Why it fits:** local-first, no external dependency.
- **Caveat:** wants self-hostable, reproducible setups.
- **Suggested title:** "Self-hosted, local-first privacy firewall for AI agents (MCP, Apache-2.0)"
- **Angle:** install steps, no cloud, runs on your machine.

## 7. r/Python

- **Why it fits:** implementation language, reusable engine.
- **Caveat:** allow sharing projects but keep it technical.
- **Suggested title:** "SecuRedact: a local-first privacy & security MCP server/engine in Python"
- **Angle:** architecture, detectors, policy engine; link to source.

## Recommendation

Start with r/ModelContextProtocol and r/LocalLLaMA (highest relevance), then
branch to r/AI_Agents and r/selfhosted. Save r/cybersecurity and r/privacy for
deeper technical/design posts after you have engaged in those communities.
