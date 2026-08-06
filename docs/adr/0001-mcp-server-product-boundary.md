# ADR 0001: MCP server product boundary

- Status: Accepted
- Date: 2026-08-06

## Context

Securedact MCP provides local privacy workflow primitives through MCP and a
provider-neutral Python engine. An enforceable Securedact gateway for provider
egress is a separate product with a separate release and trust boundary.

MCP hosts decide whether to call tools and what content to send downstream. A
misconfigured or malicious host can bypass an MCP server, ignore a blocked result,
or send the original input separately. The server cannot prove universal prompt
interception.

## Decision

This repository remains only:

- a local `stdio` MCP server;
- a reusable, local, provider-neutral privacy engine;
- tested host configuration and safe-workflow guidance.

Provider clients, provider-specific request forwarding, OpenAI-compatible proxy
routes, reverse proxies, chatbot interfaces, and universal egress enforcement do
not belong here. The normal workflow uses `prepare_for_external_ai`, continues
only for `status == "ok"`, and passes only `sanitized_text` downstream.

## Consequences

The project can reduce accidental exposure and make a safe workflow easier, but
host behavior remains outside the server trust boundary. Integration tests prove
MCP protocol behavior, not host enforcement. The separate gateway may provide an
enforceable provider boundary, but this repository neither contains nor licenses
that product.
