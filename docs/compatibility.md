# Compatibility evidence

The table distinguishes protocol evidence from real-host testing. “Not tested”
means the repository makes no compatibility claim for that host build.

| Host | OS | Tested version | Server starts | Tools listed | High-level tool | Persistent instructions | Enforcement limitation | Test date |
|---|---|---|---|---|---|---|---|---|
| MCP Python client harness | Windows | MCP SDK resolved by `uv.lock` | Yes | Yes | Yes | N/A | Harness cannot prove host routing | 2026-08-06 |
| MCP Python client harness | Ubuntu | CI job prepared | CI evidence pending | CI evidence pending | CI evidence pending | N/A | Harness cannot prove host routing | Not yet verified |
| Codex | Not tested | Not tested | Not tested | Not tested | Not tested | Template provided | Host can bypass MCP | Not tested |
| Cursor | Not tested | Not tested | Not tested | Not tested | Not tested | Template provided | Host can bypass MCP | Not tested |
| Windsurf | Not tested | Not tested | Not tested | Not tested | Not tested | Template provided | Host can bypass MCP | Not tested |

Each integration package includes an absolute-path template, safe workflow,
synthetic request, expected minimal response, limitations, and troubleshooting.
Configuration does not guarantee every prompt is intercepted.
