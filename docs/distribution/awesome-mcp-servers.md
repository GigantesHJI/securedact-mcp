# Awesome MCP Servers — Submission Package

The canonical Awesome MCP Servers list is
<https://github.com/punkpeye/awesome-mcp-servers>. (Several forks exist, e.g.
TensorBlock and mcpHQ; prefer the original `punkpeye` list for the highest
discovery value, and optionally also submit to the forks.)

Status: **NEEDS HUMAN ACTION** (open a PR). No repository file is required
beyond the existing `README.md`.

## Exact proposed list entry

Place under the **Security** category (confirm the current category name in the
target repo's `README.md`; `Security` exists in the canonical list). Maintain
alphabetical order within the section.

```markdown
- [SecuRedact](https://github.com/GigantesHJI/securedact-mcp) - Local-first privacy & security for AI agents; detects and protects PII, secrets, credentials, and sensitive files before they reach models, tools, or external destinations. Install: `pip install "securedact-mcp[ml]"`.
```

If the list uses a stricter table format in your chosen category, adapt to that
section's existing style and keep the same link + description.

## Contribution instructions (canonical punkpeye list)

1. Read `CONTRIBUTING.md` in `punkpeye/awesome-mcp-servers`.
2. Search the list for `securedact` / `GigantesHJI` to avoid duplicates.
3. Add the bullet above under the most relevant category
   (`Security` recommended; `Privacy` / `Data Protection` if present).
4. Keep alphabetical order within the section.
5. Open a pull request. The PR template asks you to confirm the format
   `[Project Name](link) - Description` and that the link works.

## PR checklist

- [ ] Entry follows the format `[SecuRedact](url) - Description`
- [ ] Placed in the correct category (`Security` or equivalent)
- [ ] Alphabetical order maintained
- [ ] Link verified working
- [ ] Project implements MCP (it does: `io.github.GigantesHJI/securedact-mcp`)
- [ ] CONTRIBUTING.md read

## Notes

- Do not fork-and-submit multiple competing lists simultaneously in a spammy
  way; submit to the canonical list first, then optionally the active forks.
- The description mirrors `docs/distribution/marketplace-metadata.md` so all
  listings stay consistent.
