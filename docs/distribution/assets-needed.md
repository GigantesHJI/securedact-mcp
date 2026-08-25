# Visual Asset Requirements

Audit of visual assets for marketplace / launch readiness. The repository
currently ships **no image assets** (only code, docs, and the live website
`securedact.com`, which is maintained separately).

## Already available

- **Website logo + hero imagery** — the live site at `securedact.com` already
  has a `SecuRedact_Logo.png`, hero illustrations, and feature icons. These live
  on the website, not in this repository. Reuse (with permission/licensing) is
  possible for consistent branding, but they are not committed here.
- **Mermaid diagrams** — `README.md` and `docs/architecture.md` contain
  text/ASCII and one Mermaid flowchart of the trust boundary.

## Missing (repository-side)

1. GitHub **social preview** image (1280×640).
2. A clean **square icon / app icon** (512×512, 1024×1024) for directory cards.
3. **AI Agent Privacy Firewall** architecture diagram (vector + PNG).
4. **Before/after terminal demo** screenshot or GIF.
5. **Product Hunt hero image** (typically 1200×630 or per PH specs).
6. A small **diagram of the local-first data flow** for README/marketplace.

## Recommended dimensions / use

| Asset | Dimensions | Use |
| --- | --- | --- |
| Social preview | 1280×640 | GitHub repo header, OpenGraph |
| Square icon | 512×512 / 1024×1024 | Directory cards, badges |
| Architecture diagram | 1600×900 (16:9) | README, docs, launch posts |
| Terminal demo | 1200×750 | README, mcp.so/marketplace, Show HN |
| Product Hunt hero | 1200×630 | Product Hunt gallery |
| Privacy firewall visual | 1600×900 | Docs, blog, launch |

## Suggested content

- **Logo/icon:** stylized shield + "SR" monogram; local-first motif (device/
  lock). Keep it readable at 32px.
- **Architecture diagram:** `User/Agent → SecuRedact (PII inspection, secret
  detection, file policy, tool policy, network/egress policy) → AI Model / Tool
  / File / Network`. A Mermaid source is provided in
  `docs/distribution/marketplace-metadata.md`.
- **Before/after terminal:** show a raw prompt containing a fake API key being
  returned as `[API_TOKEN_1]` (or blocked) by `prepare_for_external_ai`.

## Policy / process

- Do **not** generate binary graphics with repository tooling unless an explicit
  asset pipeline exists. These are recommendations for the maintainer/designer.
- Keep all demo screenshots free of real secrets, PII, or local paths.
- Prefer committing SVG (text, reviewable, no binary) where possible; rasterize
  for platforms that require PNG.
