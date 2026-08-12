<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Protocol — site

Static site for the Bloch Protocol. **No framework, no build step, no external
dependency**: seven HTML pages, one shared stylesheet, one canvas script. The
simplicity is deliberate — the previous site was a single `index.html` with no
build, and that property is kept.

## Layout

```
apps/site/
  index.html        home (hero, status strip, commitments, migration summary)
  protocol.html     signatures, consensus today/next, Coherence
  migration.html    the halt at 50,000, the gap, Genesis-4, scam warnings
  supply.html       Tokenomics V4 — 21 B hard cap (unit under review)
  brand.html        palette, typography, the mark
  build.html        validating, delegation, honest status
  docs.html         documentation index — placeholders until founder review
  assets/site.css   one shared stylesheet (tokens + light/dark, three-state)
  assets/sphere.js  the Bloch-sphere canvas (index only; reduced-motion aware)
```

## Rules the pages follow

- Every number is a constant or measurement that exists in this repository, and
  each carries an HTML comment citing its source file and line next to it.
  Never restate a constant without the citation.
- Total supply is quoted as **21,000,000,000** (`tokenomics_v4.rs:33`) and
  marked **under review**. The redenomination is not final — do not put the
  redenominated figures on the site until the constants change.
- Genesis-3 terminal height is **50,000**
  (`docs/FLEET-BRIEF-CERTIK-2026-08-12.md:79`; the 80,000 constant in
  `crates/bloch-crypto/src/core/mod.rs:438` is superseded by that decision —
  update the site if/when the constant lands).
- Zero webfonts by URL, zero CDN, zero third-party scripts.
- Theme: complete light palette on `:root`; dark under
  `@media (prefers-color-scheme: dark)` guarded with
  `:root:not([data-theme="light"])`; repeated under `:root[data-theme="dark"]`.
  No color may be defined only inside a media query.
- Accessibility: skip link, visible focus, `aria-current` nav state, AA
  contrast, `prefers-reduced-motion` honored by the canvas (single static
  frame), tables wrapped in `overflow-x: auto`, `<html lang="en">`.

## Preview locally

Open `index.html` in a browser, or:

```sh
python3 -m http.server -d apps/site 8080
```

## Deploy

Publishing is the **founder's call** — nothing deploys automatically. The
project pattern is Cloudflare Pages via wrangler, from this directory:

```sh
cd apps/site
wrangler pages deploy . --project-name bloch-protocol-site --branch main
```

(Pick/confirm the Pages project name at deploy time; the command above follows
the same pattern used for the other Pages projects in this org.)
