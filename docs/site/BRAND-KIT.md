<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch and Postern — Visual Standard

Version 1, approved September 8, 2026. This replaces the earlier white-and-emerald direction with the approved Postern Labs / Postern DEX design: graphite surfaces, warm white text, lime accents, clear sans-serif typography, and restrained geometry.

Bloch keeps its sphere symbol. Postern products use the arch from Postern DEX, available in `apps/site/assets/postern.svg`. Shared color and typography aliases live in `docs/site/assets/bloch-tokens.css`. Product stylesheets carry the same token block locally, so the wallet, explorer, and documentation do not acquire a cross-origin asset dependency.

The institutional implementation is in `apps/site/`; its `brand.html` is the public design reference. Existing locally bundled fonts can remain bundled. New font or asset CDN requests are unnecessary.

## 1. The mark

### Why this symbol needs no explanation

The protocol is named for **Felix Bloch**, and the symbol is the **Bloch
sphere** — the canonical geometric representation of a single qubit. Every
possible state of one qubit is a point on that sphere; the arrow from the
center is the state vector, one definite state picked out of all of them.

That is the whole argument. A post-quantum protocol carries the name of the
object physicists use to draw a qubit, so its mark *is* that object — circle,
equator, state vector. Nothing is invented, nothing is decorative, and anyone
who has opened a quantum-computing textbook recognizes it on sight. There is a
second, quieter resonance: the signatures that secure the chain (ML-DSA-65,
Falcon-1024) are **lattice-based**, and the hero rendering distributes its
points on the sphere as a lattice. The symbol says what the protocol is —
built for after the qubit — without a tagline.

This is what keeps the mark from being one more crypto logo. It is not an
abstract swoosh that a naming agency attached meaning to afterwards; the
meaning existed first, in physics, since 1946. Our only job is to draw it
cleanly and not embellish it.

### Construction

One geometry at every size, derived from the approved navigation mark:

- Outer circle of radius **R**, stroke weight ≈ R/7.
- Equator ellipse: `ry = 0.375 R`, at 55 % opacity — the sphere reads as a
  sphere, not a circle with a line through it.
- State vector from the center at **41.3° above horizontal**, length
  `0.785 R`, in **ink** (not accent) — the vector is the figure, the sphere is
  the ground.
- State dot: `r = 0.19 R`, filled with **accent**, far edge just inside the
  circle. The dot never touches or crosses the outline.
- At 128 px and above, the sphere gains its **vertical meridian**
  (`rx = 0.375 R`, 28 % opacity). Detail appears with size; the 24 px and
  16 px cuts drop it deliberately, and the 16 px cut enlarges the dot so the
  state survives a favicon.

The standalone SVGs carry a `prefers-color-scheme` block so they are correct
on light and dark browser chrome with no scripting. **When the mark is inlined
in a page, replace the literal colors with `var(--accent)` and `var(--ink)`**
so it follows the page theme, as the site preview does:

```html
<svg width="24" height="24" viewBox="0 0 24 24" aria-hidden="true">
  <circle cx="12" cy="12" r="10.2" fill="none" stroke="var(--accent)" stroke-width="1.5"/>
  <ellipse cx="12" cy="12" rx="10.2" ry="3.8" fill="none" stroke="var(--accent)" stroke-width="1.1" opacity="0.55"/>
  <line x1="12" y1="12" x2="18" y2="6.7" stroke="var(--ink)" stroke-width="1.6" stroke-linecap="round"/>
  <circle cx="18" cy="6.7" r="1.95" fill="var(--accent)"/>
</svg>
```

### The lockup

The wordmark is not a drawing; it is the display face doing its job:
**"Bloch Protocol"** set in the sans-serif display stack (Inter or the system UI face), weight 600,
letter-spacing −0.01em, at the same optical height as the mark, with a gap of
0.6× the type size between mark and name. Build it in HTML exactly as the
preview's `.logo` does — a lockup that is live text stays crisp at every
density, is selectable, and needs no font embedded in an SVG.

### Rules of use

- **Clear space:** keep a margin of at least **R/2** (one quarter of the
  symbol's width) free on all sides. Nothing enters it — not text, not
  borders, not the edge of a container.
- **Minimum sizes:** symbol alone, **16 px** (use the favicon cut below
  32 px, the 24 px cut from 24–96 px, the 128 px cut above). Lockup, **20 px**
  of symbol height — below that, drop the wordmark and use the symbol alone.
- **Backgrounds:** the mark sits on `--ground`, `--surface`, or `--surface-2`.
  On photography or any busy background, put it on a `--ground` chip with
  clear space around it.

**Never:**

- Never fill the sphere, add a gradient, glow, shadow, or 3-D bevel. The mark
  is line work; treat it like a figure in a paper.
- Never rotate the mark or change the vector's angle. The vector at 41.3° *is*
  the state; a different angle is a different qubit and a different logo.
- Never recolor outside the tokens. The only pairs are accent + ink (themed)
  and, where one color is forced (engraving, stamps), all-ink or all-ground.
- Never replace the "o" in "Bloch" with the sphere. The name is a physicist's
  name; it is not a canvas.
- Never redraw the equator as a straight line or a full-opacity stroke, and
  never let the dot cross the outline.
- Never animate the mark itself. The animated sphere on the site is an
  illustration (the hero canvas), not the logo.

---

## 2. Color

Dark is the initial theme. Products that already support a saved light or system preference retain that choice. The institutional site and historical pool use the dark presentation.

| Role | Dark | Light |
| --- | --- | --- |
| Page | `#101211` | `#F7FAF4` |
| Panel | `#161916` | `#FFFFFF` |
| Nested surface | `#1D221C` | `#EDF3E7` |
| Primary text | `#F2F0E7` | `#17200F` |
| Secondary text | `#A5ADA6` | `#526348` |
| Quiet data labels | `#93A08C` | `#596951` |
| Border | `#30382F` | `#D2DDC8` |
| Accent | `#C8FA72` | `#446719` |
| Text on accent | `#142009` | `#FFFFFF` |

Use `--on-accent` for text on a solid primary button. Existing product aliases such as `--brass`, `--ink`, and `--bg0` resolve to this palette. Preserve each component's variable type: explorer `--border` is a color; extension `--border` is a complete border shorthand.

Semantic statuses keep their established labels and shapes. General confirmation tokens are blue, attention is amber, and errors are red. Finality visualizations retain their existing state-to-color mappings through the shared aliases. Color alone must not communicate state; unavailable data must remain distinguishable from zero.

### Palette contrast

Computed using WCAG relative luminance. These ratios cover the listed flat color pairs, not an accessibility audit of every rendered product state.

| Pair | Dark | Light |
| --- | ---: | ---: |
| Primary text on page | 16.47:1 | 15.95:1 |
| Secondary text on panel | 7.70:1 | 6.49:1 |
| Quiet label on nested surface | 5.89:1 | 5.21:1 |
| Accent text on page | 15.56:1 | 6.23:1 |
| Primary button text on accent | 14.01:1 | 6.56:1 |
| Confirmation on its soft fill | 7.35:1 | 5.38:1 |
| Attention on its soft fill | 8.86:1 | 5.86:1 |
| Error on its soft fill | 7.13:1 | 6.20:1 |

## 3. Typography and spacing

```css
--font-ui: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
--font-display: var(--font-ui);
--font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
```

Use sans-serif for headings, navigation, and prose. Reserve monospace and tabular numerals for addresses, hashes, code, and aligned amounts. Headings use medium weight and restrained negative tracking. Default product prose is 16px; compact extension surfaces use 14px, with secondary labels at 12px. Information density can vary by product without changing the type roles.

Primary controls use a 6px radius; cards use 10–12px and a 1px border. Keep generous section spacing on institutional pages and tighter grouped data inside transactional products. On mobile, let tables scroll inside their own containers and keep essential navigation available.

## 4. Components

```css
.btn-primary {
  background: var(--accent);
  color: var(--on-accent);
  border: 1px solid transparent;
  border-radius: 6px;
  padding: 12px 20px;
  font: 500 14px var(--font-ui);
}
.card {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 24px;
}
:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 4px;
}
```

Preserve visible focus, existing keyboard behavior, saved theme preferences, and reduced-motion support. Keep live status labels tied to their source; historical pages must label their historical context. Product names, addresses, amounts, and signing prompts remain explicit.

## 5. Applying the standard

Update the local `POSTERN VISUAL STANDARD v1` token block from `assets/bloch-tokens.css`, then adjust the product-specific typography and spacing rules that follow it. The block intentionally follows legacy foundation rules so the selected palette wins for both themes. Avoid introducing a second competing palette in feature stylesheets.

The rollout covers `apps/site`, `apps/posternpool-site`, and `apps/explorer` in this repository, plus `bloch-explorer`, `postern-wallet` (web and extension), `blochprotocol-dev`, and `postern-dex/frontend`. Each repository keeps its existing runtime and release process.
