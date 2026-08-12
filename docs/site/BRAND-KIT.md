<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch Protocol — Brand Kit

This document is the visual contract for every Bloch Protocol surface: the site,
the explorer, the docs, release pages, slides. It follows the founder-approved
direction in the site preview and it is self-contained by rule: **no webfonts,
no external URLs, no third-party assets.** Every asset in this kit is an inline
SVG or a file in `docs/site/assets/`.

Files:

| File | What it is |
|---|---|
| `assets/bloch-favicon-16.svg` | Favicon cut, 16 px, theme-aware |
| `assets/bloch-mark-24.svg` | Navigation / lockup mark, 24 px |
| `assets/bloch-symbol-128.svg` | Large symbol, 128 px and up |
| `assets/bloch-tokens.css` | The design tokens, ready to include |

---

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
**"Bloch Protocol"** set in the display stack (Charter), weight 600,
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

White ground. One accent, spent deliberately. The neutrals carry a green bias
so they read as chosen next to the emerald, not as default grey. All values
live in `assets/bloch-tokens.css`.

### Core palette

| Token | Light | Dark | Role |
|---|---|---|---|
| `--ground` | `#FFFFFF` | `#0B1411` | Page |
| `--surface` | `#F1F4F3` | `#101D19` | Alternating sections, table heads, footer |
| `--surface-2` | `#E6ECEA` | `#172B24` | Nested surfaces, inactive pills |
| `--ink` | `#0D1B17` | `#EAF2EF` | Headings, primary text |
| `--ink-2` | `#33463F` | `#C3D3CD` | Secondary text, ledes |
| `--muted` | `#5D6F68` | `#8EA49C` | Captions, labels — the *smallest* ink allowed for text |
| `--line` | `#D5DEDB` | `#22352E` | Hairlines, borders |
| `--accent` | `#0E6E5A` | `#4FC0A4` | Links, primary actions, the mark, "live/now" |
| `--accent-soft` | `#E2F0EC` | `#102C25` | Accent card fill, accent pill fill |
| `--violet` | `#4B3FA8` | `#A89EF0` | The quantum/cryptography frame |
| `--violet-soft` | `#EBE9F7` | `#1B1930` | Violet card fill |

### Semantic states — and why success is not green

The accent **is** an emerald. If semantic success were also green, a success
pill would be indistinguishable from brand-accented UI — a "confirmed" badge
and a primary button would claim the same color for different meanings. So the
states deliberately avoid the accent's hue:

| Token | Light | Dark | Role |
|---|---|---|---|
| `--ok` | `#1D5FAE` | `#82B4EE` | Confirmed, finalized, verified |
| `--ok-soft` | `#E3EDF9` | `#132238` | Fill behind ok |
| `--signal` | `#B4630F` | `#E0A05C` | Attention — **large text and graphics only** in light |
| `--signal-text` | `#8A4A06` | `#E0A05C` | Attention at body/small size |
| `--signal-soft` | `#FBEEE0` | `#2A1F12` | Fill behind attention |
| `--err` | `#A8362B` | `#EC8B7D` | Failed, invalid, slashed |
| `--err-soft` | `#F9E6E3` | `#33150F` | Fill behind error |

The one carve-out: the protocol's *own present tense* — the `live` / `now`
pill on the timeline — uses the accent, on purpose. That is brand voice
("this is the chain, running"), not a semantic status. Transactional UI
(explorer states, form results, node health) uses `--ok` / `--signal` /
`--err` and never the accent.

Red–green colorblind readers get a second safeguard for free: the pair that
matters most, error vs. success, is red vs. **blue**, not red vs. green.

### Measured contrast (WCAG 2.x)

Every ratio below was computed from the hex values with the WCAG relative-
luminance formula (script: 24 pair checks per theme). AA thresholds: **4.5:1**
body text, **3:1** large text (≥ 24 px, or ≥ 18.66 px bold).

**Light theme**

| Pair | Ratio | AA |
|---|---:|---|
| ink `#0D1B17` on ground | **17.70** | pass |
| ink on surface / surface-2 | **16.00** / **14.80** | pass |
| ink on every soft fill (worst: err-soft) | ≥ **14.72** | pass |
| ink-2 `#33463F` on ground | **10.05** | pass |
| ink-2 on every soft fill (worst: err-soft) | ≥ **8.36** | pass |
| muted `#5D6F68` on ground / surface | **5.33** / **4.82** | pass |
| accent `#0E6E5A` on ground / surface | **6.18** / **5.59** | pass |
| ground on accent (primary button text) | **6.18** | pass |
| accent on accent-soft (pill) | **5.27** | pass |
| violet `#4B3FA8` on ground / violet-soft | **8.15** / **6.81** | pass |
| ok `#1D5FAE` on ground / ok-soft | **6.36** / **5.38** | pass |
| err `#A8362B` on ground / err-soft | **6.51** / **5.41** | pass |
| ground on err (solid pill) | **6.51** | pass |
| signal `#B4630F` on ground | **4.44** | **fails 4.5** — passes 3:1, so **large text only** |
| signal-text `#8A4A06` on ground / signal-soft | **6.86** / **6.01** | pass |

The one honest failure is the reason `--signal-text` exists: `#B4630F` on
white measures **4.44:1**, just under the 4.5:1 body-text bar. At body and
label sizes (including the mono uppercase banner label), use `--signal-text`.
`--signal` remains correct for large numerals, bars, and icons.

**Dark theme**

| Pair | Ratio | AA |
|---|---:|---|
| ink `#EAF2EF` on ground / surface / surface-2 | **16.43** / **15.22** / **13.11** | pass |
| ink on every soft fill (worst: accent-soft) | ≥ **13.09** | pass |
| ink-2 `#C3D3CD` on ground | **12.05** | pass |
| ink-2 on every soft fill (worst: accent-soft) | ≥ **9.60** | pass |
| muted `#8EA49C` on ground / surface | **7.07** / **6.55** | pass |
| accent `#4FC0A4` on ground | **8.38** | pass |
| ground on accent (primary button text) | **8.38** | pass |
| accent on accent-soft (pill) | **6.68** | pass |
| signal `#E0A05C` on ground / signal-soft | **8.33** / **7.18** | pass (no split token needed in dark) |
| violet `#A89EF0` on ground / violet-soft | **7.85** / **7.18** | pass |
| ok `#82B4EE` on ground / ok-soft | **8.65** / **7.39** | pass |
| err `#EC8B7D` on ground / err-soft | **7.62** / **6.82** | pass |

Rules that fall out of the numbers:

- `--muted` is the floor. Nothing lighter than `--muted` ever carries text.
  `--line` is for hairlines only.
- Text on soft fills is always `--ink` / `--ink-2` (or the state's own strong
  color) — never `--muted`-on-soft, which was not measured and is not allowed.
- In light theme, small attention text is `--signal-text`, full stop.

---

## 3. Type

Three stacks, all system:

```css
--display: Charter, "Bitstream Charter", "Iowan Old Style", "Source Serif Pro", Georgia, serif;
--body: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
--mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
```

**Why no webfont.** This site has to outlive its maintainers — that is the
point of the protocol it describes. A webfont is a runtime dependency on a
third party (or a hosting obligation on us), a render-blocking request, a
layout shift, and a privacy leak, in exchange for a letterform nobody asked
for. Charter ships with macOS/iOS; where it is absent the stack degrades
through Iowan Old Style and Source Serif to Georgia — every step is a
transitional serif with the same voice. The body is the reader's own system
face, which is what they find most legible by definition. The fallbacks are
part of the design, not a failure mode of it.

### Scale

Body base **17 px**. Measure capped at **66ch**. Headings use
`text-wrap: balance`.

| Role | Family / weight | Size | Line height | Tracking | Notes |
|---|---|---|---|---|---|
| Display / H1 | display 600 | `clamp(2.5rem, 6.5vw, 4.4rem)` | 1.04 | −0.02em | One per page |
| H2 | display 600 | `clamp(1.65rem, 3.4vw, 2.4rem)` | 1.15 | −0.015em | Section titles |
| H3 | display 600 | `1.16rem` | 1.3 | 0 | Card / phase titles |
| Lede | body 400, `--ink-2` | `1.16rem` | 1.6 | 0 | Directly under H1 |
| Body | body 400 | `1rem` (17 px) | 1.6 | 0 | Max width `--measure` |
| Small | body 400, `--ink-2` | `0.95rem` | 1.55 | 0 | Card copy, phase copy |
| Caption | body 400, `--muted` | `0.86rem` | 1.5 | 0 | Footers, subtexts |
| Eyebrow / label | mono 400, `--muted`, uppercase | `0.72rem` | 1.4 | +0.14em | Section eyebrows |
| Table header | mono 400, `--muted`, uppercase | `0.7rem` | 1.4 | +0.10em | `thead th` |
| Pill | mono 400/500, uppercase | `0.68rem` | 1 | +0.10em | State pills |
| Stat figure | display 600 | `1.6rem` | 1.2 | −0.01em | `font-variant-numeric: tabular-nums` |
| Data / code | mono 400 | `0.92–0.98rem` | 1.5 | 0 | Hashes, heights, amounts — always tabular |

Two hard rules: numerals that line up in columns (stats, tables, heights) are
always mono or `tabular-nums`, and the display serif never sets body copy —
it is for headings, stat figures, and the wordmark only.

---

## 4. Components

Copy-paste HTML+CSS. Everything references tokens from
`assets/bloch-tokens.css`; nothing is hard-coded. Include the tokens file (or
paste the `:root` blocks) first.

### Buttons — primary and ghost

```html
<a class="btn btn-primary" href="#">Read the migration plan</a>
<a class="btn btn-ghost" href="#">Run a node</a>
```

```css
.btn {
  display: inline-flex; align-items: center; gap: 0.5rem;
  padding: 0.75rem 1.35rem; border-radius: 999px;
  text-decoration: none; font-size: 0.96rem; font-weight: 500;
  border: 1px solid transparent;
  transition: transform .15s ease, background .15s ease;
}
.btn-primary { background: var(--accent); color: var(--ground); } /* 6.18:1 light, 8.38:1 dark */
.btn-primary:hover { transform: translateY(-1px); }
.btn-ghost { border-color: var(--line); color: var(--ink); }
.btn-ghost:hover { border-color: var(--accent); color: var(--accent); }
.btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
@media (prefers-reduced-motion: reduce) { .btn { transition: none; } }
```

The pill radius is reserved for buttons. Only two button kinds exist; a page
needs at most one primary.

### Card

```html
<div class="card card-accent">
  <span class="tag">Signatures</span>
  <h3>Hybrid, not hedged</h3>
  <p>ML-DSA-65 and Falcon-1024 both have to verify. Breaking one is not enough.</p>
  <p><strong>The cost:</strong> ~4.6 KB per signature against Bitcoin's 64 bytes.</p>
</div>
```

```css
.card {
  border-radius: var(--radius-card); padding: 1.75rem;
  display: flex; flex-direction: column; gap: 0.7rem;
}
.card-accent { background: var(--accent-soft); }
.card-violet { background: var(--violet-soft); }
.card-signal { background: var(--signal-soft); }
.card p { font-size: 0.95rem; color: var(--ink-2); max-width: var(--measure); }
.card .tag {
  font-family: var(--mono); font-size: 0.7rem;
  letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted);
}
```

Cards are soft fills with no border and no shadow. A card states a commitment
**with its cost attached** — that copy pattern is part of the component.

### Data table

```html
<div class="tablewrap"><table>
  <thead><tr><th>Allocation</th><th class="num-h">Genesis-4 (BLCH)</th><th class="num-h">Share</th><th style="width:32%"></th></tr></thead>
  <tbody>
    <tr><td>Validator emission — 40 years</td><td class="num">43,029,120,000</td><td class="num">43.03%</td><td><div class="bar" style="width:100%"></div></td></tr>
    <tr><td>Carried over from Genesis-3</td><td class="num">17,970,880,000</td><td class="num">17.97%</td><td><div class="bar" style="width:41.8%"></div></td></tr>
  </tbody>
</table></div>
```

```css
.tablewrap { overflow-x: auto; border: 1px solid var(--line); border-radius: var(--radius-table); }
table { border-collapse: collapse; width: 100%; font-size: 0.92rem; }
th, td { padding: 0.8rem 1rem; text-align: left; border-bottom: 1px solid var(--line); }
thead th {
  font-family: var(--mono); font-size: 0.7rem; text-transform: uppercase;
  letter-spacing: 0.1em; color: var(--muted); font-weight: 400; background: var(--surface);
}
thead th.num-h { text-align: right; }
tbody tr:last-child td { border-bottom: 0; }
td.num { font-family: var(--mono); font-variant-numeric: tabular-nums; text-align: right; }
.bar { height: 6px; border-radius: 3px; background: var(--accent); }
```

Numbers right-aligned, mono, tabular. Bars are flat accent — one series, one
color, no gradient. The wrapper scrolls; the page never scrolls sideways.

### State pill

```html
<span class="pill pill-live">live</span>      <!-- brand: the chain's own present -->
<span class="pill pill-ok">finalized</span>   <!-- semantic success -->
<span class="pill pill-signal">degraded</span><!-- semantic attention -->
<span class="pill pill-err">halted</span>     <!-- semantic failure -->
<span class="pill pill-idle">planned</span>   <!-- inert -->
```

```css
.pill {
  display: inline-block; font-family: var(--mono); font-size: 0.68rem;
  text-transform: uppercase; letter-spacing: 0.1em;
  padding: 0.16rem 0.5rem; border-radius: var(--radius-pill);
}
.pill-live   { background: var(--accent);      color: var(--ground); }      /* 6.18:1 / 8.38:1 */
.pill-ok     { background: var(--ok-soft);     color: var(--ok); }          /* 5.38:1 / 7.39:1 */
.pill-signal { background: var(--signal-soft); color: var(--signal-text); } /* 6.01:1 / 7.18:1 */
.pill-err    { background: var(--err-soft);    color: var(--err); }         /* 5.41:1 / 6.82:1 */
.pill-idle   { background: var(--surface-2);   color: var(--ink-2); }       /* 8.40:1 / 9.61:1 */
```

`pill-live` is the only pill allowed to use the accent, and only for the
protocol's own running state. Everything semantic uses the state ramps.

### Status strip

```html
<div class="status"><div class="statgrid">
  <dl class="stat"><dt>Genesis-3 height</dt><dd>37,731</dd><div class="sub">measured today</div></dl>
  <dl class="stat"><dt>Halts at</dt><dd>50,000</dd><div class="sub">consensus rule</div></dl>
  <dl class="stat"><dt>Block time</dt><dd>21.6<span class="unit"> s</span></dd><div class="sub">trailing average</div></dl>
  <dl class="stat"><dt>Signature</dt><dd class="mono-dd">ML-DSA-65 ‖ Falcon-1024</dd><div class="sub">both must verify</div></dl>
</div></div>
```

```css
.status { background: var(--surface); border-block: 1px solid var(--line); }
.statgrid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; background: var(--line); }
@media (max-width: 780px) { .statgrid { grid-template-columns: repeat(2, 1fr); } }
.stat { background: var(--surface); padding: 1.4rem var(--pad); margin: 0; }
.stat dt {
  font-family: var(--mono); font-size: 0.7rem; text-transform: uppercase;
  letter-spacing: 0.12em; color: var(--muted);
}
.stat dd {
  margin: 0.35rem 0 0; font-family: var(--display); font-size: 1.6rem;
  font-variant-numeric: tabular-nums; letter-spacing: -0.01em;
}
.stat dd.mono-dd { font-family: var(--mono); font-size: 1.05rem; }
.stat .unit { font-size: 1rem; }
.stat .sub { font-size: 0.8rem; color: var(--muted); font-family: var(--body); }
```

The strip's copy rule travels with it: **every figure is either measured and
labelled as such, or planned and labelled as such.** A number with no label
does not ship.

---

## 5. What this brand is not

Each of these is a current default — of AI-generated pages, of crypto sites —
and each was rejected for a reason, not for contrarianism:

- **No purple-to-blue gradient.** It is the single most recognizable signature
  of template output, and gradients hide the discipline of a palette: with a
  gradient you never have to commit to a color, so nothing means anything.
  Here violet is a *solid*, *measured* token with one job (the quantum frame),
  sitting next to an emerald that carries the brand alone.
- **No black-with-acid-green "terminal" theme.** It cosplays cypherpunk while
  making long documents unreadable. Bloch publishes specifications; the ground
  is white and the dark theme is a real theme with measured ratios, not an
  aesthetic.
- **No emoji as section markers.** 🚀 in a heading is a claim of excitement in
  place of a reason for it. Sections are marked by mono eyebrows and a serif
  headline — the typography of documents that expect to be cited.
- **No centering everything.** Center alignment is what a page does when it
  has one sentence per screen and nothing to compare. This system is built on
  a left-aligned 66ch measure, tables, and timelines — structures for readers,
  not for scrolling.
- **No rounded corners on everything.** Radius is a signal, so it is rationed:
  999px means "press me" (buttons only), 18px means "a grouped claim" (cards),
  14px wraps data, 5px marks a state. Tables keep hairlines; hairlines stay
  square. When everything is soft, nothing is.
- **No mascots, no coins, no rockets, no "to the moon".** The site says the
  supply is concentrated before anyone asks, attaches the cost to every
  commitment, and labels planned numbers as planned. The visual system has to
  match that register — the moment the brand hypes, the copy stops being
  believable.

The positive statement of the same rules: white ground, one accent spent
deliberately, a serif that signals published specifications, numbers that are
measured or labelled planned, and a symbol that existed in physics before the
protocol did.

---

*© Postern Labs Ltda. This kit, like the rest of the repository, is licensed
AGPL-3.0-or-later. Nothing in it is investment advice.*
