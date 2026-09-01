<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Release integrity — the G8 runbook for `bloch-pos`

Gate G8 (`docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §11): **published
binary == fleet binary, reproducible, rollback package staged and tested.**
This document is the operational definition of that sentence: what a release
*is*, how its build is made reproducible, how the fleet is compared against it,
what the rollback package contains, and which parts CI proves automatically
versus which parts remain a human sweep. A6 signs G8 against this document.

## 0. Why this gate exists — two documented incidents, not hypotheticals

1. **The published Genesis-3 release WAS the broken binary.** The release
   artifact was built from `f819e87f` — an abandoned branch — while the
   network fixes existed only on an unpublished branch running on the boxes.
   Any node built from the *official* release froze at block 10802
   ("trailing bytes in block body", the first merged-mining block). Fleet and
   release had diverged, and the divergence was invisible until fresh nodes
   died.
2. **The 2026-08-11 fleet survey found three boxes running three different
   binaries, all reporting `bloch 0.3.0-genesis2`.** One box had no source
   tree at all. Identifying what was actually running came down to md5 and
   guesswork — and reading the systemd units actively *misled*, because up to
   16 drop-ins were stacked per service and the last one alphabetically wins.

Everything below is designed backwards from those two failures.

## 1. A release is a triple, and the binary can always say which one it is

A `bloch-pos` release is the triple **(source commit, version stamp, sha256 of
the canonical binary)**. Nothing that cannot state all three is a release.

The stamp comes from `crates/bloch-pos-node/build.rs` (ported on 2026-08-12
from the Genesis-3 node's `build.rs`, commits `0f1766d` + `6ec7378` on
`deploy/g3-terminal-height` — note it had never been merged to
`integration/pos-modules`; the G4 binary was still stampless until this
change). Behaviour:

- `bloch-pos --version` → `bloch-pos-node <pkg-version> (<commit-12>[+dirty]) …`
- A build from a dirty tree is marked `+dirty` **loudly** — an unmarked dirty
  build is exactly what made the fleet unidentifiable.
- A build with no `.git` (container, CI export) takes the commit from the
  `BLOCH_BUILD_COMMIT` env var; the caller asserts the tree state, so no
  `+dirty` second-guessing. A build with neither stamps `unknown+nogit`,
  which any release gate must treat as a hard failure.
- The stamp re-derives when HEAD moves (`rerun-if-changed` on the resolved
  git dir's `HEAD`/`index` — resolved via `--absolute-git-dir`, so it is
  correct in linked worktrees, unlike the G3 original).

## 2. The reproducible build pipeline

Inputs that define the binary, and where each is pinned:

| Input | Pin | Enforced by |
|---|---|---|
| Source | git commit | the stamp (§1) |
| Compiler | `crates/bloch-pos-node/rust-toolchain.toml` (`1.94.1`) | rustup + a hard assert in `scripts/pos-release-integrity.sh` |
| Dependency graph | committed `Cargo.lock` in **both** PoS workspaces (`bloch-pos-node`, `bloch-pos-committee` — they are standalone workspaces, the root lock does not cover them) | `cargo … --locked` + post-build `git diff --exit-code` on the locks |
| Stamp | `BLOCH_BUILD_COMMIT=<commit-12>` passed explicitly | release script / CI guard |
| Profile & flags | default `release` profile, no `RUSTFLAGS` | any `RUSTFLAGS` changes the unit hash — a release build must run with `RUSTFLAGS` unset (the guard builds with a clean invocation) |
| Build path | **canonical `/build` in the release container** | §3 — measured to matter |
| Platform | the fleet target (x86_64/aarch64 Linux, per box) | the release container image, pinned by digest like `deploy/repro/build.sh` does for G3 |

Toolchain bumps are a release-integrity event: their own commit, followed by a
green `pos-release-integrity` run and a new reference hash.

## 3. Reproducibility: what was measured on 2026-08-12 (not estimated)

Host: macOS x86_64, rustc 1.94.1, `cargo build --release --locked`,
`BLOCH_BUILD_COMMIT=f384292c0ffe`, source at commit `f384292` (+ the changes
in this worktree). Five builds:

| # | Source path | Target dir | RUSTFLAGS | sha256 of `bloch-pos` |
|---|---|---|---|---|
| A | worktree | fresh `tA` | — | `bb6ffa3baff1…f2f527f` |
| B | worktree (same path as A) | fresh `tB` | — | `bb6ffa3baff1…f2f527f` — **identical to A** |
| C | copy of the two crates at a different absolute path | fresh `tC` | — | `7f1cb42b117b…4826ce6` — **differs** |
| D | same copy as C | fresh `tD` | `--remap-path-prefix=<copy>=/build` | `85c442606bb2…ae87d0328` — **differs again** |
| E/F | worktree, via the CI guard (two fresh targets) | — | — | `8853e4ce1024…0d284987` both — identical pair (hash differs from A only because the tree had progressed) |

Findings, with the concrete cause:

1. **Same path ⇒ bit-identical.** Clean double builds match exactly. No
   timestamp, parallelism or incremental nondeterminism was observed.
2. **Different path ⇒ different binary, and NOT because of embedded path
   strings.** `strings` shows zero occurrences of either source path in
   either binary. The difference is in mangled symbol hashes:
   `bloch_pos::main` is `…17hbc7018c89eb52bd9E` in build A and
   `…17ha07cd44fa19f3458E` in build C (22 symbols differ, all generic
   instantiations in the bin crate). Cause: **cargo's `-Cmetadata` for a
   path-source package hashes the absolute manifest path**, and that metadata
   seeds every symbol hash in the crate.
3. **`--remap-path-prefix` does not fix it** (measured, build D): it remaps
   debug/panic paths, not `-Cmetadata` — and `RUSTFLAGS` itself perturbs the
   unit hash, producing a third distinct binary.

Consequence — the rule this repo adopts, same one `deploy/repro/build.sh`
already embodies for G3:

> **The publishable reference hash of a `bloch-pos` release is defined only
> for the canonical containerized build** (pinned-digest base image, source at
> `WORKDIR /build`, pinned toolchain, `--locked`, `BLOCH_BUILD_COMMIT` set,
> `RUSTFLAGS` unset). Anyone rebuilding in that container at the same commit
> must get the same sha256; a native build at an arbitrary path will NOT
> match, and that mismatch alone is not evidence of tampering — rebuild in
> the container to compare honestly.

Honest-claim ladder (mirrors `REPRO.md`): today `bloch-pos` has earned
**"deterministic, same-path, single host — measured"**. It has **not** yet
earned "reproducible": that requires the two-independent-builder bit-for-bit
match of the canonical container build, and the `bloch-pos` release container
does not exist yet (§8.1). Do not use the word "reproducible" in any public
artifact for `bloch-pos` until that is green — the trademark/earned-word gate
applies.

## 4. Fleet-vs-release verification (the sweep that would have caught f819e87f)

**The authoritative answer to "what is this node running?" is the kernel, not
the unit file.** Reading `ExecStart` from the base unit misled the 2026-08-11
survey: services carry up to 16 stacked drop-ins and the last one
alphabetically wins. `systemctl cat`/`systemd-delta` are diagnosis tools for
*why* something runs; only `/proc` tells you *what* runs.

Per host, per service (`SVC` = e.g. `bloch-pos.service`), as the runbook:

```sh
PID=$(systemctl show "$SVC" -p ExecMainPID --value)
[ -n "$PID" ] && [ "$PID" != 0 ]        || echo "NOT RUNNING"
readlink "/proc/$PID/exe"                # note: may end in ' (deleted)'
sha256sum "/proc/$PID/exe"               # hashes the RUNNING image even if
                                         # the on-disk file was replaced/deleted
"$(readlink -f /proc/$PID/exe 2>/dev/null || echo /proc/$PID/exe)" --version \
  2>/dev/null || cat "/proc/$PID/cmdline" | tr '\0' ' '
```

Pitfalls, each learned the hard way:

- **` (deleted)` suffix** on the readlink means the binary was replaced on
  disk after start — the node runs the *old* bytes. Hash `/proc/$PID/exe`
  (the running image), never the path it points to.
- **`--version` of the file on disk proves nothing about the process.** After
  any binary swap, only a restart + re-sweep closes the loop.
- **Do not diff unit files to conclude anything.** If the running hash is
  wrong, *then* find the culprit with
  `systemd-delta --type=extended | grep "$SVC"` and `systemctl cat "$SVC"`.
- Nodes on this fleet are `Restart=always`; binary/flag swaps go through unit
  drop-ins, never `pkill`+`setsid` (fleet-management rule).

**Verdict per host:** `sha256(/proc/PID/exe)` must equal the published
release sha256 AND the reported stamp must equal the release stamp. Record a
sweep table — host, service, PID, exe path, sha256, `--version`, match Y/N —
in the release notes. G8 requires a sweep with **every row matching**, taken
after the release restart, plus one repeat sweep ≥24 h later (catches a box
that restarted onto something else).

The sweep is read-only and needs ~30 s per host over SSH. It is deliberately
manual (or PMO-driven) — CI must never hold fleet SSH keys.

### 4.1 The gate sweep — "will the fleet follow this flag day, or fork?"

The §4 sweep above answers *"is every box running the release?"*. It cannot
answer *"will every box follow the gate we are about to arm?"*, because two
boxes on two different stamps may still implement the same gate set, and two
boxes on the same stamp cannot differ. Arming a flag day needs the second
question answered, and before this tool existed it was unanswerable: `selfcheck`
printed `self-check passed` and silently ignored `--json`.

```sh
scripts/fleet-gate-sweep.sh --epoch <E>          # the flag day you are arming
scripts/fleet-gate-sweep.sh --epoch <E> --reference-json consensus-compat.json
```

Read-only: one `selfcheck` per host, which opens no data dir, binds no port and
writes nothing. Exit 0 = every host agrees through epoch E; exit 1 = a host
forks or cannot state its gates; exit 2 = the sweep could not run.

Three rules it enforces, each learned from a real failure:

- **It asks the RUNNING image, not the path in the host table.** Same lesson as
  §4 one level down: it resolves `/proc/PID/exe` and falls back to the
  configured path only when no node is running, saying which answered. A path
  in a hand-maintained TSV is a weaker claim than a unit file.
- **A host that cannot answer is NOT READY, never "fine".** A binary predating
  `--json` exits 0 — silence is not agreement. And a host the sweep failed to
  contact is reported as a *sweep* failure in the sweep's own words, never as a
  fact about the node.
- **Arming a gate is a release-page event** (§7.3). A gate armed on the network
  after a binary was published makes that binary consensus-dead at that epoch.

`gates_digest` equal across two binaries ⇒ compatible at every epoch, now and
later. Different ⇒ compatible only up to the first gate they differ on, which
is what `--epoch E` computes.

**Precedent, found by the first real run of this sweep (2026-09-01):** the
public-RPC box `136.244.90.238` was running `bloch-pos-fixed`, stamped
`2701feab` (2026-08-18) — a build whose `params.rs` declares **zero**
`*_ACTIVATION_EPOCH` constants, i.e. one that predates every armed flag day. It
was frozen at **height 12298, epoch 800** — the exact epoch of the first gate it
does not implement — while the archivals were at height 32454, epoch 1667. It
had been serving public RPC in that state. This is `genesis4-node-20260814`
repeating, and nothing in the release path had noticed for two weeks.

## 5. The rollback package

### 5.1 What it is

The **last known-good release**, frozen as a self-contained tarball an
operator can apply at 03:00 with no Rust toolchain, no repo access, and no
document but the README inside it. Assembled **at release time** — when
"known-good" is a provable statement — by
`deploy/rollback/make-rollback-package.sh <binary> <stamp> [outdir]`, which
was run end-to-end on 2026-08-12 against a freshly built skeleton binary.

Contents (verified by extracting the test package):

| File | Purpose |
|---|---|
| `bloch-pos` | the known-good canonical binary |
| `SHA256SUMS`, `STAMP` | its identity; `install.sh` refuses on mismatch |
| `99-rollback.conf` | systemd drop-in — `ExecStart=` reset + rollback path; named `99-` so it sorts after every stacked drop-in and therefore wins |
| `install.sh` | verify → stage to `/opt/bloch/releases/rollback-<id>/` → record what WAS running (incident log) → install drop-in → restart → **prove via `/proc` that the running hash equals the packaged hash**, failing loudly if any generator still overrides it |
| `README` | apply / un-apply instructions |

The assembler also refuses a stamp that contradicts the binary's own
`--version` (when runnable on the assembling host), so a mislabelled rollback
package cannot be produced by accident.

### 5.2 Where it is staged

- **On every fleet box:** `/opt/bloch/releases/` keeps the current release
  and the rollback package side by side — rollback must not depend on the
  network that may be the thing that broke.
- **Off-box:** the release store (R2 `postern-downloads`, same publishing
  path as other artifacts) plus the PMO machine. `deploy/rollback/dist/` in
  the repo is a build output, never committed and never the store of record.
- The package for release N is built from release **N−1** and ships in the
  same change window as N.

### 5.3 How it is tested without breaking the network (the "tested" in G8)

A package that has not passed this on a scratch host does not count for G8:

1. **Scratch host, never a fleet box** — a throwaway VM/container with
   systemd, or a lab box. Create a scratch unit (`bloch-pos-scratch.service`)
   pointing at the *current* release binary, plus two or three junk drop-ins
   (`10-…`, `20-…`) overriding `ExecStart` — deliberately simulating the
   16-drop-in mess, because that is the environment rollback actually runs in.
2. Run `sudo ./install.sh bloch-pos-scratch.service` from the extracted
   package. It must end with `ROLLBACK APPLIED AND VERIFIED` — that line is
   printed only after the running `/proc/PID/exe` hash equals the packaged
   hash, i.e. after proving it beat the stacked drop-ins.
3. Corrupt one byte of the packaged `bloch-pos` and re-run: `install.sh` must
   refuse at the `sha256sum -c` step. (Negative test — a rollback that
   installs corrupt bytes is worse than the outage.)
4. Un-apply (`rm …/99-rollback.conf`, `daemon-reload`, `restart`) and confirm
   via the §4 sweep that the host returned to the current release.
5. Once the node is consensus-bearing (not the skeleton), add the twin-node
   stage: two nodes on localhost (the same isolation method that safely
   reproduced the gossipsub mesh bug), roll one back, and confirm the pair
   still converges before the package is declared good. **Rolling back across
   a consensus flag-day can never be validated by a unit-level test** — if
   the release being protected activates a consensus change, the rollback
   package must state its safe-use window (heights before activation) in its
   README, or be marked NOT SAFE.

Applying a rollback to the live fleet is an operator decision, made by a
human, never by CI or automation.

## 6. What CI proves automatically (and what it cannot)

`pos-release-integrity` (`.gitlab-ci.yml`, `check` stage, **blocking**, ~1
min, script `scripts/pos-release-integrity.sh`, modelled on
`falcon-clean-guard`) proves on every pipeline:

1. pinned toolchain present and active for the crate directory;
2. both PoS workspaces resolve `--locked`; the committed lockfiles are not
   rewritten by the build;
3. two clean same-path builds of `bloch-pos` are **bit-identical** (fails =
   nondeterminism regression — catch it before any release is cut);
4. `bloch-pos --version` contains the exact commit under build (fails = the
   stamp broke, fleet binaries become untraceable again).

CI cannot prove, by design:

- the **canonical container hash** (needs the release container, §8.1) and
  the **two-builder** comparison — release-time, human-recorded;
- the **fleet sweep** (§4) — CI has no fleet credentials, deliberately;
- the **rollback drill** (§5.3) — needs a scratch systemd host.

Those three are the release-time checklist; the pipeline keeps the
*ingredients* (stamp, locks, toolchain, determinism) from rotting between
releases.

## 7. Release-cut checklist (what A6 signs for G8)

1. Pipeline green, including `pos-release-integrity`.
2. Canonical container build at the release commit; record
   `(commit, stamp, sha256)`; second independent builder reproduces the
   sha256 bit-for-bit.
3. Publish binary + `SHA256SUMS` (+ signature, same signing flow as the
   `SHA256SUMS` re-signing precedent). The published bytes are the bytes from
   step 2 — never a box's local build.
   Attach **`consensus-compat.json`** — the verbatim output of
   `./bloch-pos selfcheck --json` run on the published binary itself, never
   hand-written. It states the consensus flag days (activation epochs) the
   binary was built knowing, armed and inert, plus a `gates_digest`; that is
   the machine-readable answer to "which epoch range is this binary valid
   for". The defect it closes is `genesis4-node-20260814`: a published
   binary that predated the epoch-800 and epoch-1400 armings, went
   consensus-dead on schedule, and whose release page said nothing.
   Corollary: **arming a flag day is a release-page event** — the same
   change window that arms a gate must edit the current release page (title
   prefix + warning block; precedent in
   `deploy/RELEASE-CORRECTION-genesis4-node-20260814.md`) if the published
   binary does not know the new gate.
4. Assemble the rollback package from release N−1
   (`make-rollback-package.sh`), pass §5.3 on a scratch host, stage per §5.2.
5. Deploy via drop-ins; run the §4 sweep — every host must match the
   published sha256 and stamp; repeat sweep ≥24 h later. Then run the §4.1
   **gate sweep** (`scripts/fleet-gate-sweep.sh`) and require exit 0: matching
   bytes prove the rollout landed, but only matching gate sets prove the fleet
   will still be one chain after the next flag day. Re-run it, and require
   exit 0 again, immediately **before arming any activation epoch** — that run
   is the thing that gates the arming, not this one.
6. File the sweep tables and hashes in the release notes. G8 is green only
   with all six on record.

## 8. Not done here — stated, not narrowed away

1. **No `bloch-pos` release container exists yet.** `Dockerfile` /
   `deploy/repro/build.sh` build the Genesis-3 `bloch` node. The canonical
   `/build` container (pinned base digest, `BLOCH_BUILD_COMMIT`,
   `SOURCE_DATE_EPOCH`) for `bloch-pos` is specified here but not written —
   deliberately, while the crate is a skeleton whose dependency set changes
   per integration milestone. It must exist before the first real release.
2. **No two-builder measurement.** Same-path determinism is measured (§3);
   cross-builder container reproducibility is not — it needs the container
   from (1) plus a second host.
3. **The measurement platform was macOS x86_64, not the fleet's Linux.** The
   findings (path-dependent `-Cmetadata`, same-path determinism) are
   compiler-level and expected to hold on Linux, but the Linux numbers have
   not been taken. The CI job will take them on the aarch64 runner on its
   first run.
4. **The §5.3 rollback drill was not executed on a systemd host** — macOS has
   no systemd. The package was assembled, extracted and content-verified, and
   `install.sh` is syntax-checked; the drill needs a Linux scratch box.
5. **No fleet machine was touched, nothing was deployed, no sweep was run** —
   per the task rules. The §4 runbook is ready to execute.
6. **The G3 `bloch` binary on `integration/pos-modules` still has no stamp**:
   the `build.rs` from `deploy/g3-terminal-height` was ported to
   `bloch-pos-node` only. Merging it for the root crate is a separate,
   G3-touching decision this task does not make.
