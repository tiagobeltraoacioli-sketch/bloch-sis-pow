# What the recovery actually found — corrected

The first pass overstated the severity. After rebasing onto `g3-integration`,
the picture is narrower and in one place the opposite of what was claimed.

## Correction

The initial commit message on `recovery/auxpow-base` said the corrected
GHOSTDAG coloring existed only on the box, and therefore that "the fleet binary
and the repository have different consensus today". **That was wrong.**
`CORRECTED_COLORING_ACTIVATION_HEIGHT = 21_430` is already committed on
`g3-integration` at `src/consensus/mod.rs:583`, identical value. There is no
consensus divergence from that change.

## What the rebase resolved

| File | Verdict |
|---|---|
| `src/consensus/mod.rs` | Already upstream — dropped, no diff remained |
| `src/network/sync_rr.rs` | Already upstream |
| `src/main.rs` | **Upstream is ahead**; box is behind |
| `src/network/mod.rs` | **Upstream is ahead**; box is behind |
| `pool-proxy/*` | **Only on the box** — 528 lines, genuinely new |

## The finding that replaces the alarm

The auxpow box — a live mainnet producer — is running **older consensus code
than the repository**, not newer.

Its `accept_block` still derives expected difficulty with
`genesis2_expected_bits(store, block.height)`: the legacy, order-dependent
path. `g3-integration` replaced that with the ancestry-based, fail-closed
derivation added after the 2026-08-09 incident, where a node validated with the
old rule while its peers used the new one and mainnet halted at h=28080. The
box never got that fix.

Its regossip suppression window is also still 10s against gossipsub's 30s
`duplicate_cache_time`, the mismatch upstream fixed — every re-publish in the
10–30s band pays a bincode encode plus SHA-256 over a multi-MB body only to be
refused by the duplicate cache.

Both conflicts were resolved in favour of upstream.

## What was genuinely rescued

The pool-proxy merged-mining work: 528 insertions across five files including
`pool-proxy/src/addr.rs`, which existed nowhere else. It is pool and proxy
layer, not consensus. `cargo check` passes on the rebased tree.

## What this changes about the deploy

The earlier stop was still correct, but for a smaller reason than stated: the
risk was losing the pool-proxy work, not shipping divergent consensus. And it
surfaced something more useful than the thing it was looking for — the
production producer is missing a consensus fix for a split that already
happened once.
