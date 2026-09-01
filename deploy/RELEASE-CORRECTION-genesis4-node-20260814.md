<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# DRAFT — correction to release `genesis4-node-20260814` (not yet applied)

Prepared 2026-08-31. A human applies this; nothing here is published
automatically. Apply with:

    gh release edit genesis4-node-20260814 -R tiagobeltraoacioli-sketch/bloch-sis-pow \
      --title "<new title below>" --notes-file <body with the warning block prepended>

Do **not** delete the release or its assets: the binary is the historical
record of what the fleet ran on 2026-08-14, and `SHA256SUMS` there is the
only correct published digest set for the carryover (the in-repo sidecar was
wrong until 2026-08-31). Mark it, don't erase it.

## New title

    [CONSENSUS-DEAD since epoch 800 — 2026-08-22] Genesis-4 node (2026-08-14) — do not run; build from source

## Block to prepend to the release body

> ## ⚠️ This binary is consensus-dead. Do not run it.
>
> **Dead since epoch 800 — 2026-08-22 18:51:19 UTC.** This binary was built
> before any consensus flag day was armed; the source tree it was built from
> contains **no activation-epoch constants at all**. Two flag days have since
> activated on the live network:
>
> | flag day | epoch | activated (UTC) | what changed |
> |---|---|---|---|
> | `TRANSFER_WITNESS_DEDUP` + `BLOCK_BYTES_V2` (one switch, commit `8e0cb15f`) | 800 | 2026-08-22 18:51:19 | `TransferV2` (tag `0x06`, one witness per owner) becomes valid; block payload cap 256 KiB → 512 KiB |
> | `LEAKED_ROSTER` (commit `ab9ca4e1`) | 1400 | 2026-08-29 10:51:19 | the inactivity leak reaches the duty roster |
>
> From epoch 800 on, this binary **rejects blocks the network accepts** and
> forks onto a dead branch — silently: it keeps reporting a head, a height
> and a state root. There is no error to notice. (Epoch times follow from
> genesis 2026-08-13 21:31:19 UTC × 32 slots × 30 s.)
>
> **What to do instead:** build from the public mirror
> (`github.com/tiagobeltraoacioli-sketch/bloch-sis-pow`, branch `main`, at or
> after `ab9ca4e1`) with the pinned toolchain
> (`crates/bloch-pos-node/rust-toolchain.toml`, Rust 1.94.1):
>
>     cd crates/bloch-pos-node        # the toolchain pin lives here; a build
>                                     # from the repo root uses your default rustc
>     cargo build --release --locked
>     ../../target/release/bloch-pos selfcheck    # prints the flag days the build knows
>
> A binary that knows a given epoch-E flag day is valid **through** the next
> gate armed after it was built; `selfcheck --json` states this machine-
> readably (`gates_digest`, `knows_gates_through_epoch`). Compare that output
> against the current release page before trusting a node past today's epoch.
>
> The **`mainnet.manifest`, `carryover.tsv.gz` and `SHA256SUMS` assets remain
> correct** — genesis data is not versioned by flag days. Only the binary is
> dead.

## Why this correction exists (for the release-notes changelog)

The release page published a consensus-bearing binary with no statement of
which consensus rules it implements or until when they hold. Both flag days
were announced in-repo (`deploy/FLAG-DAY-EPOCH-800.md`, commit `ab9ca4e1`)
but the release page — the one thing a third party actually reads — was never
updated. Fixed forward: every future release attaches `consensus-compat.json`
(the output of `bloch-pos selfcheck --json`), and arming a flag day requires
editing the current release page in the same change window
(`deploy/RELEASE-INTEGRITY.md` §7).
