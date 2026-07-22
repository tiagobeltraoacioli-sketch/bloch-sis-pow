# `batcher.rs` — deterministic AMM batch-settlement for single-pool eUTXO contention

Status: **reference / unaudited, not consensus-wired.** This note describes
`crates/bloch-euvm/src/src/batcher.rs` as currently written. At the time of writing,
`lib.rs` contains neither `mod batcher;` nor `mod minting;` (confirmed by `grep -n
"minting\|batcher" src/lib.rs`, which returns nothing but an unrelated doc-comment
match) — both modules sit untracked and unwired, one file per workstream, exactly as
`docs/euvm-harness.md` describes for its own module. Nothing in this note or the
module changes live consensus.

## The problem it solves

`lib.rs`'s `constant_product_amm` test shows a constant-product pool living in a
single `ExtOutput`: swapping means spending that output and re-creating it with new
reserves. An eUTXO can only be spent once per block, so if N traders each build a
transaction that spends the *same* pool output, at most one lands — the other N−1 are
double-spends and get rejected outright. This is eUTXO contention on a hot,
single-state contract (the reason Cardano-style DEXes run a batcher/aggregator rather
than letting traders spend the pool directly).

## What it does

`batcher.rs` is a pure, in-memory settlement engine: given a pool `ExtOutput` and a
slice of `SwapOrder`s, it produces one `Settlement` that folds every order into a
*single* pool continuation plus one settlement output per order — a transaction that
spends the pool exactly once and serves the whole batch.

- `SwapOrder { owner_validator, give_asset, give_amount, want_asset, min_out }` — an
  economic swap request. `canonical_key()` is a fixed-width, big-endian, field-order-
  fixed encoding used purely as a sort key.
- `settle(pool, orders, fee_bps, gas_budget)` — (1) reads the pool's two reserve assets
  off `BTreeMap` iteration (already canonical: `asset0 < asset1`); (2) sorts orders by
  `canonical_key()`, so the fold never depends on submission order; (3) folds each
  order in turn against the *running* reserves using `amm_out` (checked-`i128`
  constant-product floor with a fee), accepting it (reserves move, a `Fill` is
  recorded) or dropping it (reserves untouched, the give is refunded intact) when it
  targets the wrong assets, underflows its `min_out`, or the flat `GAS_PER_ORDER`
  budget is exhausted.
- `pool_continuation` / `fill_outputs` / `build_settlement_tx` turn a `Settlement`
  into the actual `EuTx` shape `lib.rs` understands: the pool spent once at
  `inputs[0]`, its continuation at `outputs[0]`, one settlement output per order after
  it.

## Determinism properties

- **Order-independent by construction.** `settle` sorts by `canonical_key()` before
  folding — no `HashMap`, no wall-clock, no float. The same *multiset* of orders
  yields a byte-identical `Settlement` under any permutation of the input slice
  (`determinism_independent_of_submission_order`: reversal + three shuffles all equal
  the base run).
- **Checked arithmetic in the pricing formula.** `amm_out` uses `i128` `checked_*`
  end-to-end and returns `None` only on overflow (unreachable for `u64` reserves in
  practice, but the caller still has to handle it — and `settle` does, by dropping the
  order rather than panicking or wrapping).
- **Invariant-preserving.** Every accepted fill keeps `k` non-decreasing
  (`amm_out_never_drains_and_grows_k` exercises a fee/input spread), so the aggregate
  batch satisfies `new_a·new_b ≥ old_a·old_b`. This is proven against the *real*
  `lib.rs` pool validator, not just asserted algebraically:
  `batch_respects_invariant_and_passes_pool_validator` builds the settlement tx and
  runs it through `crate::validate_tx`, and `draining_settlement_would_be_rejected`
  hand-tampers a settlement to prove the same validator actually bites.
- **Never drains.** `amm_out`'s floor formula is strictly `< reserve_out` for any
  finite input, so no single order — however large (`u64::MAX / 2` is tested) — can
  empty a reserve; an order that asks for more than the invariant allows is dropped
  and refunded deterministically, never partially filled below its own limit.
- **Value conserved.** Per asset, `old_reserve + Σgive == new_reserve + Σ(fills ∪
  refunds)` holds across the continuation and every settlement output
  (`value_conserved_across_pool_and_fills`), and the built tx separately passes
  `lib.rs`'s own per-asset conservation check inside `validate_tx`.

## Gas — a batch-sizing bound, not the VM's gas

`GAS_PER_ORDER` (100, flat) is charged inside `settle()` purely to cap how many
orders one batch considers: once the running total would exceed `gas_budget`, that
order and every later one in canonical order are dropped and refunded — a
deterministic cutoff (`gas_budget_caps_and_is_deterministic` shows a 2-order budget
against a 4-order batch fills exactly two, drops exactly two, and the split is
shuffle-invariant). **This is a separate accounting scheme from `lib.rs`'s real
per-op VM gas** (`gas_cost`: `VerifySig`/`VerifyEcdsa` 1000, hashing 60, arithmetic 4,
everything else 1, charged per `Op` executed inside `run`/`spend`). Once
`build_settlement_tx`'s output is actually fed to `validate_tx` with a `gas_limit`,
the gas actually spent is driven by how many ops the pool validator and every
funding validator execute — not by `GAS_PER_ORDER × orders_considered`. A batch sized
to fit under one budget is not guaranteed to fit under the other in either direction;
see the review note below.

## Mapping to Ustav

Not applicable. This module settles a two-asset constant-product pool; it has no
contact with `state.rs`'s registry/holder-set/root machinery or `minting.rs`'s policy
model, and doesn't need to — an Ustav-governed asset would simply be one of the two
pool assets (its `AssetId` is still just 32 bytes to the batcher) with its own
transfer/minting rules enforced by its own validator elsewhere in the transaction,
outside anything `batcher.rs` inspects or changes.

## Honest status

- **Reference only, not consensus-wired.** `settle`/`build_settlement_tx` are pure
  functions over in-memory data; the module doesn't gossip orders, doesn't select or
  rotate a batcher operator, and isn't reachable from any node code path. `lib.rs`
  does not declare `mod batcher;` — wiring it in is a one-line, separate, reviewable
  edit (see Integrate-phase note below), matching the crate's stated "step 5" gate in
  `INTEGRATION.md`.
- **Order authorization is out of scope, and the API doesn't yet carry a slot for
  it.** The module's own doc comment says orders are "already authenticated," but
  concretely: `SwapOrder` has no signature/redeemer field, and
  `build_settlement_tx` hardcodes `redeemer: vec![]` for every input it builds
  (pool and funding alike). That's a fair thing to defer, but it means the gap isn't
  just "unimplemented" — there is currently no field anywhere in this module's types
  through which a per-order PQ signature could flow into the built `EuTx` without a
  type change. Worth deciding explicitly before wiring, not discovering at
  integration time.
- **The `funding_validator` is one shared program for the whole batch, not each
  trader's own.** See the API review below — this is stronger than an "out of scope"
  note; it's a mismatch between what `SwapOrder::owner_validator`'s doc comment claims
  and what the code does.
