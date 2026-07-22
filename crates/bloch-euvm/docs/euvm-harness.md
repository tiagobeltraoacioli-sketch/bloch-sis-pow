# `harness.rs` — reference model of the `accept_block` activation hook (step 5.0)

Status: **reference / unaudited, not consensus-wired.** This note describes
`crates/bloch-euvm/src/harness.rs` as written in worktree `wf_2b65b17d-75a-30`. At the
time of writing the file is **not yet part of the build** — `lib.rs` does not contain
`pub mod harness;` (confirmed by diff against the tracked file); the integrator adds
that one line separately. Nothing in this note or the module changes live consensus.

## What it does

`bloch-euvm`'s `INTEGRATION.md` (step 5) plans a single deterministic hook inside the
node's `accept_block`: below a fork height, ignore eUTXO entirely and commit bytes
exactly as today; at/above it, run the eUTXO transactions through `validate_block`
under a gas ceiling and burn part of the BLCH fee. `harness.rs` is that plan turned
into runnable code and tests, entirely inside this crate, with zero contact with the
real node:

- `BlockModel { height, legacy_bytes, eu_txs }` stands in for "the block as the hook
  sees it" — explicitly *not* the node's real `Transaction`/block type.
- `is_feature_active(height) = height >= EUVM_ACTIVATION_HEIGHT`, a `const fn`, is the
  entire activation gate — a plain comparison, no committee/quorum/finality gadget
  (matching `INTEGRATION.md`'s note that the earlier `bloch-ffg` committee design was
  dropped in favor of pure-PoW, height-gated hard forks).
- `EUVM_ACTIVATION_HEIGHT` is pinned at `u64::MAX`: an inert sentinel, so shipping this
  file activates nothing. Real activation is a later, separate, reviewable edit to one
  constant.
- `accept_block_model(&BlockModel, &dyn SigVerifier, GasCeilings) -> Result<AcceptOutcome, AcceptError>`
  dispatches on that gate:
  - **Below activation:** returns `legacy_bytes` unchanged; `eu_txs` are read but never
    touched — this is the byte-identity invariant from `INTEGRATION.md` ("old blocks
    must re-validate identically on resync, VULN-01 style").
  - **At/above activation:** calls `validate_block` (per-tx and block gas ceilings, the
    existing DoS bound), sums the BLCH fees with checked arithmetic, splits them with
    `fee_burn(total, EUVM_BURN_BPS)` (20% burned), and commits
    `legacy_bytes ‖ encode_eu_section(n_txs, gas_used, burned, to_miner)`.
- `legacy_committed_bytes(&BlockModel)` is the "feature literally absent" reference —
  used by the tests to prove the compiled-in-but-inactive path and the
  feature-absent path produce identical bytes.

It orchestrates `lib.rs`'s existing engine (`validate_block`, `EuTx`, `TxError`,
`fee_burn`, `SigVerifier`) and reimplements none of value conservation, validator
execution, or gas metering. No `lib.rs` item had to be made newly `pub`.

## Determinism properties

- The gate is a pure integer comparison (`height >= EUVM_ACTIVATION_HEIGHT`) with no
  per-node state, wall-clock, or vote — every node evaluates it identically, and the
  test `activation_flips_exactly_at_height_identically_per_node` simulates 32
  independent "nodes" agreeing at every probed height.
- Fee summation uses `checked_add`, rejecting with `AcceptError::FeeOverflow` rather
  than silently wrapping.
- `encode_eu_section` is little-endian, length-implicit (fixed-width fields), with no
  float, clock, or hash-map iteration in the encoding path — same inputs produce the
  same bytes on every run (`fee_burn_splits_correctly` re-runs `accept_block_model` and
  asserts identical `committed_bytes`).
- `over_gas_ceiling_rejected_deterministically` re-evaluates the same over-budget block
  50 times and asserts an identical `Err` every time, then shows an ample ceiling
  accepts the same block — isolating the gas bound as the sole cause of rejection.
- The legacy path is unconditional and total: it never inspects `eu_txs`, so no
  future change to `EuTx`'s shape can perturb bytes committed today.

## Gas properties

The harness adds no new gas model — it is a direct pass-through to `lib.rs`'s existing
per-tx (`per_tx_gas`) and block-wide (`block_gas`) ceilings via `validate_block`, i.e.
the same DoS bound already covered by `lib.rs`'s own `block_gas_ceiling` test.
`GasCeilings`/`DEFAULT_GAS_CEILINGS` (10M per-tx / 100M per-block) are explicitly
documented as **illustrative**, not a consensus-blessed schedule — real values are an
integration/audit-time decision, as `INTEGRATION.md` §"Consensus-test plan" implies
(item 4, "DoS bounds").

## Mapping to Ustav

Not applicable to this module, and the doc says so honestly rather than stretching a
connection: `harness.rs` only imports `fee_burn`, `validate_block`, `EuTx`,
`SigVerifier`, `TxError` from `lib.rs`'s core VM/transaction layer. It does not touch
`minting.rs` (native minting policies) or `state.rs` — the module that carries the
"hard Ustav problem" (an Ustav token's registry/holder-set/snapshot/allow-deny state,
committed as a 32-byte sparse-Merkle root in the datum). Those are separate, already
self-described "reference / unaudited, not consensus-wired" modules with their own
honest-boundaries sections.

If an Ustav-bearing eUTXO is integrated later, it is — from this hook's point of
view — just another `EuTx` whose validator happens to assert a state root against
`ctx`; it would flow through the same `accept_block_model` path, subject to the same
height gate, the same gas ceilings, and the same byte-identity invariant below
activation. Nothing in `harness.rs` special-cases it, and nothing would need to.

## Honest status

- **Reference only, not consensus-wired.** `BlockModel` is a model; `legacy_bytes` is
  an opaque stand-in for the node's real canonical serialization. This mirrors
  `lib.rs`'s and `INTEGRATION.md`'s own framing exactly — step 5.0 is "PLAN, not
  wired."
- **Inert by construction.** `EUVM_ACTIVATION_HEIGHT = u64::MAX`; every real height is
  inactive; the crate carries its own empty `[workspace]` and is not yet a node
  workspace member, so none of this reaches a running node today.
- **`lib.rs` is untouched.** The only integration-phase change queued is one line,
  `pub mod harness;`, added by the integrator — confirmed absent from the tracked
  `lib.rs` as of this note.
- **Test count independently reproduced.** Copying the crate to a scratch directory,
  adding `pub mod harness;` there, and running `cargo test` reproduces **24 passed, 0
  failed** (17 pre-existing lib.rs tests + 7 new harness tests) — matching the dev
  report.
- **Known modeling gap (flagged in the module's own doc comment, worth restating
  here):** the active-path `eu_section` commits only four aggregate counters
  (`n_txs`, `gas_used`, `fee_burned`, `fee_to_miner`) — not a hash of the transactions'
  actual contents. Two blocks with different `eu_txs` that happen to share those four
  numbers would produce byte-identical `committed_bytes` under this harness. That is
  acceptable for a harness whose job is to pin down the height gate and the
  feature-off byte-identity property, but it must **not** be carried into a real
  `accept_block`: a real implementation must commit a transaction-content hash (e.g.
  an eUTXO Merkle root), not just aggregate counters, or the active-path commitment is
  non-binding/malleable. The module comment already says "the real node would commit
  an eUTXO Merkle root here" — treat that line as load-bearing, not decorative.
- **PQ verifier plumbing is present but unexercised by this module's own tests.** All
  seven harness tests spend from the trivial "anyone" (`PushInt(1)`) validator, so no
  test here ever calls `SigVerifier::verify`/`verify_ecdsa` (the harness's
  `NoopVerifier::verify` always returns `false` and is simply never reached). The
  interaction between a real/mock PQ verifier and `EuTx`/`validate_tx` is exercised
  elsewhere, in `lib.rs`'s own suite (`hybrid_ecdsa_and_pq_validator`, `p2pkh_validator`,
  `multisig_2_of_3`) — but the harness's own accept-block-hook tests do not confirm
  that a signature rejection surfaces correctly through `accept_block_model`. Anyone
  extending this harness for a real audit should add at least one active-path test
  using a validator that actually calls `VerifySig`/`VerifyEcdsa` against a
  rejecting mock verifier.
