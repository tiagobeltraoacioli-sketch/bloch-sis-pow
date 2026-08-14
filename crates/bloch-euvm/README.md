# bloch-euvm — native eUTXO contract VM (foundation)

> **Genesis-3-era crate.** This was designed and built for the proof-of-work
> chain, which stopped at height 39,918 on 2026-08-13. The live chain is
> **Genesis-4, proof of stake**, and this VM is **not wired into it** — see
> the "designed ≠ built ≠ booted" table in the root `README.md`. The direction
> for contracts at L1 has since moved to an EVM
> (`docs/adr/ADR-040-evm-and-ustav-at-l1.md`), for which no code exists yet.
> Kept buildable for audit. Read every present-tense sentence below about
> "the chain" as describing Genesis-3.

A **deterministic, gas-metered eUTXO smart-contract VM** for Bloch — the first,
self-contained increment of the native contract layer designed in the
validators/BaaS study (**§5-quater**, "VM de contratos nativa").

> **Status: FOUNDATION / reference. NOT wired into node consensus.**
> This is a standalone library with tests only. Nothing here validates or produces
> real Bloch blocks yet. It exists to prove the design is buildable and to give the
> consensus integration (step 5) a tested, deterministic core to plug in. Unaudited.

## Why eUTXO (not an EVM bolt-on)

Genesis-3 was a **UTXO + post-quantum + pure-PoW + ownerless** chain — all four
words held when this was written; the PoW chain has since closed and the
ownerless thesis was retracted (ADR-036). The study evaluated
three models and chose **eUTXO** (Cardano/Ergo style): outputs carry a `validator`
(a program) + `datum` (local state); spending runs the validator. It is UTXO-native,
deterministic, parallel, PQ-friendly, and keeps the chain's character — unlike an
account-based EVM overlay (which dilutes PQ purity and adds global mutable state).

## What is implemented and tested (15 tests, all green)

Run: `cargo test` (isolated — the empty `[workspace]` keeps it out of the node build).

| Step | Capability | Key tests |
|---|---|---|
| **1** | The VM: deterministic stack machine, gas metering, opcodes (checked `i128` arithmetic, SHA-256d/SHAKE-256, `VerifySig` via host, `Verify`) | `p2pkh_validator`, `multisig_2_of_3`, `hashlock_validator`, `gas_exhaustion`, `deterministic` |
| **2** | Extended output (`ExtOutput{value, validator_hash, datum}`) + the spend model (revealed program must hash to `validator_hash`) + tx-output introspection → stateful continuation | `spend_binds_program_to_output`, `continuation_counter_contract`, `validator_hash_stable` |
| **3** | Transaction/block validation — the shape of the block-acceptance hook: per-tx value conservation, run every validator with the whole tx visible, per-tx and per-block gas ceilings, `fee_burn` split | `tx_conserves_value_and_runs_validators`, `tx_value_not_conserved_rejected`, `tx_validator_rejection`, `amm_style_continuation_tx`, `block_gas_ceiling`, `fee_burn_split` |
| **4** | Native multi-asset `Value` (Cardano-style) + per-asset conservation + a real **constant-product AMM** (a pool holding two assets; swaps enforced by `new_a·new_b ≥ old_a·old_b`) | `constant_product_amm` |

The AMM test is the headline: **a native Uniswap-core, no bridge, on real assets** —
a valid swap passes; a swap that would drain the pool is rejected by the validator.

## Design properties (the ones a consensus VM needs)

- **Deterministic:** checked `i128` (no float, no wrap), no I/O, no clock, canonical
  `BTreeMap` value ordering. Same inputs → same result on every node.
- **Gas-metered:** every op costs gas from a budget; runaway programs abort — the DoS
  bound, enforced per-tx and per-block.
- **Program-bound:** an output commits to `SHA-256d(encode_program(validator))`; you
  cannot run a different program than the one the output authorizes.
- **Post-quantum-ready:** signature verification is a host callback
  ([`SigVerifier`]), so the real **ML-DSA-65 ‖ Falcon-1024** verifier from
  `bloch-crypto` plugs in without touching the VM. The multisig test is exactly the
  **bridge-custody primitive (§5-ter)** the current fixed script lacks; the hash-lock
  test is the **HTLC / atomic-swap** primitive.

## Mapping to the study

- **§5-quater** (native eUTXO VM) — this crate is its step-1..4 implementation.
- **§5-ter** (wBLCH bridge) — the multisig validator is the on-Bloch custody the
  bridge needs (which the fixed P2PKH script cannot express).
- **§5-bis** (ETH-style fee burn) — `fee_burn(fee, burn_bps)` models the base-fee
  burn; the VM meters gas paid in BLCH.
- **§5-quinquies** (parallel merge-mined chains) — each parallel chain runs this same
  VM; nothing here assumes a single chain.

## Honest boundaries & what's next

- **Not consensus-wired.** The `EuTx`/`validate_tx` here is a *model* of the hook, not
  the node's real `Transaction`/`accept_block`.
- **Step 5 — integrate into the real node** (behind a flag, on a dedicated branch,
  with consensus tests and a third-party audit before any activation). This is the
  line that touches the live chain; it is intentionally **not** done here.
- **Step 6 — merged mining (AuxPoW)** for the parallel-chain model. (An earlier draft
  paired this with an FFG committee; FFG has been **dropped** — the base is pure PoW
  with deterministic, proof-gated validation, and any activation is a height-gated
  hard fork, never a committee vote.)
- Not yet modelled: minting policies (native token issuance), a higher-level contract
  language over these opcodes, and the batcher/routing layer for AMM concurrency.

## Files

- `src/lib.rs` — the whole VM: `Val`, `Op`, `run`, `ExtOutput`/`Value`, `spend`,
  `validator_hash`, `validate_tx`/`validate_block`, `fee_burn`, and the 15 tests.
