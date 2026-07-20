# Step 5 — integrating the eUTXO VM into node consensus (PLAN, not wired)

Branch: `euvm/integrate`. **Nothing here changes the live validation path.** This is
the design + task plan for wiring `bloch-euvm` (VM) and `bloch-ffg` (committee-
governed activation) into the node, to be implemented behind a flag, tested against
consensus, and **only ever activated by a 14-of-21 committee quorum at a coordinated
height** — never by shipping this code.

## Invariant that governs everything

> When the `euvm` feature is **inactive** (default, and until the committee
> activates it at its height), the node must behave **byte-for-byte** as today.
> Old blocks must re-validate identically on resync (VULN-01 style: no silent fork).

So integration is *additive*: a new output kind and a new spend path that only
engage for eUTXO outputs, gated by `is_feature_active(...)`.

## The activation gate (bloch-ffg)

```
active = height >= EUVM_ACTIVATION_HEIGHT
      && bloch_ffg::is_feature_active(&committee, &FeatureActivation{feature:"euvm", height},
                                      &committee_sigs, &pq_verifier, height)
```

- The committee, the activation record, and the 14-of-21 signatures live **on-chain**
  (a committee-registry commitment + an activation transaction), so every node checks
  the same thing deterministically.
- Below the activation height, `active == false` and none of the new code runs.

## Data-model mapping (node `Transaction` ↔ eUTXO)

Today (`crates/bloch-crypto/src/core/mod.rs`): `TxOutput { value: u64, script_pubkey:
Vec<u8> }`; `script_pubkey` is a 20-byte `SHA3-256(pubkey)[..20]` (fixed P2PKH).

Additive change (only meaningful when the feature is active):
- Reserve a `script_pubkey` **tag** that means "eUTXO output": e.g. a length/prefix
  that current P2PKH can never collide with. An eUTXO output encodes
  `{ validator_hash: [u8;32], datum, multi_asset_value }`.
- A legacy P2PKH output maps to the trivial eUTXO validator "check 1 PQ sig vs this
  hash" — so the old model is a strict subset (`bloch-euvm`'s `p2pkh_validator` test
  is exactly this). No migration of existing UTXOs.

## Where the hook goes

`src/main.rs` `accept_block` → per-tx validation. Add, guarded by `active`:
1. For each input spending an eUTXO output: run `bloch_euvm::spend(...)` with the
   real `Ctx` built from the spending tx (sighash in `fields[0]`, `tx_outputs`,
   `self_value`), and the **real PQ verifier** as the `SigVerifier` (ML-DSA-65‖
   Falcon-1024 from `bloch-crypto`).
2. Enforce per-asset value conservation (`validate_tx`) including native tokens.
3. Meter gas per tx and a **block gas ceiling**; fee paid in BLCH, base-fee **burned**
   per `fee_burn(fee, EUVM_BURN_BPS)` (§5-bis).
4. Legacy-only blocks take the unchanged path — the new code is skipped entirely.

The miner (block builder) mirrors the same checks so it never builds an invalid block
(the existing "miner and validator agree by construction" discipline).

## Workspace wiring

`bloch-euvm` and `bloch-ffg` currently carry an empty `[workspace]` (own roots, out of
the node build) so they cannot destabilize the live node. Integration step:
- Remove their `[workspace]` tables; add them to the node workspace `members`.
- Add `bloch-euvm`/`bloch-ffg` as **optional** path deps under a `euvm` feature in the
  node `Cargo.toml`; `default = []`. With the feature off, they are not compiled in.
- Provide a `SigVerifier` adapter in the node that calls `bloch_crypto::verify`.

## Consensus-test plan (the gate to any activation)

1. **Feature-off identity:** a corpus of historical blocks re-validates byte-identical
   with the feature compiled off AND compiled-on-but-inactive.
2. **Activation determinism:** all nodes flip at the same height iff the on-chain
   14-of-21 activation is present; with 13 sigs, none activate.
3. **eUTXO happy/again-paths:** P2PKH-as-validator, multisig, hash-lock, AMM swap,
   token conservation — mirrored from `bloch-euvm`'s unit tests but through the real
   `Transaction`/sighash/PQ verifier.
4. **DoS bounds:** a block exceeding the gas ceiling is rejected identically on every
   node.
5. **Resync/fork-safety:** a node syncing from genesis across the activation height
   reaches the same tip as one that was online.
6. **Adversarial:** malformed eUTXO scripts, gas-exhaustion, value-inflation attempts,
   and continuation-escape attempts all fail closed.

## Explicitly NOT in this branch yet

- No edits to `accept_block`, the miner, `Transaction`, or `bloch-crypto`.
- No workspace change (the crates stay isolated until the above tests exist).
- No activation constant is set live.

The order is deliberate: **plan → feature-gated wiring + consensus tests → external
audit → committee-signed activation at a height.** This document is step-5.0.
