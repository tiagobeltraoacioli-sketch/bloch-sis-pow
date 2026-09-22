# Wave 49: bounded pre-signed clawback fee ladder

Date: 2026-09-18. Branch: `codex/audit-crypto-vault-round2`. Starting
point: `1acd578`. Scope: local vault construction, non-custodial API, tests and
documentation only. No funds moved, product or consensus rule activated,
service deployed, key handled, or public network contacted.

## Recovered findings

The exact BV-02 and BV-08 sources were recovered from
`a79c88b:docs/audit/deep-audit-2026-09-16/A9-bitcoin-vault-ustav.md`.
BV-02 records that setting an RBF sequence does not let a keyless watchtower
replace a clawback: every changed output/fee has a different `SIGHASH_ALL`, so
the recovery key must authorize each replacement. Handing that key or a signing
oracle to the watchtower makes it custodial and able to redirect funds. BV-08
records that fixed pre-signed fees can become inadequate during the delay
window and that the builders had no dust, excessive-fee or estimation policy.

The earlier checked builders already addressed money range, subtraction, dust
and a conservative ten-percent fee ceiling, while documentation retracted the
claim that RBF alone grants replacement authority. A usable finite pre-signing
mechanism was still absent.

## Local implementation

`build_clawback_fee_ladder_checked` is an additive API for new construction. It
accepts two to 32 absolute fees in strictly increasing order. Each candidate:

- spends the same non-null trigger outpoint with an RBF-enabled sequence;
- pays the same caller-selected safe destination;
- independently passes money-range, subtraction, dust and ten-percent fee
  checks; and
- returns its own BIP-143 `SIGHASH_ALL` for offline recovery-key signing.

The focused regression signs every returned candidate with a real secp256k1
recovery key and executes the branch-B script with the existing evaluator. It
also proves distinct transaction IDs/sighashes and refuses empty, one-step,
duplicate, decreasing, oversized, excessive-fee and null-outpoint schedules.

The shield API exposes the same behavior at
`POST /vault/clawback-ladder`. It returns unsigned transaction bytes and
per-step sighashes only. The owner signs all steps locally and may give the
finite signed package—not the key—to a watchtower. Existing routes and legacy
builders are unchanged.

## Honest boundary

BV-02 and BV-08 remain `PARTIAL`. Strictly increasing absolute fees do not by
themselves prove BIP-125 acceptance: incremental relay fees, mempool state and
node policy can change. This wave does not estimate current fees, choose the
schedule, distribute or refresh signed packages, implement CPFP, authenticate
the anchored safe destination, or operate a watchtower. The ten-percent ceiling
can itself be insufficient during extreme congestion. Those facts are returned
and documented instead of being hidden behind an “RBF-enabled” claim.

The trigger outpoint can be prepared from the segwit unvault transaction before
broadcast because its txid excludes witness data, but callers must persist and
verify the exact unvault/clawback package before funding. No existing funded
vault is reinterpreted or automatically migrated.

## Validation

- `cargo test --locked -p bloch-pq-vault clawback_fee_ladder --offline`: two adversarial/cryptographic regressions passed.
- `cargo test --locked clawback_ladder_returns_distinct_presignable_replacements --offline` in `services/pq-shield-api`: one API regression passed.
- `cargo test --locked -p bloch-pq-vault --offline`: 35 passed, zero failed.
- `cargo test --locked --offline` in `services/pq-shield-api`: 19 passed, zero failed.
- `git diff --check`: passed.

Ledger counts are unchanged (`IMPLEMENTED: 71`, `PARTIAL: 98`, `UNARMED
CANDIDATE: 15`, `PROTOCOL DECISION: 5`, `BASE CHANGED: 7`, `OPEN: 1`): this
wave materially narrows two partials but does not claim their external
operational boundaries are closed.
