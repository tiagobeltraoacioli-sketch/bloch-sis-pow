# Wave 177 — EN-08 single admission transaction identity

Date: 2026-09-19
Comparison base: `7d3efbde`

## Reproduced residual

The private transaction-admission path derived `PosTransaction::txid()` for
the recent-inclusion lookup, derived it again for the pending-mempool lookup,
and derived it a third time inside `Mempool::insert` for a new transaction.
A pending duplicate therefore paid two derivations and a new transaction paid
three.

The identity is witness-free but proportional rather than free: transfer
roots fold their inputs and outputs, and funded deposits build their intent
preimage. Repeating the same derivation on the single consensus thread added
no admission evidence.

## Correction and invariants

`on_transaction_from_canonical` now derives the identity once from the owned
transaction and reuses it for both duplicate indexes and eventual mempool
identity accounting. A private engine-module insertion seam accepts that
prepared identity. The existing self-contained `Mempool::insert` remains for
callers and fixtures without a prepared identity and delegates to the same
implementation.

The recent-inclusion check still precedes the pending check, and both still
precede the refusal bar, capacity planning, structural and cryptographic
validation. Mempool keys, witness-variant multiplicity, source accounting,
byte accounting, replacement/removal behavior, broadcast bytes, RPC output,
errors, verdicts and limits are unchanged. There is no wire, public API,
disk-format, protocol, activation or consensus change.

## Adversarial coverage

- `prepared_txid_insert_matches_authority_and_preserves_variant_multiplicity`
  compares ordinary and prepared insertion state, inserts two different
  canonical witness variants with one identity, and proves that sequential
  removal decrements multiplicity before reopening that identity.
- `transaction_admission_derives_one_txid_for_checks_and_insertion` pins the
  private production path to one `txid()` derivation, both keyed duplicate
  checks and the prepared insertion seam.
- Existing included-duplicate, pending witness-variant and signed RPC/gossip
  sweep regressions retain end-to-end verdict, retention and selection
  coverage.

## Validation

```text
cargo test -p bloch-pos-node --bin bloch-pos \
  prepared_txid_insert_matches_authority_and_preserves_variant_multiplicity \
  --offline
# 1 passed; 0 failed; 623 filtered out

cargo test -p bloch-pos-node --bin bloch-pos \
  transaction_admission_derives_one_txid_for_checks_and_insertion --offline
# 1 passed; 0 failed; 623 filtered out

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 605 passed; 0 failed; 19 ignored; 61.29s

git diff --check
# clean
```

The complete node suite ran outside the restricted sandbox because transport
fixtures bind localhost sockets.

## Residual boundary

- Canonical encoding, the one required transaction-identity derivation,
  admission cryptography and successful-receipt SHA3 remain.
- Replacing an existing canonical mempool key still derives the removed
  entry's identity for decrement accounting; new admission does not have an
  existing entry at that key.
- The prepared helper is private to the engine module because supplying an
  identity from a different transaction would corrupt duplicate accounting.
- This correction makes no heap/RSS or latency claim and does not address
  non-preemptible transition work, transport copies, peer policy or Sybil
  resistance. `EN-08` remains `PARTIAL`.
