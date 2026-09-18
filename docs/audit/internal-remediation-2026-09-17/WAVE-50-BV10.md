# Wave 50 BV-10: versioned recovery context

Date: 2026-09-18. Branch: `codex/audit-crypto-vault-wave50`. Starting point:
`d914a77`. Scope: local vault recovery metadata, tests and documentation only.
No funded output, network service, deployment, activation or existing key/
preimage derivation was changed.

## Recovered finding

The exact BV-10 source was recovered from
`a79c88b:docs/audit/deep-audit-2026-09-16/A9-bitcoin-vault-ustav.md`. Recovery
preimage `r` is deterministic in the PQ secret and a caller-selected `vault_id`.
The original code did not persist the vault ID or key-derivation family. Trying
the wrong V1/V2 family produces a different PQ secret and therefore a different
preimage, while reusing an ID after disclosure makes the new hashlock preimage
publicly known.

The earlier checked restore compared a caller-supplied context against the
funded `H(r)`, which made a wrong guess a refusal, but it still left all context
metadata and version selection to an external backup convention.

## Additive recovery record

`RecoveryContextV1` is a public, opt-in metadata record. It contains no seed,
private key or recovery preimage. Its canonical bounded encoding records:

- a format magic and version;
- the exact `VaultKeyDerivation` family (V1, V2 or V3);
- Bitcoin mainnet/test-family selection;
- a non-empty, at-most-1024-byte vault ID; and
- the recovery hash committed by the funded vault.

Decoding rejects unknown versions, derivation/network tags, a nonzero reserved
byte, empty/oversized IDs, an all-zero placeholder hash, truncation and trailing
bytes. Restore derives only the recorded family and then requires the caller's
independently retained network and funded recovery hash. Metadata substitution
therefore fails either before derivation or at the existing preimage/hash check;
there is no fallback that silently tries another family.

All historical derivation functions and HKDF bytes remain unchanged. Existing
backups can continue using `restore_recovery_secret_v1`; the new envelope is for
explicit adoption by new backup workflows.

## Honest residual boundary

BV-10 remains `PARTIAL`. The record is not signed and must not be treated as an
authority for `H(r)`; restoration deliberately requires an independent funded
commitment. It does not allocate vault IDs, prove randomness or uniqueness,
maintain a cross-backup reuse registry, observe an on-chain reveal, enforce
single use, or prove current PQ-key possession. Those are lifecycle/product
responsibilities and cannot be inferred safely by this local library.

Ledger aggregate counts are unchanged because one partial was narrowed rather
than closed.

## Validation

- Focused tests cover canonical round trips and exact recovery for V1/V2/V3.
- Adversarial tests cover wrong network/hash, vault-ID and derivation
  substitution, every truncated prefix, trailing bytes, unknown tags,
  noncanonical reserved data, empty/oversized IDs and zero hashes.
- `cargo test --locked -p bloch-pq-vault --offline`: 38 passed, zero failed.
- `git diff --check`: passed.

The ledger remains at `IMPLEMENTED: 71`, `PARTIAL: 98`, `UNARMED CANDIDATE:
15`, `PROTOCOL DECISION: 5`, `BASE CHANGED: 7`, `OPEN: 1`, `REFUTED IN AUDIT:
1`, `VERIFIED POSITIVE: 2` (200 retained finding rows).
