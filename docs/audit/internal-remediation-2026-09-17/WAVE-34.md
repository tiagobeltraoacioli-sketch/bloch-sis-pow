# Internal audit remediation, thirty-fourth wave — 2026-09-18

Base: `f394e18`; branch `fix/internal-audit-20260917`. This wave reconciles
existing versioned key-derivation work; no historical key bytes changed.

## Seed-domain separation

CR-04 reported that the historical Bitcoin companion identity and vault V1
feed the same raw BIP39 seed bytes into both the Bitcoin master derivation and
hybrid PQ key generation. The compatibility entry points still do exactly that
and cannot be changed in place without changing existing identities.

New explicit paths already narrow the finding:

- the Bitcoin-wallet V2 PQ KDF derives keygen material as
  `SHA3-256("bloch-btc-wallet/pq-seed/v2" || seed)` while leaving the Bitcoin
  derivation unchanged;
- vault V2 consumes that domain-separated PQ seed and moves its classical keys
  to a dedicated hardened branch;
- vault V3 uses independent hardened hot/recovery role children and a distinct
  vault-V3 PQ domain, with the derivation version persisted explicitly.

The full `bloch-btc-wallet` and `bloch-pq-vault` suites pass: 38 tests, including
V1 compatibility vectors, V1/V2 divergence, wallet/vault receive-chain
separation, V3 hardened-role non-derivability from the public parent, network
separation and versioned restore.

CR-04 moves to partial, not implemented. The unversioned wallet and vault
entry points remain V1 for compatibility, already-created identities/funds do
not migrate themselves, and application callers must persist and select the
new derivation explicitly. The ledger retains all 200 rows: 66 implemented,
82 partial, 38 open, seven base-changed, four protocol decisions, one unarmed
candidate, one refuted by the original audit and one verified positive.
