# Wave 175 — integration of RPC ownership, KDF preflight and integrity aliases

Date: 2026-09-19
Integration head: `a1bff51e`

## Integrated corrections

- `f23b4b40` moves the unchanged v1/v2 wallet KDF ceilings ahead of every
  Base64 decode, while retaining the existing validation order for keyfiles
  whose KDF parameters are in policy.
- `f8461461` requires each legacy integrity double-build output to be a
  regular non-symlink file with exactly one hard link before hashing or
  execution, with adversarial symlink and hard-link fixtures for both sides.
- `a1bff51e` removes the proportional transaction clone and second canonical
  encoding from successful and duplicate `sendrawtransaction` handling. The
  decoded transaction and its one canonical byte owner move through a private
  admission seam, while the public receipt contract remains unchanged.

The ledger references WAVE-172, WAVE-173 and WAVE-174 without changing their
parent findings from `PARTIAL`. These corrections do not satisfy any external
release or operational gate.

## Validation

```text
cargo test -p bloch-wallet-cli --bin postern-wallet --offline
# 246 passed; 0 failed; 4 ignored

python3 scripts/pos-release-integrity.selftest.py
# PASS

umask 000; python3 scripts/pos-release-integrity.selftest.py
# PASS

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 603 passed; 0 failed; 19 ignored; 62.69s

W172 focused receipt/ownership/RPC-gossip tests
# 4 x 1 passed; 0 failed; 621 filtered out

git diff --check
# clean
```

The W172 focused RPC/gossip fixture was run outside the restricted sandbox
because it binds a localhost transport. Independent cross-review approved all
three waves without blocking findings.

## Ledger state

The inventory remains 200 rows with 200 unique IDs and no duplicate IDs:

- `IMPLEMENTED`: 71
- `PARTIAL`: 98
- `UNARMED CANDIDATE`: 15
- `PROTOCOL DECISION`: 5
- `BASE CHANGED`: 7
- `OPEN`: 1
- `REFUTED IN AUDIT`: 1
- `VERIFIED POSITIVE`: 2

## Release boundary

The MW binary is **not ready for launch**. Repository-local tests do not
replace the remaining mandatory evidence:

- two independently authenticated canonical Linux builds and comparison;
- hosted CI plus source, builder, image and tool provenance;
- signed and published release and rollback artifacts with independent
  approval;
- a fresh independently signed weak-subjectivity envelope, authenticated
  signer arrangement and distributed pin evidence (SR-02/SR-03);
- the scratch-systemd rollback drill; and
- staged canary and fleet `/proc` digest evidence.

No binary was signed, published, deployed or released in this wave.
