# Wave 143 — rollback publication, replay and secret-copy integration

Date: 2026-09-19
Integration head before this report: `2d0e09a9`

## Integrated corrections

- Wave 140 makes rollback publication fail closed across ordinary command
  failures and filename collisions. Both outputs are copied to exclusive
  temporary files in the output filesystem; atomic no-overwrite hard links
  publish the public key first and the tarball completion artifact last.
  Cleanup removes a final name only when inode identity proves it belongs to
  the current invocation.
- Wave 141 reuses one bounded raw-frame scratch allocation during cold
  block-log replay after the existing cap, overflow and truncation preflights.
  Decoded envelopes remain fully owned and disk/error semantics are unchanged.
- Wave 142 places the password denylist's trimmed/lowercased repository copy
  under `Zeroizing<String>` ownership without changing policy, Unicode
  behavior, API, KDF, RNG, ciphertext or output bytes.

## Review findings closed before integration

The first Wave 140 draft had two review blockers and was not committed:

1. it published the tarball before the adjacent public key; and
2. assigning a cleanup target before a replacing `mv` could remove a file
   created by a concurrent actor.

The final design validates the tarball privately, uses hard-link publication
that refuses existing names atomically, and checks inode identity before
cleanup. Tests inject both a final-link failure and an exact collision race.

## Validation

```text
cargo test -p bloch-crypto --features wallet-cli --offline
# 237 passed; 0 failed; 4 ignored

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 593 passed; 0 failed; 19 ignored; 62.37s

bash -n deploy/rollback/make-rollback-package.sh
bash -n deploy/rollback/make-rollback-package.selftest.sh
# passed

rollback focused fixture harness
# 11 passed: 7 SHA cases, publication failure, publication race,
# and 2 pre-existing collision cases
```

The full crypto and node suites ran outside the restricted sandbox for their
localhost fixtures. The rollback fixture harness used a temporary non-signing
minisign shim only to reach the new failure paths. The complete cryptographic
selftest still requires a real disposable minisign installation and is not
claimed as locally completed.

The findings ledger remains 200 rows with 200 unique IDs and unchanged status
counts. INF-09, NET-22 and CR-07 remain `PARTIAL` with their residuals stated
in the ledger and individual reports.

## Release status

The binary is **not ready for release**. These local corrections do not replace
the remaining external release evidence:

- two independently authenticated canonical Linux builds and comparison;
- hosted CI plus source, builder, image and tool provenance;
- signed and published release and rollback artifacts with independent
  approval;
- a fresh independently signed WS envelope, authenticated signer arrangement
  and distributed pin for SR-02/SR-03;
- a scratch-systemd rollback rehearsal; and
- staged canary and fleet `/proc` digest evidence.

No binary was built, signed, published or deployed by this wave.
