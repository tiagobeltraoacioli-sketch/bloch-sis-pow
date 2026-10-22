# Genesis-4 node 1708953d — validator hardening

Signed Linux x86-64 upgrade release, source commit
`1708953d839d55d461afed80802abacfdb8360c2`.

This release includes the existing pre-activation slashing-evidence guard,
host-level signer locking and durable signing-history protection, detection of
unexpected signatures from the same validator identity, attestation retry
improvements, stricter node-local ML-DSA relay verification, and the finality-certificate RPC. It also contains the integrated
HF1/HF2/HF3 implementation with every new activation gate disabled.

**This binary schedules no new hard fork.** The frozen finality set, own-target
votes, canonical-signature activation, ML-DSA consensus pin, growth cap, new PQ
suite and KES activation remain disabled. The frozen-set review still has three
failing activation tests; this release does not enable that mechanism. Existing
mainnet activation epochs remain unchanged.

Binary SHA-256:

```text
d540e0e446cb7f6761b705bf38d2c348e954954e46d055ced2f4fbbfc604a444
```

Verify the owner-signed checksum before installation:

```sh
minisign -Vm SHA256SUMS -p bloch-release-20260922.pub
sha256sum --check SHA256SUMS
chmod 755 bloch-pos
./bloch-pos --version
```

The first version line must identify the full source commit above.
`VERSION.txt` and `buildinfo.json` contain the expected binary identity.
`BUILD-INFO` preserves the canonical build output, including its original
unsigned-candidate labels; `release.json` records subsequent release status.

Upgrade an existing synchronized Genesis-4 node in place, one validator at a
time per host. Stop the service cleanly, preserve its complete data directory,
validator identity, signing records and signer anchor, replace the executable,
then restart with the existing service configuration. Retain the old executable.
Verify the running executable hash, chain synchronization, finalized checkpoint,
signer-anchor initialization and a new attestation before proceeding.

First boot may require a full historical replay followed by the normal
64-slot doppelganger observation period. Do not bypass that observation or
remove signing-history files. A node on an old branch requires a separately
verified recovery; replacing its executable alone is not a resynchronization
procedure. Do not copy another validator's keys or signing records.

This upgrade bundle does not include keys, passphrases, chain data, genesis
material or a fresh weak-subjectivity checkpoint. It is not a complete
fresh-node onboarding bundle. Linux ARM64 is not qualified by these artifacts.

Validation: 4,051 normal Rust tests passed, with 71 explicitly ignored tests;
the exact candidate replayed 157,148 historical mainnet blocks to the independently
recorded state root. A clean build with Docker cache disabled reproduced the
same binary bytes on the build host. Both production recovery snapshots replayed 161,390 blocks to state root
`b41522508ae82fd929470ac6154e2bfe32cbe54c19ec24718b943f1641f4d9b5`.

Production validation completed on October 21, 2026 at 17:35 UTC. Canaries
`n01` and `n45` synchronized to slot 198247, finalized epoch 6193 on the
reference chain, and attested after their complete 64-slot observation windows
(first epochs 6193 and 6194). Both held the signer-anchor lock, had matching
anchor and data-directory signing records, and showed zero restarts or fatal
or doppelganger events. Their recovery locks were released. These observations
cover two validators; the rest of the fleet has not yet migrated to this release.

The release-owner signature has been verified. The signed manifest authenticates
the binary checksum. Release metadata and these notes describe subsequent checks.

Do not downgrade signing-history files during rollback. An older executable may
reject the newer record format; retain all current signer records and validate
compatibility before considering a binary rollback.
