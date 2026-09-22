# Wave 163 — finality cleanup, v2 ownership and export-mode integration

Date: 2026-09-19
Integration head before this report: `94d5c319`

## Integrated corrections

- Wave 160 replaces repeated FIFO search/removal during finality-refusal orphan
  cleanup with one bounded parent-to-child index, descendant walk and
  order-preserving retain.
- Wave 161 reuses the authenticated v2 plaintext allocation for the returned
  private key, overwriting the former header/seed prefix and wiping the
  remaining old logical tail before truncation. The independent seed owner
  required by the public compatibility API remains.
- Wave 162 rejects group/other-writable canonical wrapper exports before
  hashing, metadata parsing or publication, and makes its fake-engine modes
  deterministic even under an inherited `umask 000`.

Independent reviews verified reachable subtree equivalence, survivor tuple and
counter preservation, overlap-safe in-place secret movement, v2 API/error/KDF/
AES parity, wrapper check ordering and POSIX-mode parity with the comparator.
The wrapper review also reproduced and fixed an initial ambient-umask dependency
in the selftest before integration.

## Validation

```text
cargo test -p bloch-crypto --features wallet-cli --offline
# 243 passed; 0 failed; 4 ignored

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 599 passed; 0 failed; 19 ignored; 63.90s

bash -n scripts/build-pos-release-container.sh
bash -n scripts/build-pos-release-container.selftest.sh
bash scripts/build-pos-release-container.selftest.sh
bash -c 'umask 000; bash scripts/build-pos-release-container.selftest.sh'
# both complete selftest runs: PASS
```

The full crypto and node suites ran outside the restricted sandbox so their
localhost fixtures could bind. The wrapper selftests use a fake container
engine and do not supply independent build or provenance evidence.

The findings ledger remains 200 rows with 200 unique IDs and unchanged status
counts: 71 `IMPLEMENTED`, 98 `PARTIAL`, 15 `UNARMED CANDIDATE`, five
`PROTOCOL DECISION`, seven `BASE CHANGED`, one `OPEN`, one
`REFUTED IN AUDIT` and two `VERIFIED POSITIVE`. EN-08, CR-07 and INF-01 remain
`PARTIAL`.

## Release status

The binary is **not ready for release**. Remaining launch gates still include:

- two independently authenticated canonical Linux builds and comparison;
- hosted CI plus source, builder, image and tool provenance;
- signed and published release and rollback artifacts with independent
  approval;
- a fresh independently signed WS envelope, authenticated signer arrangement
  and distributed pin for SR-02/SR-03;
- a scratch-systemd rollback rehearsal; and
- staged canary and fleet `/proc` digest evidence.

No binary was built, signed, published or deployed by this wave.
