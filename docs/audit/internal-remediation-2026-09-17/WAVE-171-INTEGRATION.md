# Wave 171 — borrowed replay, bounded disclosure and comparator integration

Date: 2026-09-19
Integration head before this report: `b59bb685`

## Integrated corrections

- Wave 168 makes deep canonical replay borrow retained envelopes directly from
  the block map instead of cloning the entire replay prefix into a temporary
  aggregate. Required per-block transition ownership remains unchanged.
- Wave 169 gives the shared `verify-bundle`/`watch` CLI loader a 64 MiB file
  budget with a one-byte excess probe before Serde allocation.
- Wave 170 requires exactly one hard link for all three artifacts in each
  comparator input tree, complementing its existing type, mode, directory and
  cross-tree identity checks.

Independent reviews verified replay order and state-root equivalence across
the snapshot fallback, exact-limit and one-byte-over disclosure behavior, and
the comparator's six hard-link checks under both ordinary and permissive
caller umasks. Review also narrowed two documentation claims: the disclosure
budget preserves canonical/ordinary serialization rather than arbitrarily
padded JSON, and comparator checks are per input tree rather than one global
six-file preflight.

## Validation

```text
cargo test -p bloch-crypto --features wallet-cli --offline
# 245 passed; 0 failed; 4 ignored

cargo check -p bloch-pos-node --bin bloch-pos --offline
# passed

cargo test -p bloch-pos-node --bin bloch-pos --offline
# 601 passed; 0 failed; 19 ignored; 61.38s

bash -n scripts/compare-pos-release-builds.sh
bash -n scripts/compare-pos-release-builds.selftest.sh
bash scripts/compare-pos-release-builds.selftest.sh
bash -c 'umask 000; bash scripts/compare-pos-release-builds.selftest.sh'
# both complete comparator selftest runs: PASS
```

The full crypto and node suites ran outside the restricted sandbox so their
localhost fixtures could bind. Comparator selftests use synthetic local trees
and do not supply independent build or provenance evidence.

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
