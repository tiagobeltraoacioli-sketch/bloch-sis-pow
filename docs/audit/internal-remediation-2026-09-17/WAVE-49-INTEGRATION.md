# Wave 49 integration checkpoint

Date: 2026-09-18. Branch: `fix/internal-audit-20260917`. Comparison base:
`1acd578`. This checkpoint combines four-agent implementation and independent
cross-review. No consensus gate was armed, no production binary was built or
signed, and no deployment, fleet host, credential, fund or public network was
changed.

## Ledger result

All 200 finding rows and their classifications remain intact:

- 71 `IMPLEMENTED`;
- 98 `PARTIAL`;
- 15 `UNARMED CANDIDATE`;
- 5 `PROTOCOL DECISION`;
- 7 `BASE CHANGED`;
- 1 `OPEN`;
- 1 `REFUTED IN AUDIT`; and
- 2 `VERIFIED POSITIVE`.

This wave materially narrows INF-01, INF-11, KS-07, BV-02 and BV-08, but does
not misclassify local tooling as external release, fleet or relay evidence.
SR-03 remains the sole open finding because the repository still has no
independent signer set and signed fresh checkpoint envelope.

## Integrated changes

INF-01 now has a canonical `/build` container candidate. The Rust image,
Debian archive view, committed source archive, lockfile, compiler, build stamp
and commit timestamp are pinned or checked. Output remains explicitly unsigned
and unauthorized. A fail-closed comparator checks two distinct executable
artifacts, internal checksums and the complete eight-field metadata. It refuses
the same directory supplied twice, but builder independence still requires
separately authenticated build records.

INF-11's blocking-job posture guard now recognizes the hardened clippy gate in
both CI providers and refuses more waiver, conditional execution, inheritance
and shell-success masking shapes. Its supported parser remains deliberately
narrow; hosted branch protection and arbitrary YAML/shell semantics are not
claimed.

KS-07 gains an explicit offline tail-repair command. It repeats inspection
under the data-directory lock, requires the exact inspected offset, accepts
only an incomplete or all-zero suffix, durably creates a private non-replacing
backup, then truncates and synchronizes the log. It does not auto-repair at
boot, infer mid-log corruption or replace the missing per-frame checksum.

BV-02/BV-08 gain bounded 2–32-step clawback fee ladders. Fees are strictly
increasing; each replacement is independently checked and produces its own
`SIGHASH_ALL` digest. The public-only API returns unsigned alternatives for
offline pre-signing, allowing a keyless watchtower to receive finite options
without `recovery_sk`. Dynamic estimation, package refresh/delivery, CPFP,
anchor provenance and relay/BIP-125 qualification remain outside this change.

## Independent review corrections

Cross-review found and corrected four integration defects:

- the release comparator no longer describes one directory supplied twice as
  two independent outputs;
- non-executable binaries and noncanonical or differing complete metadata are
  refused;
- the block-log operations guide now describes the new mutating command; and
- a literal patch marker was removed from CLI help and pinned by a regression.

The vault wave's swapped `BASE CHANGED`/`OPEN` prose counts were also corrected
to match the mechanically verified ledger.

## Validation

- Full `bloch-pos-node` tests passed outside the socket-restricted sandbox:
  504 unit tests passed, 19 benchmark/rehearsal tests were ignored, and every
  integration target passed. The initial sandbox run's 147 failures were all
  local-socket `PermissionDenied` errors. The post-review block-log CLI suite
  then passed 3/3.
- Store tests passed 26/26. The repair CLI tests cover exact-offset refusal,
  immutable failure, durable removed-byte preservation and clean help output.
- `bloch-pq-vault` passed 35/35 and `pq-shield-api` passed 19/19.
- The security guard passed 23 adversarial fixtures and verified eight
  blocking jobs in each CI provider. The test guard passed 37 fixtures and
  confirmed explicit coverage of eight live crates in both providers.
- The release comparator self-test passed honest comparison plus six refusal
  cases. Shell syntax, comment/constant checks and `git diff --check` passed.

Docker/BuildKit was unavailable, so the canonical container was not built and
its base digest, APT snapshot and Linux output were not exercised locally.
This is a release blocker, not a skipped test represented as green.

## Launch boundary

The new binary is **not ready to launch**. At minimum, two independently
authenticated Linux builders must reproduce the canonical container bytes;
hosted CI must be green; release and rollback artifacts need signatures and
independent approval; a fresh weak-subjectivity signer set/envelope must exist;
rollback must be rehearsed on a scratch systemd host; and a staged rollout must
finish with `/proc` digest verification across the fleet. No production
readiness notice should be issued before those records exist.
