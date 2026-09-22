# Internal audit remediation — 2026-09-17

Status: **partial remediation, not release approval**. Branch `fix/internal-audit-20260917`, based on `b066e3c` in the isolated `bloch-audit-remediation` worktree. No fleet host, external validator, deployed service, or published binary was changed.

The sections below preserve the first-wave scope and validation (`203b410`). See [second-wave implementation and limits](WAVE-2.md), [third-wave corrections](WAVE-3.md), [fourth-wave corrections](WAVE-4.md), [fifth-wave corrections](WAVE-5.md), [sixth-wave corrections](WAVE-6.md), [seventh-wave corrections](WAVE-7.md), [eighth-wave corrections](WAVE-8.md), [ninth-wave release candidate work](WAVE-9.md), [tenth-wave lifecycle admission work](WAVE-10.md), [eleventh-wave stale-duty quarantine](WAVE-11.md), [twelfth-wave transfer reconciliation and attestation replay work](WAVE-12.md), [thirteenth-wave hybrid transfer admission](WAVE-13.md), [fourteenth-wave derivation-tripwire hardening](WAVE-14.md), [fifteenth-wave lifecycle prose and CI guard reconciliation](WAVE-15.md), [sixteenth-wave attested-image access hardening](WAVE-16.md), [seventeenth-wave terminal-carryover reconciliation](WAVE-17.md), [eighteenth-wave funded decode/judge separation](WAVE-18.md), [nineteenth-wave delegation eligibility ownership](WAVE-19.md), [twentieth-wave fee/tokenomics reconciliation](WAVE-20.md), [twenty-first-wave live state registry reconciliation](WAVE-21.md), [twenty-second-wave validation-stack reconciliation](WAVE-22.md), [twenty-third-wave lifecycle mutation verification](WAVE-23.md), [twenty-fourth-wave domain-registry reconciliation](WAVE-24.md), [twenty-fifth-wave arithmetic and observability hardening](WAVE-25.md), [twenty-sixth-wave protocol-prose reconciliation](WAVE-26.md), [twenty-seventh-wave rollback authentication reconciliation](WAVE-27.md), [twenty-eighth-wave public RPC exposure gate](WAVE-28.md), [twenty-ninth-wave authenticated body admission](WAVE-29.md), [thirtieth-wave SIS test-profile correction](WAVE-30.md), [thirty-first-wave retired-consensus isolation](WAVE-31.md), [thirty-second-wave boot-switch hardening](WAVE-32.md), [thirty-third-wave observer-position reconciliation](WAVE-33.md), [thirty-fourth-wave seed-domain reconciliation](WAVE-34.md), [thirty-fifth-wave doppelgänger-control reconciliation](WAVE-35.md), [thirty-sixth-wave vault-boundary reconciliation](WAVE-36.md), [thirty-seventh-wave hybrid-custody execution](WAVE-37.md), [thirty-eighth-wave Chameleon trust-boundary reconciliation](WAVE-38.md), [thirty-ninth-wave legacy-vout reconciliation](WAVE-39.md), [fortieth-wave pool-advisor reconciliation](WAVE-40.md), [forty-first-wave fork-choice reconciliation](WAVE-41.md), [forty-second-wave local closeout](WAVE-42.md), [forty-third-wave legacy accounting reconciliation](WAVE-43-LEGACY.md), and [protocol blockers](PROTOCOL-BLOCKERS.md) for subsequent work. The finding ledger tracks all waves; a local implementation is not a production security closure.

The resumed pass continues with [asynchronous reorg publication](WAVE-43-STORAGE.md),
[checked vault construction](WAVE-43-VAULT.md), and
[network transport reconciliation](WAVE-43-NETWORK.md). The four-track result
and its combined validation are recorded in the [2026-09-18 integration
checkpoint](WAVE-44-INTEGRATION.md). Continued work records the lifecycle
metering/runbook reconciliation in [Wave 45 ST-12](WAVE-45-ST12.md) and the
mainnet manifest-input tripwires in [Wave 45 ST-11](WAVE-45-ST11.md). The
same pass stages a [deliberately inactive TX-10 resource
candidate](WAVE-45-TX10.md). Wave 46 begins by reconciling the existing
[inactive fee-to-stake candidate](WAVE-46-TX08.md) and the repaired
[inactive Rewards V2 candidate](WAVE-46-TX09.md), then reconciles their
interaction with the [inactive RANDAO-grinding candidate](WAVE-46-FC04.md).
The related [sub-epoch duty-view finding](WAVE-46-FC08.md) is retained as
partial because its source-checkpoint half still needs late-inclusion rules;
the same pass stages the separate [inactive ST-13 activation-queue
candidate](WAVE-46-ST13.md).
Wave 47 starts with an [honest observer-reward message](WAVE-47-ST15.md), while
the underlying whistleblower attribution remains a protocol choice.
Wave 47 also adds an [inactive FC-05 slot-tiebreak
candidate](WAVE-47-FC05.md) that removes the exact next-slot root-grinding
lever while leaving proposer boost, balancing, and same-slot grinding open.
The [Wave 45–47 integration checkpoint](WAVE-47-INTEGRATION.md) records the
combined 200-row ledger, final validation, inactive-gate review, and the seven
findings that still require external evidence or protocol decisions.
Wave 48 begins with [fail-closed operational boundaries](WAVE-48-OPERATIONS.md)
for the read-only fleet verifier and weak-subjectivity release check; neither
change rotates a live credential or creates the still-missing signed envelope.
It also records the [FC-07 disjoint-finality proof and unresolved protocol
choice](WAVE-48-FC07.md); it changes no consensus rule.
Wave 48 also adds a jointly gated, [deliberately inactive slashing-economics
candidate](WAVE-48-ST03-ST04.md): correlation accounting uses effective
exposure consistently and self-slashing loses its 32-epoch withdrawal
advantage. The cap-free E+1 ejection path remains an explicit protocol-policy
residual; no activation or deployment occurred.
The same wave stages a [funded-queue cancellation candidate](WAVE-48-ST16.md)
behind an inert gate and adds a [fail-closed LG-01 evidence
intake](WAVE-48-LG01.md) without changing any historical balance. The combined
result, validation and remaining external boundary are recorded in the
[Wave 48 integration checkpoint](WAVE-48-INTEGRATION.md).
The next pass begins with a [canonical `bloch-pos` container
candidate](WAVE-49-INF01.md). Its recipe and two-builder comparator close a
repository gap, but no Linux build, signature, publication or rollout is
claimed.
Wave 49 adds a [bounded pre-signable clawback fee
ladder](WAVE-49-VAULT-FEE-LADDER.md) so a keyless watchtower can receive finite
RBF alternatives without receiving the recovery key. Dynamic fee selection,
package delivery and relay-policy qualification remain outside that local
construction change.
The [Wave 49 integration checkpoint](WAVE-49-INTEGRATION.md) combines the
release, CI, block-log recovery and vault work, including independent review
findings and the remaining launch blockers.
Wave 50 removes the simultaneous raw whole-log boot copy via
[streaming block-log decode](WAVE-50-EN23.md). Decoded history, quadratic cold
replay, retention growth and production-scale recovery qualification remain.
Wave 50 adds a [strict BV-10 public recovery context](WAVE-50-BV10.md) that
records the vault key family, network, vault ID and funded recovery hash for
deterministic restore. Wave 51 adds an opt-in
[PQ-authenticated context envelope](WAVE-51-BV10-SIGNED-CONTEXT.md) verified
against an independently trusted owner key before restore. Neither change
provides a global reuse/single-use registry or on-chain PQ proof.
External weak-subjectivity onboarding now requires a [mandatory independently
distributed signer-arrangement pin](WAVE-50-SR02.md), including fail-closed CLI
tuple parsing. The V1 checkpoint digest still does not bind the arrangement.
Metrics bound beyond loopback now require an [explicit public-exposure
acknowledgement](WAVE-50-NET21.md); this is not authentication, TLS or firewall
evidence. The [Wave 50 integration checkpoint](WAVE-50-INTEGRATION.md) records
the four-agent review, validation and unchanged launch blockers.
Wave 51 makes the deterministic PQ test override
[scoped-only](WAVE-51-CR08.md), removes repeated fork-choice work from
[canonical cold replay](WAVE-51-EN23-LINEAR-REPLAY.md), and makes block serving
[fail boundedly on an unusable index](WAVE-51-NET22.md). The
[Wave 51 integration checkpoint](WAVE-51-INTEGRATION.md) records cross-review,
the final green local suites and the still-open external launch gates.
Wave 52 removes whole-object [`VaultKeys` cloning](WAVE-52-BV09.md), adds an
independent [default Argon2 allocation ceiling](WAVE-52-KS11.md), fingerprints
the [effective build environment](WAVE-52-KS09.md), and moves
[validator registry RPC reads](WAVE-52-NET01.md) off the consensus thread. The
[Wave 52 integration checkpoint](WAVE-52-INTEGRATION.md) records the four-agent
review, validation and unchanged external release boundary.
Wave 53 adds [Bitcoin-network-aware anchor verification](WAVE-53-BV11.md),
serves [static build identity before the engine queue](WAVE-53-EN18.md),
reserves [devnet backlog capacity before payload decode](WAVE-53-NET22.md),
and makes deploy-image review [fail closed on YAML
inheritance](WAVE-53-INF14.md). The [Wave 53 integration
checkpoint](WAVE-53-INTEGRATION.md) records adversarial lexer review, final
validation and the unchanged external launch gates.

## Scope and source reconciliation

Reviewed the six supplied audit artifacts. The audit describes `562e220`; this patch starts from the persisted-recovery release lineage instead. Its lifecycle gates already activate authenticated exits, slashing evidence, withdrawals, funded admission and RANDAO recommit at epoch 2884. The leak-recovery gate is 2880. Those facts invalidate several statements that the corresponding features are universally inert, but do not prove which binary any independent validator runs. Historical replay must retain old epoch rules.

The complete [finding ledger](FINDINGS.md) retains all 197 area findings plus LD-01–03. Counts are **finding rows, including duplicates**, not independent vulnerabilities. Implemented changes have local test evidence; they are not evidence of live remediation. Many original findings remain open.

## Implemented behavior

- Mempool admission checks referenced inputs, ownership, duplicates, block fit and value conservation at the current base fee before hybrid verification. Missing parents and fee-dependent mismatches return a retryable refusal. Unconfirmed transaction packages remain unsupported.
- Mempool encoded payload is capped at 16 MiB in addition to transaction count. Object storage, encoded keys and indexes add memory overhead. Cached txid/source indexes remove repeated whole-mempool hashing. Alternate encodings and signatures share a pending identity.
- Proposal selection skips transactions that do not fit instead of stopping selection. Legacy unauthenticated exits are not proposed. Consensus still follows the epoch gates.
- Authenticated future gossip waits in a 32-entry / 16 MiB queue until its slot. Future blocks cannot immediately enter fork choice. Held attestations pass through the existing startup-slot doppelganger check.
- Inbound devnet connections are limited to 32 per IP (128 globally), and RPC connections to 8 per IP (64 globally). Shared get-blocks budgets persist across reconnects: 8/s, burst 32 per IP; 64/s, burst 128 globally. The address budget map is bounded. IPv4-mapped IPv6 addresses are normalized. These limits are node-local and require NAT/topology qualification before fleet rollout.
- Sync pages have an aggregate 8 MiB payload budget. libp2p requests read only a 13-byte request plus a rejection sentinel. Identify advertisements cannot replace configured dial bookkeeping, and peer-score setup failures stop startup.
- RPC bounds parsed JSON values and echoed IDs. At most 16 calls can await the engine, including work whose HTTP caller has timed out. More state queries use the immutable published head; remaining engine RPC methods and per-peer fairness are still open.
- Key generation locks the data directory and refuses to replace an existing identity. New sealing requires 12 passphrase characters. Existing sealed keys remain readable. Passphrase-file permissions are checked on the production path. Private files are written atomically and fsynced. WS secret buffers and permissions are hardened.
- Transfer/funded-deposit block budgets are checked before execution, with cumulative checks after every transaction charge. This changes error precedence for already-invalid blocks, not the intended accepted block set. Unmetered legacy transaction classes remain a separate issue.
- Faucet address cooldowns canonicalize hex case; JSON content type and Fetch Metadata checks reject browser cross-site/form submissions. Python amount parsing rejects Unicode numerals and oversized wire values; the SDK generator carries the same fix.
- Vault API refuses PQ keys that previously reached a panicking wrapper and explicit CSV delays below 144. Signed anchors reject trailing bytes. Watchtower documentation no longer claims RBF alone gives a keyless watcher replacement authority. Existing low-level vault derivation and spending formats are unchanged.
- Root Rust toolchain is pinned to 1.94.1. Source digests include C `.macros` inputs, hidden source directories and the toolchain pin. Docker excludes common secret files. Root rustls is 0.23.45 and rustls-webpki is 0.103.15, addressing [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html).

## Consensus candidates, deliberately inactive

FC-01 has a regression reproducing an all-zero duty roster and a candidate fallback to the unleaked consensus roster. `DUTY_ROSTER_RECOVERY_ACTIVATION_EPOCH = u64::MAX` means production behavior is unchanged. This is **not a closed liveness finding**. Its gated regression passed again after the final gate-helper change. The candidate affects every consumer of the consensus roster, including the rewards-v2 path, and must be qualified with complete outage/rejoin, partition, finality, rewards, historical replay and weak-subjectivity tests before activation. No activation epoch is proposed here.

TX-10 now also has a transaction-count candidate behind
`STAKING_TX_METERING_ACTIVATION_EPOCH = u64::MAX`. The 4,096 ceiling is not
consulted in production and its regression proves the pre-gate verdict is
unchanged. It must not be armed without historical replay, non-reference
producer analysis, resource qualification, and a coordinated fleet release.

For FC-02/ST-01 the proposed direction is stake-proportional weight rather than a calendar allocation that gives one outsider a supermajority. Counting public keys cannot establish independent operators. No cohort economics were silently changed; a reviewed protocol decision and coordinated validator release remain required.

## Validation

Commands run with Rust 1.94.1 and the checked-in dependency resolution:

- `cargo test -p bloch-pos-committee --offline`: committee library 424 passed, 4 ignored; all committee integration suites passed (185 additional tests, 2 ignored).
- `cargo test -p bloch-pos-node -p bloch-pq-vault --offline`: node unit tests 391 passed, 19 ignored; all node integration suites passed, including the real three-process cold-start sync test. Vault 22 passed. Ignored activation rehearsals were not counted as passed.
- `cargo test --manifest-path services/pq-shield-api/Cargo.toml`: 11 passed.
- `npm test` in `tools/faucet`: selftest and all 10 security tests passed.
- `PYTHONPATH=sdk/python python3 -m unittest discover -s sdk/python/tests`: 3 passed.
- Configured root `cargo-audit`: no reported vulnerabilities. Existing accepted advisory exceptions still apply; this is not an all-lockfile audit or a claim that ignored risks disappeared. The bincode exception now explicitly acknowledges first-party restart-cache usage.
- The separate RPC timeout/queue regression passed (1 test): timed-out callers cannot free capacity while the engine still holds the work.
- `cargo clippy -p bloch-pos-node -p bloch-pos-committee -p bloch-pq-vault --all-targets --offline`: passed with warnings, after using the shared epoch-gate helper for the unarmed recovery candidate.

The first broader run exposed a cold-start fixture expecting only `validator.key`; it now also expects the advisory `LOCK` file created by safe key generation. It still rejects any donated block log/state and passes the full sync comparison.

**CI limitation:** `cargo fmt --all -- --check` reports formatting differences across 281 files, including unchanged base files. A workspace-wide formatting migration is not mixed into this security patch because it would conflict extensively with parallel EVM/DEX/bridge work. The formatter gate is not claimed green. `cargo-deny`, all-lockfile scanners, release reproducibility, Linux production benchmarks, lifecycle mutation scripts and ignored flag-day rehearsals were not run in this pass.

## Remaining release blockers

1. Qualify and coordinate the liveness/economics/partition safety changes; do not activate the candidate merely because its isolated test passes. Review FC-07 and the interaction of inactivity leak with weak subjectivity.
2. Complete consensus-thread resource isolation and per-peer verification/fairness budgets; bound noncanonical block retention and qualify stale-state signing behavior. Current limits are mitigations, not DDoS immunity.
3. Separate operator credentials, prove host-loss fencing, prepare independent WS signatures and signed release/rollback artifacts. Source edits cannot establish that remote credentials were rotated or independent signers approved a checkpoint.
4. Integrate product-owner changes for vault key separation/hardened recovery derivation, watchtower fee strategy, Coherence note authorization and bridge custody before enabling those products. Never reinterpret existing vault addresses by changing V1/V2 derivation in place.
5. Resolve ledger provenance with reproducible source data. The second wave makes the legacy exporter fail on corrupt rows; that does not explain the historical missing subsidy. Do not rewrite Genesis-4 balances from an inferred missing subsidy.
6. Consolidate EVM, DEX, bridge and aggregator branches, repair inherited CI formatting and run a complete pinned release qualification. Inventory actual binaries on independently operated validators before proposing an activation epoch.

A reviewed upgrade should first run on an isolated chain and observer canary, then on authorized validators with measured restart recovery and rollback checks. This document does not claim a production recovery-time SLA from Mac debug tests.
