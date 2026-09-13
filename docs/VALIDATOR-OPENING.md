# Validator opening release checklist

Status: **blocked by conflicting live finalized checkpoints observed on
2026-09-13 UTC**. The read-only survey found 56 RPCs on one finalized history,
six on another and one stale node. Index 63 was subsequently located inactive
on HOST-006, with an older masked copy on CLASSIC-003. See the
[preflight and approved recovery reference](audit/VALIDATOR-ACTIVATION-PREFLIGHT-2026-09-13.md).
The isolated candidate schedules leak recovery at epoch 2880 and the lifecycle
at epoch 2884 on 2026-09-14; this is not a completed deployment. The earlier four-process devnet did not reconverge
after a 300-slot partition; its two groups reported conflicting finalized
roots at epoch 13 under historical pre-1,400/pre-2,700 rules. This does not
establish a new defect in the current mainnet regime. See the scope below.
Implementation reference: `21a9311` (ADR-041), merged in `22b8b7f`.

## Implemented prerequisites

- Funded registration consumes existing UTXOs and verifies both hybrid-PQ roles.
- Activation requires finalized funding, the eight-epoch delay and the
  four-validator per-epoch churn limit.
- State-aware mempool validation precedes eviction and relay; lifecycle
  transactions are revalidated on head changes.
- Deposit signing requires a trusted local genesis manifest before key unlock.
- Authenticated exit uses 0x0C; withdrawal uses 0x0D; RANDAO recommit uses
  0x0A. Bytes 0x07–0x09 remain retired.
- Withdrawals pay backed stake to committed credentials; unissued genesis
  principal is written off. Evidence submission and automatic withdrawal and
  RANDAO renewal are implemented.

These are implementation findings, not deployment or independent-audit claims.
The September 8 admission review describes an older base; its reproductions
must not be interpreted as the current disposition of every finding.

## Local qualification

Run from the release checkout and retain the commit, commands and complete
logs. A failed build, zero matching tests or infrastructure failure is not a pass.

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee -p bloch-pos-node
python3 scripts/rehearse-validator-admission.py
python3 scripts/check-validator-lifecycle-mutations.py
bash scripts/hardened-clippy.sh
```

The isolated rehearsal co-activates all five gates at zero. It exercises
funded registration, finality, new proposer and attester duties, authenticated
exit, evidence prosecution, the withdrawal delay, automatic withdrawal,
spending the payout and replay. A separate short-chain build exercises RANDAO
renewal. This does not prove compatibility across a future finite activation
boundary or transport behavior between independent processes.

The mutation check must pass its unmodified control and kill all eight
withdrawal guard mutations. Both isolated checks preserve shipping constants.

Local evidence on 2026-09-12, against implementation `4eec48b`:

- `check-validator-lifecycle-mutations.py`: control passed; all eight mutations
  killed (activation, maturity, one-shot, indeterminate provenance, credential,
  narrowing, output collision and write-off overflow).
- `check-tests-blocking.selftest.py`: all 15 cases passed.
- `check-tests-blocking.py`: both pipeline live-crate guards passed.
- `cargo +1.94.1 test --locked -p bloch-pos-node --test validator_deposit_cli`:
  the sealed offline prepare/sign/inspect and overwrite-refusal test passed.
- `rehearse-validator-admission.py`: full lifecycle and invalid-state mempool
  rehearsal passed, followed by the short-chain automatic RANDAO renewal test.
  The source-integrity check confirmed that shipping gates remained unarmed.
- `devnet-particao-report.test.py`: eight regression fixtures passed, rejecting
  missing/partial samples, idle genesis, no proposals, divergent heads and
  missing/conflicting state roots.
- Four-process transport control (1,000 ms slots; restart boundaries 20, 60,
  110): final samples agreed at slot 107, height 98, block
  `0a3c95789d46408b8eeb116552aea5d44c467a0a7acac21fabf7ec3a2d162c14`, state root
  `e1f3549329222f53f2923916602407bd30a9d7bb5eb5ca798e024b49a4ecbc78`.
  Finality was still epoch zero; this short control does not demonstrate
  finality recovery. Intermediate RPC samples were at different slots.

This evidence does not complete the release-candidate checklist below.

### Failed partition qualification

Four independent processes, 500 ms slots, split at slot 30, reconnected at
330, stopped at 490. The partition lasted 300 slots (9.375 epochs). Lifecycle
gates were unarmed; this is a transport/consensus diagnostic of the existing
implementation, not a demonstration that funded admission caused the failure.

After reconnection, nodes 0/1 reported finalized epoch 13 with root
`479fa3d190133e9e7827ed4a3368ec05a06cefe12426315f8dcd3c3da813465c`;
nodes 2/3 reported the same finalized epoch with root
`f170cb74814355c24a9c36d60086f95b18aa9f362ead8b8f4830b5dbb9f15a84`.
The harness returned exit status 1. Unlike different moving-head samples,
these conflicting finalized checkpoint claims cannot be explained by sampling
adjacent slots alone. Root cause has not been established.

Scope correction: the devnet started at epoch zero, below the shipped
`LEAKED_ROSTER_ACTIVATION_EPOCH = 1400` and
`LEAK_RECOVERY_ACTIVATION_EPOCH = 2700`. The network-level limitation of
leak-adjusted quorums is already documented in
[`finality.rs`](../crates/bloch-pos-committee/src/finality.rs), including the
founder-selected one-half denominator floor and its residual conflicting-quorum
risk. This result is consistent with that documented limitation; it is not a
new funded-admission regression and does not qualify current-era recovery.
The selected floor must not be silently changed as an onboarding repair.

[RPC snapshots and terminal log lines](audit/reproducers/validator-partition-2026-09-12.json)
preserve all three phases. Reproduce with a fresh disposable directory:

```sh
cargo +1.94.1 build --locked -p bloch-pos-node --bin bloch-pos
BLOCH_KEYSTORE_ALLOW_PLAINTEXT=1 BLOCH_POS_BIN="$PWD/target/debug/bloch-pos" \
  bash scripts/devnet-particao.sh /tmp/bloch-partition-fresh \
  4 500 30 330 490 split
```

The harness creates throwaway keys and skips doppelganger observation only
for those fresh devnet identities. Never use production keys or data paths.
The matching timing control (500 ms; boundaries 30/330/490; full mesh in every
phase) passed on 2026-09-12 with all four nodes agreeing in each final phase
sample. The final sample was slot 486, height 468, with a common finalized
checkpoint at epoch 13. Its snapshots and terminal lines are included in the
same evidence file. Both runs generated fresh devnet keys/manifests; the
control isolates the schedule, not every randomized input.

Still qualify the intended activation-era rules and production transport,
and state the accepted partition assumptions before claiming recovery or
selecting mainnet L. A successful connected control does not turn the
partition result into a pass.

## Remaining release evidence

- [ ] Passing local qualification logs for the exact release candidate.
- [ ] Before/at/after finite-L compatibility rehearsal, including replay and
  old/new binary agreement below L.
  The compressed current-regime finite-boundary and unarmed/armed build
  comparison now pass; exact deployed-binary qualification remains pending.
- [ ] Independent processes and data directories connected through P2P:
  funded joining, late joining, restart after reveals, and consistent state
  roots at the same block.
- [ ] Partition longer than the activation delay, competing registrations,
  finality recovery and pending authentication after registry growth.
- [ ] Multi-epoch devnet soak across at least three epoch boundaries, including
  evidence prosecution and post-slash withdrawal; retain transaction IDs,
  block IDs, finalized checkpoints and payout-spend evidence.
- [ ] Verify the operator's actual RPC endpoint serves `getvalidatoradmission`,
  `getvalidatorbykey` and transaction status, and that authenticated submission
  reaches the intended upgraded node.

Endpoint observation, 2026-09-12: `https://posternlabs.com/g4rpc` rejected
`getvalidatoradmission` with JSON-RPC `-32601` and `reason: method_not_allowed`.
This is a proxy restriction, not evidence that admission is active or inactive
on its upstream node. Use an operator-controlled node or qualify an updated
proxy before directing candidates to that endpoint.

`scripts/devnet-particao.sh` is a generic partition diagnostic. Its head
snapshots alone do not qualify funded joining or the full lifecycle.

## Coordinated mainnet activation

1. Record the founder-approved finite epoch L, measured current network epoch,
   fleet inventory and deployment window with sufficient upgrade time.
2. Set admission, authenticated exit, withdrawal, slashing evidence and RANDAO
   recommit to that same L in one reproducible release. Keep legacy unfunded
   deposit/delegation disabled. Re-run qualification against that candidate.
3. Publish the release artifact digest and activation notice. Upgrade and
   verify every validating node against the inventory before L, recording
   binary digest and RPC observations. Investigate any conflicting state roots
   for the same block before proceeding.
4. After L, complete a controlled funded lifecycle through a settled mainnet
   withdrawal and spend of its payout. The real withdrawal delay applies;
   do not shorten production parameters to complete qualification faster.
5. Announce external-validator opening only after that settlement, as required
   by [ADR-041](adr/ADR-041-validator-exit-and-withdrawal.md).

After activation, reverting to a pre-L binary is not a safe rollback. A
pre-activation postponement requires a coordinated replacement release before
the previously announced L; record the fleet's acceptance of the new schedule.

Operator preparation and offline deposit commands are in the
[funded admission specification](specs/BLOCH-FUNDED-VALIDATOR-ADMISSION.md).


### Independent-process funded joining — 2026-09-13

`rehearse-validator-joining-network.py` passed with two independent processes
and fresh throwaway identities. Funded admission was refused before epoch 4,
accepted after epoch 4, and the joining identity became active at epoch 12 on
both processes. Its own process then proposed and attested. Both ended at slot
703, height 703, state root
`f2fe37df18c1b49b37cde8b9ce60a42ac280019cbf0145b60549b49c233afc8a`.

The fixture funds the deposit through a real encoded genesis allocation and
uses the real hybrid signatures. Existing finite gates are compressed to epoch
1; the five lifecycle gates are at epoch 4. Plaintext opt-in and the disabled
doppelganger wait apply only to these newly generated devnet identities.
Shipping parameters remained unchanged. This demonstrates transport admission,
finalized registration, activation and duties; the longer exit/slash/withdrawal
cycle remains covered by the separate lifecycle rehearsal.

[Retained network evidence](audit/reproducers/validator-joining-network-2026-09-13.json)
includes both active registry records, the pre-L refusal, the accepted deposit
and complete terminal roots. CI now runs this rehearsal as a blocking step.

A subsequent rehearsal with default duplicate-instance protection enabled
also passed, ending at slot 703, height 640 and state root
`a334b8732b18ae71f72090e02fa5f37b1c390fa41bf09f154046de917fac5753`.
Both stores include the joining validator's proposals and attestations.
A warm restart of a copy of the stopped founder store replayed all 640 blocks,
completed the post-replay observation window, and resumed duties exactly at
its deadline slot 1012 without a false duplicate report. See
[protected rehearsal evidence](audit/reproducers/validator-joining-network-protected-2026-09-13.json).
The current CI rehearsal uses default observation; the earlier bypassed run
above remains historical evidence.


### Monday candidate schedule

The operator selected Monday, 2026-09-14 and delegated the best technical time.
The candidate uses epoch 2880 at 21:31:19 UTC (18:31:19 America/Sao_Paulo)
for leak recovery and lifecycle epoch 2884 at 22:35:19 UTC (19:35:19 local).
Every signer and serving archival must be upgraded before the first boundary.
Qualification or readiness failure requires a coordinated postponement before
that boundary; a partial fleet must never cross it. Source scheduling alone
does not authorize announcing broad external-validator opening before the
ADR-041 controlled withdrawal-and-spend qualification.
