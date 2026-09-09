# Validator lifecycle implementation verification

Date: 2026-09-09. Base: `58b07c7e0600dfbcea54cfd2c1bfd463a5cee1ab`.
This report records local implementation evidence, not a mainnet activation
approval. All five lifecycle constants remain `u64::MAX`.

## Implemented

- ADR-041 codecs: `ExitV2 = 0x0C`, `Withdraw = 0x0D`,
  `RandaoRecommit = 0x0A`; `0x07` through `0x09` remain tombstoned.
- Explicit committed funded provenance, per-genesis-record unissued
  principal, minimum bond history and the withdrawal write-off counter.
  A funded bond pays its remaining balance; an unbacked bond pays accrual
  only. All withdrawal checks precede mutation.
- Evidence observation enters normal transaction admission and relay.
  Slashing records the bond floor and cannot pay rewards from unissued
  principal. Exit, evidence and renewal retain the existing signature and
  prosecution rules.
- State-aware funded admission before mempool eviction or relay, pending
  funding/key conflict checks and lifecycle revalidation after head changes.
  Libp2p transaction forwarding waits for the engine verdict.
- Offline exit/withdrawal commands, trusted-genesis checks before deposit
  signing, RPC lifecycle details, automatic own withdrawal and private,
  restart-safe RANDAO generations.
- Proposed finalized eligibility for funded activation, with the existing
  eight-epoch minimum and four-per-boundary churn, without backdating.
- Missing-parent synchronization repair discovered during partition testing.

The contract and operator commands are in
[BLOCH-VALIDATOR-LIFECYCLE.md](../specs/BLOCH-VALIDATOR-LIFECYCLE.md).

## Verification

Rust was pinned to `1.94.1`; Cargo commands used `--locked`. No dependency
or lockfile changes were required.

| Check | Result |
|---|---|
| `cargo test --locked -p bloch-pos-committee` | 608 passed across 12 test/doc suites; 6 ignored |
| `cargo test --locked -p bloch-pos-node` | 393 passed across 10 suites; 20 ignored |
| Full lifecycle and mempool rehearsal | 2 passed in 489.60 seconds, including post-slash withdrawal, spend and replay |
| Short-chain RANDAO rehearsal | 1 passed in 6.71 seconds; multiple renewals and restart checks |
| Withdrawal guard mutations | Control passed; 8/8 mutations killed by executed test failures |
| Committee hardened Clippy score | Existing baseline preserved: panics 0, arithmetic 186, other 0 |
| Node hardened Clippy score | Existing baseline preserved: panics 8, arithmetic 0, other 0 |
| CI test-posture guard | Eight live crates remain blocking in both existing pipelines |

The node suite includes a cold node synchronizing over real libp2p with
three processes, encrypted keystore tests, offline CLI tests and regression
guards against claiming that production finality already has active slashing.
The ignored performance/release tests are not represented as passing tests.
The other workspace crates and the whole-workspace hardened script were not
rerun locally; the changed consensus/node targets were checked directly.

Reproduction:

```sh
cargo +1.94.1 test --locked -p bloch-pos-committee -p bloch-pos-node
python3 scripts/rehearse-validator-admission.py
python3 scripts/check-validator-lifecycle-mutations.py
python3 scripts/check-tests-blocking.py
```

The lifecycle script compiles a disposable source copy with all five gates
at zero. Two independent engine states exchange actual signed attestations,
encoded blocks and transactions. The scenario registers a funded key,
waits for finalized eligibility, observes its proposal and included
attestation, signs an exit, observes and prosecutes a conflicting proposal,
waits through the real 2,048-epoch withdrawal lock, automatically cranks the
withdrawal, spends the payout with the credential key and replays the chain.
The test advances a test-only clock; it does not wait for 23 wall-clock days.
Proposer selection is observed rather than assumed within a small fixed
window. A second pass uses 16-reveal chains to exercise multiple automatic
renewals, missed-slot recovery and restart identity checks. Production has
no switch to activate either test configuration.

Mutation checks remove activation, maturity, one-shot, indeterminate backing,
credential length, checked narrowing, output collision and write-off overflow
guards separately. A compiler or infrastructure error does not count as a
killed mutation. The checked-out source is never mutated by either script.

### Four-process partition regression

The existing devnet partition script ran with four throwaway validators,
1,000 ms slots, split at slot 35, heal at slot 70 and stop at slot 110. The
shipping gates remained disabled. The disposable-key doppelganger observation
window was bypassed only for this test.

| Run | Observation |
|---|---|
| No-partition control | 4/4 converged in every phase; final sampled head `abb39f18`, finalized epoch 1 |
| Partition before repair | Two branches during the split; one node still diverged after healing |
| Partition after repair | Expected two branches while split; 4/4 converged after healing on `b86d05cd`, slot 108, height 85; no own-block refusals or `NotInCommittee` errors |

Both complete control and partition runs took 116 seconds. The repaired run
crossed three epoch boundaries. Its sampled finality remained at epoch zero;
this run proves head reconvergence, not a sustained post-partition finality
recovery or a fleet activation rehearsal.

The failure was caused by requesting only slots newer than the local head
when an unknown parent belonged to an older competing branch. Repair starts
a bounded request window before the earliest orphan, floored at the local
finalized block. A focused regression proves that successive missing parents
move this cursor backwards while the committed head/root remain unchanged.
Existing response pagination, ingress limits and sync cadence still apply.

Reproduction (use a new disposable directory and free local ports):

```sh
cargo +1.94.1 build --locked -p bloch-pos-node --bin bloch-pos
BLOCH_POS_BIN="$PWD/target/debug/bloch-pos" \
  BLOCH_KEYSTORE_ALLOW_PLAINTEXT=1 BLOCH_NO_DOPPELGANGER=1 \
  BASE_PORT=28910 RPC_BASE=29010 \
  bash scripts/devnet-particao.sh /tmp/bloch-lifecycle-partition 4 1000 35 70 110 split
```

## Release work still required

1. Review the proposed finalized-eligibility rule and the combined consensus
   diff, then choose and announce the common lifecycle epoch `L`.
2. Reconcile ADR-041 T-6 with `SlashingState`'s existing one-prosecution rule.
   `an_ejected_validator_is_not_punished_again` expressly rejects a second
   prosecution of the same validator. The implementation preserves that
   rule; it does not implement a later correlated debit of an already-slashed
   residue. The withdrawal-lock tests must not be used to claim otherwise.
3. Complete a coordinated transport soak with the lifecycle enabled,
   including prosecution, post-slash withdrawal and sustained finality.
   The engine rehearsal and shipping-gate transport control are separate
   pieces of evidence, not that combined fleet gate.
4. Conduct the fresh weak-subjectivity ceremony with the required 2-of-3
   independently controlled signatures, including an external signer.
   An unsigned checkpoint does not replace the signed envelope.
5. Build a reproducible release, verify it on every participating fleet node,
   perform the coordinated devnet/dual/libp2p migration and observe convergence.
   A single dual node does not bridge blocks between the two meshes.
6. Settle a full mainnet withdrawal before announcing public validator
   admission. No production deployment, activation, signing ceremony or
   independent cryptographic/consensus audit was performed in this work.
