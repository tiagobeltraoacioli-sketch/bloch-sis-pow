<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Funded delegation lifecycle

Status: implementation candidate, consensus gate unarmed

This document specifies the funded replacement for legacy transaction tag
`0x04` (`Delegate`). The legacy message names an amount without consuming an
eUTXO and therefore remains permanently disabled. No rule in this document is
active until an explicit, coordinated activation epoch is released to the
entire validating fleet.

## Safety properties

1. Every bonded satoshi is removed from a transparent eUTXO owned by the
   funding key. Fees and change conserve the remainder exactly.
2. A delegation is controlled by the funding key that created it. The
   validator operator cannot deactivate, redirect, or withdraw it.
3. Activation uses the existing delegation warm-up budget. Inclusion never
   gives immediate consensus weight.
4. A validator may accept at most 500,000,000 BLCH of delegated principal.
   Pending, active, cooling-down, and withdrawable positions reserve capacity
   until withdrawal. This fixed limit replaces the legacy percentage cap for
   the delegated component after activation; own stake is outside this limit.
   Cohort caps, inactivity leaks, and pro-rata slashing still apply.
5. Deactivation uses the existing cool-down budget. Withdrawal additionally
   waits the validator weak-subjectivity delay after the position has become
   fully inactive.
6. Principal, rewards, and slash losses are isolated per position. Withdrawing
   one position cannot consume another position's credit or loss.
7. Every intent commits to the canonical genesis-manifest digest, its replay
   bound (inclusive expiry for creation or exact epoch for lifecycle actions),
   all economic fields, and a role-specific SHA3-256 domain.

## Identities and committed state

Each funded delegation allocates a monotonically increasing `delegator_id`
and an append-only `position`. A committed owner record binds the identifier
to `SHA3-256(funding_pubkey)`. Allocating a new identifier for every position
is deliberate: one wallet may create many positions, while the existing
reward and slash ledgers are keyed by `delegator_id`. The one-position rule
keeps all accounting isolated without ambiguous pro-rata withdrawals.

The state commits:

- `delegator_id -> owner_hash`;
- the existing delegation record at its append-only position;
- whether that position has been withdrawn;
- the epoch in which that position first became fully inactive.

The existing delegator fee, issuance-reward, and slash-loss ledgers remain the
authoritative accounting for that position's identifier. Withdrawal consumes
and clears those entries atomically.

## Wire messages

The exact tags are allocated in `docs/WIRE-NAMESPACE-REGISTRY.md` before code
lands. All integers are little-endian. Variable-length fields have a `u32`
length prefix. Hybrid public keys and signatures use suite 1, ML-DSA-65 AND
Falcon-1024.

### `FundedDelegate`

Fields:

- network domain and inclusive expiry epoch;
- funding public key and a strictly ordered, duplicate-free input list;
- validator public-key hash;
- amount;
- change value and script hash;
- maximum base-fee rate, priority-fee rate, and reserved transaction bytes;
- funding signature.

Consensus resolves the validator by its committed public-key hash, refuses a
missing, slashed, or exiting validator, validates the minimum amount, resolves
every input from committed state, checks ownership and exact conservation,
verifies the signature, spends the inputs, creates change, allocates the
position and owner record, and queues the delegation for the next epoch.
It rejects an amount that would put the sum of all unwithdrawn positions
behind that validator above 500,000,000 BLCH. The aggregate check happens
before any input is spent, so splitting a deposit across owners or pending
transactions cannot bypass the limit.

### `FundedUndelegate`

Fields:

- network domain and exact inclusion epoch;
- delegator identifier and delegation position;
- funding public key;
- signature.

Consensus verifies the owner binding and signature and refuses withdrawn,
already-deactivating, or unknown positions. Deactivation begins in the next
epoch and drains under the same budget as activation.

### `FundedDelegationWithdraw`

Fields:

- network domain and exact inclusion epoch;
- delegator identifier and delegation position;
- funding public key;
- destination script hash;
- maximum base-fee rate and signature.

Consensus requires the position to be fully inactive and at least
`WITHDRAWAL_DELAY_EPOCHS` past its first fully inactive epoch. Fully inactive
means both the fixed cool-down has elapsed and the churn-budget resolver
reports zero activated satoshis for the position. The created output is:

```text
principal
- committed slash loss
+ committed fee reward
+ committed issuance reward
- actual base fee
```

The transition refuses underflow, an output below the transfer minimum, an
already-withdrawn position, a fee above the signed ceiling, or an output
collision. It creates exactly one eUTXO, marks the position withdrawn, masks
it from future slash exposure, and clears its three account ledgers.

### `ValidatorCommissionUpdate`

Tag `0x11` changes the validator's commission on rewards from delegated stake.
The registered validator hybrid key signs the network domain, exact inclusion
epoch, validator index, and new basis-point rate. The principal is never
charged; at 500 basis points the operator receives 5% of delegated rewards and
the delegator receives 95%.

Consensus permits a commission increase only when the validator has no live or
pending delegation position. A decrease remains permitted while delegations
exist. This prevents an operator from raising the rate after a delegator has
committed stake.

## Activation and rollout

The implementation initially ships with the funded-delegation activation
epoch set to `u64::MAX`. Arming it requires:

1. exhaustive encoding, conservation, authorization, replay, cap, warm-up,
   cool-down, withdrawal-delay, reward, and slashing tests;
2. a multi-node mixed-version rehearsal showing old and new nodes agree below
   the boundary and old nodes fail closed at the boundary;
3. deployment and binary-digest verification across every validator;
4. publication of the activation epoch and signed release artifact;
5. one small-value mainnet lifecycle before any operational bulk delegation.

The operational request of 2026-09-30 supersedes the previous 350,000 BLCH
batch: thirty positions of 10,000,000 BLCH each, 300,000,000 BLCH total, and
500 basis points of commission for the 95 controlled validators. Those
validators occupy registry indices 0–64 and 66–95; index 65 is outside the
controlled fleet. Commission updates must finalize before funded positions
are created, because even an unactivated pending position prevents a later
increase. Batch construction, signing, and broadcasting remain separate
operational steps. No transaction or activation follows from this document.

The subsequent clarification sets **500,000,000 BLCH as the delegation
limit**, not a contribution to each validator. The requested contribution
remains 10,000,000 BLCH for each of the 30 expansion validators. The cap is
a uniform funded-delegation consensus rule; the list of 95 commission
updates is an operator-specific transaction plan, not a registry whitelist
in consensus.

### Qualification result, 2026-10-01 UTC

Activation remains unarmed. The released delegation resolver has a cap
discontinuity: its fixed-point calculation can round to zero, and
`Registry::validators` treats zero as an uncapped amount. An offline probe
using the unchanged resolver from release `4d4c5075` produces:

| Equal funded positions | BLCH per position | Computed cap, sat | Delegated weight per validator, sat |
| --- | ---: | ---: | ---: |
| 30 | 10,000,000 | 0 | 1,000,000,000,000,000 |
| 35 | 10,000,000 | 0 | 1,000,000,000,000,000 |
| 36 | 10,000,000 | 2 | 2 |
| 95 | 10,000,000 | 184,025,910,235,569 | 184,025,910,235,569 |

These are delegated components, before own stake, cohort caps, and inactivity
leaks. They are not final proposer probabilities. The same synthetic
30-position batch takes 563 epoch budgets to warm up fully, assuming no
other positions or exits. That is a model result, not a live-chain forecast.

Reproduce without keys or network access:

```sh
cargo run -p bloch-pos-committee --example funded_delegation_readiness --locked --offline
cargo test -p bloch-pos-committee --lib funded_delegation --locked --offline
```

The candidate uses `validators_with_absolute_cap` behind the funded lifecycle
gate. The four rows above then retain the full activated 10,000,000 BLCH of
delegated weight each. No existing principal is rewritten. Before the gate,
the old weight calculation is preserved for historical replay.

The 22 focused tests pass, including the requested 95 commission updates,
preservation of registry index 65, unchanged principal and supply, signed
intent domain/epoch/key binding, rejection of a commission increase after a
pending funded position, conservation for 30 positions of 10 million, both
30- and 95-position stress cases at the 500-million ceiling, aggregate-limit
rejection, capacity release after owner withdrawal, and issuance accounting.
The complete committee suite passes 681 tests, with six measurement tests
ignored by their existing annotations.
These tests use synthetic keys and the test verifier. They do not establish
real hybrid-signature interoperability, mixed-version agreement, historical
replay, or mainnet readiness.

The released implementation also has an issuance dependency:
`REWARDS_V2_ACTIVATION_EPOCH` remains unarmed. With only its original funded
delegation implementation enabled, `close_epoch` supplies
zero delegated stake and zero commission to the issuance calculation, so
delegators receive no issuance-ledger credit. Producer-fee sharing is a
different path. The existing
`rewards_v2_settles_delegator_issuance_share` regression confirms the before/
after gate behavior. Rewards-v2 also changes attestation-credit validity,
leak-adjusted reward weights, and proposer credits; it cannot be silently
enabled as though it were only a commission setting. The candidate therefore
settles funded delegators' issuance under the complete funded-delegation gate
while retaining the existing participation-credit rules. It partitions the
roster's already-computed effective weight between own and delegated origins
before applying commission, rather than adding delegation a second time.
Tests establish 5% of delegated issuance goes to the operator, principal is
unchanged, total minting stays within the epoch budget, and enabling the gate
in a state without delegations leaves the epoch root unchanged.

Both `REWARDS_V2_ACTIVATION_EPOCH` and
`FEE_STAKE_DECOUPLE_ACTIVATION_EPOCH` remain unarmed. The funded-delegation
gate is also unarmed. Full historical replay, real hybrid-signature lifecycle
qualification, multi-node mixed-version rehearsal, coordinated release, and
the small mainnet lifecycle remain outstanding. No production binary,
commission, principal, or activation epoch changed during this qualification.

### Shipping-binary compatibility and hybrid authorization, 2026-10-01 UTC

The Linux candidate from commit `7c4710bb54b4430ac5814a7e26280bce9e07cccc`
(SHA-256 `98d066dc41e156f1bb4fea5f3a6a3db79108645e10dec0e6188134cede679768`)
was exercised alongside deployed baseline commit
`4d4c5075872c622fdd26aa418a9d249ec95fbcea`
(SHA-256 `fb8a65cbd9721d794bd4c2151b50d82d85a7df2299d59d7bad44a7635c30b46a`).
The reproducible harness is `scripts/qualify-mixed-l1-candidate.py`.

Three independent validator processes ran old/new/old binaries on loopback
libp2p, using fresh hybrid keys and a synthetic bound genesis. A fourth,
candidate observer started with an empty data directory after head slot 101.
The normal 64-slot doppelganger window remained enabled. The test used
500-millisecond slots and stopped at slot 256.

- All four processes agreed on 96 finalized blocks, including full block IDs
  and state roots. All three validator indices proposed finalized blocks.
- The late observer independently acquired and validated history predating
  its startup. Finality reached checkpoint epoch 5 on all four nodes.
- Baseline and candidate each replayed the same stopped, synthetic block log
  from genesis in both devnet and libp2p modes. All four results were slot 255,
  192 blocks, and state root
  `f7df5c8455bc404661a70dc8109c29ccbc3b6b05e87975dba76b2652c427264c`.
- No production datadir or signing identity was used. The 15 existing
  validator services on the test host remained running.

This establishes mixed shipping-version agreement over this synthetic
pre-activation history. It does **not** establish agreement across an armed
fork boundary, historical mainnet replay, or mainnet bootstrap readiness.

Four additional node tests use actual ML-DSA-65 and Falcon-1024 signatures
through `HybridVerifier`, rather than the committee's synthetic verifier:

```sh
cargo test -p bloch-pos-node --bin bloch-pos funded_delegation_tests --locked --offline
```

They verify canonical round-trips; rejection when either signature component
is corrupted; binding to network, epoch, inputs, validator, amount, change,
withdrawal destination, position, and commission rate; separation of owner
and validator authority; and refusal of all four signed transaction types by
the shipping node without committed-state or mempool mutation. The shipping
gate is also checked at epochs 0, 4329, `u64::MAX - 1`, and `u64::MAX`.

The separate `scripts/rehearse-funded-delegation.py` runner copies source to
a disposable directory and arms only the funded-delegation gate there. It
runs the ignored real-hybrid lifecycle test; the shipping gate and the real
cool-down and withdrawal delays remain unchanged. This test is separate from
the four ordinary shipping tests and must report its own successful result
before its lifecycle evidence can be counted.

The isolated lifecycle run passed on 2026-10-01 UTC. It used two in-process
node engines, a fresh validator key and owner key, the real hybrid verifier,
and a synthetic genesis allocation. Commission was set to 500 basis points
before funding a 10-BLCH position. Real signed blocks carried the funding,
deactivation, and withdrawal. The owner received issuance; an early payout
was excluded; the unchanged 32-epoch cool-down and 2,048-epoch withdrawal
delay elapsed; and the payout equaled principal plus credited fees and
issuance, less slash losses and the withdrawal fee. A second owner-signed
withdrawal to another destination was excluded without a second payout.

Both engines agreed after every applied block. Their independent full
replays from synthetic genesis matched the resulting states at slot 66722,
epoch 2085, after 2,275 blocks. The selected lifecycle test passed in 813.73
seconds. The four shipping authorization tests also passed; the positive
lifecycle test remains ignored in the ordinary suite because it requires
the separate isolated compilation. No shipping consensus constant changed.

This in-process result does not exercise a funded lifecycle through the
external CLI/RPC and network transport, nor does the mixed shipping-binary
test exercise a scheduled activation boundary. Those rehearsals, historical
mainnet replay, coordinated deployment, a signed activation release, and a
small-value mainnet lifecycle remain prerequisites to production activation.

### Offline operator workflow and committed position query

`bloch-pos funded-delegation --help` describes the offline preparation,
inspection and signing commands for all four funded intents. Signing requires
both a trusted genesis manifest and the exact independently reviewed signing
root. Files are created exclusively with owner-only permissions. These commands
never submit transactions or enable the activation gate. Commission inspections
require the validator public key when a signature is present; independently
check the validator index against the registry before signing.

Submit reviewed, signed canonical hex through the existing `sendrawtransaction`
RPC. The consensus transaction ID printed by the CLI is the identifier for
`gettxstatus`; the submission's local hash is not that ID. All four intents now
receive committed-state and signature validation before RPC/gossip admission,
with the existing per-source verification budget. Funded input conflicts are
reserved across pending deposits, delegations and transfers.

`getfundeddelegation(position)` returns a single committed funded position,
owner hash, principal, activated stake, deactivation/inactivity/maturity epochs,
withdrawn status and reward/loss ledgers. An absent or legacy position returns
null. The response is a head-state observation, not proof of finality: use
`gettxstatus` and finalized block identity before accounting for settlement.
Inactive positions still owe the full withdrawal delay; the RPC reports those
states separately. This interface does not change consensus or activation.
