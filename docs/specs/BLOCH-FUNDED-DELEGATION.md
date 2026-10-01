<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Funded delegation lifecycle

Status: design candidate, consensus gate unarmed

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
4. Delegated stake remains subject to the existing per-validator effective
   stake cap and pro-rata slashing rules.
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

### Qualification result, 2026-10-01 UTC

Activation remains blocked. The production delegation resolver has a cap
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

The 17 focused tests pass, including the requested 95 commission updates,
preservation of registry index 65, unchanged principal and supply, signed
intent domain/epoch/key binding, rejection of a commission increase after a
pending funded position, and conservation for 30 positions of 10 million.
These tests use synthetic keys and the test verifier. They do not establish
real hybrid-signature interoperability, mixed-version agreement, historical
replay, or mainnet readiness.

There is also an issuance dependency: `REWARDS_V2_ACTIVATION_EPOCH` remains
unarmed. With only funded delegation enabled, `close_epoch` still supplies
zero delegated stake and zero commission to the issuance calculation, so
delegators receive no issuance-ledger credit. Producer-fee sharing is a
different path. The existing
`rewards_v2_settles_delegator_issuance_share` regression confirms the before/
after gate behavior. Rewards-v2 also changes attestation-credit validity,
leak-adjusted reward weights, and proposer credits; it cannot be silently
enabled as though it were only a commission setting.

The intended denominator and treatment of own stake must be resolved before
changing the cap. The separate `FEE_STAKE_DECOUPLE_ACTIVATION_EPOCH` also
remains unarmed; enabling it changes additional reward behavior and is not a
substitute for a scoped delegation correction. Neither gate nor a live
validator's commission was changed during this qualification.
