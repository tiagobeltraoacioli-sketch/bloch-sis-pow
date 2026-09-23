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

The planned operational batch is thirty positions of 350,000 BLCH each,
10,500,000 BLCH total. Batch construction, signing, and broadcasting are
separate operational steps and are not authorized by merging this protocol.
