<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Funded delegation lifecycle

Status: scheduled candidate at epoch 4669; qualification blocked, not deployed

The current candidate proposes **2026-10-04 18:35:19.962 UTC**
(**15:35:19.962 America/Sao_Paulo**), epoch **4669**, slot **149408**.
It supersedes the epoch-4528 preview. The full CLI/RPC lifecycle failed its
finality-lag assertion; postponing the gate does not repair that failure or
authorize deployment. See the final rescheduling record below.

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

### Mainnet history and finite activation qualification (2026-10-01)

The deployed `4d4c5075` binary, the `7c4710bb` candidate and the new offline
CLI/RPC candidate `8f0e429d` each replayed the same 108,474-block finalized
mainnet prefix from genesis without a state cache. Each exited successfully at
slot 138,751 with state root
`aa599c8f7c30d1633a5c9412b499db2e0d8edc8559ec1c3b4df7a4c7d790b088`.
The anchor is block
`fa66d4d2ee5435b0e3e7c576df8e543162d54e2323011443028d2d5cf24ebaee`.
This qualifies that frozen history, not fresh network bootstrap or exchange
settlement. The shipping delegation gate remains unarmed.

A separate lab build compressed the existing finite current-regime gates to
epochs one and two, then armed funded delegation at epoch eight. The baseline
control used identical compressed historical gates and left delegation unarmed.
At 500 ms slots, three candidate validators and an old observer agreed before
activation. The candidates finalized commission, funded delegation and exit
transactions submitted through the public CLI/RPC; the old observer refused the
first activated transaction block and stopped following that branch. Forged
operator signatures, forged delegation signatures, a commission increase after
funding and premature withdrawal were refused at RPC admission. Replaying the
416-block activated finalized prefix reproduced its exact root on the armed
build; the unarmed control rejected it. This test did not wait for mature payout.

Two faster fixture limitations are retained in the evidence rather than counted
as passes. Three proposers at 25 ms developed excessive finality lag and short
reorganizations. A single proposer at 25 ms exhausted all 8,192 RANDAO reveals:
without another proposer, no block could include its renewal. That fixture kept
attesting but stopped advancing its head. The full network lifecycle runner
therefore requires three proposers; it also checks progress against the wall
slot, not only the gap between head and finality. These are distinct from the
already passed in-process real-delay lifecycle rehearsal.

`python3 scripts/rehearse-funded-delegation.py --admission-only` reproduces the
short real-hybrid admission and input-reservation checks in a gate-zero source
copy. `scripts/rehearse-funded-delegation-rpc.py` runs the external finite-gate
CLI/RPC scenario with fresh keys in a new directory. Its `--activation-only`
mode deliberately stops before maturity; a full result is only a pass after
exact payout accounting and a second withdrawal refusal. No production service,
key or balance is modified by these qualification workflows.


## October 1 initial scheduled candidate and unattended qualification (superseded)

The operator initially requested an automatic upgrade of the 95 inventoried
validators and funded-delegation activation approximately two days later. That
superseded candidate scheduled epoch **4528**, slot **144896**, at **2026-10-03 04:59:19.962 UTC**
(**01:59:19.962 America/Sao_Paulo**). This is an epoch/slot boundary, not a
predicted produced-block height. The Genesis-4 manifest SHA3-256 remains
`f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966`.
Only the funded-delegation gate changes; historical gates, the 32-epoch
cooldown, 2048-epoch withdrawal delay and 500,000,000 BLCH principal ceiling
remain unchanged. The requested 500-basis-point operator commissions still
require finalized commission transactions after activation.

This schedule in source is **not evidence of deployment or a release**.
The October 1 preflight matched all 95 expected services and public identities
on nine hosts to the deployed `4d4c5075` binary. Mainnet reported 139 active
validators; the other 44 are outside this service inventory. Their upgrade
readiness is unresolved and must not be inferred from the approximately 92.1%
of effective stake represented by the inventoried fleet.

Full CLI/RPC attempt `rpc-network-04` stopped after a three-second read RPC
timeout, before maturity. It remains a failed attempt. The runner now records
and retries read-only transport failures at most three times, while retaining
all consensus, payout and finality assertions. It never automatically retries
an ambiguous transaction submission. Attempt `rpc-network-05` uses three
proposers, 100 ms slots, real protocol delays and a persistent systemd service
with a three-hour bound. Its eventual report, exact scheduled-artifact replay,
independent build comparison and network readiness are release gates.


### Unattended qualification handoff

Scheduled candidate source: `c43dbd667295fb8314c22a156c6e696b9f5c88c0`.
The 37 focused committee tests and four real-hybrid node tests passed; two
lab-only node tests remain deliberately ignored in the shipping test run.
Authenticated builders `host652474` and `host652475` independently ran the
pinned canonical-container recipe and produced byte-identical Linux x86-64
executables. The canonical output comparator passed. Binary SHA-256:
`bd58e25faab8ed3fb1ba67096f64e48ec65e8a66e248b3fda8c5d7a814c95a06`.

Full CLI/RPC attempt `rpc-network-05` failed after 2892.748 seconds when the
head reached epoch 899 while finality remained at 883. The retained logs show
continued proposals and later justification; they do not establish a finalized
root conflict. This failure is not converted into a pass. A new complete
three-proposer attempt, `rpc-network-06`, uses 500 ms slots, unmodified protocol
delays, the same assertions, and a persistent 12-hour systemd unit. Nominal
withdrawal maturity takes approximately nine hours. The exact scheduled
release also has a separate persistent mainnet replay job against the pinned
108,474-block prefix.

The local unattended controller compares independent builds, verifies the
exact-artifact replay and mature payout evidence, and only then creates a
locally signed candidate package. It stops on qualification failure. It has
**no production restart or deployment path** while readiness of the other 44
active validators remains unresolved. The 95-service migration plan is a
non-executing draft with one canary, at most one restarting identity per host,
and at most one eighth of measured effective stake offline per wave. Its
preflight must be refreshed before any future rollout. No production service,
commission, funded position, or P2B approval changed in this handoff.


The exact scheduled-artifact replay subsequently passed with the same
108,474-block anchor root as the baseline. The unattended publication path
was configured to publish a **prerelease**, only after the full CLI/RPC test
also passes and while at least 24 hours remain before activation. It first
uploads a draft, downloads and compares all seven signed-package assets, and
only then publishes. It targets the exact candidate commit on a separate
release branch, preserving `main` and the stable/latest release. Repository
write access was checked with a successful non-mutating push dry run. Public
release creation and production rollout had not occurred at this handoff;
network readiness remains a separate deployment blocker.

### Signed preview publication

At the operator's subsequent request, the same pinned executable was published
as an explicitly unqualified, signed preview on October 1. The
[GitHub preview release](https://github.com/tiagobeltraoacioli-sketch/bloch-sis-pow/releases/tag/funded-delegation-epoch-4528-preview)
and the [L1 validator guide](https://blochl1.com/validators/guide#delegation-preview)
provide the binary, build information, publication-snapshot metadata, release
notes, trusted-key reference, checksum manifest and detached Minisign signature.
All seven assets downloaded anonymously from each destination matched the
signed local package byte for byte. Native Minisign independently verified the
manifest against the existing trusted release key. This preview is not marked
as the latest stable release and does not approve a production rollout.

The site deployment uses source commit
`07f85c9dacf20420e8df24056a222094fac092f9`, preserving the existing stable
downloads and P2B receipt-validation changes. Its 213 tests passed, seven
optional tests skipped, and the production build succeeded. The entry and guide
bundles served by `blochl1.com` matched that build. The signed preview metadata
remains an immutable publication snapshot; subsequent qualification results
will be recorded in the GitHub release notes.

An independent observation at **2026-10-01 13:45:09 UTC** found the unchanged
`rpc-network-06` service running. All three candidate nodes were at epoch 589,
finalized epoch 587, one slot behind the wall slot, and agreed on the common
finalized block and state root. The third validator had completed its first
RANDAO renewal. Withdrawal maturity remains epoch 2095, so this is progress
evidence, not a full lifecycle pass. The local controller now records both
public links and retains the conditional, separately tagged qualified
prerelease path. Production migration remains unconfigured.

### Rescheduled three-day candidate

At the operator's October 1 request, the boundary moved from epoch **4528** to
**4669**, slot **149408**, at **2026-10-04 18:35:19.962 UTC**
(**15:35:19.962 America/Sao_Paulo**). The request was recorded at
2026-10-01 18:31:30.865140 UTC. The new boundary is the first epoch start at or
after 72 hours from that instant; it is not a predicted produced-block height.
The pinned manifest encodes genesis time `1786656679962` ms and slot duration
`30000` ms, with 32 slots per epoch. The manifest digest is unchanged.

The earlier complete `rpc-network-06` lifecycle failed after **14965.375
seconds** with `finality lag exceeds rehearsal budget`, before mature payout.
The unattended controller stopped and marked the earlier GitHub preview's
qualification as stopped. That failure remains open. Moving the mainnet date
does not change the finite-gate laboratory or count it as a pass.

Only the funded-delegation boundary changes in this reschedule. Historical
consensus gates, cooldown/withdrawal delays, signatures, the 500-million-BLCH
principal ceiling and commission behavior remain unchanged. Regression checks
also require delegation to remain disabled at the obsolete epoch 4528 and
through 4668. The published epoch-4528 executable cannot be rescheduled by
configuration; it is superseded and must not be used for the new schedule.
A separately built, signed and versioned candidate is required. Its exact
artifact needs independent build comparison and historical replay again.

No production validator was migrated by this workflow. A qualified release
and rollout remain blocked on a successful complete CLI/RPC lifecycle and
coordinated readiness outside the 95-validator inventory. The operator's
requested 5% commissions still require separate finalized transactions.


### Full rehearsal failure: growing synchronous restart-cache work

Analysis of `rpc-network-06` retains its failure: the head reached epoch 934
while finality remained at 921. The three nodes each wrote roughly 1,000
restart caches. Median cache-write time grew from about 103 ms below slot
10,000 to about 560 ms after slot 28,000, exceeding the 500 ms laboratory slot.
The logs also record about 100 short reorganizations per node. These are
observations from the failed run, not a completed lifecycle qualification.

`write_local_cache` previously re-read and SHA3-hashed the complete block log
on the consensus thread every 32 blocks and after a reorganization. The repair
maintains the exact framed-log fingerprint through durable writes. Reorganization
writers compute the replacement fingerprint while streaming their staging file
and publish it only after the log is durable. Partial writes and uncertain
publication invalidate the fingerprint; a preflight refusal preserves it.
Startup seeds it from the repaired authoritative log. Cache recovery still
independently hashes the on-disk prefix, verifies the cache checksum, source
identity, canonical frame boundary and restored state root.

Regressions compare the incremental digest with an independent full-file hash
across appends, same-size replacements, asynchronous replacement plus append,
torn-tail recovery and restart. They cover short writes, rejected frames and
out-of-band same-length corruption. A cache-specific work counter requires zero
historical bytes scanned while writing caches and a full independent disk scan
when restoring one. The CLI/RPC runner now retains its final liveness sample,
all three node observations, exact build identities and cache/reorg metrics.
Its finality limits, real cooldown, withdrawal delay and payout assertions remain
unchanged. A corrected full network rehearsal is still required before approval.

### Follow-up rehearsal failure and indexed fork-choice inputs

The cache correction alone did not complete the lifecycle. `rpc-network-07`
(50 ms slots) failed with a 23-epoch finality lag; `rpc-network-08` (100 ms)
failed after 3,104 seconds with a 12-epoch lag on node 0. The latter first
reorganized around slots 16,834–17,924 and reached about epoch 965. Median
cache writes remained 1 ms on all three nodes. Neither run reached the mature
payout, and both failures remain qualification blockers.

The next correction removes full-history parent/child map reconstruction and
weight propagation from each head computation. `BlockInventory` owns the
envelopes and derived child/vote indexes, with no mutable map access that could
bypass index maintenance. The queried weight graph contains only descendants
of the current justified checkpoint. Historical votes are still folded in the
exact previous block-ID, body and loose-pool order: the legacy latest-message
store is order-sensitive in the presence of equivocation, so replacing it with
an arrival-order cache would change consensus behavior. Current canonical
stakes and both existing tie-break regimes are unchanged. Synthetic cycles use
the unchanged full rebuild to preserve its original global step bound.

Differential regressions cover random insertions, same-ID replacements,
removals, missing parents, cycles, changing stakes and loose votes, as well as
the legacy equivocation ordering and historical carriers outside the live
subtree. The retained canonical envelopes, child index and historical vote
summaries still grow with chain history; this is not bounded-history storage.
The new candidate requires its own complete lifecycle, independent artifact
comparison, exact-artifact mainnet replay and strict cache restart before any
qualification claim. The real protocol delays and liveness assertions remain
unchanged, and production rollout remains blocked.

The local optimized benchmark uses a 64-block live suffix, three historical
votes every 32 blocks and twelve head computations per case. At 4,096, 32,768
and 65,536 retained blocks, full rebuilds averaged 2.098, 28.142 and 65.574 ms;
indexed computations averaged 0.060, 0.155 and 0.313 ms respectively, with
identical selected heads. These are local synthetic measurements of fork
choice, not whole-node throughput or a completed network qualification.
