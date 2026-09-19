# Wave 79 — NET-04 / EN-08 pending-capacity preflight

Date: 2026-09-19
Starting consolidation: `6a30397`

## Residual addressed

Wave 78 bounded attributed and unattributed held attestations, but every one
of those limits was evaluated only after hybrid signature verification. Once a
source, source/root, duty, root, root-set or unattributed bucket was full, a
stream of novel frames could therefore keep paying consensus-thread crypto
even though none could be retained.

The frames still required a validator key to carry valid signatures if they
wanted to enter the pool, but saturation itself did not stop repeated invalid
or valid variants from reaching the most expensive admission step.

## Hardening

The gossip pool now computes the first missing root and preflights every
pending-only capacity limit before hybrid verification. A saturated frame is
an `Ignore`, exactly as it was after verification; capacity pressure remains
local state and never becomes peer guilt.

The ordering preserves the important boundaries:

- committee membership and key resolution still run first;
- a frame is never accepted or held without a valid hybrid signature;
- known-root attestations bypass pending preflight and still authenticate, so
  pool saturation cannot hide an invalid message on the acceptance path;
- the missing-root order, counter priority, FIFO eviction, source identity,
  wire encoding, consensus validity and persistent state are unchanged;
- pending-pool state and counters cannot change between preflight and hold
  because one `&mut AttestationPool` operation owns the sequence; and
- the missing-root observation separately relies on the snapshot-stable
  `BlockLookup` contract described below.

The capacity rules are centralized in `pending_capacity_reason`, avoiding
duplicated checks and preserving the prior limit priority.

## Adversarial coverage

The source/root regression fills one attributed share with authenticated
attestations, then supplies a novel overflow frame to a verifier that panics if
called. The frame returns `PendingSourceRootLimit` without invoking crypto and
without changing the pool. The control half presents a bad signature whose
roots are known and proves it is still verified and rejected despite the same
source's saturated pending share.

The existing exact-bound regressions now use the same panic sentinel on every
other overflow path: duty, root, root-set, aggregate attributed source,
aggregate unattributed ingress and unattributed root. Together the seven
capacity reasons prove that no saturated pending-only branch reaches hybrid
verification, while their capacity-reopening controls continue to authenticate
and hold once an entry leaves.

The ordering comment now distinguishes the state actually protected by
`&mut AttestationPool` from the chain view. Pending counters cannot change
during one call; the production engine separately lends an immutable chain
view, and the public `BlockLookup` contract must provide snapshot-stable
answers for the duration of `process`.

Focused validation:

```text
cargo test -p bloch-pos-committee gossip::tests --offline
# 27 passed; 0 failed

git diff --check -- crates/bloch-pos-committee/src/gossip.rs \
  docs/audit/internal-remediation-2026-09-17/WAVE-79-NET04-PENDING-PREFLIGHT.md
# passed
```

Compiler output contained only pre-existing unused-code and unused-doc
warnings. The source file also retains inherited whole-file rustfmt drift; this
change does not mechanically reformat unrelated lines.

## Residual risk

- One admitted hybrid verification remains non-preemptible.
- A key-holding validator can still consume bounded verification work while
  its pending bucket has capacity, and known-root frames always authenticate.
- Multiple normalized identities can partition per-source limits; NAT/proxy
  sharing can make honest peers contend for one share.
- The 256-entry aggregate FIFO intentionally admits a newer authenticated
  entry by evicting the oldest when all narrower limits permit it.
- Fully populated held state still requires bounded cooperative replay turns
  to drain.

External binary release gates are unchanged: independently authenticated
Linux build comparison, hosted CI evidence, signed release/rollback artifacts,
fresh independent WS evidence, scratch-host rollback rehearsal and staged
canary evidence remain required.
