<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Coherence C1.1 — the nullifier-set commitment

```
Document:   COHERENCE-C1.1
Status:     RATIFIED 2026-08-12 (founder)
Amends:     COHERENCE-C1.md
Closes:     BLOCH-COHERENCE-UNDER-POS.md F9 and F13
Implements: crates/coherence-core/src/lib.rs (NullifierSet, verify_non_membership)
```

## Why an amendment exists at all

C1 froze the shielded pool's formats: note, commitment, nullifier derivation,
the commitment accumulator, the spend statement, the wire format. It named **the
global nullifier set** as consensus state — and never said how that set is
committed. In the code the set was a bare `HashSet` with no canonical root
(finding F9).

Under proof of work that was survivable, because nothing outside the node ever
had to agree on the set's digest. Under proof of stake it is not: `state_root`
commits every consensus component (§5.5 of the migration design), so the set
needs a root, and a state-syncing node needs to be able to check it.

Two things follow, and they are the whole of this document:

1. **This is an addition, not a change.** Nothing C1 froze moves. `DOM_CM`,
   `DOM_NF`, `DOM_MT`, `TREE_DEPTH = 32`, the nullifier derivation binding leaf
   position, the spend statement — all untouched. A migration sweep that
   re-domained any of them would itself be the reset §6.6.1 forbids.
2. **It had to be settled before the genesis ceremony, not after.** The root is
   a leaf of the genesis `state_root`, so it is an input to the genesis block
   id. An interim commitment (which is what shipped between 2026-08-11 and this
   rev — a SHA3-256 hash of the sorted set under a `BLCH4:` tag) would have had
   to be replaced, and replacing it after the ceremony changes the identity of
   the chain's first block.

## 1. The nullifier-set root

A **sparse Merkle tree over the 256-bit nullifier keyspace**, SHAKE-256, keyed
by the nullifier itself.

```
DOM_NFSET   = b"bloch:coherence:nfset:v1"
NFSET_DEPTH = 256                                   one level per key bit
node        = SHAKE256_32( DOM_NFSET ‖ left ‖ right )
empty_leaf  = SHAKE256_32( DOM_NFSET ‖ "empty-leaf" )
present     = SHAKE256_32( DOM_NFSET ‖ "present" )   leaf value at an occupied key
```

`empty[d]` is the root of an all-empty subtree of height `d`, built once from
`empty_leaf` upward. The root of a set is computed by descending only where keys
exist; an all-empty subtree short-circuits to its precomputed root, so cost is
bounded by the occupied paths and not by the keyspace.

The domain tag is its own — a node of this tree can never be reinterpreted as a
node of the commitment tree, and that is checked by test rather than asserted.

### 1.1 Why a sparse tree and not a running hash

`H(prev ‖ nf)` is cheaper and was rejected for two reasons, in this order:

- **The root must be a function of the set.** A running hash makes insertion
  order consensus. Two honest nodes that applied the same blocks in a different
  order — or one that undid and redid a reorg — would commit different roots for
  identical state. That is the same failure shape as the 2026-08-08 incident,
  and it is not a hypothetical here because reorgs are ordinary under PoS.
- **Non-membership must be provable.** What a spend verifier needs is
  "`nf` ∉ set as of this anchor". A hash chain cannot show that; a sparse tree
  can, and the same proof shape serves a §6.6.4 pruning proof and any future
  light client.

An honest note on the second: in a sparse tree an all-empty sibling path proves
a whole *region* empty, so a single non-membership proof legitimately covers
many absent keys at once. That is a property of the structure, not a weakness —
what the verifier concludes ("this key is absent") is true for every key the
proof covers.

### 1.2 Mutation rules

Insert-only in normal operation (§6.6.1). `insert` returns false if the
nullifier is already present, and **that return value is the double-spend
check** — a caller that ignores it has removed the check.

`remove` exists solely for reorg undo, driven by the disconnected block's
recorded nullifiers. Removing a nullifier that was not undone by a disconnected
block resurrects a spent note. Undo restores the exact earlier root, which is
what makes a disconnect safe; pinned by test.

### 1.3 Who computes it

`coherence-core`, and nowhere else. The node, the SP1 guest and the genesis
ceremony all call the same code — for a structure whose root is consensus, a
second implementation is a fork waiting to ship.

The PoS consensus crate does **not** compute it. It carries the 32-byte root as
opaque bytes, which is the §6.6.1 posture (carried, never recomputed). The
interim commitment removed by this rev lived in that crate, under a `BLCH4:`
tag, computed with SHA3-256 — the PoS layer reaching into the shielded pool's
business, and the reason the interim value existed at all.

## 2. F13 — the empty-leaf constant

C1 §1.4 states, of the **commitment** accumulator:

> Empty subtrees use a fixed `EMPTY_LEAF = SHAKE256_32(DOM_MT ‖ 0^0)`.

The code computes `SHAKE256_32(DOM_MT ‖ "empty-leaf")`, and always has, on both
branches and therefore inside the SP1 guest.

**The document moves, not the code.** The constant is baked into every anchor
the pool has ever produced and into the proving circuit; changing it would
invalidate existing anchors and every proof against them, to fix a sentence.
C1 §1.4 is corrected to read:

```
EMPTY_LEAF = SHAKE256_32( DOM_MT ‖ "empty-leaf" )
```

This is a documentation correction to a frozen format, which is the only kind of
change to C1 this rev makes — the format itself was never what the sentence
said.

## 3. What this rev does **not** do

Stated so the next reader does not assume more was settled than was:

- It does not implement shielded-transaction application under PoS. The pool is
  inert: `expected_coherence` derives the header binding from the parent's
  committed roots, and no block changes them yet (DEV-3's scope).
- It does not define the `shield_tx` / unshield value bridge (F10). Value still
  cannot enter or leave the pool.
- It does not add shielded storage (F11); on restart the node rebuilds an empty
  pool.
- It does not make any privacy claim. The chain remains a zero-security testnet
  in this respect until the C4 audit, exactly as C1 says.
- It does not change `ANCHOR_HISTORY`, the spend statement, or the proof system.

## 4. Consequences to carry forward

- The genesis ceremony's Coherence artifact now commits the C1.1 root. An empty
  pool commits the **empty-set root**, not zeros — "no pool" and "an unset
  field" must not be indistinguishable in the state tree, and a test pins it.
- `COHERENCE-G11-SHADOW-FORKS.md` describes the interim commitment; its Fork-A
  and Fork-C steps now exercise the ratified one. The shadow forks remain the
  acceptance evidence for G11.
- Anyone holding a genesis block id from a rehearsal run before 2026-08-12 must
  regenerate it. That is the cost of settling this now instead of later, and it
  is the small version of the cost.
