<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Rollout: the verifier reads the committed registry

Operational plan for shipping the change that makes consensus signature checks
resolve keys from the **committed validator registry** instead of from a table
built once at boot from the genesis manifest.

Sibling of `docs/RELANCA-G4-DIAS-DE-BANDEIRA.md` and
`docs/LEAKED-ROSTER-FLAG-DAY.md`. It differs from both in one structural way,
and the difference is the reason this file exists:

> **There is no activation constant, and there must not be one.**

Everything below follows from that.

---

## 0. Status

Nothing here has been deployed. Nothing has been armed. No fleet host was
touched in producing this document; chain state was read only from the two
keyless archivals (`139.180.166.5`, `139.180.173.231`, port 8080). The
uniformity procedure in §5 is written to be run, not reported as run.

---

## 1. What ships

Branch `fix/verifier-reads-registry`, three commits descending from the
release lineage (`g4-node-20260901` = `7a83ca89`) — not from `main`, which is
not what the fleet runs:

| commit | subject |
|---|---|
| `d9e4aebf` | the verifier reads the registry (consensus) |
| `e39bf259` | gate 3 + `Manifest::pubkeys()` (node) |
| _(this one)_ | this document |

What they change:

- `SignatureVerifier::verify(validator_index, ..)` is **deleted**. The trait
  keeps only `verify_with_key(pubkey, ..)`.
- A new `KeyLookup` trait resolves index → key, implemented by the committed
  registry (`BTreeMap<u32, ValidatorRecord>`, `CommittedState`, and the
  slice/`Vec` forms in `state_root.rs`).
- Six call sites now name the state they judge against. Inside the transition
  (proposer signature, included attestations, slashing evidence): the block's
  **pre-state**. On gossip ingest: the **same `rolled_to(epoch)` snapshot that
  already drew the committee**.
- `HybridVerifier` becomes a unit struct holding no key material.
- Absence is a distinct verdict — `UnknownValidator` / `UnknownProposer`,
  never `BadSignature`; and on gossip it is `Ignore`, never `Reject`.
- Gate 3 (boot identity) moves from the manifest to the registry, past replay.
- `Manifest::pubkeys()` is repaired from positional to index-keyed.

## 2. Why there is no activation constant

The usual G4 pattern is a wall-clock or epoch gate held at `u64::MAX` until a
flag day. It is the wrong instrument here, and using it would manufacture the
exact failure it is meant to prevent.

A gate would read "below epoch E, resolve keys from the manifest; at or above
E, resolve them from the registry". Below E that is a promise to keep
rejecting a registered validator's genuine signature — i.e. to keep the defect
deliberately. At E every node would switch on a clock, and any node not on the
armed binary would be forked out at that instant, which is precisely the E=1400
hazard the runbook for that day describes.

The change does not need one, because it is **inert by construction** while the
registry equals the genesis set (§3), and because a disagreement about it is
bounded to liveness rather than safety (§4). Ungated and uniform is strictly
safer than gated.

The thing that *does* need a flag day is **deposits** — and that is a separate
decision, taken later, by the founder (§6).

## 3. The inertness proof

The claim: while the registry equals the genesis set, the new registry lookup
and the deployed binary's index lookup return **the same bytes for every
index**, and both answer `None` past the end.

This must be proven in code, not over the wire: `getvalidator` exposes only
`pubkey_hash` and a `pubkey_bytes` length, never key bytes, so no RPC
comparison can establish byte equality.

Proven by `crates/bloch-pos-node/src/genesis.rs`:

| test | what it establishes |
|---|---|
| `registry_lookup_equals_the_manifest_table_at_genesis` | For both the devnet and mainnet manifest fixtures, the committed registry and the **deployed** boot table return identical bytes at every index, and both return `None` for eight indices past the end. |
| `inertness_ends_at_the_first_deposit` | The precondition is not decorative: at the first deposited index the registry answers and the boot table cannot. This is the exact moment the change stops being inert. |
| `the_manifest_table_no_longer_empties_sparse_indices` | The repaired `pubkeys()` is itself inert on a dense manifest, and no longer yields an empty key on a sparse one. |

The reference table is **copied, not called** — the test reproduces the body at
`g4-node-20260901:crates/bloch-pos-node/src/genesis.rs` verbatim. Calling the
current `pubkeys()` would prove only that the build agrees with itself.

### 3.1 The precondition, measured

Read from both archivals on 2026-09-02, epoch 1750, height 35119. Both
returned the identical `block_id` and `state_root`, so the two-node read
quorum is satisfied:

- `validators: {total: 64, active: 64}`
- indices 0–63 all resolve; index 64 returns
  `validator 64 is not in the committed registry (64 registered)`
- all 64: `activation_epoch: 0`, `exit_epoch: null`, `slashed: false`
- 64 **distinct** `pubkey_hash` values — the index → key map is injective on
  the live chain, empirically, not only structurally

No deposit has ever landed. The registry *is* the genesis set. Inertness holds
today.

### 3.2 What actually holds inertness — read this before §6

Inertness is preserved by **node-local mempool policy, not by consensus.**

`engine::admissible` refuses `Deposit` and `Delegate` outright, but it is
reached only from `Engine::on_transaction`, the mempool admission path.
`CommittedState::apply_transaction` applies a `Deposit` with **no height,
epoch, or flag-day gate of any kind**. A deposit carried inside a block
bypasses `admissible` entirely and allocates index 64.

Consequences, stated plainly:

1. There is no consensus rule preventing index 64 from existing. The only
   thing preventing it is that every producer on the fleet runs a binary whose
   mempool refuses deposits.
2. "Arming the deposit flag day" is therefore not setting a constant. It is
   *lifting a refusal in node-local policy* — and lifting it on **one**
   producer is enough to create index 64 for the whole network.
3. So there is no coordination point in the code, and no tripwire. The repo's
   own §0 rule ("the constant, the tripwire and the doc enter in the same
   commit") cannot be satisfied by a change that has no constant.

**Recommendation, for the founder's decision and not actioned here:** before
deposits are opened, add a genuine consensus gate — a
`DEPOSIT_ACTIVATION_EPOCH` in `params.rs`, held at `u64::MAX`, checked in the
`Deposit` arm of `apply_transaction`. That does *not* have the §2 problem: it
makes every node agree that deposits are invalid before E and valid after,
which is a shared rule, not a divergent one. It converts the arming from an
operator's discretion into an auditable, in-consensus event.

## 4. The mixed-fleet hazard

The author's finding, and the reason ordering is the whole plan.

Once index 64 exists and is drawn for a committee:

| | old binary | new binary |
|---|---|---|
| resolves key for index 64 | `None` → `BadSignature` | registry → verifies |
| verdict on a block containing that attestation | **reject** | **accept** |

The two halves of the fleet then disagree about block validity — a fork, on
the safety axis, not a propagation delay. **Partial deployment is strictly
worse than either uniform state**: an all-old fleet is consistently broken (no
deposit can vote) and an all-new fleet is consistently correct, but a mixed
fleet splits.

This is bounded in one respect that matters. Because the registry is
append-only — indices allocated `keys().next_back() + 1` and never reused, no
production path mutating `ValidatorRecord::pubkey`, nothing ever removing a
record — two registries can differ only by **presence**, never by **content**.
A stale registry can be *missing* an index; it can never hold a *different*
key at one. So a node that is merely behind declines a signature it cannot yet
resolve and recovers as it catches up. That is why gossip absence is `Ignore`
and never `Reject`, and it is the difference between this and the 2026-08-08
`expected_bits` class of defect. It does **not** rescue the mixed-binary case
above, where the disagreement is permanent rather than transient.

## 5. The uniformity check

Modelled on the E=1400 audit, with one honest gap named.

**Order:** roll the binary, prove uniformity, and only then consider §6. Never
the reverse.

1. **Pin the artifact.** Build once, record `sha256sum` of the release binary.
   Every host is verified against that one hash before its process is
   restarted, exactly as `rollout-classico-e1400.sh` does. A host whose hash
   diverges is aborted, not retried.
2. **Pre-check the validator key.** `sha256sum` of `<node>/validator.key`
   before and after, per host. E=1400 caught real mistakes with this.
3. **`selfcheck` before `run`.** The subcommand exists (`main.rs:95`); a
   binary that fails it never replaces a running node.
4. **One node at a time**, waiting for each to rejoin. Every restart costs a
   full replay — roughly 21 minutes of silent RPC and a real gap in that
   node's duties — so the roll must be paced against the fleet's finality
   margin, not run in parallel.
5. **Enumerate liveness by RPC, never by SSH** (`16400 + i`). SSH coverage of
   the fleet has been incomplete before and reading it as fleet membership has
   produced wrong conclusions.
6. **Prove uniformity, do not assume it.** After the roll: every validator in
   the fleet answers on its RPC port; every one agrees with both archivals on
   `state_root` at a common height; no node is on a divergent branch (compare
   `height` and `block_id`, not `epoch` — a divergent node answers and attests
   and looks healthy doing it). The roll is not complete while any validator
   is unreachable: an unreachable node is an unknown binary, and §4 is about
   binaries, not about reachability.

### 5.1 The gap: binary identity is not observable over RPC

There is **no build-identity field in the RPC on this lineage** — `rpc.rs`
exposes no commit hash or binary digest. So step 6 can prove that 64 nodes
agree on chain state, which is necessary, and cannot prove that 64 nodes are
running the same binary, which is what §4 actually requires. Agreement on
state root is not evidence of binary uniformity while the change is inert —
that is precisely what inert means.

Until that gap is closed, uniformity rests on the per-host hash check in step
1, which requires SSH access to every host that runs a validator, and on
nothing else.

**Recommendation:** land `rpc/build-identity` before the roll. The work already
exists — `51d10357 rpc: getbuildinfo — say which binary is answering, and which
consensus lineage it is on` — and it is exactly the missing instrument: it
turns uniformity from an inventory taken over SSH into a query answered by
every node on the port the fleet is already enumerated on. Landing it first
also means the roll can be audited *while it happens* rather than reconstructed
afterwards, and it is the cheapest item in this document.

Note the ordering trap: `getbuildinfo` can only report on nodes that already
run a binary containing it. Rolling it out is itself a fleet roll. Either land
it in the same binary as this change — so the first roll is also the last one
that has to be audited by hash — or accept that this roll is audited by SSH.

## 6. Arming deposits — not now, and not by this document

Only after §5 completes, and only on the founder's decision:

1. The `admissible` refusal of `Deposit`/`Delegate` **stays up** for the whole
   roll and past it. It is the only thing holding inertness (§3.2).
2. Before it comes down, the open blockers recorded elsewhere still apply and
   are not addressed by this change: deposits mint stake without consuming an
   eUTXO, voluntary exit has no production path, and there is no tool that
   signs a checkpoint.
3. Prefer adding the consensus `DEPOSIT_ACTIVATION_EPOCH` gate (§3.2) over
   lifting a mempool refusal, so that the arming is one auditable event rather
   than 64 independent operator actions.

## 7. Rollback

Rolling back is safe **only while inertness holds** — i.e. only while no
deposit has landed. Once index 64 exists, reverting a node to the old binary
puts it on the losing side of §4; the old binary cannot verify the newcomer
and will reject blocks the rest of the fleet accepts. After the first deposit,
the old binary is not a rollback target at all.

The same asymmetry is the reason §6 must never begin before §5 finishes: the
roll is reversible right up until deposits are armed, and irreversible after.
