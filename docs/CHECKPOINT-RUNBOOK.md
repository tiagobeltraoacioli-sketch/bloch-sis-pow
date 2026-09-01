<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Weak-subjectivity checkpoint runbook

How to mint, sign, assemble, publish and verify a Genesis-4 weak-subjectivity
checkpoint. Written to be followed by an operator who did not write the tool.

Normative definitions live in code, not here:
`crates/bloch-pos-committee/src/ws.rs` (the checkpoint, the signing root, and
the acceptance rules), `crates/bloch-pos-node/src/ws_boot.rs` (the two file
framings and the boot enforcement), `crates/bloch-pos-node/src/ws_tool.rs`
(these commands). The design document is
`docs/specs/BLOCH-WEAK-SUBJECTIVITY.md`.

---

## 0. Why this is not optional

Under proof of work a fresh node needs only the genesis: forging a heavier
history costs as much as living the real one. Under proof of stake it does
not. Once a validator's stake has cleared withdrawal, its key can sign anything
forever at zero cost — so a quorum of *exited* validators can manufacture a
complete alternative history whose every signature verifies. Nothing inside the
protocol lets a syncing node tell that forgery from the chain the network
actually lived.

So the node refuses. A node with no finalized history of its own, whose only
anchor is older than `ws::WS_PERIOD_EPOCHS`, exits with
`ERR_WS_REQUIRE_CHECKPOINT`; a long-offline node past the same window exits with
`ERR_WS_STALE`. **Both refusals are the mechanism working.** A published,
signed checkpoint is the only sound way back in — which means that if no one
publishes one, no new validator can ever join.

Check where the window stands before anything else:

```
bloch-pos ws-verify --envelope <latest published env.bin> \
                    --signer-set <set.bin> \
                    --genesis <manifest> \
                    --rpc <a node you run>
```

The `FRESHNESS` line says `FRESH`, `STALE` or `EXPIRED`. `STALE` means publish
now. `EXPIRED` means new nodes are already being turned away.

---

## 1. Cadence and who signs

- Publish at every finalized epoch that is a multiple of
  `ws::WS_PUBLICATION_INTERVAL_EPOCHS` (256). Against the window this leaves
  roughly a 7.8× margin: six consecutive ceremonies can fail before the newest
  published checkpoint ages out. The seventh miss is a liveness event.
- Phase A arrangement (spec §6.1): **2-of-3, at least one external.** The three
  holders are the Foundation, Postern Labs, and the external audit firm. Two
  founder-adjacent keys are deliberately not a quorum — `verify_envelope`
  returns `ExternalQuorumNotReached` for that combination, so the rule is
  enforced by every client, not by ceremony discipline.
- The arrangement has a review clock. Twelve months after `--adopted-epoch`
  envelopes start warning; three months after that they are **refused**
  (`ArrangementExpired`, the §6.3 dead-man's switch). `ws-verify` prints both
  epochs. Do not discover this at the cliff.

---

## 2. One-time setup: the three signer keys

Checkpoint signers are **not** validators. Their keys do not exist until the
three holders create them, and nothing in this repository holds or must ever
hold them.

Each holder, **once, on their own machine, air-gapped, in an unobservable
session** (no shared shell, no screen recording, no CI log):

```
bloch-pos ws-keygen --out foundation      # or: postern, auditor
```

Writes:

| file             | mode | leaves the machine? |
| ---------------- | ---- | ------------------- |
| `foundation.pk`  | 0644 | yes — this is public |
| `foundation.sk`  | 0600 | **never**            |

The `.sk` file is plaintext hex at 0600. That is adequate only on a machine
that is genuinely air-gapped and physically controlled; it is not adequate on a
laptop that travels. Keep the offline backup on separate media, and treat loss
and compromise the same way — both require governance to rotate the arrangement
under a new `--id`.

Each holder sends their `.pk` to whoever assembles the arrangement, and **reads
the file's SHA3-256 aloud on a call while doing it**. The arrangement is only
as good as the belief that slot *i* holds the key you think it does.

### Build the arrangement file

`--signer` order **is** the signer index. `signer_index` in every envelope
indexes into this order, so the published table and this command line must list
the same keys in the same order. Once published, never reorder a set — reissue
it under a new `--id`.

```
bloch-pos ws-signer-set \
  --id 1 \
  --threshold 2 \
  --min-external 1 \
  --adopted-epoch <the epoch this arrangement takes effect> \
  --signer foundation.pk:internal \
  --signer postern.pk:internal \
  --signer auditor.pk:external \
  --out checkpoints/signer-set-1.bin
```

It prints `policy: matches the §6.1 Phase A policy (2-of-3, ≥1 external)`. If
it prints `MATCHES NEITHER §6.1 PHASE`, stop: that is fine for a drill and
wrong for publication.

`signer-set-1.bin` is public. Publish it alongside every envelope — a node
needs both (`--ws-checkpoint` *and* `--ws-signer-set`).

---

## 3. The 2-of-3 ceremony, three machines, no key ever shared

Roles below: **M** is the mint/assembly machine (online, no keys). **S0**,
**S1**, **S2** are the three signers' own machines (offline, one key each).
Only M touches the network.

### Step 1 — M: mint the checkpoint (no keys involved)

```
bloch-pos ws-checkpoint \
  --genesis genesis/mainnet.manifest \
  --rpc <nodeA:port>,<nodeB:port> \
  --epoch <latest finalized multiple of 256> \
  --signer-set-id 1 \
  --out checkpoints/wscheckpoint-<epoch>
```

Give **at least two** `--rpc` endpoints, on **different hosts** — see the
concrete endpoint table in `CHECKPOINT-CEREMONY-CHECKLIST.md` §3, which names
the two that are reachable from outside the fleet today. Two ports on one box
are two validator processes but one witness, and `ws-checkpoint` now says so
rather than counting them as two. A
forked node answers as confidently as a correct one; the tool refuses on any
disagreement and prints a single-endpoint warning if you give it only one. This
fleet has had real forks — treat the warning as a stop.

The command refuses any epoch the chain has not finalized, derives the
epoch-boundary block by the same convention the finality store votes
(`engine::checkpoint_root`: the last canonical block strictly before the
epoch's first slot), cross-checks that against the node's own finalized root,
and recomputes `network_id` and `genesis_root` from the manifest exactly as a
booting node does.

Outputs `wscheckpoint-<epoch>.bin` (the 154 canonical bytes — this is the
artifact) and `wscheckpoint-<epoch>.json` (a human view — not the artifact),
and prints the **ws digest**.

> `validator_set_root` is all zeros and that is correct. See §6.

### Step 2 — M → S0, S1, S2: distribute

Send each signer the same three things:

1. `wscheckpoint-<epoch>.bin` (154 bytes — small enough for any channel),
2. the `.json` view,
3. the **ws digest**, over a *different* channel than the file.

### Step 3 — each signer, on their own machine: check, then sign

Each signer independently re-derives the digest and compares it against what
the other two signers see. It is 64 hex characters — it fits in a phone call.
That comparison is the ceremony. If any signer's digest differs, someone was
handed a different checkpoint, and signing is the one thing they must not do.

A signer who runs their own node should re-mint the checkpoint themselves
(step 1, same flags, `--issued-at` fixed to the published value) and confirm
they get a byte-identical file.

Then, offline:

```
bloch-pos ws-sign \
  --key foundation.sk \
  --pubkey foundation.pk \
  --checkpoint wscheckpoint-<epoch>.bin \
  --out foundation.sig
```

`--pubkey` makes the tool verify its own signature through the real path
before writing it — a signature that does not verify dies here, not at an
assembly with two other people waiting. Always pass it.

What is signed is `ws_digest`, recomputed on the signing machine from the 154
bytes. A signer is never asked to sign a bare digest handed to them, because a
bare digest matches no artifact anyone can check.

`foundation.sig` contains no secret and can be sent over any channel.

### Step 4 — M: assemble, or fail to

```
bloch-pos ws-envelope \
  --checkpoint checkpoints/wscheckpoint-<epoch>.bin \
  --signer-set checkpoints/signer-set-1.bin \
  --genesis genesis/mainnet.manifest \
  --sig 0:foundation.sig \
  --sig 2:auditor.sig \
  --out checkpoints/wscheckpoint-<epoch>.envelope.bin
```

The index in `--sig <index>:<file>` is the signer's 0-based position in the
arrangement, as in step 2 of §2. Getting it wrong is caught, not published.

Before it writes anything, this command runs `ws::verify_envelope` — the exact
function a booting node runs — on the envelope it just built, and then again on
the envelope re-read from its own file bytes. **Nothing is written unless both
pass.** An under-quorum envelope, one with no external signature, one naming
the wrong arrangement, one with a mispaired index, or one whose checkpoint was
altered after signing cannot come out of this command. On success it prints
`ACCEPTED by ws::verify_envelope`.

`--genesis` is optional but should always be given: without it the network-id
and genesis-root checks are made against the checkpoint's own claims, which is
circular. The tool says so when you omit it.

### Step 5 — verify as a stranger would, then publish

```
bloch-pos ws-verify \
  --envelope checkpoints/wscheckpoint-<epoch>.envelope.bin \
  --signer-set checkpoints/signer-set-1.bin \
  --genesis genesis/mainnet.manifest \
  --rpc <a node you run>
```

Prints every field, a per-signature verdict, the quorum arithmetic, the
arrangement's review and hard-stop epochs, the freshness verdict, and one
`VERDICT:` line. Exit status is non-zero if the envelope is refused.

Publish, together, to **at least two independent channels** (site, release
pages, explorer, announcement channel):

- `wscheckpoint-<epoch>.envelope.bin`
- `signer-set-1.bin`
- the ws digest, in the announcement text

Agreement of the digest across independent channels is the evidence. The
artifact's own say-so is not.

---

## 4. What an operator joining the network does

```
bloch-pos run --data-dir <dir> \
              --ws-checkpoint wscheckpoint-<epoch>.envelope.bin \
              --ws-signer-set signer-set-1.bin
```

Before starting, they should run the `ws-verify` of step 5 themselves and
compare the printed digest against a second publication channel.

Boot refusals and what they mean:

| message | meaning |
| --- | --- |
| `ERR_WS_REQUIRE_CHECKPOINT` | Fresh node, anchor older than the window. Get a newer envelope. |
| `ERR_WS_STALE` | This node was away longer than the window. Get a newer envelope. |
| `WS_CONFLICT` | The published checkpoint contradicts this node's OWN finality. The node keeps its database and does **not** reorganize. Escalate immediately: either the signers published a false checkpoint or this node is on a forged branch. Never resolve this by deleting a data directory — that is how evidence disappears. |
| `Acceptance::Conflict` at boot | Two validly-signed checkpoints for one epoch with different digests. A replaced publication or an equivocal quorum. Compare digests across channels before trusting either. |

---

## 5. If a ceremony cannot be held

Six consecutive missed publications are survivable; the seventh is a liveness
event. If a signer is unreachable, the other two plus the external signer are
enough only if the external minimum is met — with Phase A that means the
auditor's signature is *mandatory* for every publication. Plan the calendar
around the external signer, not around the Foundation.

If the arrangement is approaching its hard stop, the fix is governance adopting
a new arrangement under a new `--id`, not more signatures. `ws-verify` prints
the hard-stop epoch on every run so this is visible months ahead.

---

## 6. `validator_set_root` is all zeros, and that is correct

Every checkpoint this tool mints carries
`validator_set_root = 0000…0000`. This is deliberate, it is what the node
itself does, and it does **not** mean the checkpoint fails to pin the validator
set.

- **The validator set is pinned, by `state_root`.** `state_root` is the root of
  the single state SMT, and every `ValidatorRecord` is a leaf in it under
  `TAG_VALIDATOR` (`state_root::build_state_tree_inner`). Pinning `state_root`
  pins the registry cryptographically.
- **`validator_set_root` is a separate convenience commitment.** Spec §4.3 step
  2 reserves it so a checkpoint-syncing node can verify a downloaded registry
  *without first rebuilding the whole state tree*. It is an optimisation of a
  verification path, not the verification itself.
- **Nothing computes such a root anywhere in this repository**, and
  checkpoint-sync state download does not exist yet (see the "honestly not
  wired" note in `ws_boot`'s module docs — this node syncs by replaying full
  blocks). So there is no producer and no consumer.
- **`ws::verify_envelope` never reads the field.** It is bound into `ws_digest`
  — so it is signed, and cannot be edited in a published artifact without
  invalidating every signature — and nothing else.
- The node passes the same zeros to `ws::genesis_anchor` (`engine.rs`: "no
  validator-set SMT root exposed at this milestone").

**The forward hazard, written down so it is not discovered later:** when
checkpoint-sync state download (§4.3.2) is implemented, it must **refuse** an
all-zero `validator_set_root` rather than treat it as "matches". A naive
implementation that compares a computed root against zeros and passes would
turn today's honest placeholder into tomorrow's bypass. Checkpoints published
before that day will need re-issuing with a real root; `ws-checkpoint` already
accepts `--validator-set-root <hex32>` for that day.
