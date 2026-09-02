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
  returns `ExternalQuorumNotReached` for that combination.

  **Read that claim precisely, because it is weaker than it sounds.** Every
  client enforces the numbers stated in the *arrangement file it was given*,
  not the numbers §6 states. `ws::matches_policy` is the function that compares
  the two, and no acceptance path calls it — a fact confirmed by grep, not
  assumed. So an arrangement file declaring `min_external = 0`, or seating one
  key in two slots, produces a "2-of-3" that one founder-adjacent holder can
  satisfy alone, and every client accepts it without comment. §2 below says
  what to do about that; the short version is that the arrangement file is part
  of the trust anchor and must be checked across channels exactly like the
  checkpoint.
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
  --current-epoch <the epoch the chain is at right now> \
  --signer <path>/foundation.pk:internal \
  --signer <path>/postern.pk:internal \
  --signer <path>/auditor.pk:external \
  --out checkpoints/signer-set-1.bin
```

### Read the two derived epochs before you continue

The command prints:

```
review due at epoch <r> (+365 days), refused from epoch <h> (+456 days) — §6.3
```

`--adopted-epoch` is the one value on this command line whose mistyping is
invisible afterwards. Both deadlines are derived from it by adding a fixed
41,040 epochs, so **any** large value pushes them past every epoch the chain
will ever reach — 10^12 is about thirty million years of sixteen-minute
epochs, and nothing overflows — while `u64::MAX` clamps the addition outright.
In every such case the §6.3 refusal and the twelve-month review warning are
comparisons that can never be true, permanently, and the resulting envelope is
indistinguishable from a correct one. That is why `--current-epoch` is
required: it is the stated reference the value is checked against, and a
ceremony that cannot say what epoch it is running at is not ready to sign.

### Two things this file can silently be, and neither is visible later

**`signer-set-1.bin` carries the quorum RULE, not just the keys**, and it
reaches a node over the same unauthenticated channel as the envelope. Every
node enforces the numbers *this file states*. Nothing on the acceptance path
compares them against §6 — `ws::matches_policy` exists and, until this work,
was called only from tests.

1. **`--min-external 0`** produces a file that says "no outside witness
   required". A Foundation + Postern quorum then verifies on every client and
   the artifact looks perfectly ordinary. **"Every valid Phase A quorum
   contains the auditor" is a property of this file, not of the code.**
2. **One key in two slots** produces a 1-of-3 wearing a 2-of-3's clothes: the
   quorum counts distinct *indices*, never distinct *keys*, so a single holder
   signs once, the identical signature is listed at both indices, and every
   rule passes. Seat the duplicate once `internal` and once `external` and the
   external minimum falls in the same stroke.

`ws-signer-set` refuses to write either; `ws_boot::decode_signer_set_file` now
refuses to *load* a duplicate-key arrangement at all, which covers every node
rather than only ceremonies run with this tool; and a node that loads an
arrangement matching neither §6 phase now says so loudly at boot, naming
`min_external = 0` when that is the reason. **None of that helps anyone who
was handed a different file.** That is what the fingerprint is for.

It prints `policy: matches the §6.1 Phase A policy (2-of-3, ≥1 external)`. If
it prints `MATCHES NEITHER §6.1 PHASE`, stop: that is fine for a drill and
wrong for publication.

`signer-set-1.bin` is public. Publish it alongside every envelope — a node
needs both (`--ws-checkpoint` *and* `--ws-signer-set`) — and **publish its
SHA3-256 fingerprint the way you publish the ws digest**. The command prints
it. Agreement of the fingerprint across independent channels is the only thing
that makes the arrangement as checkable as the checkpoint it accompanies.

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

Give **at least two** `--rpc` endpoints, on independently operated nodes. A
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

First, read the artifact on your own machine. No keys, no arrangement, no
network:

```
bloch-pos ws-verify --checkpoint wscheckpoint-<epoch>.bin
```

It prints every field and the `WS DIGEST` those bytes hash to. Compare that
digest against the one the coordinator announced **through a channel that is
not the one the file arrived on**, and against what the other two signers
read. If they differ, stop. Do not sign.

Then, offline:

```
bloch-pos ws-sign \
  --key <path>/foundation.sk \
  --pubkey <path>/foundation.pk \
  --checkpoint wscheckpoint-<epoch>.bin \
  --signer-index 0 \
  --out foundation.partial
```

`--signer-index` is your 0-based slot in the arrangement: Foundation 0,
Postern 1, auditor 2. It is recorded *inside* the output file, so a
coordinator who later pairs the files wrongly is told which file was signed as
which slot instead of being told a signature is bad.

`--pubkey` makes the tool verify its own signature through the real path
before writing it — a signature that does not verify dies here, not at an
assembly with two other people waiting. Always pass it.

What is signed is `ws_digest`, recomputed on the signing machine from the 154
bytes. A signer is never asked to sign a bare digest handed to them, because a
bare digest matches no artifact anyone can check.

The output is a **partial signature**, not a bare signature: it carries the
digest it was made over, your slot, and the bytes. That digest is what lets the
coordinator distinguish "this signer was shown a different checkpoint" — which
names a person to call — from "this file is corrupt", which names nobody. Read
your own back before sending it:

```
bloch-pos ws-verify --partial foundation.partial
```

`foundation.partial` contains no secret and can be sent over any channel. It is
the **only** file that leaves the signing machine.

### Step 4 — M: assemble, or fail to

```
bloch-pos ws-envelope \
  --checkpoint checkpoints/wscheckpoint-<epoch>.bin \
  --signer-set checkpoints/signer-set-1.bin \
  --genesis genesis/mainnet.manifest \
  --sig 0:foundation.partial \
  --sig 2:auditor.partial \
  --out checkpoints/wscheckpoint-<epoch>.envelope.bin
```

The index in `--sig <index>:<file>` is the signer's 0-based position in the
arrangement, as in step 2 of §2. Getting it wrong is caught, not published.

The index in `--sig <index>:<file>` must agree with the slot recorded inside
the partial; if it does not, the command names which file was signed as which
slot and refuses.

Before it writes anything this command runs two gates. First
`ws_boot::combine`, which checks the *shape* of the quorum while the signers
are still reachable — threshold, external minimum, index validity, no signer
counted twice, the arrangement's §6.3 window, and that **every partial was made
over this checkpoint's digest**. A signature over last epoch's checkpoint, or
over one with an edited root, is named here as `DigestMismatch` against the
signer who made it, before any cryptography runs. `combine` also fixes the
signature order, so two coordinators who collected the files in different
orders publish byte-identical envelopes.

Then `ws::verify_envelope` — the exact function a booting node runs — on the
envelope it just built, and again on the envelope re-read from its own file
bytes. **Nothing is written unless all of them pass.** An under-quorum envelope, one with no external signature, one naming
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

---

## 7. Never re-mint an epoch that has already been published

This one halts nodes, and nothing in the artifact hints at it.

`issued_at` is documented as informational — `ws::verify_envelope` never reads
it, deliberately, so that an artifact checked at boot does not depend on the
verifying machine's clock. But it *is* one of the nine fields inside
`canonical_serialize`, so it is inside `ws_digest`. **Two mints of the same
epoch made at different wall-clock seconds are two different artifacts.**

The anti-rollback rule (`ws::accept`) keys on the epoch:

| stored | incoming | verdict |
| ------ | -------- | ------- |
| epoch E | epoch > E | `Store` — supersedes cleanly |
| epoch E | epoch < E | `Ignore` — a stolen old quorum cannot refresh a node backward |
| epoch E, digest X | epoch E, digest X | `Ignore` — re-delivery is a no-op |
| epoch E, digest X | epoch E, digest **Y** | **`Conflict`** |

and `ws_boot::boot` turns `Conflict` into a refusal to start, by design: two
validly-signed checkpoints for one epoch mean a quietly-replaced publication or
an equivocal quorum, and that must never be a silent overwrite.

So:

> **Publishing a checkpoint for epoch E, and later publishing a corrected one
> for the same epoch E, bricks the boot of every node that stored the first.**
> Both quorums are valid. Both attest the same history. The roots are
> identical. The node still refuses, because from inside the protocol this is
> indistinguishable from an equivocating signer set.

Concretely:

- **Never publish an interim, provisional, or "we'll redo it properly" mint.**
  There is no such thing as a draft checkpoint. The first artifact you publish
  for an epoch is the only one that epoch can ever have.
- **If a published checkpoint is wrong, correct it at the NEXT publication
  epoch** (`E + 256`), not at `E`. A higher epoch is `Store` and supersedes
  cleanly, with no node refusing anything.
- **Re-minting is safe only if it is byte-identical.** That is why
  `ws-checkpoint` takes `--issued-at` and why the drill's re-mint check pins
  the exact bytes: an identical re-mint is `Ignore`, a near-identical one is
  `Conflict`. When a signer re-mints to check the coordinator's work, they must
  pass the published `--issued-at`, or they will produce a different digest and
  reasonably conclude they have been shown a forgery.
- **Fix the `issued_at` before you distribute anything.** It cannot change
  after the first signature, and it cannot change after publication either.

`bloch-pos ws-verify --checkpoint <file>` prints this warning next to
`issued at`, so a signer meets it before signing rather than after.

---

## 8. Verifying a completed checkpoint independently, before publishing

Anyone can run this; it is the check that makes publication safe rather than
hopeful. It needs only the two published files and a genesis manifest.

```
bloch-pos ws-verify \
  --envelope checkpoints/wscheckpoint-<epoch>.envelope.bin \
  --signer-set checkpoints/signer-set-1.bin \
  --genesis genesis/mainnet.manifest \
  --rpc <a node you run>
```

Read all of it, not just the `VERDICT:` line:

1. **`WS DIGEST`** — must equal what every signer read on their own machine.
2. **`epoch`, `block root`, `state root`** — re-mint them yourself from two
   archivals on different hosts (`ws-checkpoint`, with `--issued-at` set to the
   published value) and confirm the file is byte-identical.
3. **The arrangement block** — `quorum`, `adopted at epoch`, `review due`,
   `hard stop`. If `min_external` is 0, or the shape is not 2-of-3 / 3-of-5,
   the arrangement is not the one §6 describes regardless of what the
   announcement says.
4. **The arrangement fingerprint** — compare against an independent channel.
   This file carries the quorum rule; an attacker who can substitute it does
   not need to forge a signature.
5. **Per-signature verdicts** — confirm that the `EXTERNAL` line is present and
   `VALID`. That, and only that, is what makes the quorum contain the auditor.
6. **`FRESHNESS`** — a checkpoint older than 2,016 epochs is refused by a fresh
   node no matter how well it is signed.

Publish only after at least two people have done this on machines that share
nothing.

---

## 9. The refusals, and how they were checked

A signer whose output the verifier accepts is half a test. The other half is
that the toolchain refuses what it must, and that each refusal is load-bearing
rather than decorative.

**Executable:** `scripts/ws-ceremony-drill.sh <path-to-bloch-pos> [workdir]`
runs the whole ceremony with disposable keys and then forges bad artifacts *by
byte surgery, outside the toolchain*, so the drill tests the verifier and not
the tool's willingness to refuse itself. 40 checks; every one must pass. It
reads two archival RPCs and writes nothing outside its workdir.

**Unit:** `cargo test -p bloch-pos-node --bin bloch-pos ws_` — 37 tests
covering the combination rules, the arrangement-clock bound, the duplicate-key
arrangement, and the re-mint conflict above. The whole node binary is 161
passed / 11 ignored.

> **Profile note, so nobody repeats a wasted hour.** The ceremony changes are
> all in `bloch-pos-node`; `crates/bloch-pos-committee/` is untouched. If you
> nevertheless run the committee crate's suite, run it `--release`. In a debug
> profile a single test there —
> `beacon::tests::every_reveal_verifies_and_the_chain_walks_down_to_the_seed`,
> which walks all 8,192 steps of a SHAKE-256 RANDAO chain — takes about a
> minute unoptimized, and the 301-test suite takes tens of minutes. That is
> slowness, not a hang, and it predates this work.

Each refusal below was confirmed *by violation*: the named check was deleted,
the suite was run to confirm exactly the paired test went red, and the check
was restored.

| check deleted | test that went red |
| ------------- | ------------------ |
| `combine`: the `p.digest != digest` binding | `combine_refuses_a_partial_over_a_different_root`, `..._for_a_different_epoch` |
| `combine`: the duplicate-index check | `combine_refuses_the_same_signer_counted_twice` |
| `combine`: the external minimum | `combine_refuses_a_quorum_that_violates_the_policy`, `combine_agrees_with_verify_envelope` |
| `combine`: the deterministic ordering | `combination_is_order_independent` |
| `arrangement_window`: the lower bound | `the_arrangement_window_bounds_every_adopted_epoch` |
| `decode_signer_set_file`: the saturating-clock refusal | `the_decoder_refuses_an_overflowing_arrangement_clock` |
| `decode_signer_set_file`: the duplicate-key refusal | `one_key_in_two_slots_is_a_forgeable_quorum_and_the_decoder_refuses_it` |

Two tests deliberately assert a *weakness* rather than a defence, so that the
day someone fixes it upstream, the test fails and the fix is noticed:
`one_key_in_two_slots...` asserts that `ws::verify_envelope` still accepts a
duplicate-key arrangement, and `the_external_minimum_is_only_as_good_as_the_arrangement_file`
asserts that `min_external = 0` still verifies.

---

## 10. Which epoch to sign — measured 2026-09-02, and how to re-measure it

Measured at 2026-09-02 ~18:40 UTC against both archivals, which agreed:
chain epoch **1775**, finalized **1773**, height 35,906.

Re-measure before acting; these numbers rot by one epoch every sixteen minutes:

```
for h in <archival-a> <archival-b>; do
  curl -s -X POST "http://${h}:8080" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}'
done
```

Both must agree before you trust either. Genesis is unix `1786656679`, so
epoch *E* begins at `1786656679 + E * 960`.

### The arithmetic

A checkpoint at epoch *E* lets a fresh node sync until wall epoch
`E + WS_PERIOD_EPOCHS` (2,016). With no checkpoint at all, the anchor is the
genesis (epoch 0) and the deadline is epoch 2,016 itself.

| anchor | fresh sync works until | date |
| ------ | ---------------------- | ---- |
| genesis (epoch 0) — **today's situation** | epoch 2,016 | **2026-09-05 07:07 UTC** |
| epoch 1,536 (the minted, unsigned artifact) | epoch 3,552 | 2026-09-22 08:43 UTC |
| epoch 1,792 (the next publication epoch) | epoch 3,808 | 2026-09-25 04:59 UTC |

Epoch 1,792 begins **2026-09-02 19:23 UTC** and is finalized roughly two epochs
later.

### The recommendation

**Sign epoch 1,792**, not 1,536, if the three holders can be assembled after it
finalizes. It is the cadence-correct publication epoch
(`is_publication_epoch(1792)`), it buys three more days, and it does not start
its life having already spent 12% of its window — 1,536 was finalized around
2026-08-30 and is over 240 epochs old before anyone has signed it.

**Sign epoch 1,536 instead** if, and only if, the holders are available *now*
and would not be available after 19:23 UTC. It clears the 2026-09-05 cliff,
which is the thing that actually matters, and it is the artifact the drill has
already rehearsed byte-for-byte. Publishing 1,536 does not foreclose 1,792: a
higher epoch is `Acceptance::Store` and supersedes cleanly. The one-way door of
§7 is *within* an epoch, not between epochs.

**Do not sign an epoch that is not a multiple of 256.** Nothing enforces it —
`ws::verify_envelope` never checks publication cadence — but the every-256
rhythm is what the six-missed-ceremonies margin is computed against, and an
off-cadence artifact makes the next scheduled one ambiguous.

### What this changes about the deadline

The 2026-09-05 07:07 UTC date is real and it is close, but it is **not** a
chain event and **not** a rollout dependency. `ws.rs` — the consuming half of
this mechanism, including `verify_envelope` — is byte-identical between the
release tag, the fleet commit, and every branch that carries the ceremony tool.
The 64 running validators are unaffected either way; nothing needs to land,
roll, or restart for a published checkpoint to be usable. What the date decides
is whether a new validator or an exchange can stand up a fresh node at all.

So the deadline is a **product and onboarding** deadline, not an operational
one, and the critical path is entirely human: three key holders, on three
machines, who do not exist yet as of this writing. Everything a ceremony needs
in software is in this repository and rehearsed.
