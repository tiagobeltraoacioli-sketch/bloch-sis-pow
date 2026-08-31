<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch PoS — Node-Local Slashing Protection (signing history)

```
Document:   BLOCH-SLASHING-PROTECTION
Status:     CURRENT — describes shipped code
Created:    2026-08-31
Owner:      PMO
Code:       crates/bloch-pos-node/src/signing_history.rs
            crates/bloch-pos-node/src/engine.rs  (the two gates, the
            doppelganger watch, the boot refusal)
            crates/bloch-pos-node/src/main.rs    (keygen, protection-export,
            protection-import, --accept-new-signing-history,
            --doppelganger-epochs)
Relates:    BLOCH-POS-NODE-INTEGRATION.md, BLOCH-ATTESTATION-GOSSIP.md
```

Until this shipped, a `bloch-pos` validator kept **no record of what it had
already signed**. The only per-validator file in a data directory was
`validator.key`; nothing in the process prevented one key from signing on two
machines, or from re-signing an old duty after a rollback. The defence was
operational discipline — one team running all 64 validators and using
`systemctl disable` religiously. That does not survive strangers running
validators on rented machines, restoring VM snapshots, or keeping a "backup"
node warm. This document specifies the node-local record that replaces
discipline with a refusal.

---

## 0. Scope: node-local policy, not consensus

Everything here changes what a node will **sign**, never what it will
**accept**. Two nodes, one with this protection and one without, validate
every block and attestation identically; there is no wire change, no state
change, and therefore **no flag day**. A node can adopt or drop it
unilaterally.

The risk the mechanism removes is a validator signing something slashable
(5% of stake plus ejection, per `bloch-pos-committee`'s `slashing` module).
The risk it introduces is exactly the dual: **a node refusing to sign when
it should** — one missed proposal or one missed attestation after a crash, a
few epochs of missed duties after a restart, or a validator that refuses to
start over a broken file. Every refusal path is deliberately biased that way,
because a missed duty costs a reward and an equivocation costs stake. An
operator who sees the node refuse should read the refusal message, not
delete the file that produced it.

## 1. The record

Per validator key, the store keeps three watermarks:

| field                  | meaning                                                      |
|------------------------|--------------------------------------------------------------|
| `highest-proposed-slot`| highest slot this key ever signed a **block proposal** for   |
| `max-source-epoch`     | highest source epoch this key ever signed an attestation with|
| `max-target-epoch`     | highest target epoch this key ever signed an attestation for |

plus two identity bindings: the **validator public key** (the suite-enveloped
hybrid key, verbatim) and the **network** (the genesis-manifest digest), so a
history can never be silently applied to a different key or a different
chain.

Signing is permitted only strictly above the watermarks:

- a proposal only for `slot > highest-proposed-slot`;
- an attestation only for `source >= max-source-epoch` **and**
  `target > max-target-epoch`.

That refuses all three slashable offences against everything previously
signed: a **double proposal** needs `slot <= highest`, a **double vote**
needs `target <= max-target`, and a **surround vote** in either direction
needs `source < max-source` or `target <= max-target`. Watermarks are
stricter than a full list of signed pairs — they also refuse some pairs a
full list would allow — but for this protocol the strictness is free: an
honest validator attests once per epoch with a non-decreasing justified
source and proposes at strictly increasing slots, so the honest sequence
never trips a watermark. Only a rewind does. In exchange the store is
fixed-size, needs no pruning policy, and exports to five lines of text.

## 2. Crash ordering — the load-bearing rule

**The watermark is advanced and fsynced BEFORE the signature is produced,
never after.** `SigningHistory::record_proposal` / `record_attestation`
return `Ok` only once the new record is durable (write to a temp file,
`fsync` the file, `rename` over `signing_history.bin`, `fsync` the
directory); only then may the caller sign. The crash cases:

- **crash before the record is durable** — nothing was signed and nothing is
  recorded; the duty happens (or not) after restart. Safe.
- **crash after the record, before or during signing/broadcast** — the store
  claims a signature that may never have existed; on restart the node
  refuses to re-sign that duty. **One missed duty, zero equivocations.**
  Fail safe by construction.

The reverse order (sign, then record) has a window in which a signature
exists with no record, and a crash there re-signs after restart — precisely
the accident this store exists to prevent. The order is not configurable.
If the record cannot be written (disk full, permissions, unreachable
directory), the signature is **refused**: a signature the store cannot
remember is a signature a restart can repeat.

## 3. On-disk format (`signing_history.bin`)

One file per data directory, next to `validator.key`. Little-endian, no
framing beyond the fields themselves (same conventions as the node's codec):

```
offset  size  field
0       8     magic  "BSIGHIS1"
8       1     flags  bit0 network-bound, bit1 has-proposal, bit2 has-attestation
9       32    network digest        (zeros when not network-bound)
41      4+N   pubkey                (u32 length prefix, then the bytes)
..      8     highest proposed slot (meaningful iff bit1)
..      8     max source epoch      (meaningful iff bit2)
..      8     max target epoch      (meaningful iff bit2)
```

Trailing bytes are an error. `source >= target` in a stored pair is treated
as corruption. A file that fails to parse is **never** treated as "start
fresh" — see §5.

Writes are whole-file and atomic (temp + fsync + rename + directory fsync):
a crash mid-write leaves either the old record or the new one, never a torn
file. A leftover `signing_history.bin.tmp` is inert.

## 4. Interchange format (export / import)

The migration artifact is deliberately human-readable — small enough to read
aloud over a phone before a key migration:

```
bloch-signing-history v1
network: <64 hex chars, or `unbound`>
pubkey: <hex of the suite-enveloped hybrid pubkey>
highest-proposed-slot: <u64, or `none`>
max-source-epoch: <u64, or `none`>
max-target-epoch: <u64, or `none`>
```

Lines beginning `#` and blank lines are ignored. The parser is strict:
unknown keys, missing keys, a half-present source/target pair, or
`source >= target` are errors — a protection file that parses "mostly"
protects mostly.

Commands:

- `bloch-pos protection-export --data-dir <dir> [--out <file>]` — write the
  history in the format above (stdout by default).
- `bloch-pos protection-import --data-dir <dir> --from <file>` — install the
  history, or **merge** it into an existing one. Merging is element-wise
  max: watermarks only ever go **up**, so an import can make the node refuse
  more, never less. An import is refused when the record names a different
  validator key, or a different network, than the destination holds.

### The migration procedure (the safe path, made the easy one)

Moving `validator.key` to another machine without its history is exactly how
double-signing happens — the new machine has no idea what the key already
signed. The procedure is therefore:

1. **Stop the old node.** Confirm the process is dead, not restarting
   (`systemctl disable --now`, then check). The export is only meaningful
   once nothing can add to the history.
2. On the old machine: `bloch-pos protection-export --data-dir <dir> --out
   history.txt`.
3. Carry `history.txt` **with** the key to the new machine.
4. On the new machine, **before the first `run`**: `bloch-pos
   protection-import --data-dir <dir> --from history.txt`.
5. Start the node. It binds the history to the key and the network and
   signs only above the imported watermarks.

Because `keygen` writes an empty `signing_history.bin` beside every new key,
a key created by this binary never exists without a history file — the only
way to reach "key without history" is to copy `validator.key` alone, and §5
makes that a refusal to start rather than a silent fresh start.

## 5. Missing or unreadable store: refuse to start

A node holding `validator.key` but no readable `signing_history.bin`
**refuses to run**. Missing history on a used key means the key's past is
unknown, and signing blind over an unknown past is the accident. The
refusal message spells out both exits:

- the key HAS signed before → export where it ran, import here (§4);
- the key has GENUINELY never signed on this network → start once with
  `--accept-new-signing-history`, the loud explicit first-boot override. It
  prints a banner stating what the operator just asserted, creates an empty
  history bound to this network, and should be dropped from the command line
  after that boot.

An unreadable or corrupt file is an error naming the repair path
(`protection-import`), never a fresh start: deleting a history because it
would not parse is deleting the record of what the key signed.

## 6. The doppelganger watch (startup)

The store cannot see a **concurrent** twin — two machines each hold their
own file and each happily advances it. What can see a twin is the network:
an active validator attests every epoch, and those attestations arrive
through this node's signature-verified gossip pipeline. So on a restart into
an already-running chain, the node stays **deliberately silent** for
`--doppelganger-epochs` epochs (default 2) and listens. A verified
attestation, or a canonical block, by its **own validator index**, for a
slot inside the silent window — a slot this node provably did not sign,
since the watch kept it from signing at all — means the key is live
elsewhere. The node raises a permanent alarm, refuses every future duty,
and **exits**, telling the operator to find and stop the other signer.

Precisely bounded, so nobody reads more protection into it than exists:

- the window test is on the **message's signed slot**, not arrival time, so
  a twin's vote from inside the window still convicts when it arrives late,
  while anything at or after the window's end proves nothing (past that
  slot it could be this node's own signature echoed back);
- the watch begins two slots after boot (mirroring the boot grace), so a
  signature this node's previous life released in the boot slot — crash and
  restart within one slot, or ±1 slot of clock skew — is not mistaken for a
  twin;
- history syncing in (slots before the watch began) never alarms;
- blocks count only once **canonical** — canonical is the one state in
  which the proposer signature is known verified; an unverified header's
  proposer index is a byte anyone can write, and must not let a stranger
  shut validators down by forging it;
- two nodes started at the same moment with the same key are both silent
  for the window and detect nothing: the watch catches the common accidents
  (warm backup, restored snapshot, forgotten systemd unit), not a
  synchronized double start;
- a boot at the chain's slot 0 skips the watch — no history exists in which
  a twin could already have signed;
- the cost is real: every restart forfeits the window's duties. That is the
  same liveness-for-safety trade as the signing guard, priced at roughly
  two epochs of rewards per restart.

`--doppelganger-epochs 0` disables the watch, with a warning. It exists for
a chain launch orchestrated by a single operator; a machine whose twin might
exist should never run with it. Note the launch pitfall the slot-0 skip does
not cover: a validator that boots a few slots *past* slot 0 (key loading and
setup easily eat a short genesis head start) arms the watch, and a whole
fleet doing so silences itself for the window and produces no chain until it
ends. A coordinated launch should pass `--doppelganger-epochs 0` explicitly
(`tests/cold_start.rs` does, with the reasoning in comments).

## 7. What this protects against, and what it cannot

Protects (all pinned by tests):

- **double proposal** after a crash, rollback, or restored snapshot —
  `signing_history.rs` unit tests + the engine-seam rewind test;
- **double and surround votes**, both directions;
- **crash between record and sign** — fails safe as one missed duty;
- **restored VM snapshot** — everything signed before the snapshot was
  taken is already in the snapshot's store (record-before-sign guarantees
  it) and is refused on restore;
- **key migrated with its history** — the imported watermarks travel;
- **warm backup discovered at startup** — the doppelganger watch (§6).

Cannot protect:

- **two machines signing concurrently past the watch window** — each holds
  an independent store; no node-local record closes this. Only the operator
  running one node per key does;
- **duties signed after a snapshot was taken**, when the pre-snapshot copy
  is restored *and* the post-snapshot machine kept running — that is the
  two-machine case above (the watch catches it at the restored node's next
  restart, not instantly);
- **a partitioned twin** — the watch only sees what gossip delivers.

The slashing consequence itself (evidence, penalty) is consensus-side work
in `bloch-pos-committee::slashing` and is out of scope here; this mechanism
exists so an honest operator never produces that evidence.
