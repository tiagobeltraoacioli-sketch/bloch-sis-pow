<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Weak-subjectivity ceremony — operator checklist

Follow this literally. You do not need to understand the protocol to run it.
The reasoning lives in `docs/CHECKPOINT-RUNBOOK.md`; this file is the
execution script, rehearsed end to end on 2026-08-31 with throwaway keys.

Every command below is the real one. Substitute only the values in `<>`.

---

## 0. Roles, machines, and the one rule that matters

| role | machine | holds | touches the network |
| --- | --- | --- | --- |
| **M** — assembler | online workstation | **no keys, ever** | yes |
| **S0** — Foundation | air-gapped, holder 0's own | `s0.sk` | no |
| **S1** — Postern Labs | air-gapped, holder 1's own | `s1.sk` | no |
| **S2** — external auditor | air-gapped, holder 2's own | `s2.sk` | no |

**The rule: a `.sk` file never leaves the machine that generated it.** Not to
M, not to a password manager shared with anyone, not into a terminal that is
being recorded. Everything else in this document is recoverable. That is not.

**S2 must sign every publication.** The arrangement requires at least one
external signature, so S0+S1 alone is *not* a quorum — this is enforced by
software and was verified in rehearsal (it fails with
`ExternalQuorumNotReached`). Schedule the ceremony around S2's calendar.

---

## 1. One-time, per holder — generate the key (≈ 0.3 s of machine time)

On the holder's OWN air-gapped machine, in a session nobody is watching or
recording:

```
bloch-pos ws-keygen --out <s0|s1|s2>
```

Produces `<name>.pk` (public, mode 0644) and `<name>.sk` (secret, mode 0600).

Then, **still on the holder's machine**, print the fingerprint of the PUBLIC
file and keep it to read aloud in step 2:

```
shasum -a 3-256 <name>.pk        # macOS/BSD
sha3sum -a 256 <name>.pk         # Linux, if available
python3 -c "import hashlib,sys;print(hashlib.sha3_256(open(sys.argv[1],'rb').read()).hexdigest())" <name>.pk
```

Send only the `.pk` file to M. Any channel is fine for it.

**Checkpoint before continuing:** `ls -l` and confirm the `.sk` is `-rw-------`.
If it is not, fix the mode, then treat the key as compromised and regenerate.

---

## 2. One-time — build the arrangement on M

### On the call (all three holders present, voices recognised)

Each holder reads their `.pk` fingerprint aloud. M reads back what M received.
**Confirm all three fingerprints are DIFFERENT from each other.** If two match,
stop: one key seated in two slots turns a 2-of-3 into a 1-of-3, and the
publication tooling — not the network — is what refuses it (see §6, F11).

Write the three fingerprints into the ceremony record, in slot order. The order
you list them below **is** the signer index, forever.

### Then, on M

```
bloch-pos ws-signer-set \
  --id 1 \
  --threshold 2 \
  --min-external 1 \
  --adopted-epoch <the epoch this arrangement takes effect> \
  --current-epoch <the epoch the chain is at now> \
  --signer s0.pk:internal \
  --signer s1.pk:internal \
  --signer s2.pk:external \
  --out checkpoints/signer-set-1.bin
```

**Expected output — both lines, or stop:**

```
wrote checkpoints/signer-set-1.bin: signer set id 1, 2-of-3, ≥1 external, adopted at epoch <E>
policy: matches the §6.1 Phase A policy (2-of-3, ≥1 external)
```

If it says `MATCHES NEITHER §6.1 PHASE`, you mistyped a flag. Do not publish.

`signer-set-1.bin` is **public**. It ships with every envelope, forever.

---

## 3. Every publication — mint the checkpoint on M (≈ 9 s)

No keys are involved in this step.

```
bloch-pos ws-checkpoint \
  --genesis genesis/mainnet.manifest \
  --rpc <nodeA:port>,<nodeB:port> \
  --epoch <latest finalized multiple of 256> \
  --signer-set-id 1 \
  --out checkpoints/wscheckpoint-<epoch>
```

Two `--rpc` endpoints on **independently operated** nodes. If the tool prints a
single-endpoint warning, stop and find a second node — this fleet has forked
before, and a forked node answers as confidently as a correct one.

Produces `wscheckpoint-<epoch>.bin` (154 bytes — **this is the artifact**),
`wscheckpoint-<epoch>.json` (human view, not the artifact), and prints the
**ws digest**: 64 hex characters.

`validator_set_root` printed as all zeros is **correct**. Do not "fix" it.

**Write the ws digest on paper.** It is the only value spoken in step 5.

---

## 4. Every publication — distribute (≈ seconds; the files are tiny)

Send each of S0, S1, S2 the same two files:

- `wscheckpoint-<epoch>.bin` (154 bytes)
- `wscheckpoint-<epoch>.json`

**Never send the ws digest over the same channel as the .bin file.** The file
goes by one route (email, shared drive, USB); the digest is spoken on the call
in step 5. Sending both together means an attacker who controls that one
channel can substitute a checkpoint *and* the digest that vouches for it, and
the ceremony verifies a forgery perfectly.

Also never send: any `.sk` file (§0), or the arrangement file down a channel
you have not published it on — but the arrangement is public, so it is not a
secret, only an integrity concern.

---

## 5. Every publication — the call, then each signer signs (≈ 0.15 s each)

### On the call

Each of S0, S1, S2 independently derives the digest **on their own machine**
from the 154 bytes they received:

```
python3 -c "import json;print(json.load(open('wscheckpoint-<epoch>.json'))['ws_digest'])"
```

(A holder who runs their own node should instead re-run step 3 with the same
flags plus `--issued-at <the published value>` and confirm a byte-identical
`.bin`. That is the strongest form of this check.)

**All three read the 64 hex characters aloud. They must match, character for
character, and match the digest M wrote on paper in step 3.**

If any digest differs: **STOP. Nobody signs.** Somebody was handed different
bytes. Signing is the one action that cannot be undone. Escalate.

This comparison *is* the ceremony. Everything else is typing.

### Then each signer, offline, on their own machine

```
bloch-pos ws-sign \
  --key <name>.sk \
  --pubkey <name>.pk \
  --checkpoint wscheckpoint-<epoch>.bin \
  --signer-index <your slot> \
  --out <name>.partial
```

**Always pass `--pubkey`.** It makes the tool verify its own signature before
writing it, so a bad signature dies here instead of at assembly with two other
people waiting.

`<name>.partial` (≈ 9 KB) contains no secret. Any channel. It records the ws
digest it was signed over, so a coordinator can tell a signature over another
checkpoint from a corrupt file — and name the signer to call.

---

## 6. Every publication — assemble on M (≈ 0.12 s)

```
bloch-pos ws-envelope \
  --checkpoint checkpoints/wscheckpoint-<epoch>.bin \
  --signer-set checkpoints/signer-set-1.bin \
  --genesis genesis/mainnet.manifest \
  --sig 0:s0.partial \
  --sig 2:s2.partial \
  --out checkpoints/wscheckpoint-<epoch>.envelope.bin
```

The number in `--sig <n>:<file>` is that signer's slot from step 2. Use the two
signatures you actually have — but **one of them must be index 2** (the
external signer).

**Expected output, or stop:**

```
ACCEPTED by ws::verify_envelope — wrote ... 2 signature(s)
quorum 2-of-3 met, 1 of ≥1 external
```

Always pass `--genesis`. Without it the chain-identity check is circular and
the tool says so.

---

## 7. Every publication — verify as a stranger, then publish (≈ 0.12 s)

```
bloch-pos ws-verify \
  --envelope checkpoints/wscheckpoint-<epoch>.envelope.bin \
  --signer-set checkpoints/signer-set-1.bin \
  --genesis genesis/mainnet.manifest \
  --rpc <a node you run>
```

Read four lines and stop if any is wrong:

1. every listed signature says `VALID`
2. `... external of ≥1 required` shows at least 1
3. `FRESHNESS ... FRESH` (`STALE` means publish a newer epoch now;
   `EXPIRED` means new nodes are already being turned away)
4. `VERDICT: ACCEPTED by ws::verify_envelope.`

If you see `!!!! UNSOUND ARRANGEMENT`, the signer-set file is bad — not the
signatures. Do not publish. Go back to §2.

### Publish, to at least two independent channels

- `wscheckpoint-<epoch>.envelope.bin`
- `signer-set-1.bin`
- the ws digest, **in the announcement text**

Agreement of the digest across independent channels is the evidence. The
artifact's own say-so is not.

---

## 8. What an operator joining the network runs

```
bloch-pos run --data-dir <dir> \
              --ws-checkpoint wscheckpoint-<epoch>.envelope.bin \
              --ws-signer-set signer-set-1.bin
```

Both flags are required together. Before starting, they should run the §7
`ws-verify` themselves and compare the digest against a second channel.

---

## 9. When a step fails — the table

Everything below was reproduced deliberately in rehearsal.

| what you see | what happened | what to do |
| --- | --- | --- |
| `QuorumNotReached { got: 1, need: 2 }` | Only one signature. | Collect one more. Nothing is wrong. |
| `ExternalQuorumNotReached { got: 0, need: 1 }` | You used S0+S1. | Get S2's signature. No amount of internal signing fixes this. |
| `DuplicateSigner { index: n }` | The same slot listed twice — usually one signer's file collected from two places. | Use two *different* signers' files. |
| `UnknownSignerIndex { index: n }` | A `--sig` index that does not exist in the arrangement. | Fix the `<index>:` prefix. Slots are 0-based. |
| `BadSignature { index: n }` | Three possible causes, in order of likelihood: the indices are **mispaired** (right files, wrong numbers); the signer signed **different bytes**; the file is corrupt. | Re-check the `--sig` pairing against §2's table first. If the pairing is right, the digest comparison in §5 failed to catch a substituted checkpoint — **escalate, do not retry.** |
| `WrongSignerSet { got: A, expected: B }` | Envelope and signer-set file are from different arrangements. | Use arrangement A's file, or re-mint with `--signer-set-id B`. More signatures cannot fix it. |
| `ArrangementExpired { hard_stop_epoch: E }` | The arrangement passed review + grace. | Governance must adopt a new arrangement under a **new `--id`**. Signing harder does not help. `ws-verify` prints this epoch on every run — it should never surprise you. |
| `WrongNetwork` / `WrongGenesisRoot` | Wrong manifest, or an artifact from another chain. | Check `--genesis`. |
| `signer-set id 0 is reserved` | You passed `--id 0`. | The first real arrangement is `--id 1`. |
| `FRESHNESS ... STALE` | Valid, but past the halfway mark of the window. | Publish the next epoch now. ~11 days of margin remain. |
| `FRESHNESS ... EXPIRED` | Valid signatures, useless artifact. | A fresh node given this still refuses. Publish immediately; this is a liveness incident. |
| `!!!! UNSOUND ARRANGEMENT` | Two slots hold the same public key. | **Security incident.** The arrangement is a 1-of-n. Do not publish. Re-run §2 confirming all three fingerprints differ. |
| `WS_CONFLICT` at a joiner's boot | The published checkpoint contradicts that node's own finality. | **Escalate immediately.** Either the signers published a false checkpoint or that node is on a forged branch. Never delete a data directory to "fix" this — that destroys the evidence. |

**A signature that does not verify is never fixed by signing again.** Find out
why first.

---

## 10. Timing — what to put in the calendar

Machine time for the whole ceremony is under 20 seconds. Measured, on one
laptop, against the live chain:

| step | machine | cold run | warm run |
| --- | --- | --- | --- |
| `ws-keygen` (per holder, once) | S0/S1/S2 | 0.18 – 1.5 s | 0.12 – 0.16 s |
| `ws-signer-set` (once) | M | 0.11 s | 0.07 s |
| `ws-checkpoint` mint, 2 endpoints | M | 8.6 s | 12.2 s |
| `ws-sign` (per signer) | S0/S1/S2 | 0.13 s | 0.08 s |
| `ws-envelope` assemble | M | 0.12 s | 0.07 s |
| `ws-verify` | M | 0.12 s | 0.08 s |

Every step except the mint is **under a fifth of a second**. The mint is
entirely network: it makes about three JSON-RPC calls per endpoint, and the
measurement above went through a TLS-fronted public endpoint. Against nodes on
your own network it is well under a second. It is not a step to plan around.

Transferring the artifacts adds nothing: the checkpoint is **154 bytes**, a
signature ≈ 9 KB, the envelope ≈ 9 KB, the arrangement ≈ 11 KB. A signer on
another continent costs a few seconds of transfer, not minutes.

**The cost is entirely human.** Budget for one 30-minute call with all three
holders on it, and schedule it around the external signer, who is mandatory.
Allow a day of slack for a holder who cannot make the call — the cadence
tolerates six consecutive missed publications, so a slipped ceremony is not an
emergency. The seventh is.
