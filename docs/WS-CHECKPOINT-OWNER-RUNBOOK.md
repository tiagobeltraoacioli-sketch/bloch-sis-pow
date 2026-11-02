<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Weak-subjectivity checkpoint: owner runbook, November 2026

This runbook covers one job: publish a mainnet weak-subjectivity checkpoint
that is less than 2,016 epochs old, and keep one published from now on.
`docs/CHECKPOINT-RUNBOOK.md` is the general ceremony guide. This file applies
it to the chain as it stands on 2026-11-02, with the existing signer
arrangement, the exact commands and the calendar.

Everything here was read from release `78d4921c` / fleet commit `fa980367`.
The weak-subjectivity code (`crates/bloch-pos-committee/src/ws.rs`,
`crates/bloch-pos-node/src/ws_boot.rs`, `crates/bloch-pos-node/src/ws_tool.rs`)
is byte-identical between those two commits (`git diff 78d4921c fa980367`
touches none of them), so the signed fleet binary is the tool to use.

## 1. Why this is needed now

- A node with no finalized history of its own boots only if its newest trust
  anchor is less than `WS_PERIOD_EPOCHS` = 2,016 epochs old (`ws.rs:140`,
  `ws_boot.rs` `boot`, `BootDecision::RequireCheckpoint`).
- Without a published checkpoint the only anchor is the genesis anchor at
  epoch 0. The chain is past epoch 7,290, so a wiped validator, a new
  validator, an exchange node or an explorer started from an empty data
  directory exits with `ERR_WS_REQUIRE_CHECKPOINT` and status 78 (agent 106
  saw this on the mainnet binary).
- The last published checkpoint (epoch 3328, published 2026-09-26) stopped
  admitting fresh nodes at epoch 5344, on 2026-10-12 06:35 UTC.
- Running nodes are not affected. Their own finality is their anchor. Their
  `ws_latest.bin` still holds the genesis anchor, which is why keeping that
  file after a wipe does not help (agent 106, node B2).

## 2. What a checkpoint is, from the code

### 2.1 The signed object: 154 bytes

`WeakSubjectivityCheckpoint::canonical_serialize` (`ws.rs`), fixed width,
little-endian, in this order:

| Field | Bytes | Value for mainnet |
|---|---|---|
| `version` | 2 | 1 |
| `network_id` | 4 | 1228832244 (`0x493e7df4`): first 4 bytes, LE, of SHA3-256 of `genesis/mainnet.manifest` |
| `genesis_root` | 32 | `9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415` |
| `epoch` | 8 | the finalized epoch attested; use a multiple of 256 |
| `block_root` | 32 | id of the last canonical block strictly before slot `epoch * 32` |
| `state_root` | 32 | that block's header `state_root` |
| `validator_set_root` | 32 | all zeros; the tool refuses any other value |
| `issued_at` | 8 | Unix seconds at minting; inside the digest |
| `signer_set_id` | 4 | 1 (the existing arrangement); 0 is reserved for genesis |

`ws_digest = SHA3-256("BLCH4:WSCKPT" zero-padded to 16 bytes ‖ the 154 bytes)`.
The digest is what signers sign and what announcements quote.

### 2.2 Files

| File | Framing (`ws_boot.rs`) | Role |
|---|---|---|
| `wscheckpoint-<E>.bin` | the 154 bytes | what is signed |
| `wscheckpoint-<E>.json` | view only, quotes `ws_digest` | for people |
| `<name>.partial` | `BPOSWSP1` ‖ index ‖ digest ‖ signature | one signer's output, no secret |
| `wscheckpoint-<E>.envelope.bin` | `BPOSWSE1` ‖ 154 bytes ‖ u32 count ‖ (u8 index, length-prefixed signature)… | `--ws-checkpoint` input |
| `signer-set-1.bin` | `BPOSWSS1` ‖ id ‖ threshold ‖ min_external ‖ adopted_epoch ‖ count ‖ (external flag, raw public key)… | `--ws-signer-set` input |
| `ws_latest.bin` (in the data dir) | the 154 bytes of the newest checkpoint this node accepted | written by the node |

### 2.3 Who signs, with what key

- Signers are **not validators**. Each signer key is a hybrid
  **ML-DSA-65 ‖ Falcon-1024** keypair (suite `0x0001`) made by
  `bloch-pos ws-keygen`. `.pk` is hex, 0644; `.sk` is **plaintext hex**, 0600,
  with no passphrase. `ws-sign` refuses an `.sk` readable by group or others.
- A signature is valid only if **both** halves verify over `ws_digest`
  (`staking::verify_hybrid`, `WsHybridVerifier`). Signatures are randomised:
  signing the same bytes twice gives different signature bytes.
- The node only accepts an arrangement with the shape of Phase A (2-of-3, at
  least 1 external) or Phase B (3-of-5, at least 2 external); anything else
  is refused at boot before any signature is checked
  (`verify_envelope_with_shape_policy`). One key in two slots is refused.
- **The arrangement already exists.** `signer-set-1.bin`, published with the
  epoch 3328 checkpoint (commit `b2298330`, `checkpoints/epoch-3328/`):

  | Property | Value |
  |---|---|
  | id, rule | 1, 2-of-3, at least 1 external |
  | adopted epoch | 0 (review warning after epoch 32,850; refused after 41,040) |
  | file size, SHA-256 | 11,270 bytes, `b2ea7f0ca9356a3d82bcd2a3f6a1e1a1b997a809b3bc91a063c90d7852566643` |
  | **SHA3-256 fingerprint (the operator pin)** | `bccb7c5ee127f806ac7da69a6dfab0a0b1c3d2750d6224bbfb652baa3322d627` |
  | slot 0 raw key SHA-256 | `5efc54eb57f3226be416a04f7d64fb4a49a0dc21cca445added49b293699957a` |
  | slot 1 raw key SHA-256 | `afa529461b5fbb89a4d33e34538980cb32dc001277c46be1fd7d38efc7b7b9dc` |
  | slot 2 raw key SHA-256 | `ad59580111aceedba4c12958132cc5cdf30f209c73abdb765d4d3eb0de89e3ac` |

  All three slots are flagged external. The epoch 3328 publication disclosed
  that all three keys were used on one operator-controlled machine. Reusing
  this arrangement means operators keep the same pin; it also keeps that
  custody limitation, which every publication must state again.
- Where the three `.sk`/`.pk` files are: **TBD-owner**. This runbook never
  needs them on an online machine.

### 2.4 How a node consumes it

```
bloch-pos run ... --ws-checkpoint <envelope.bin> --ws-signer-set <signer-set-1.bin> --ws-signer-set-sha3 <fingerprint>
```

- All three flags or none (`WsConfig::from_args`); they must come before any
  `--`. An envelope without the pin is refused.
- Boot order (`ws_boot::boot`): load `ws_latest.bin` (or store the genesis
  anchor); check the pin; check the arrangement shape; verify the envelope
  (version, network id, genesis root, signer-set id, hard stop, indices,
  threshold, external minimum, every signature); check the epoch lies inside
  the arrangement window; compare with the node's own finality
  (a contradiction is a `WS_CONFLICT` alarm and is not admitted); then
  anti-rollback: a newer epoch replaces `ws_latest.bin`, an older one or the
  same digest is ignored, the same epoch with a different digest refuses the
  boot.
- Freshness at boot uses the wall clock and the manifest's slot clock:
  `anchor_age = wall_epoch − anchor.epoch`; a node without own finality boots
  only if `anchor_age < 2016`.
- After boot the node **still replays the whole chain from genesis**. There
  is no state download. The checkpoint is a floor and a cross-check: when the
  node's own finality reaches the checkpoint epoch, the roots must match, and
  for a node that started without finality a mismatch exits with status 78.
  Agent 106 measured about 15 h for today's chain this way, against 97 s for
  a refill from a healthy node's files.
- Once accepted, `ws_latest.bin` keeps the checkpoint, so later restarts do
  not need the flags. Leaving the flags in a unit file is harmless (same
  digest: ignored).

### 2.5 Freshness thresholds

| Age of the newest published checkpoint (epochs) | `ws-verify` says | Fresh install |
|---|---|---|
| below 1,008 (`WS_FRESH_EPOCHS`) | `FRESH` | boots |
| 1,008 to 2,015 | `STALE` (publish a newer one) | boots |
| 2,016 or more | `EXPIRED`, exit non-zero | `ERR_WS_REQUIRE_CHECKPOINT` |

One epoch is 960 s. 2,016 epochs are 22.4 days. Epoch `E` starts at
`1786656679 + E * 960`.

## 3. Pick the epoch

Use the newest **finalized** epoch that is a multiple of 256. On 2026-11-02 at
21:45 UTC the wall epoch is 7290, so that is **7168** (started 2026-11-01
12:59 UTC, before the HF1 gate at 7180). It admits fresh nodes until wall epoch
9183; it is refused from epoch 9184, **2026-11-23 22:35 UTC**.

`ws-checkpoint` refuses an epoch the node has not finalized, so the check is
built in. If 7168 is not finalized on two RPCs, do not pick another epoch by
hand: find out why finality stopped first.

Never publish an epoch that has already been published with different bytes.
Two artifacts for one epoch make every node that stored the first refuse to
boot (`Acceptance::Conflict`). A correction goes into the next multiple of
256.

## 4. Produce and sign (the owner runs this; no agent touches keys)

Two machines:

- **M**, online, no keys: mints, assembles, verifies.
- **S**, offline, holds the signer keys: signs.

Both use the same `bloch-pos` binary, built from `fa980367` (or the release
binary `78d4921c`). Check its SHA-256 against the release record first.

### 4.1 On M: check finality on two RPCs

```
curl -s -X POST http://80.240.16.185:8080 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}'
```
```
curl -s -X POST http://199.247.22.8:8080 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"getchaininfo","params":[]}'
```

Both must show `finalized.epoch` of at least 7168 and the same root.

### 4.2 On M: mint

```
mkdir -m 700 -p ~/ws-publication
```
```
bloch-pos ws-checkpoint --genesis genesis/mainnet.manifest --rpc 80.240.16.185:8080,199.247.22.8:8080,139.180.173.231:8080 --epoch 7168 --signer-set-id 1 --publication-dir ~/ws-publication/registry --out ~/ws-publication/wscheckpoint-7168
```

It writes `wscheckpoint-7168.bin` and `.json`, prints each RPC's boundary block
and the ws digest, and refuses if the RPCs disagree, if 7168 is not finalized,
or if the chain does not start from the manifest. `--publication-dir` keeps a
registry so a second run for the same epoch reuses the first `issued_at`
instead of minting a conflicting artifact. Write down `issued_at` from the
JSON; anyone re-deriving the file needs it.

### 4.3 Carry `wscheckpoint-7168.bin` to S and read it before signing

```
bloch-pos ws-verify --checkpoint wscheckpoint-7168.bin
```

The `WS DIGEST` printed on S must equal the digest printed on M. Compare it
over a different channel than the one the file travelled on.

### 4.4 On S: sign with two of the three keys

Find each key's slot: the SHA-256 of the raw key (the `.pk` hex, decoded,
without its 4-byte suite header) must equal the slot's value in §2.3.

```
python3 -c 'import hashlib,sys; print(hashlib.sha256(bytes.fromhex(open(sys.argv[1]).read().strip())[4:]).hexdigest())' TBD-owner-slot0.pk
```

Then, for two slots (here 0 and 1):

```
bloch-pos ws-sign --key TBD-owner-slot0.sk --pubkey TBD-owner-slot0.pk --checkpoint wscheckpoint-7168.bin --signer-index 0 --out slot0-7168.partial
```
```
bloch-pos ws-sign --key TBD-owner-slot1.sk --pubkey TBD-owner-slot1.pk --checkpoint wscheckpoint-7168.bin --signer-index 1 --out slot1-7168.partial
```

`--pubkey` makes the tool verify its own signature before writing it. Only
the `.partial` files leave S.

### 4.5 On M: assemble

```
bloch-pos ws-envelope --checkpoint ~/ws-publication/wscheckpoint-7168.bin --signer-set signer-set-1.bin --genesis genesis/mainnet.manifest --sig 0:slot0-7168.partial --sig 1:slot1-7168.partial --out ~/ws-publication/wscheckpoint-7168.envelope.bin
```

Nothing is written unless the partials match this checkpoint's digest, the
quorum and shape rules hold, and the node's own `ws::verify_envelope` accepts
the result. It prints `ACCEPTED by ws::verify_envelope`.

### 4.6 On M: verify as an operator would

```
bloch-pos ws-verify --envelope ~/ws-publication/wscheckpoint-7168.envelope.bin --signer-set signer-set-1.bin --genesis genesis/mainnet.manifest --rpc 80.240.16.185:8080 --require-fresh
```

Expect `FRESH` and `VERDICT: ACCEPTED`. Then check the pin of the file you are
about to publish:

```
python3 -c 'import hashlib,sys; print(hashlib.sha3_256(open(sys.argv[1],"rb").read()).hexdigest())' signer-set-1.bin
```

(`openssl dgst -sha3-256` gives the same on Linux; the LibreSSL shipped with
macOS has no SHA3.) It must print `bccb7c5ee127f806ac7da69a6dfab0a0b1c3d2750d6224bbfb652baa3322d627`.

### 4.7 Optional: boot test on a scratch observer

On a machine with no validator key and an empty data directory, start an
observer with the three flags (see `docs/THIRD-PARTY-QUICKSTART.md` for the
peer and carryover flags). The log must show
`weak subjectivity: anchored at epoch 7168 (...), WITHOUT own finality`.
Stop it after that line if you do not want a full sync.

## 5. Publish

Publish the same files on at least two channels you control, for example the
Bloch repository under `checkpoints/epoch-7168/` (as epoch 3328 was), the
release pages and blochl1.com:

- `wscheckpoint-7168.envelope.bin`
- `signer-set-1.bin` (unchanged)
- `wscheckpoint-7168.bin` and `wscheckpoint-7168.json`
- `SHA256SUMS` of the four files
- a README with the epoch, block root, state root, `issued_at`, ws digest,
  the arrangement fingerprint, the refusal date (epoch 9184,
  2026-11-23 22:35 UTC) and the custody statement of §2.3

Put the **ws digest** and the **arrangement fingerprint** in the announcement
text itself, on a channel other than the file host. Never replace a
published file for the same epoch.

## 6. How operators verify and use it

1. Download the files and check `SHA256SUMS`.
2. Get the arrangement fingerprint and the ws digest from a second channel
   and compare them with the SHA3-256 of `signer-set-1.bin` (command of §4.6).
3. Run `ws-verify` with `--rpc <a node they trust>` and `--require-fresh`
   (command of §4.6). Read the `WS DIGEST`, `epoch`, `block root`,
   `FRESHNESS` and `VERDICT` lines.
4. If they run a synced node, re-derive the artifact and compare bytes:

```
bloch-pos ws-checkpoint --genesis genesis/mainnet.manifest --rpc <their-node>:8080 --epoch 7168 --signer-set-id 1 --issued-at <published issued_at> --out ./rederived-7168
```
```
cmp ./rederived-7168.bin wscheckpoint-7168.bin
```

5. Start the node from an empty data directory with
   `--ws-checkpoint wscheckpoint-7168.envelope.bin --ws-signer-set signer-set-1.bin --ws-signer-set-sha3 bccb7c5ee127f806ac7da69a6dfab0a0b1c3d2750d6224bbfb652baa3322d627`.
6. **Do not restart the node during the first part of the sync.** After a
   node has finalized anything of its own, a restart while its own finality
   is still 2,016 or more epochs behind the wall clock, and before it holds
   the checkpoint block, halts with `ERR_WS_STALE recovery halted` and exit
   78 (test `owner_runbook_restart_during_sync_before_the_checkpoint_block_halts`).
   With today's chain that is roughly the first 5,300 epochs of the replay,
   most of the 15 hours. If it happens, stop the node, remove the chain
   files (`blocks.*`, `meta.*`, `state.cache*`) but keep `ws_latest.bin`,
   `validator.key`, the keystore files and the slashing-protection files, and
   start again; it starts as a fresh node under the stored checkpoint. For a
   validator you operate, refilling from a healthy node
   (`docs/L1-STUCK-NODE-RUNBOOK.md` on `codex/recovery-r6-20261102`) is
   faster and avoids this.
7. Exit status 78 means a weak-subjectivity refusal. The exchange unit
   template sets `RestartPreventExitStatus=78`; keep that.

## 7. Cadence

The code's cadence is one checkpoint at every multiple of 256 epochs (about
every 2.8 days; `WS_PUBLICATION_INTERVAL_EPOCHS`). The hard requirement is
weaker: the newest published checkpoint must always be younger than 2,016
epochs. To keep it below the 1,008-epoch `STALE` line, publish at least every
third multiple of 256 (768 epochs, about 8.5 days).

| Epoch | Starts (UTC) | Can be minted from about | STALE from | Refused from |
|---|---|---|---|---|
| 7168 | 2026-11-01 12:59 | now | 2026-11-12 17:47 | 2026-11-23 22:35 |
| 7424 | 2026-11-04 09:15 | 2026-11-04 10:03 | 2026-11-15 14:03 | 2026-11-26 18:51 |
| 7680 | 2026-11-07 05:31 | 2026-11-07 06:19 | 2026-11-18 10:19 | 2026-11-29 15:07 |
| 7936 | 2026-11-10 01:47 | 2026-11-10 02:35 | 2026-11-21 06:35 | 2026-12-02 11:23 |
| 8192 | 2026-11-12 22:03 | 2026-11-12 22:51 | 2026-11-24 02:51 | 2026-12-05 07:39 |
| 8448 | 2026-11-15 18:19 | 2026-11-15 19:07 | 2026-11-26 23:07 | 2026-12-08 03:55 |
| 8704 | 2026-11-18 14:35 | 2026-11-18 15:23 | 2026-11-29 19:23 | 2026-12-11 00:11 |
| 8960 | 2026-11-21 10:51 | 2026-11-21 11:39 | 2026-12-02 15:39 | 2026-12-13 20:27 |

"Can be minted from" assumes finality two epochs behind the head, as seen on
2026-10-30. The KES enforcement gate (epoch 8620, 2026-11-17) does not touch
checkpoint signers: their keys are not validator keys.

Recommended schedule: 7168 now, then 7936 (2026-11-10), 8704 (2026-11-18) and
every 768 epochs after that. Add a daily check that alerts on anything but
`FRESH`:

```
bloch-pos ws-verify --envelope <latest envelope> --signer-set signer-set-1.bin --genesis genesis/mainnet.manifest --rpc 80.240.16.185:8080 --require-fresh
```

It exits non-zero only on `EXPIRED`, so the alert should also match the word
`STALE` in its output.

## 8. What this does not solve

- The checkpoint is a trust anchor, not a proof. With all signer keys under
  one operator, it is the owner's word, as the epoch 3328 README said.
- A fresh node still replays from genesis (about 15 h today, growing).
- If the signer keys are lost, a new arrangement (id 2) needs new keys, a new
  fingerprint, and every operator must change their pin.
- The arrangement's own clock refuses envelopes for epochs above 41,040
  (2027-11-12), and warns after epoch 32,850 (2027-08-13); a new arrangement
  is needed before that.
