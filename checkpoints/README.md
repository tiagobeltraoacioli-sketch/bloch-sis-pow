<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Weak-subjectivity checkpoints — the published artifacts

This directory is the publication home of the artifacts that
`bloch-pos run --ws-checkpoint <file> --ws-signer-set <file>` consumes
(`crates/bloch-pos-node/src/ws_boot.rs`). The mechanism has been in the node
since the weak-subjectivity gate landed; what this directory adds is the
*produced* side: real checkpoints for the live chain, and the ceremony that
signs them. The formats are defined in code, not here —
`crates/bloch-pos-committee/src/ws.rs` (canonical checkpoint + verification
rules) and `ws_boot.rs` (file framings) are normative; the spec is
`docs/specs/BLOCH-WEAK-SUBJECTIVITY.md`.

## Files

- `wscheckpoint-<epoch>.bin` — the canonical 154-byte checkpoint
  (`WeakSubjectivityCheckpoint::canonical_serialize`, ws.rs). This is what
  signers sign (via its `ws_digest`) and what `ws-envelope` wraps.
- `wscheckpoint-<epoch>.json` — the human-readable view of the same artifact,
  quoting the 64-hex `ws_digest`. The JSON is a *view*; the binary is the
  artifact (spec §2.3).
- `wscheckpoint-<epoch>.envelope.bin` — checkpoint + quorum signatures, the
  file `--ws-checkpoint` takes. **Exists only after the signing ceremony.**
- `signer-set-<id>.bin` — the signer arrangement `--ws-signer-set` takes.
  **Exists only after the signer keys exist** (see the ceremony below).

## How a checkpoint is minted (no keys involved)

```
bloch-pos ws-checkpoint \
  --genesis genesis/mainnet.manifest \
  --rpc <nodeA:port>,<nodeB:port> \
  --epoch <latest finalized multiple of 256> \
  --signer-set-id 1 \
  --out checkpoints/wscheckpoint-<epoch>
```

The tool refuses any epoch the chain has not finalized, derives the
epoch-boundary block by the same convention the finality store votes
(`engine::checkpoint_root`: last canonical block strictly before the epoch's
first slot), requires every `--rpc` endpoint to agree, and binds the artifact
to this chain by recomputing `network_id` and `genesis_root` from the
manifest exactly as a booting node does. Anyone can re-run it against their
own node and must get byte-identical output (`issued_at` aside, which is
fixed in the published artifact).

## The signing ceremony (Phase A, spec §6.1: 2-of-3, ≥1 external)

The signer keys are **not** validator keys and do not exist until the three
Phase A holders — the Foundation, Postern Labs, and the external audit firm —
each generate one. Nothing in this repository holds or must ever hold them.

Each holder, once, on their own air-gapped machine:

```
bloch-pos ws-keygen --out <holder-name>
# → <holder-name>.pk  (public: hand to the set assembler)
# → <holder-name>.sk  (secret, 0600: never leaves the machine)
```

Assemble and publish the arrangement (public keys only; `--signer` order is
the signer index, so publish the order with the keys):

```
bloch-pos ws-signer-set --id 1 --threshold 2 --min-external 1 \
  --adopted-epoch <adoption epoch> \
  --signer foundation.pk:internal \
  --signer postern.pk:internal \
  --signer auditor.pk:external \
  --out checkpoints/signer-set-1.bin
```

For each published checkpoint, each signer independently:

1. re-derives the checkpoint against a node they run or trust
   (`ws-checkpoint` as above, or recompute the digest from the `.bin`) and
   compares the `ws_digest` — signers verify what they sign, they do not
   take the file's word for it;
2. carries the 154-byte `.bin` to the signing machine and runs

```
bloch-pos ws-sign --key <holder>.sk --pubkey <holder>.pk \
  --checkpoint wscheckpoint-<epoch>.bin --out <holder>-<epoch>.sig
```

3. returns the `.sig` file (a signature is public — any channel works).

Assemble and verify exactly as a booting node would:

```
bloch-pos ws-envelope --checkpoint wscheckpoint-<epoch>.bin \
  --sig 0:foundation-<epoch>.sig --sig 2:auditor-<epoch>.sig \
  --out checkpoints/wscheckpoint-<epoch>.envelope.bin

bloch-pos ws-verify --envelope checkpoints/wscheckpoint-<epoch>.envelope.bin \
  --signer-set checkpoints/signer-set-1.bin \
  --genesis genesis/mainnet.manifest
```

`ws-verify` enforces every §2.2 rule, including that no quorum of purely
internal keys verifies. Publish the envelope, the signer-set file, and the
64-hex `ws_digest` on every channel (site, release pages, explorer,
announcement channel) — the digest fits in a chat message, which is the
out-of-band property the whole mechanism needs.

## Honesty notes, carried from the code

- A checkpoint is a **trust anchor, not a proof** (ws.rs module docs).
  Phase A is founder-adjacent trust with one outside witness; it must never
  be described as decentralised.
- The published checkpoint can never override a running node's own finality
  (`ws::cross_check`); it moves only fresh installs and the long-offline.
- `validator_set_root` is all-zeros at this milestone — and checkpoint-sync
  state download, now shipped, deliberately does NOT need it: the registry
  is committed leaf-by-leaf inside `state_root`, so the one root already
  verifies the downloaded registry (spec §4.3.2-impl). The field stays in
  the format for a future registry-only fast path; this artifact is
  unaffected.
- Checkpoint-sync **state download is wired** (2026-08-31): a node started
  with `--ws-checkpoint <envelope> --state-sync` downloads the checkpoint's
  committed state from peers in resumable chunks (or takes a local file via
  `--state-snapshot`), refuses it unless the recomputed state root
  reproduces this artifact's `state_root`, and syncs forward from the
  boundary block instead of replaying from genesis. The serving side exports
  boundary states automatically at publication epochs; `bloch-pos run
  --export-state-epoch <E> --export-state-out <file>` produces the artifact
  for any past epoch by replay.

## Current artifact — epoch 1536 (mainnet, minted 2026-08-31, UNSIGNED)

Derived from the live chain (RPC 139.84.201.52:16400; the chain's finalized
epoch was 1588 at derivation, so epoch 1536 — the latest finalized publication
epoch, 1536 = 6×256 — is deep inside finality):

    epoch               1536
    boundary slot       49151  (block height 28377, reported finalized: true)
    block_root          d5b3a12207af3010a611b737be15877db476ce9629520e08c552b8995bf23d32
    state_root          84cceba212f6443cc5d9fd67ce578a3ae0f34cba5e5877d8082748b282db0780
    network_id          1228832244  (0x493e7df4 — LE of the manifest digest's first 4 bytes)
    genesis_root        9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415
    validator_set_root  0 (milestone convention, see above)
    issued_at           1788185511
    signer_set_id       1  (Phase A — keys DO NOT EXIST YET; see the ceremony)

    ws_digest           a5d047674074251c7a2031266ac2a3c7e05a82960959ffef847bb4291e744e44

The digest was reproduced by an independent implementation (SHA3-256 over
`DS_WSCKPT ‖ 154 bytes`, fields rebuilt from the JSON view) before
publication. **This artifact is unsigned**: it becomes distributable the
moment two of the three Phase A holders run the ceremony above — the first
being the Foundation/Postern pair plus the external auditor, and any 2-of-3
quorum MUST include the auditor (rule 4 is client-enforced; an internal-only
envelope is refused as `ExternalQuorumNotReached`, verified against this very
artifact in a key drill on 2026-08-31).

Derivation was corroborated by ONE reachable node at mint time — below the
two-node bar this repo's own RPC front (g4rpc) enforces for reads. That is
exactly why the ceremony step "each signer re-derives the digest against
their own node" is not optional: with three independent re-derivations, the
published artifact rests on three witnesses, not one.
