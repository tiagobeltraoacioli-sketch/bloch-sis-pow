<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Epoch 3328 — operator-published checkpoint

Published September 26, 2026. These are the existing, unchanged Genesis-4
checkpoint bytes issued at Unix time `1789930007`. The current September 24
release verifies all three signatures and accepts the envelope. At the
verification epoch, **3959**, its age was 631 of the permitted 2,016 epochs:
**FRESH**. Two live archival nodes agree on its finalized block and state.

**Trust limitation:** the local ceremony record states that all three signing
keys were used on the same operator-controlled machine. Independent custody
and an external auditor's attestation have **not** been established. The three
`EXTERNAL` labels in the arrangement are declarations, not identity evidence.
This publication makes an operator-controlled anchor available; it does not
certify an independently signed Phase-A ceremony. No new signatures were made.
Operators whose policy requires independent custodians must wait for that
requirement to be met. Other operators must explicitly accept this trust model
and authenticate the signer-set fingerprint through a separate trusted channel
before using the files.

## Public artifacts

| File | Purpose |
| --- | --- |
| [wscheckpoint-3328.envelope.bin](wscheckpoint-3328.envelope.bin) | Canonical checkpoint and three hybrid signatures; input to `--ws-checkpoint` |
| [signer-set-1.bin](signer-set-1.bin) | Public keys and quorum rule; input to `--ws-signer-set` |
| [wscheckpoint-3328.bin](wscheckpoint-3328.bin) | The exact 154 signed checkpoint bytes |
| [wscheckpoint-3328.json](wscheckpoint-3328.json) | Human-readable checkpoint fields |
| [SHA256SUMS](SHA256SUMS) | SHA-256 of the four unchanged artifacts |
| [verification.json](verification.json) | Verification, provenance, expiry and custody limitations |

No private signing keys, validator keys, SSH credentials or access manuals are
part of this package. The envelope authenticates the canonical checkpoint;
the JSON records, checksums and this README are supplementary publication data.

## Identity and deadline

```text
network_id             1228832244 (0x493e7df4)
genesis_root           9953da73a2794e190b1c551a787f39d6486a288f40b69ecc361281d5a893e415
epoch                  3328
boundary_slot          106493
block_root             386df5c04e116b755014e8e6b5aca0120be633401266b348ff1daf3f181896f9
state_root             09c0bfbe8cbe63127a27b9e80dd75a03792e2db6995abbfb1929dfb5202ba52c
ws_digest              f4f067929ee881f671df54a5849edec4106c712f28b2286ab1a7fc58e587fbc0
signer_set_id          1
signer_set_SHA3-256     bccb7c5ee127f806ac7da69a6dfab0a0b1c3d2750d6224bbfb652baa3322d627
envelope_SHA-256        66c7f832e5d644388e439c965014810e283347624404dca9b343bb5ae4c1d18d
```

The arrangement has three distinct keys, quorum 2 and a minimum of one declared
external signer. The manifest, signatures, quorum shape, age, block and state
were checked. The two archivals are operated by the same organization; agreement
between them is not proof of independent governance or custody.

The soft staleness threshold is epoch **4336**. Fresh installations refuse the
checkpoint from epoch **5344**, **October 12, 2026 at 06:35:19 UTC**
(03:35:19 in Brasília). Recalculate age using the current wall clock; this
page's publication date is not a freshness check. Existing synchronized nodes
rely on their own finalized history and do not need a restart for publication.

## Verification and running a node

Follow the [public observer guide](../../docs/PUBLIC-OBSERVER-2026-09-26.md)
for the signed executable, genesis, carryover, fingerprint verification,
freshness check and launch command. An observer uses no validator key or stake.

The two public bootnodes accepted TCP connections on September 26. Their live
archivals agreed at finalized epoch 3957 and confirmed this boundary block as
finalized. This review did **not** perform a complete fresh-node replay using
this package. A running process is not evidence of completed synchronization;
compare finalized roots and sync lag after replay.

The epoch-1536 publication expired on September 22 and must not be used for a
new installation. This package preserves epoch 3328's original bytes and
`issued_at`; it does not re-mint or replace the artifact within the same epoch.
The [checkpoint runbook](../../docs/CHECKPOINT-RUNBOOK.md) defines the independent
ceremony and 256-epoch renewal cadence. Epoch 3840 was already finalized at this
review and is eligible for the next ceremony; publishing another locally signed
checkpoint alone would not establish independent custody.
