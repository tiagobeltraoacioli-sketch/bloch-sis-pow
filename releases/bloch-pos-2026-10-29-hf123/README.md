# Genesis-4 node 78d4921c — scheduled network upgrades HF1, HF2, HF3

Signed Linux x86-64 release, source commit
`78d4921c3ec6ba41829f3878eed47f8d3bb96230`.

**This release schedules three network upgrades. Every node operator
(validators, RPC and archival nodes, exchanges running their own node) must
install it before epoch 7180 (2026-11-01 16:11:19 UTC).** A node that is not
upgraded by then will not follow the upgraded chain from epoch 7180.
Operators of L2 infrastructure and historical indexers must install builds
made against this release earlier, before epoch 7178 (2026-11-01 15:39:19 UTC).

All times are UTC. Epoch E starts at 2026-08-13 21:31:19 UTC + E × 960 s.

| Upgrade | Epoch | Start (UTC) |
| --- | --- | --- |
| HF1: claim finality on the chain's own history, frozen finality set | 7180 | 2026-11-01 16:11:19 |
| HF1: own-target vote counting | 7186 | 2026-11-01 17:47:19 |
| HF2: canonical encoding for validator consensus signatures, slashing-evidence admission v2, validator activation growth cap | 7270 | 2026-11-02 16:11:19 |
| HF3: optional SLH-DSA + Falcon spend suite (0x0003), optional post-quantum key rotation, KES registration opens | 7360 | 2026-11-03 16:11:19 |
| HF3: KES enforcement (binds once registered keys cover at least 90% of stake) | 8620 | 2026-11-17 16:11:19 |

One binary covers every step; no second installation is needed.

Binary SHA-256:

```text
700631b040a3a4b2299017162dd4a2c5f521bb49d5fa3c9ed677ba285673794e
```

## What changes for whom

- **Users, wallets, exchanges:** nothing in how deposits, withdrawals and
  transfers are created, signed, verified or priced. Addresses, transaction
  format, fees and mempool rules for transactions are unchanged at every epoch.
- **L1 withdrawal claims from the L2 bridge:** claim format, signing and
  amounts are unchanged. From epoch 7180 a claim is released only against a
  finalized checkpoint that belongs to this chain's own history. On a healthy
  chain this always holds. See the L2 section below for the one-time pause.
- **Validators:** from epoch 7270, consensus messages (votes, proposals,
  evidence) must use the canonical signature encoding; the upgraded node does
  this automatically. From epoch 7360 each validator registers a forward-secure
  (KES) key once:
  `bloch-pos kes keygen --dir <data-dir>`, then
  `bloch-pos kes register --dir <data-dir> --genesis <manifest> --out <file>`,
  and broadcast the hex in `<file>` with `sendrawtransaction`. Registration is
  refused before epoch 7360. Register before epoch 8620 (2026-11-17 16:11:19
  UTC). A validator that has not registered keeps signing with its static key.
  Never keep copies of an evolved KES key file and never run two copies of the
  same validator key.
- **Optional features (HF3):** the SLH-DSA + Falcon suite (0x0003) and
  post-quantum key rotation are opt-in. Existing keys keep working unchanged.
- **RPC:** `getchaininfo` gains two additive fields, `signature_suites` and
  `hard_forks`, that report the activation epochs compiled into the answering
  binary. `getl2settlement` gains additive fields (see below). Existing fields
  keep their names and meanings.
- **Node reliability:** the node no longer holds its engine thread when fork
  choice alternates between two heads; it stops on the current head and
  re-evaluates on the next block or vote. Node-local only, no consensus change.

## Bloch L2 (chain 700770)

| L1 epoch | UTC | What L2 users, bridges and exchanges see |
| --- | --- | --- |
| 7178 | 2026-11-01 15:39 | Deadline for L2 infrastructure (followers, producers, attestors, and the L1 RPC endpoints they read) to run builds against this release |
| 7180 | 2026-11-01 16:11 | Claim pause begins (one time) |
| ~7182 | ~2026-11-01 16:43 | Claims expected to resume, once a checkpoint of epoch 7180 or later is finalized |
| 7186 | 2026-11-01 17:47 | No L2 change |
| 7270 | 2026-11-02 16:11 | No L2 change for deposits or claims |
| 7360 | 2026-11-03 16:11 | No L2 change for deposits or claims; funding keys stay suite 0x0001 |
| 8620 | 2026-11-17 16:11 | No L2 change for deposits or claims |

**Deposits (0x14).** Unchanged at every epoch: format, signing, timing, fields
and tooling (`bloch-pos l2-deposit`).

**Withdrawal claims (0x16).** Format and signing are unchanged: the same
`l2-claim prepare/sign`, the same attestor partials, the same bytes. As today,
a claim requires its settled root to be in the finalized prefix. From epoch
7180 it also requires that the finalized checkpoint is this chain's own
checkpoint at its epoch.

**One-time pause at epoch 7180.** Own checkpoint roots are recorded from epoch
7180 on, so claims wait until a checkpoint of epoch 7180 or later is
finalized: about 2 epochs (~32 minutes, expected around 16:43 UTC), longer if
finality is slow. A claim broadcast in that window is dropped by block
producers as not yet final (the same handling as today's not-yet-final
claims) and must be broadcast again afterwards. Deposits, L2 blocks and
settlements continue during the pause. The pause is over when
`getl2settlement` reports `finalized_checkpoint.epoch` of 7180 or higher.
Bridges and exchanges: do not broadcast claims from 16:11 UTC until then, or
simply retry.

**If L1 finality halts (from epoch 7180).** The L2 keeps producing and
settling blocks, but L2 `safe`/`finalized` stop advancing and no claims are
released until L1 finality resumes.

**RPC.** `getl2settlement` gains additive fields: `withdrawals.claimable`,
`claimable_large`, `finalized_checkpoint` (`epoch`, `root`, `own_root`,
`own_chain_rule_active`) and a `finalized` flag on `matured` /
`matured_large`. Tooling that proves against `matured[_large]` keeps working
whenever that root is finalized, as is already required today.

**HF2 (epoch 7270).** Deposit and claim signatures (funding signature and
attestor partials) are judged as today, before and after the fork. Only
validator consensus messages move to the canonical encoding.

**HF3 (epoch 7360).** Deposits and claims are not affected. The optional suite
0x0003 applies to eUTXO spends only. L2 deposits and claims are still funded
from a suite 0x0001 key, even if a wallet moved to 0x0003. The L2 attestor set
and claim verification are unchanged.

**L2 operators.** Install builds made against this release on every follower,
producer and attestor host before epoch 7178 (2026-11-01 15:39:19 UTC). On
first start the follower re-verifies retained history (30-60 minutes per
host); upgrade attestor hosts one at a time, keeping at least 3 of 5 up. The
L1 RPC endpoints the L2 reads must also run this release: a follower behind a
non-upgraded L1 node stalls at the fork. Never skip a block.

## Verify and install

The release key is `bloch-release-20260922.pub`, minisign key ID
`1A5D96A5C4955EF7`, public key
`RWT3XpXEpZZdGtghC5SmyRj2VRTAGUfO5KxBucYVTRfriNE13wsXhfj6` (the same key that
signed the previous releases).

```sh
minisign -Vm SHA256SUMS -p bloch-release-20260922.pub
sha256sum --check SHA256SUMS
chmod 755 bloch-pos
./bloch-pos --version
```

The signature's trusted comment reads
`bloch-pos hf123 armed 78d4921c E1 7180 E2 7270 E3 7360 KES 8620`. The first
version line must show the full source commit above:

```text
bloch-pos-node 0.1.0-mainnet (78d4921c3ec6ba41829f3878eed47f8d3bb96230) (Genesis-4, block version 0xb10c0005)
```

`VERSION.txt` and `buildinfo.json` contain the expected binary identity.
`BUILD-INFO` preserves the canonical build output, including its original
unsigned-candidate labels; `release.json` records the release status. The
signed manifest authenticates the binary checksum.

Upgrade one validator at a time per host. Stop the service cleanly, keep the
complete data directory, validator identity, signing records and signer
anchor, replace the executable and restart with the existing service
configuration. Retain the old executable. Wait for synchronization, a
finalized checkpoint and a new attestation before the next validator. The
first boot may replay history and then observe the normal 64-slot
doppelganger window; do not bypass it. Do not downgrade signing-history files
and do not copy another validator's keys or signing records.

Before epoch 7180 the previous release (`1708953d`) still follows the same
chain; from epoch 7180 only this release does. This upgrade bundle contains no
keys, passphrases, chain data, genesis material or bootstrap checkpoint. Linux
ARM64 is not qualified by these artifacts.

## Validation

Canonical container build; 4,062 Rust tests passed across the four test stages
(71 explicitly ignored); full replay of mainnet history (174,032 blocks, head
slot 211072) to state root
`4cec3a86e80ef9a7f399d82891531438ad879ab62a81205081b793ffb41336f4`, identical
to the previous release; and replay of the same history with every upgrade
activated early, which kept the history valid.
