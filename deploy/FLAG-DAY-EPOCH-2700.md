<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Flag day — epoch 2700 (`LEAK_RECOVERY_ACTIVATION_EPOCH`)

**Epoch 2700 = 2026-09-12 21:31 UTC.** Every fleet node must be running a
binary built after the keystore-migration and transport-default fixes below
land, with its keystore already sealed, **before** the chain reaches that
epoch. This is not advisory: a partial rebuild forks the fleet at 2700, and
the new binary refuses to boot on a plaintext keystore at all, so "do
nothing" is not the safe default it was for epoch 800.

Authority for every claim below is a file or a constant, not this document —
if a citation and the source disagree, the source wins and this runbook is
stale.

## What activates

| constant | value | effect from epoch 2700 |
|---|---|---|
| `LEAK_RECOVERY_ACTIVATION_EPOCH` | 2700 | closes the 2026-08-24 finality-divergence arithmetic (Round-1 C2/C3) |

This is the **only** consensus gate armed on the live chain today. The other
seven new gates (`EXIT_AUTH_ACTIVATION_EPOCH`,
`FEE_STAKE_DECOUPLE_ACTIVATION_EPOCH`, `SLASHING_EVIDENCE_ACTIVATION_EPOCH`,
`RANDAO_RECOMMIT_ACTIVATION_EPOCH`, `DUST_RULE_ACTIVATION_EPOCH`,
`TX_BYTES_BOUND_ACTIVATION_EPOCH`, `ANCESTRY_SEED_ACTIVATION_EPOCH`) stay at
`u64::MAX` through this flag day — they are a separate, later decision, and
arming any of them here is explicitly out of scope for this rollout (see the
Round-3 remediation audit, §4.2, for the prerequisites each one still needs).

## Prerequisites — both must land before this flag day is scheduled

### 1. Keystore migration: `bloch-pos keys seal`

**Status: LANDED** (`crates/bloch-pos-node/src/keys.rs`, `main.rs`; commit
`d953fcc` on the round-4 branch). What ships, exactly:

```
bloch-pos keys seal    --dir <datadir> [--passphrase-file <0600 file>]
bloch-pos keys inspect --dir <datadir>
```

- The passphrase comes from a mode-checked `0600` file (`--passphrase-file`,
  or `BLOCH_KEYSTORE_PASSPHRASE_FILE`), or from a **non-echoing terminal
  read with confirmation** when neither is given. It is **never** accepted on
  the command line (`--passphrase <text>` is refused with exit 2) — argv is
  visible in `ps` and in shell history. Minimum 12 characters.
- Refuses to run while a node holds the data dir lock (`LOCK`): sealing
  underneath a live validator is the double-identity hazard the lock exists
  for. Stop the node first.
- Reads the plaintext `BPOSKEY1` file (this command IS the explicit
  operator decision to read it once and end it; no global opt-in flag is
  needed), seals it under Argon2id (64 MiB / t=3 / p=1) + XChaCha20-Poly1305
  to a **`0600` temporary file in the same directory**, `fsync`s it,
  **decodes it back under the passphrase and compares every field** before
  installing it, renames it over `validator.key`, `fsync`s the directory,
  zero-fills the old inode through a handle opened before the rename
  (best effort on journaling / copy-on-write filesystems), and re-loads the
  installed file as a last check.
- Refuses an already-sealed (`BPOSKEY2`) file: passphrase rotation is a
  different operation and this tool does not pretend to be it.
- Exits non-zero and leaves `validator.key` untouched on any I/O error,
  decode error, verification mismatch or confirmation mismatch.
- `keys inspect` prints only the public header (format, index, pubkey
  sha3-256, KDF cost, file mode, length) and whether the data-dir lock is
  free. It opens nothing and prints no secret byte.

Its test suite (`keys.rs` unit tests and `tests/keys_seal_cli.rs`, which
drives the shipped binary) covers: seal → load round trip and signing with
the same key; the plaintext opt-in no longer opening the sealed file; wrong
passphrase fails loud; refusal while a node holds the lock; refusal of an
already-sealed file; refusal of argv / world-readable file / non-tty stdin
passphrase sources; `inspect` printing no secret. Confirm they are green on
the branch being rolled out.

**Also landed in the same commit and relevant to this restart:**

- The node now **refuses a keystore that is group- or other-readable**
  (`chmod 0600` it first; `keys inspect` shows the mode).
- The slashing-protection watermark file is **bound to the validator key and
  the network** on its first write after the upgrade (`BPOSSLP2`). A data
  dir restored from another validator's backup is refused at boot naming the
  mismatch — restore the right `slashing_protection.bin`, never delete it.

### 2. Transport default (H-2)

**Status: RESOLVED** (same commit `d953fcc`): `None => Devnet` is restored,
matching `--help`, `net.rs`, the README and `deploy/bootnodes/verify-bootnodes.sh`,
and the compiled-in libp2p listen address is **loopback**
(`/ip4/127.0.0.1/tcp/16400`). A node restarted on an unchanged unit file
therefore comes up exactly as before this wave: devnet mesh, no swarm. A
move to `dual` is a unit-file change (`--transport dual --p2p-listen
/ip4/0.0.0.0/tcp/16400`) rolled host by host, with the firewall allowlist
updated first — never a compiled-in default. Verify per § Transport-default
verification below.

### 3. Doppelgänger protection — plan 32 minutes per restart

The rebuilt node observes **two epochs (64 slots, 32 minutes)** after every
boot for attestations or blocks bearing its own validator index before it
starts duties, and refuses to start if it sees one (`engine.rs`, R6 HIGH-8).
Every restart in the sequencing below therefore costs that validator 32
minutes of duties; schedule the per-validator batches so that the fleet's
attesting weight never drops below the finality threshold with the observing
nodes counted as absent. `--no-doppelganger-check` / `BLOCH_NO_DOPPELGANGER=1`
disables the observation and is **not** recommended for this rollout — the
window is exactly what catches a keystore that was copied to a second host.

## The rebuild is all-or-nothing

If the fleet does not rebuild by epoch 2700, **nothing breaks** — every node,
upgraded or not, agrees on every rule until that epoch, because
`LEAK_RECOVERY_ACTIVATION_EPOCH` is read from committed `self.epoch`, never a
wall clock. If the fleet rebuilds **partially**, the fleet **forks at
2700**: nodes past the gate apply the leak-recovery arithmetic, nodes behind
it do not, and the two groups derive different state roots from the same
block from that epoch on.

There is no safe partial state between "every validator has sealed its
keystore and is running the fixed binary" and "no validator has rebuilt yet."
Anything in between is worse than either endpoint.

### Sequencing

1. Confirm both prerequisites above are on the branch that will ship this
   flag day (both landed in commit `d953fcc`; re-run their tests there).
2. Dry-run `bloch-pos keys seal` against a copy of one real keystore, off the
   fleet, and confirm the sealed key opens with `bloch-pos keygen-public` or
   an equivalent read-only check before touching any live validator.
3. For each of the 64 validators, **in an order that never drops fleet
   liveness below the finality threshold** (do not seal and restart more
   than a third of the active committee weight concurrently — see the
   `genesis_cohort` taper for the current concentration if that fraction is
   unclear):
   a. Stop the node.
   b. Run `bloch-pos keys seal --dir <datadir> --passphrase-file <0600 file>`
      (or type the passphrase at the prompt), confirm exit 0, then
      `bloch-pos keys inspect --dir <datadir>` and confirm `format : sealed`.
   c. Confirm `validator.key` decodes as `BPOSKEY2` (`file` or a hex dump of
      the first 8 bytes — do not rely on the tool's own report; audit by
      reading the bytes, the same lesson epoch 800 already taught this
      fleet).
   d. Deploy the rebuilt binary (built from the branch with both
      prerequisites applied).
   e. Start the node **without** `--allow-plaintext-keystore` — its absence
      is now the proof the key is sealed, not an assumption.
   f. Confirm the node reaches head and is attesting (§ Verification below)
      before moving to the next validator.
4. Audit the **entire** fleet by binary hash and by keystore magic bytes
   after the rollout — not by trusting a rollout script's own "nothing to
   do" report (epoch 800's rollout silently skipped two validators running
   under unexpected process names; assume the same class of miss here).
5. Confirm every validator is past epoch 2699 and running the fixed binary
   **before** the chain's wall-clock estimate reaches epoch 2700. If any
   validator cannot be confirmed, treat the flag day as not ready and escalate
   per the abort criteria below — do not let the deadline force a partial
   rebuild through.

## Transport-default verification

However H-2 is resolved, verify it on **every** rebuilt node before it
rejoins:

```sh
# Confirm no unexpected all-interfaces listener:
ss -tlnp | grep 16400
#   expect: nothing bound to 0.0.0.0:16400 unless --transport dual was
#   explicitly passed on this node's unit file and that is intended for it.

# Confirm the node's own account of its transport matches the unit file:
journalctl -u bloch-pos-node --since "5 min ago" | grep -i transport
#   the logged transport must equal what the unit file's ExecStart passes,
#   not a value the binary chose because none was given.
```

If a node shows a listener on `0.0.0.0:16400` that its operator did not
configure, stop it and do not let it rejoin until the transport-default fix
(§2 above) is confirmed present in the binary it is running.

## Verification: finalized progression across two nodes

After each validator rejoins, and again once the fleet has crossed epoch
2700, confirm finality is actually advancing — not merely that the process
is up:

```sh
# On two independently-operated nodes (never two nodes sharing an operator,
# a network path, or a keystore — that proves nothing about the network):
bloch-pos-cli getchaininfo --rpc-bind <node-A-rpc>
bloch-pos-cli getchaininfo --rpc-bind <node-B-rpc>
```

Confirm, on both:

- `finalized_epoch` is present and non-decreasing across repeated calls a
  few minutes apart (the engine's downward ratchet refuses a lower value —
  if you observe one on the same node, that is the ratchet firing, not
  healthy progress; see Round-3 audit M-1).
- `finalized_epoch` on node A and node B agree once both have had time to
  receive the same attestations (a persistent disagreement between two
  honest, well-connected nodes past 2700 is a fork, and is an abort
  condition — see below).
- Once past 2700, `finalized_epoch` has advanced by at least one epoch
  relative to its value observed just before 2700 was reached, on **both**
  nodes, before declaring the flag day complete.

## Rollback plan

There is no forward-compatible rollback for a consensus-gated constant once
blocks past the activation epoch exist: a node reverted to the pre-fix
binary cannot validate those blocks and will fork itself off the network it
is trying to rejoin. Rollback is therefore scoped to **before** any node has
produced or accepted a block at or past epoch 2700:

- If a defect in the rebuilt binary is discovered during rollout (steps 1-4
  above) and no node has yet crossed epoch 2700 on the new binary, halt the
  rollout, revert the affected validators to their prior binary **with their
  original plaintext keystore untouched** (the seal step is additive — it
  replaces `validator.key` in place, so reverting the binary without
  reverting the key file means the old binary can no longer read it; keep a
  copy of the pre-seal `validator.key` until the flag day is confirmed
  successful fleet-wide), and re-plan.
- If a node has already produced a signature under both the old (unsealed)
  and new (sealed) key material during a botched migration, treat that as a
  potential key-handling incident, not a routine rollback — follow
  `deploy/BACKUP-AND-HOST-LOSS.md`'s fencing procedure before deciding
  whether that validator's key is still trustworthy to run.
- Once any node has accepted a block past epoch 2700 under the new rules,
  rollback is no longer available for the fleet as a whole — the only path
  forward is completing the rebuild on every remaining node.

## Abort criteria

Do not arm this flag day — hold the rollout and re-plan — if, before epoch
2700 is reached:

- `bloch-pos keys seal` / `keys inspect` are not present, or their tests
  (§1 above; `keys.rs` and `tests/keys_seal_cli.rs`) are not green, on the
  branch being rolled out.
- The transport default (§2) disagrees anywhere with the compiled
  behaviour (`decide_transport`'s `None` arm, the `--help` text, `net.rs`,
  the bootnode verifier), or `DEFAULT_P2P_LISTEN` is not loopback.
- Fewer than 64 of 64 validators can be confirmed sealed, on the fixed
  binary, and attesting, with enough margin before 2700 to fix stragglers
  without crossing the epoch mid-rollout.
- Two independently-operated nodes show a persistent `finalized_epoch`
  disagreement at any point during rollout, past or pre-2700 — this is a
  fork-in-progress, not a flag-day readiness question, and takes priority
  over the deadline.
- Any validator's `validator.key` cannot be confirmed as `BPOSKEY2` by
  reading its magic bytes directly (not by trusting the migration tool's
  exit code alone) after the seal step.

A missed flag day is a six-day delay to closing Round-1 C2/C3. A forked
fleet, or a double-signed key from a botched migration, is materially worse
than a delay. When in doubt, do not arm.
