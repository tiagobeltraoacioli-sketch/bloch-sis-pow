<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Backup policy and host-loss runbook

**Why this exists.** On 2026-08-21 two validator indices (16 and 35) were
found running on two nodes each, with the same private key, on different
heads (`deploy/FLAG-DAY-EPOCH-800.md`, "Fixed during this rollout"). That is
the double-signing condition slashing protection exists to prevent, and it
happened without any attacker: a restored or re-copied key ran alongside the
key it was restored from, on a live twin, because nothing forced the old
copy to prove itself dead first. This document is the fix: a backup policy
that keeps `validator.key` out of routine backups, and a host-loss runbook
whose first step is proving the old host cannot sign, before anything is
restored.

## Backup policy

**`validator.key` is excluded from routine backups.** Routine backup here
means anything scheduled, anything that runs unattended, and anything whose
restore path an operator has not personally rehearsed for this exact file.
The reasons stack:

- A restored key is, by definition, a second copy of a private key that once
  ran. The only way a second copy is safe to run is if the first copy is
  provably dead (see "Fencing before restore" below) — and a routine,
  automated backup has no way to know, at restore time, whether that
  condition holds. A human deciding to restore a specific key, deliberately,
  after checking, is the only safe path.
- The slashing-protection watermark (`slashprot.rs`) that makes double-
  signing detectable lives **next to** `validator.key`, not inside it. A
  backup that restores the key without the watermark restores exactly the
  amplification of the failure mode above: a key with no memory of what it
  has already signed.
- Bulk backup systems are a lateral-movement target precisely because they
  aggregate what individual hosts do not have all in one place. Sixty-four
  validator keys reachable from one backup credential is a worse single
  point of failure than sixty-four hosts that must each be compromised on
  their own.

**What every host backs up routinely instead:**

| Data | Backed up? | Why |
|---|---|---|
| `blocks.log`, chain state | Yes | Public, replayable from peers anyway; backup only saves replay time |
| `slashprot` watermark DB | Yes, **paired with its host's key** — never restored to a different host | Restoring the watermark without the key it belongs to is meaningless; restoring the key without the watermark reopens the double-sign window |
| Node configuration, unit files | Yes | No secret material |
| `validator.key` | **No** — see below | Sole custody is the point |

## Sealed offline copies — one per key, not a backup

Every validator key gets **exactly one** sealed offline copy, made once, at
key generation or at the epoch-2700 seal migration
(`deploy/FLAG-DAY-EPOCH-2700.md`), never refreshed by an automated job:

1. Seal the key with `bloch-pos keys seal` (or, if the key was already
   sealed, copy the `BPOSKEY2` file as-is — never re-derive a new passphrase
   for the offline copy alone, that would make two sealed copies of the same
   key with two different unlock secrets, which is one more thing to lose
   track of).
2. Copy the sealed file to offline, air-gapped media (there is no reason for
   this file to ever touch a network after this step — it is already
   encrypted at rest, so the transfer medium is about custody, not
   confidentiality-in-transit).
3. Store the media and the passphrase **separately**, under separate
   custody. Neither alone reconstructs the key.
4. Log the copy: which validator index, which host it was taken from, the
   date, and the SHA-256 of the sealed file (not the key material — the
   file, so a later "is this the same copy" check does not require decrypting
   anything).
5. Do not make a second copy "to be safe." One sealed offline copy per key is
   the recovery path for host loss; a second copy is a second place the key
   can leak from, for no recovery benefit the first copy did not already
   provide.

## Host-loss runbook

**Fencing before restore is not optional and is not a formality — it is the
only thing that would have prevented 2026-08-21.**

### Step 1 — Prove the old host is dead

Before restoring anything, prove the lost host cannot sign, from the
network's point of view, not merely from the operator's belief that it is
down:

1. **Revoke its network path.** Remove the host's entry from every allowlist
   it appeared in (see `deploy/SSH-ROLE-SEPARATION.md` for where those live,
   and the fleet's per-IP P2P/RPC allowlist wherever it is maintained).
   Revoke, don't merely stop advertising — an allowlist entry that is simply
   unused but still present is one misconfiguration away from letting the
   old host back in.
2. **Confirm no attestations from that validator index for N slots**, where
   N is chosen so that the confirmation window is longer than any plausible
   network partition that could make a live host look silent
   (`deploy/monitoring/rules.yml`'s equivocation and finality-stall windows
   are the reference points — do not pick N shorter than those). Check via
   two independently-operated nodes' RPC (never trust the lost host's own
   report — it is the thing being fenced):
   ```sh
   bloch-pos-cli getvalidatorstatus --rpc-bind <node-A-rpc> --index <N>
   bloch-pos-cli getvalidatorstatus --rpc-bind <node-B-rpc> --index <N>
   ```
   Confirm both agree the index has produced nothing for the full window.
3. **If the host is reachable at all**, stop the validator process on it and
   confirm the stop (process exit, not just "the API says it's stopping") —
   do not proceed on the assumption that revoking network access alone
   prevents a process that is still running from producing a signature it
   then cannot transmit; a signature that is later replayed after the
   network path is restored is still a slashable equivocation.
4. **Only once 1–3 are all confirmed**, treat the old host as dead.

### Step 2 — Restore, on a new host, from the sealed offline copy

1. Restore `validator.key` (the sealed `BPOSKEY2` copy, from custody, with
   its passphrase from separate custody) to the **new** host only. Never to
   the old host, even if it becomes reachable again later — a host that was
   fenced stays retired (see "Exit and replace" below).
2. Do **not** restore the old host's `slashprot` watermark alongside it if
   there is any doubt about whether the old host produced a signature after
   the last watermark checkpoint was taken — the watermark's entire purpose
   is refusing to re-sign anything already signed, and a watermark older
   than the actual last signature is worse than none, because it creates
   false confidence rather than an honest gap. If the old host's true last
   signed slot cannot be established with certainty, treat the watermark as
   unknown and initialize a fresh one that refuses to sign anything at or
   before the highest slot/epoch this validator index is known to have
   attested or proposed at (queried from peers, per Step 1.2) — conservative
   in the direction of refusing to sign, never permissive.
3. Start the validator on the new host and confirm it begins attesting from
   a slot after the fencing window, never before.

### Step 3 — Exit and replace, do not un-fence

A fenced host does not get unfenced. If it turns out to have been a false
alarm (network partition, not a real loss), the correct outcome is still a
**new** validator identity on that host if it rejoins, not restoring its old
allowlist entry and key. Re-admitting a host whose "death" was never
conclusively proven, using the same key it held before, reintroduces exactly
the two-copies-one-key risk this runbook exists to close.

If the validator's bonded stake needs to move to a new key entirely (rather
than the same key on a new host), that is an ordinary voluntary exit,
subject to the same gates as any other exit: **deposits are gated** — the
churn limit and deposit gate that bound how much stake can move in or out
per epoch apply to a replacement exactly as they would to a new entrant
(`docs/specs/BLOCH-POS-STAKE-CHURN.md`). Do not treat "this is a recovery,
not new entry" as a reason to bypass the gate — the chain has no way to
distinguish the two, and a bypass here is a bypass an attacker could also
claim.

## Summary checklist

- [ ] `validator.key` is not in any routine/automated backup path on this host.
- [ ] Exactly one sealed offline copy exists per key, logged with its SHA-256, date, and source host.
- [ ] The copy's passphrase is stored separately from the copy itself.
- [ ] Host-loss response starts with fencing (network revocation + N-slot silence confirmation on two independent nodes), never with restore.
- [ ] A fenced host is never re-admitted under its old key.
- [ ] Any key replacement goes through the ordinary deposit/exit gate, not an out-of-band shortcut.
