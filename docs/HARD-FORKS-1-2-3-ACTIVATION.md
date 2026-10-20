# Hard forks 1, 2 and 3: activation schedule, go/no-go and notices

Status: **schedule proposal, nothing armed.** Written Tue 2026-10-20 at
mainnet epoch 6090 against the running release `b4a21fb6`. Revised the same
day after the owner decision and the reviews in §0.2. Every gate named here
is `u64::MAX` (inert) in every branch at writing. The founder arms the
constants himself, in one release commit. Every epoch below is a
**PLANNED** value until it appears in the armed release commit and its
pinning test. Agents do not arm, sign or publish.

Supersedes the calendar of `docs/SECURITY-FLAG-DAY-PLAN.md` (commit
`b0adf854`, FD-1 2026-11-17 at 8610/8616/8622, FD-2 2026-12-15 at 11130,
FD-3 in 2027). Its dependency analysis (§1, §2) still holds.

---

## 0. Inputs and decisions

### 0.1 Mainnet clock

Read-only RPC `https://blochl1.com/g4rpc`, `getchaininfo`, Tue 2026-10-20
13:42:37 UTC:

| | |
| --- | --- |
| head | slot 194902, height 158896, **epoch 6090**, slot-in-epoch 22 |
| finality | justified 6089, finalized 6088 (`finalized_height` 158827). Healthy: finalized = head − 2. |
| validators | 149 total, 106 active, active stake 204 664 788.9 BLCH |
| witnesses | 2/2 archivals corroborate and agree on head |
| block at slot 194902 | `timestamp` 1792503739 = 1786656679 + 194902 × 30 |

Genesis-4: `genesis_time` = unix **1786656679** (2026-08-13 21:31:19 UTC,
also `docs/CHECKPOINT-RUNBOOK.md`). `SLOT_DURATION_SECS = 30`,
`SLOTS_PER_EPOCH = 32` (`crates/bloch-pos-committee/src/params.rs`), so one
epoch is 960 s (16 min) and a day is 90 epochs.

```
epoch_start_utc(E) = 1786656679 + 960 × E        first_slot(E) = 32 × E
lead of N hours     = 3.75 × N epochs            (72 h = 270 epochs, 24 h = 90)
```

The epoch number is binding. Clock times are estimates. BRT = UTC − 3 (no
daylight saving).

### 0.2 Owner decision and review outcome (2026-10-20)

1. **Nothing changes for deposits and withdrawals.** L1 transfer signing,
   transaction format and fees stay exactly as they are today. So do L2
   bridge deposits and withdrawals. No exchange or wallet has to change any
   signing tooling.
2. **`SIG_CANONICAL` is re-scoped to validator consensus messages only:**
   attestations, block proposals, and validator lifecycle and RANDAO
   messages. Transaction witnesses keep the historical verification rule.
3. **The frozen finality set (FS) and own-target votes (OT) are NO-GO this
   week.** Both stay `u64::MAX` in this release and go to a later flag day
   with their own qualification. So HF1 this week is **claim finality (CF)
   alone**. The earlier "CF and FS activate together" requirement is
   withdrawn for this release. FS and OT will come later, in a later
   release, at an epoch after CF.
4. **The HF2 and HF3 gates are likely to ship disabled** (`u64::MAX`) in this
   release. The final call is made at the release gate (§3.0, R1). Their
   epochs below are provisional and only apply if the founder arms them
   before signing.

### 0.3 What each fork contains (branches at writing)

| Fork | Gate constant(s) | Branch (all descend from `b4a21fb6` unless noted) | This release |
| --- | --- | --- | --- |
| **HF1** | `NATIVE_CLAIM_FINALITY_ACTIVATION_EPOCH` (CF) | `codex/hf1-core-20261020` | **planned to arm** |
| (later) | `NATIVE_FINALITY_SET_ACTIVATION_EPOCH` (FS) | `codex/hf1-core-20261020` | **`u64::MAX`: NO-GO this week** |
| (later) | `NATIVE_OWN_TARGET_ACTIVATION_EPOCH` (OT) | `codex/hf1-owntarget-20261020` | **`u64::MAX`: NO-GO this week** |
| HF2 | `SIG_CANONICAL_ACTIVATION_EPOCH`, re-scoped to validator consensus messages | `codex/hf2-sigdet-20261020` (scope change pending) | likely `u64::MAX` |
| HF2 | `HF2_SLASHING_V2_EPOCH` (alias `NATIVE_SLASHING_ACTIVATION_EPOCH`): P5a evidence pre-admission. Node-local relay policy on the wall epoch, not consensus. | `codex/hf2-slashing-20261020` | likely `u64::MAX` |
| HF2 | `NATIVE_GROWTH_CAP_ACTIVATION_EPOCH` | `codex/hf2-growthcap-20261020` (uncommitted) | `u64::MAX` |
| HF3 | `bloch_crypto::crypto::NATIVE_SLHDSA_SUITE_ACTIVATION_EPOCH` and `params::NATIVE_SLHDSA_SUITE_ACTIVATION_EPOCH`, which must be equal | `codex/hf3-slhdsa-20261020`, `codex/hf3-tags-20261020` (port from `dd287b6c` pending) | likely `u64::MAX` |
| node-only (rides along) | no gate: p3a signer hardening, `getfinalitycertificate`, equivocation watcher, epoch-start attestation deferral, participation tool | `codex/hf-node-only-20261020` | included |

Out of scope, staying `u64::MAX`: `SLASHING_ECONOMICS_V2_ACTIVATION_EPOCH`,
`SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH` and every other inert gate.
`SLASHING_EVIDENCE_ACTIVATION_EPOCH = 2884` and
`PRE_ACTIVATION_OFFENCE_REFUSAL_EPOCH` stay unchanged. KES is not part of
HF3.

**What CF does to users.** CF only changes which finalized checkpoint an
L2 withdrawal claim may rely on: it must be this chain's own. Deposits,
withdrawal transactions, claim formats and fees do not change. On a healthy
chain claims behave as today. The one visible effect is that **L2 withdrawal
claims wait about 2 epochs (≈ 32 min) right after E1**, until the first
checkpoint recorded under the rule finalizes. Withdrawals requested in that
window complete after it, unchanged.

### 0.4 Rollout capacity (binding constraint)

- Own fleet: about 60 validators on 5 hosts. Each upgrade takes about 90 min
  per validator, at most 5 in parallel, one per host. **A full pass is 12
  waves × 90 min = 18 h**, or about 27 h with 50% slack.
- The emergency release `b4a21fb6` is still rolling out. Every HF branch
  descends from it (checked with `git merge-base --is-ancestor`). A
  validator not yet on `b4a21fb6` goes straight to the HF release. Rules:
  1. Keep rolling `b4a21fb6` until the HF release is signed, then stop
     scheduling new `b4a21fb6` upgrades.
  2. Never start an HF upgrade on a host while a `b4a21fb6` upgrade is
     running there.
  3. The release commit must have `b4a21fb6` as an ancestor.
- Every replacement release (postpone or disarm) also costs at least 18 h of
  own rollout, so every go/no-go that can change a gate sits at least 24 h
  before that gate.
- Only one full rollout fits this week, so everything this week ships in
  **one binary**.

### 0.5 Ordering constraints (hard)

| # | Constraint | Why |
| --- | --- | --- |
| O1 | `CF = E1`. `FS = OT = u64::MAX` in this release. | Owner and review decision (§0.2). CF alone is complete. It closes the double-payout path of a split without changing vote weights. |
| O2 | Later releases: `FS >= CF` and `OT >= FS` | OT needs the frozen denominator. Without it, OT lowers counted participation on both sides of a split and speeds up minority finality under the leak. |
| O3 | E1 is reached by a finalizing chain | CF claims pause until the first checkpoint recorded under the rule finalizes. |
| O4 | If HF2 is armed: `E2 >= E1 + 90` (24 h) | Disarm window. Moving a gate takes a replacement release plus 18 h of own rollout. |
| O5 | `SIG_CANONICAL ∈ {E2, u64::MAX}`, `HF2_SLASHING_V2_EPOCH ∈ {E2, u64::MAX}` | One HF2 epoch, if any. |
| O6 | `E3 > SIG_CANONICAL`, planned E2 + 12. If `SIG_CANONICAL` is inert, HF3 is inert too. | A new suite must enter consensus under the canonical policy. |
| O7 | The two `NATIVE_SLHDSA_SUITE_ACTIVATION_EPOCH` constants are equal | Otherwise the verifier accepts the suite while fees still price it as a hybrid. |
| O8 | `E1 >= publication_epoch + 270` (72 h) | Minimal operator lead time (§2). |
| O9 | Transaction validity, mempool admission and fees for transactions are byte-identical to `b4a21fb6` at every epoch | Owner decision §0.2 (1). The `hf2-sigdet` node relay policy that refuses non-canonical **transaction** encodings at the mempool must be removed or limited to validator messages. |

---

## 1. Schedule

### 1.1 Plan A (recommended, meets "this week")

Precondition: the signed release and the notice are **published by Wed
2026-10-21 16:11 UTC (13:11 BRT), epoch 6190**. Otherwise use Plan B. Do
not compress the 72 h lead time.

| Item | Epoch (PLANNED) | First slot | UTC | BRT |
| --- | --- | --- | --- | --- |
| Scope freeze (CF in; FS and OT out; HF2/HF3 decision) | ~6114 | | Tue 10-20 19:55 | 16:55 |
| **Publication deadline** (signed binary + notice, T−72 h) | **6190** | 198080 | Wed 10-21 16:11 | 13:11 |
| Own fleet 100% on the release (latest) | 6340 | 202880 | Fri 10-23 08:11 | 05:11 |
| **HF1 GO/NO-GO** (T−24 h) | **6370** | 203840 | Fri 10-23 16:11 | 13:11 |
| Optional exchange pause (standard hard-fork caution) | 6458 | 206656 | Sat 10-24 15:39 | 12:39 |
| **HF1: claim finality (CF)** | **6460** | **206720** | **Sat 10-24 16:11** | **13:11** |
| HF1 health check (finality continuous, claims resumed) | 6464 | 206848 | Sat 10-24 17:15 | 14:15 |
| HF1 all-clear | ~6466 | | Sat 10-24 17:47 | 14:47 |
| *Only if armed:* HF2/HF3 GO/NO-GO | 6466 | | Sat 10-24 17:47 | 14:47 |
| *Only if armed:* **HF2** (validator-message signatures, P5a policy) | 6550 | 209600 | Sun 10-25 16:11 | 13:11 |
| *Only if armed:* **HF3** (SLH-DSA suite 0x0003) | 6562 | 209984 | Sun 10-25 19:23 | 16:23 |

If HF2/HF3 ship disabled (the likely case), they need a later release with
its own rollout and at least 72 h of notice. The earliest that release
could activate is the week of 2026-10-26. FS and OT then follow at a later
flag day (§0.2).

### 1.2 Plan B (publication slips by one day)

Publication by **Thu 2026-10-22 16:11 UTC, epoch 6280**: HF1 GO/NO-GO at
6460 (Sat 10-24 16:11 UTC), **HF1 at 6550 (Sun 10-25 16:11 UTC)**. If HF2/HF3
are armed, they move to 6640 and 6652 (Mon 10-26 16:11 and 19:23 UTC). If
publication slips past Thu 16:11 UTC, HF1 cannot be activated safely this
week.

### 1.3 Why this is the most aggressive safe calendar

- The earliest possible publication is about 26 h from now. That window has
  to hold the integration, the armed build, the tests, a full-history replay
  and the founder's signature.
- 72 h is the shortest lead time we have used. The E5850 L2 activation
  reached 89.2% upgraded stake with it. Own stake (about 89%) alone does not
  pass the 90% readiness bar, so externals need real time.
- Each GO/NO-GO sits at T−24 h because a replacement release needs 18 h of
  own rollout.
- With FS and OT out, HF1 is one gate. Its risk is the smallest of the set:
  it adds state and changes no vote weight.

---

## 2. Minimal operator-upgrade lead time

| Audience | Minimum | Deadline (Plan A) |
| --- | --- | --- |
| External validators, archival/RPC nodes, bootnodes, explorers, indexers, bridge operators | **72 h** from the signed binary to E1, with the upgrade done by T−24 h so the readiness check counts it | **Fri 10-23 16:11 UTC** (epoch 6370) |
| Exchanges (Coinstore, P2B) | **Node upgrade only.** No wallet, signer, address or fee change. | Fri 10-23 16:11 UTC |
| Own fleet | 18 h rollout (27 h with slack), starting right after the signature | 100% by Fri 10-23 08:11 UTC |

---

## 3. Go / no-go checklists (hard criteria)

Every check runs on the **exact armed release commit** unless noted, and is
recorded with date, commit and verdict. One failed hard criterion means
NO-GO.

### 3.0 Release gate (before signature, Wed 10-21, before 16:11 UTC)

| # | Criterion | Pass |
| --- | --- | --- |
| R1 | Written scope decision. CF armed. FS and OT at `u64::MAX`. HF2 and HF3 each armed or `u64::MAX`. A gate is armed only if its branch is merged, re-scoped as in §0.2 (SIG_CANONICAL: validator messages only) and covered by R3–R6. Otherwise it is `u64::MAX` and the notice names it "not in this release". | written decision |
| R2 | `git merge-base --is-ancestor b4a21fb6 <release>` | exit 0 |
| R3 | `cargo test --workspace` (mainnet build and devnet features). The armed pinning test asserts O1, O4–O8 on literal values, plus `FS == OT == u64::MAX`. | all green |
| R4 | `scripts/l2-activation/replay-mainnet-history.sh --candidate <armed> --baseline b4a21fb6 --expect-root/--expect-slot` from two archivals | `VERDICT: PASS`, identical head root |
| R5 | `scripts/l2-activation/qualify-mixed-fleet.py` at devnet-relative E1 (and E2/E3 if armed) | old node forks exactly at E1, upgraded 3/4 keep finalizing, claims pause after E1 and resume within about 2 epochs |
| R6 | **Transaction invariance (O9).** A corpus of transfers and L2 deposit/withdraw/claim transactions produced by the `b4a21fb6` wallet/CLI (including every accepted historical encoding) is admitted by the release mempool, is valid before and after every armed gate, and is charged identical fees | identical admission, validity, fees |
| R7 | CF split reproduction: one withdrawal paid on both branches below the gate, refused above it | reproduces / fixed |
| R8 | Replacement releases built, replay-qualified (R4) and signed together with the armed one: **D0** everything disarmed, plus **D1** HF2/HF3 disarmed if they are armed | signed and ready |
| R9 | Reproducible build. `SHA256SUMS` signed by the founder (minisign key `1A5D96A5C4955EF7`). Agents never touch the signing key. | signature verifies |

### 3.1 HF1 GO/NO-GO, Fri 10-23 16:11 UTC (epoch 6370)

| # | Criterion | Pass |
| --- | --- | --- |
| H1.1 | R1–R9 recorded PASS | yes |
| H1.2 | Devnet soak of the armed build (devnet-relative gates, mixed old and new nodes) | ≥ 24 h past the devnet E1 equivalent (and E3, if armed), no `StateRootMismatch`, finality continuous, claims resumed, memory flat |
| H1.3 | 100% of own validators, both archivals and all bootnodes report the release commit. No own validator offline for more than 2 epochs in the last 6 h. | yes |
| H1.4 | **Readiness ≥ 90% of active stake** on the release (version or banner). Needs at least about 1% external stake confirmed. | ≥ 90% |
| H1.5 | Both exchange nodes (Coinstore, P2B) confirmed upgraded, in writing | both |
| H1.6 | Chain finalizing normally: finalized ≥ head − 3 over the last 90 epochs | yes |
| H1.7 | No validator key runs on two hosts. Signer protection (p3a) is active on every own validator. | yes |

NO-GO: publish D0 at once and roll it to the own fleet (18 h fits before
E1). Then announce new epochs with at least 72 h of notice.

### 3.2 At E1 (Sat 10-24 16:11 UTC), abort rule

| # | Check by E1 + 4 (epoch 6464) | Pass |
| --- | --- | --- |
| A1.1 | No upgraded node logs `StateRootMismatch` or `WS_CONFLICT` at or after 6460 | yes |
| A1.2 | Finality continuous: finalized epoch ≥ 6462 | yes |
| A1.3 | `getl2settlement` reports `withdrawals.finalized_checkpoint.own_chain_rule_active = true` and `own_root == root`. Claims resumed. | yes |
| A1.4 | A test transfer, an L2 deposit and an L2 withdrawal claim made with the **old** (`b4a21fb6`) wallet/CLI after E1 are included and finalized | yes |

If any check fails: announce, keep exchanges paused, and ship a forward
hotfix. Never fall back to the old binary after E1.

### 3.3 Only if HF2/HF3 are armed: GO/NO-GO, Sat 10-24 17:47 UTC (epoch 6466)

| # | Criterion | Pass |
| --- | --- | --- |
| H2.1 | A1.1–A1.4 PASS | yes |
| H2.2 | Devnet (H1.2) crossed the E2 and E3 equivalents. Validator attestations and proposals under the canonical rule were counted, and participation did not drop. | yes |
| H2.3 | R6 re-run across devnet E2/E3: transactions unaffected | yes |

NO-GO: publish **D1** at once. The own rollout (18 h) lands before 6550.
At E2 and E3: no root mismatch and finality continuous by E + 4. If E2 is
unhealthy, halt own validators at 6561 (before E3). The chain stalls and
does not fork twice.

---

## 4. What happens to nodes that do not upgrade

**At E1 (6460).** CF writes the chain's own checkpoint roots into the L2
state, so the first block of 6460 has a different state root. A node on
the old binary (including `b4a21fb6`) **rejects it with `StateRootMismatch`
and stops following the chain.** It finalizes nothing after that point.

- **Validators** on the old binary disappear from the upgraded chain. They
  earn nothing and accrue inactivity penalties there, under today's rules.
- Old-binary validators may keep producing a minority branch. It **cannot
  finalize**: they hold far less than two thirds of stake. An exchange that
  credits only finalized deposits on its own node is not exposed. A
  non-upgraded exchange node simply stops crediting, and its withdrawals
  stop confirming.
- **Recovery:** install the release and restart. If the node only stopped,
  it continues from its last valid block. If it stored minority-branch
  blocks after E1, the new release refuses to replay them. In that case,
  restore a data directory backed up before E1, or bootstrap from a
  snapshot (`docs/SNAPSHOT-BOOTSTRAP.md`).

**At E2/E3 (only if armed).** These apply only to validator consensus
messages and the optional new suite. Transactions are unaffected (O9). Any
node not on the release has already stopped at E1.

**No rollback after a gate.** Once a block at or after a gate finalizes,
the remedy is a forward release. Before E1, going back to `b4a21fb6` is
safe.

---

## 5. Armed values (filled by the founder only)

The epochs in this file are **PLANNED**. The ARMED column is copied from
the signed release commit and from nowhere else.

| Constant | Source today | PLANNED Plan A | PLANNED Plan B | **ARMED** (release commit) |
| --- | --- | --- | --- | --- |
| `NATIVE_CLAIM_FINALITY_ACTIVATION_EPOCH` | `u64::MAX` | 6460 | 6550 | `{{ARMED}}` |
| `NATIVE_FINALITY_SET_ACTIVATION_EPOCH` | `u64::MAX` | `u64::MAX` (NO-GO) | `u64::MAX` | `{{ARMED}}` |
| `NATIVE_OWN_TARGET_ACTIVATION_EPOCH` | `u64::MAX` | `u64::MAX` (NO-GO) | `u64::MAX` | `{{ARMED}}` |
| `SIG_CANONICAL_ACTIVATION_EPOCH` (validator messages only) | `u64::MAX` | `u64::MAX` (likely), else 6550 | else 6640 | `{{ARMED}}` |
| `HF2_SLASHING_V2_EPOCH` | `u64::MAX` | `u64::MAX` (likely), else 6550 | else 6640 | `{{ARMED}}` |
| `NATIVE_GROWTH_CAP_ACTIVATION_EPOCH` | `u64::MAX` | `u64::MAX` | `u64::MAX` | `{{ARMED}}` |
| `crypto::NATIVE_SLHDSA_SUITE_ACTIVATION_EPOCH` | `u64::MAX` | `u64::MAX` (likely), else 6562 | else 6652 | `{{ARMED}}` |
| `params::NATIVE_SLHDSA_SUITE_ACTIVATION_EPOCH` | `u64::MAX` | same as above | same | `{{ARMED}}` |
| release commit / SHA-256 | | | | `{{COMMIT}}` / `{{SHA256}}` |
| D0 / D1 commits | | | | `{{D0}}` / `{{D1}}` |

---

## Appendix A. GitHub release notes (draft)

> DRAFT. Do not publish until §3.0 has passed and every `{{…}}` holds an
> ARMED value from §5. Delete the bracketed HF2/HF3 lines if those gates
> ship disabled.

```markdown
# bloch-pos {{VERSION}}: mandatory node upgrade, hard fork at epoch {{E1}}

**Every node operator must upgrade by {{UPGRADE DEADLINE, e.g. Fri 2026-10-23 16:11 UTC}}.**
A node that has not upgraded stops following the chain at epoch {{E1}}
(first slot {{32×E1}}, expected {{Sat 2026-10-24 16:11 UTC}}). The epoch
number is binding. Times assume 30 s slots and 32 slots per epoch.

## Nothing changes for deposits, withdrawals or fees

L1 transfers (signing, format, fees) and L2 bridge deposits and withdrawals
work exactly as before. Wallets, signers and addresses need no change. Only
the node software must be upgraded.

## What changes at epoch {{E1}}

- An L2 withdrawal claim is accepted only against a finalized checkpoint
  that is this chain's own. On a healthy chain this changes nothing. During
  a network split, it prevents one withdrawal from being paid on two
  branches.
- Right after {{E1}}, L2 withdrawal claims wait about 2 epochs (about 32 min)
  until the first checkpoint recorded under the new rule finalizes. After
  that they proceed as usual.

[{{If armed:}} At epoch {{E2}}, validator attestations and block proposals
must use the canonical signature encoding (validator software only;
transactions are unaffected). At epoch {{E3}}, the optional signature suite
0x0003 (SLH-DSA-SHAKE-128s + Falcon-1024) becomes available. Existing keys
and fees are unchanged.]

**Node-only (active on install):** signer hardening (per-key lock and
rollback guard), new RPC `getfinalitycertificate`, equivocation watcher.

Nothing changes before {{E1}}. This release produces the same blocks and
state roots as the current one and replays the full history unchanged.

## Verify

    minisign -Vm SHA256SUMS -p bloch-release-20260922.pub   # key id 1A5D96A5C4955EF7
    sha256sum --check SHA256SUMS

Commit `{{COMMIT}}`. Linux x86-64 SHA-256 `{{SHA256}}`.

## Not upgrading

At {{E1}} an old node rejects the first block (`StateRootMismatch`) and
stops. An old validator stops earning and accrues inactivity penalties. To
recover, install this release. If the node stored blocks after {{E1}},
restore a pre-{{E1}} backup or a snapshot.

## Go / no-go

GO requires at least 90% of active stake on this release at {{T−24 h}}.
Otherwise a signed replacement release disarms the gate and must be
installed before {{E1}}. Status is posted on {{CHANNEL}}.
```

## Appendix B. Telegram notice (draft)

```text
MANDATORY NODE UPGRADE: Bloch L1 hard fork at epoch {{E1}}

Release: bloch-pos {{VERSION}} ({{COMMIT short}}), signed, SHA-256 {{SHA256 short}}
Download and verify: {{RELEASE URL}}

Upgrade deadline: {{Fri 2026-10-23 16:11 UTC}}
Activation: epoch {{E1}} ≈ {{Sat 2026-10-24 16:11 UTC}} (the epoch number is binding)

What changes: L2 withdrawal claims are accepted only against this chain's own finalized checkpoint. Claims wait ~32 min right after activation.
What does NOT change: deposits, withdrawals, transaction signing, formats and fees. No wallet changes.

Nodes that do not upgrade stop following the chain at epoch {{E1}}.
Validators: never run one key on two hosts.

Only trust hashes from the signed release page, never from chat.
Reply with your node version to {{CONTACT}} so we count you in the readiness check.
```

## Appendix C. Exchange email (draft, Coinstore and P2B)

```text
Subject: Bloch (BLCH) mandatory node upgrade before epoch {{E1}} ({{Sat 24 Oct 2026}})

Dear {{Coinstore | P2B}} team,

Bloch L1 activates a consensus upgrade at epoch {{E1}}, expected around
{{Sat 2026-10-24 16:11 UTC}} (the epoch number is binding).

Only a node upgrade is required. Deposits, withdrawals, transaction signing,
address formats and fees do not change. Your wallet and signing setup need
no change.

1. Release
   bloch-pos {{VERSION}}, commit {{COMMIT}}, Linux x86-64 SHA-256 {{SHA256}}.
   Signed with our release key (minisign, key id 1A5D96A5C4955EF7).
   Download: {{RELEASE URL}}. Please verify the signature, not only this email.

2. Deadline
   Upgrade your BLCH node by {{Fri 2026-10-23 16:11 UTC}}.

3. Please
   a. Reply with the output of `bloch-pos --version` once upgraded. We count
      confirmations in our go/no-go decision.
   b. Keep crediting deposits only once they are finalized on your own node.
   c. Optional, as with any hard fork: pause BLCH deposits and withdrawals
      from about {{Sat 15:39 UTC}} (epoch {{E1−2}}) until our all-clear,
      expected within about 2 hours.

4. If your node is not upgraded
   It stops following the chain at epoch {{E1}}: deposits stop being credited
   and withdrawals stop confirming until you install the release. No funds
   are at risk if you credit only finalized deposits.

5. If we postpone
   We publish a signed replacement release and a new epoch at least 72 hours
   ahead, and we email you directly.

Contacts: {{OPERATOR CONTACT}} (coordination), {{SECURITY CONTACT}} (private).

Best regards,
{{NAME}}, Bloch
```
