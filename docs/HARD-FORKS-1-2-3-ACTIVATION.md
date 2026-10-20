# Hard forks 1, 2 and 3: activation schedule, go/no-go and notices

Status: **schedule proposal, nothing armed.** Written Tue 2026-10-20 at
mainnet epoch 6090 against the running release `b4a21fb6`. Every gate named
here is `u64::MAX` (inert) in every branch at writing. The founder arms the
constants himself, in one release commit. Every epoch below is a
**PLANNED** value until it appears in the armed release commit and the
pinning test. Agents do not arm, sign or publish.

Supersedes the calendar of `docs/SECURITY-FLAG-DAY-PLAN.md` (commit
`b0adf854`, FD-1 2026-11-17 at 8610/8616/8622, FD-2 2026-12-15 at 11130,
FD-3 in 2027). Its dependency analysis (§1, §2) still holds. This file only
compresses the calendar to "all three active this week" and states what
that compression costs.

---

## 0. Inputs

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

### 0.2 What each fork contains (branches at writing)

| Fork | Gate constant(s) | Branch (all descend from `b4a21fb6` unless noted) | State at writing |
| --- | --- | --- | --- |
| **HF1** | `NATIVE_CLAIM_FINALITY_ACTIVATION_EPOCH` (CF) | `codex/hf1-core-20261020` | committed, inert |
| HF1 | `NATIVE_FINALITY_SET_ACTIVATION_EPOCH` (FS, frozen finality set). `NATIVE_FINALITY_SET_PRUNE_AFTER_EPOCHS = 90` and `NATIVE_FINALITY_SET_RECOVERY_EPOCHS = []` stay as they are. | `codex/hf1-core-20261020` | committed, inert |
| HF1 (conditional) | `NATIVE_OWN_TARGET_ACTIVATION_EPOCH` (OT, FFG counts own-chain source/target only) | `codex/hf1-owntarget-20261020` | **merge in progress, conflicts unresolved** |
| **HF2** | `SIG_CANONICAL_ACTIVATION_EPOCH` (canonical signature encodings, v2 suite-bound context). Consensus change **and wallet-facing**. | `codex/hf2-sigdet-20261020` | committed, inert |
| HF2 | `HF2_SLASHING_V2_EPOCH` (alias `NATIVE_SLASHING_ACTIVATION_EPOCH`): P5a evidence pre-admission. **Node-local relay policy on the wall epoch, not consensus.** | `codex/hf2-slashing-20261020` | committed, inert |
| HF2 (conditional) | `NATIVE_GROWTH_CAP_ACTIVATION_EPOCH` (funded-activation growth cap) | `codex/hf2-growthcap-20261020` | uncommitted work in progress |
| **HF3** | `bloch_crypto::crypto::NATIVE_SLHDSA_SUITE_ACTIVATION_EPOCH` (verifier accepts suite 0x0003) **and** `params::NATIVE_SLHDSA_SUITE_ACTIVATION_EPOCH` (per-suite verify gas). They must be equal. | `codex/hf3-slhdsa-20261020`, `codex/hf3-tags-20261020` (port of `p9a`/`p9f`/`tag-alloc`, which are on `dd287b6c`) | **not yet on the `b4a21fb6` line** |
| node-only (rides along) | none: p3a signer hardening, `getfinalitycertificate`, equivocation watcher, epoch-start attestation deferral, participation tool | `codex/hf-node-only-20261020` | committed |

Out of scope, stay `u64::MAX`: `SLASHING_ECONOMICS_V2_ACTIVATION_EPOCH`,
`SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH`, every other inert gate. KES is
not on the mainnet line and is **not** part of HF3. Unchanged:
`SLASHING_EVIDENCE_ACTIVATION_EPOCH = 2884` and
`PRE_ACTIVATION_OFFENCE_REFUSAL_EPOCH` (the HF2 tripwire already pins that
HF2 never moves them).

### 0.3 Rollout capacity (binding constraint)

- Own fleet: about 60 validators on 5 hosts. Each upgrade takes about 90 min
  per validator, at most 5 in parallel, one per host.
  **Full pass = 12 waves × 90 min = 18 h**, or about 27 h with 50% slack.
- The emergency release `b4a21fb6` is still rolling out. Every HF branch
  descends from `b4a21fb6` (checked with `git merge-base --is-ancestor`).
  So **a validator not yet on `b4a21fb6` goes straight to the HF release**,
  with no second pass. Rules:
  1. Keep rolling `b4a21fb6` until the HF release is signed. Then stop
     scheduling new `b4a21fb6` upgrades.
  2. Never start an HF upgrade on a host while a `b4a21fb6` upgrade is still
     running there (one validator per host at a time).
  3. The HF release commit must have `b4a21fb6` as an ancestor. The release
     script refuses otherwise. That way the HF rollout can never regress the
     emergency fix.
- Consequence: **every replacement release (postpone or disarm) also costs
  ≥ 18 h of own rollout.** Every go/no-go below that can change a gate must
  be at least 24 h before that gate.
- Only one full rollout fits in this week. **All three forks therefore ship
  in ONE armed binary** with three activation epochs.

### 0.4 Ordering constraints (hard)

| # | Constraint | Why |
| --- | --- | --- |
| O1 | `CF == FS` (= **E1**) | Founder requirement. Also: FS freezes the quorum denominator at the same epoch from which CF refuses claims against a foreign checkpoint, so no window has one without the other. |
| O2 | `OT >= FS`, planned `OT = E1 + 6`. `OT = u64::MAX` is allowed (HF1 ships without it). | Own-target filtering without a frozen denominator lowers counted participation on both sides of a split and speeds up minority finality under the leak. The +6 gives attribution: a divergence at E1 is CF/FS, one at E1+6 is OT. |
| O3 | FS activation epoch reached by a **finalizing** chain | FS doc: the first set is the duty roster at that epoch. A stalled chain at E1 freezes a bad set. |
| O4 | `E2 >= E1 + 90` (24 h) | (a) Disarm window: a release moving HF2/HF3 needs 18 h of own rollout. (b) One full FS prune horizon (90 epochs) passes, so non-upgraded validators are out of the finality set by the first finalized handoff before HF2 changes signature rules. (c) Growth cap changes activation epochs, which feed the FS candidate. Qualify it on top of FS behavior. |
| O5 | `SIG_CANONICAL == E2`, `HF2_SLASHING_V2_EPOCH == E2`, `GROWTH_CAP ∈ {E2, u64::MAX}` | One HF2 epoch for operators and exchanges. P5a is relay policy only and has no consensus ordering requirement. Keeping it on E2 just avoids a fourth date. |
| O6 | `E3 > SIG_CANONICAL`, planned `E3 = E2 + 12`. If `SIG_CANONICAL` is inert, HF3 is inert too. | A new suite must enter consensus under the canonical/Bound policy (one byte form, suite-bound contexts), never under the historical permissive verifier. |
| O7 | `crypto::NATIVE_SLHDSA_SUITE_ACTIVATION_EPOCH == params::NATIVE_SLHDSA_SUITE_ACTIVATION_EPOCH` | Otherwise a verifier accepts the suite while fees price it as a hybrid (≈ 1.07 M gas of CPU sold for 72 748). |
| O8 | `E1 >= publication_epoch + 270` (72 h) | Minimal operator lead time (§2). |

---

## 1. Schedule

### 1.1 Plan A (recommended, meets "this week")

Precondition: the signed release and the notice are **published by Wed
2026-10-21 16:11 UTC (13:11 BRT), epoch 6190**. If they are not, use Plan B.
Do not compress the 72 h lead time.

| Item | Epoch (PLANNED) | First slot | UTC | BRT |
| --- | --- | --- | --- | --- |
| Scope freeze, integration branch cut | ~6114 | | Tue 10-20 19:55 | 16:55 |
| **Publication deadline** (signed binary + notice, T−72 h) | **6190** | 198080 | Wed 10-21 16:11 | 13:11 |
| Own fleet 100% on HF release (latest) | 6340 | 202880 | Fri 10-23 08:11 | 05:11 |
| **HF1 GO/NO-GO** (T−24 h, last point a replacement can still land) | **6370** | 203840 | Fri 10-23 16:11 | 13:11 |
| Exchanges pause BLCH deposits/withdrawals | 6458 | 206656 | Sat 10-24 15:39 | 12:39 |
| **HF1: CF + FS** | **6460** | **206720** | **Sat 10-24 16:11** | **13:11** |
| HF1 health check (finality resumed, claims resumed) | 6464 | 206848 | Sat 10-24 17:15 | 14:15 |
| HF1 (conditional): OT | **6466** | 206912 | Sat 10-24 17:47 | 14:47 |
| **HF2/HF3 GO/NO-GO** (E2 − 84 epochs, 22.4 h before E2) | 6466 | | Sat 10-24 17:47 | 14:47 |
| HF1 all-clear to exchanges (if OT healthy) | ~6470 | | Sat 10-24 18:51 | 15:51 |
| Exchanges pause again | 6548 | 209536 | Sun 10-25 15:39 | 12:39 |
| **HF2: SIG_CANONICAL + P5a policy (+ growth cap)** | **6550** | **209600** | **Sun 10-25 16:11** | **13:11** |
| HF2 health check | 6554 | 209728 | Sun 10-25 17:15 | 14:15 |
| HF3 stop point (own validators halted here if HF2 is unhealthy) | 6561 | | Sun 10-25 19:07 | 16:07 |
| **HF3: SLH-DSA suite 0x0003 (verifier + fee)** | **6562** | **209984** | **Sun 10-25 19:23** | **16:23** |
| All-clear to exchanges | ~6566 | 210112 | Sun 10-25 20:27 | 17:27 |

Spacing: E1 → OT is 6 epochs (96 min). E1 → E2 is 90 epochs (24 h). E2 → E3
is 12 epochs (3 h 12 min).

### 1.2 Plan B (publication slips by one day)

Publication by **Thu 2026-10-22 16:11 UTC, epoch 6280**.

| Item | Epoch (PLANNED) | UTC | BRT |
| --- | --- | --- | --- |
| HF1 GO/NO-GO | 6460 | Sat 10-24 16:11 | 13:11 |
| **HF1: CF + FS** | **6550** | Sun 10-25 16:11 | 13:11 |
| OT (conditional) | 6556 | Sun 10-25 17:47 | 14:47 |
| HF2/HF3 GO/NO-GO | 6556 | Sun 10-25 17:47 | 14:47 |
| **HF2** | **6640** | Mon 10-26 16:11 | 13:11 |
| **HF3** | **6652** | Mon 10-26 19:23 | 16:23 |

Plan B activates HF1 this week, but HF2 and HF3 fall on Monday. Squeezing
HF2 to Sunday (E1 + 12) would remove the disarm window O4. The only stop
mechanism left would be halting own validators, and the finality-set prune
horizon would not have elapsed. **Not recommended.** If publication slips
past Thu 16:11 UTC, HF1 cannot be safely activated this week.

### 1.3 Why this is the most aggressive safe calendar

- **Earliest publication is about 26 h from now.** Integration (two branches
  still in progress), an armed build, tests, a full-history replay and the
  founder's signature all have to fit before it.
- **72 h** is the shortest lead time we have used. The E5850 L2 activation
  reached 89.2% upgraded stake with it. Own stake (≈ 89%) alone does not
  pass the 90% readiness bar (§3, G8), so externals need real time.
- **T−24 h for each GO/NO-GO** comes from the 18 h own rollout of any
  replacement release, plus margin.
- **E2 = E1 + 24 h** is the smallest spacing that keeps a real disarm option
  (O4).
- **E3 = E2 + 12 epochs** is acceptable without a disarm window because HF3
  is **latent**: suite 0x0001 is priced exactly as before
  (`suite_verify_gas(0x0001) == HYBRID_VERIFY_GAS`). Nodes only behave
  differently once a 0x0003 signature is used. If HF2 is unhealthy, the stop
  mechanism is halting own validators at E3 − 1 (the chain stalls and does
  not fork twice).

---

## 2. Minimal operator-upgrade lead time

| Audience | Minimum | Deadline (Plan A) |
| --- | --- | --- |
| External validators, archival/RPC nodes, bootnodes, explorers, indexers, bridge operators | **72 h** from the signed binary to E1. Upgrade requested by T−24 h, so the readiness check counts them. | upgrade by **Fri 10-23 16:11 UTC** (epoch 6370) |
| Exchanges (Coinstore, P2B): node | same as above | Fri 10-23 16:11 UTC |
| Exchanges: **wallet / signer** (HF2 is wallet-facing) | upgraded signer tooling by E2 − 24 h | Sat 10-24 16:11 UTC |
| Own fleet | 18 h rollout (27 h with slack), starting immediately after signature | 100% by Fri 10-23 08:11 UTC |

HF2 and HF3 come from the same binary, so their lead time is ≥ 96 h. No
second install is needed unless a replacement release is announced.

---

## 3. Go / no-go checklists (hard criteria)

Every check runs on the **exact armed release commit** unless noted, and is
recorded below with date, commit and verdict. One failed hard criterion
means NO-GO. Nobody gets to "accept the risk" at the meeting.

### 3.0 Release gate (before signature, Wed 10-21, before 16:11 UTC)

| # | Criterion | Pass |
| --- | --- | --- |
| R1 | Scope frozen. OT and growth cap are **in** only if their branch is merged, tests pass and they are covered by R4/R5. Otherwise they stay `u64::MAX` and are named "deferred" in the notice. HF3 is in only if the SLH-DSA port to the `b4a21fb6` line is merged with its tag allocation. | written decision |
| R2 | `git merge-base --is-ancestor b4a21fb6 <release>` | exit 0 |
| R3 | `cargo test --workspace` (mainnet build and devnet features), including the **armed pinning test** asserting O1–O8 with the literal epochs | all green |
| R4 | `scripts/l2-activation/replay-mainnet-history.sh --candidate <armed> --baseline b4a21fb6 --expect-root/--expect-slot` from two archivals | `VERDICT: PASS`, candidate and baseline roots identical at head |
| R5 | `scripts/l2-activation/qualify-mixed-fleet.py` extended to E1, OT, E2, E3 (devnet-relative epochs) | old node forks exactly at E1, upgraded 3/4 keep finalizing through every gate, claims pause after E1 and resume within ~2 epochs |
| R6 | Branch reproductions (p2b-style): CF double payout, foreign-target finality, leak-denominator minority finality | each reproduces below its gate and is fixed above it |
| R7 | Partition harness: splits 89/11 and 50/50 with FS (and OT if in scope), held long enough for the leak to matter, then healed | never two conflicting finalized checkpoints, no L2 withdrawal paid on both branches, the 11% side never finalizes |
| R8 | Two **replacement releases** built, replay-qualified (R4) and signed together with the armed one: **(D1)** HF2/HF3 disarmed (E1 and OT unchanged), **(D0)** everything disarmed | both signed and ready to publish |
| R9 | Reproducible build, `SHA256SUMS` signed by the founder (minisign key `1A5D96A5C4955EF7`). Agents never touch the signing key. | signature verifies |

### 3.1 HF1 GO/NO-GO, Fri 10-23 16:11 UTC (epoch 6370)

| # | Criterion | Pass |
| --- | --- | --- |
| H1.1 | R1–R9 recorded PASS | yes |
| H1.2 | Devnet soak of the armed build (gates relative to devnet epochs, mixed old/new nodes, all three gates crossed) | ≥ 24 h past the devnet E3 equivalent, no `StateRootMismatch`, finality continuous, memory flat |
| H1.3 | Own fleet: 100% of own validators, both archivals and all bootnodes report the release commit; no own validator offline for more than 2 epochs in the last 6 h | yes |
| H1.4 | **Readiness ≥ 90% of active stake** on the release, measured by version/banner. That needs at least about 1% external stake confirmed. | ≥ 90% |
| H1.5 | Both exchange nodes (Coinstore, P2B) confirmed upgraded, in writing | both |
| H1.6 | Chain finalizing normally: finalized ≥ head − 3 for the last 90 epochs | yes |
| H1.7 | No validator key runs on two hosts. Signer protection (p3a) is active on every own validator. | yes |

NO-GO: publish D0 at once and roll it to the own fleet. 18 h fits before
E1. New epochs follow with a fresh notice of at least 72 h. Interim
exchange rules stay in force.

### 3.2 At E1 (Sat 10-24 16:11 UTC), abort rule

| # | Check by E1 + 4 (epoch 6464) | Pass |
| --- | --- | --- |
| A1.1 | No upgraded node logs `StateRootMismatch` or `WS_CONFLICT` at or after 6460 | yes |
| A1.2 | Finality resumed: finalized epoch ≥ 6462 | yes |
| A1.3 | `getl2settlement` → `withdrawals.finalized_checkpoint.own_chain_rule_active = true` and `own_root == root`; claims resumed | yes |
| A1.4 | Finality set formed: its total equals the duty-roster stake at 6460 (± validators that did not upgrade) | yes |

If A1.1 or A1.2 fails **before OT**: halt own validators before 6466 (the
chain stalls, it does not fork again). Announce, and publish D1 with OT also
disarmed.

### 3.3 HF2/HF3 GO/NO-GO, Sat 10-24 17:47 UTC (epoch 6466)

| # | Criterion | Pass |
| --- | --- | --- |
| H2.1 | A1.1–A1.4 PASS, and OT (if armed) crossed 6466 with finality continuing | yes |
| H2.2 | Both exchanges confirmed in writing that their **wallet/signer** is upgraded and that they hold no pre-signed, unbroadcast BLCH transaction across E2 | both |
| H2.3 | The wallet/CLI in the release signs v2 (`Bound`) from E2 on its own. Shown on devnet in H1.2. | yes |
| H2.4 | No own node's mempool is refusing transactions from the exchanges' signers since the node upgrade. The node relay policy already refuses non-canonical encodings. | yes |

NO-GO: publish **D1** at once (HF2 and HF3 disarmed). The own rollout
(18 h) lands before 6550. HF2/HF3 get new epochs with ≥ 72 h notice. If
only H2.2 fails, D1 is still required. Do not activate a wallet-facing
fork without both exchanges confirming.

### 3.4 At E2 (Sun 10-25 16:11 UTC) and E3

| # | Check | Pass |
| --- | --- | --- |
| A2.1 | By 6554: no root mismatch, finalized ≥ 6552, attestations signed v2 and counted (participation not lower than before E2 by more than the non-upgraded share) | yes |
| A2.2 | Test transfer signed by the release CLI after E2 is included and finalized | yes |
| A2.3 | If A2.1 or A2.2 fails: **halt own validators at 6561** (before E3), announce, then hotfix | n/a |
| A3.1 | By 6566: no root mismatch, finality continuous. A test 0x0003-signed transfer is included, charged the SLH-DSA verify gas and finalized. | yes |

---

## 4. What happens to nodes that do not upgrade

**At E1 (6460).** CF writes the chain's own checkpoint roots into the L2
state, and FS adds the finality set to the committed finality state. The
first block of 6460 therefore has a different state root. A node on the old
binary (including `b4a21fb6`) **rejects it with `StateRootMismatch` and
stops following the chain**. It finalizes nothing after that point.

- A **validator** on the old binary disappears from the upgraded chain. On
  that chain it earns nothing and accrues inactivity penalties. In the
  frozen finality set its stake counts zero but stays in the denominator
  until the first finalized handoff after 90 epochs of absence (24 h)
  prunes it. While non-upgraded stake is in the set, it raises the bar
  everyone else must clear. **If it exceeded one third of the set, finality
  would halt.** That is why readiness needs 90%. Once it upgrades and its
  votes are included again, it rejoins the set at the next handoff.
- Old-binary validators may keep producing a minority branch. It **cannot
  finalize** (far below two thirds). Exchanges that credit only on
  finalized state of their own node are not exposed. A non-upgraded
  exchange node simply stops crediting and stops seeing withdrawals
  confirm.
- **Recovery:** install the release and restart. If the node only stopped,
  it continues from its last valid block. If it stored minority-branch
  blocks after E1, the new release refuses to replay them. Restore the data
  directory from a backup taken before E1, or bootstrap from a snapshot
  (`docs/SNAPSHOT-BOOTSTRAP.md`).

**At E2 (6550).** Only `Bound` (v2) signatures are valid in consensus.
Validators and wallets on the release switch on their own. A v1 signature
stops being valid, **including any pre-signed transaction that has not been
broadcast**: re-sign it with the upgraded wallet. Even before E2, upgraded
nodes refuse non-canonical encodings (headerless, padded Falcon) at the
mempool door, so old signer tooling should be upgraded together with the
node.

**At E3 (6562).** Suite 0x0003 (SLH-DSA-SHAKE-128s + Falcon-1024) becomes
valid, priced per suite. Nothing changes for existing keys or fees. A node
that somehow missed only this gate would split on the first 0x0003 use, but
any node not on the release has already stopped at E1.

**No rollback after a gate.** Once a block at or after a gate finalizes, the
remedy is a forward release, never the old binary. Before E1, going back to
`b4a21fb6` is safe.

---

## 5. Armed values (filled by the founder only)

The epochs in this file are **PLANNED**. The table below is the only place
armed values are recorded, copied from the signed release commit.

| Constant | Source today | PLANNED Plan A | PLANNED Plan B | **ARMED** (release commit) |
| --- | --- | --- | --- | --- |
| `NATIVE_CLAIM_FINALITY_ACTIVATION_EPOCH` | `u64::MAX` | 6460 | 6550 | `{{ARMED}}` |
| `NATIVE_FINALITY_SET_ACTIVATION_EPOCH` | `u64::MAX` | 6460 | 6550 | `{{ARMED}}` |
| `NATIVE_OWN_TARGET_ACTIVATION_EPOCH` | `u64::MAX` | 6466 or `u64::MAX` | 6556 or `u64::MAX` | `{{ARMED}}` |
| `SIG_CANONICAL_ACTIVATION_EPOCH` | `u64::MAX` | 6550 | 6640 | `{{ARMED}}` |
| `HF2_SLASHING_V2_EPOCH` | `u64::MAX` | 6550 | 6640 | `{{ARMED}}` |
| `NATIVE_GROWTH_CAP_ACTIVATION_EPOCH` | `u64::MAX` | 6550 or `u64::MAX` | 6640 or `u64::MAX` | `{{ARMED}}` |
| `crypto::NATIVE_SLHDSA_SUITE_ACTIVATION_EPOCH` | `u64::MAX` | 6562 | 6652 | `{{ARMED}}` |
| `params::NATIVE_SLHDSA_SUITE_ACTIVATION_EPOCH` | `u64::MAX` | 6562 | 6652 | `{{ARMED}}` |
| release commit / SHA-256 | | | | `{{COMMIT}}` / `{{SHA256}}` |
| D1 / D0 commits | | | | `{{D1}}` / `{{D0}}` |

The arming commit must also replace each `*_gate_is_inert` tripwire with a
pinning test that asserts O1–O7 on the literal values.

---

## Appendix A. GitHub release notes (draft)

> DRAFT. Do not publish until §3.0 has passed and every `{{…}}` holds an
> ARMED value from §5.

```markdown
# bloch-pos {{VERSION}}: mandatory upgrade, hard forks 1, 2 and 3

**Every node operator must upgrade by {{UPGRADE DEADLINE, e.g. Fri 2026-10-23 16:11 UTC}}.**
This release activates three consensus changes at fixed epochs. A node that
has not upgraded stops following the chain at epoch {{E1}}.

| Fork | Epoch | First slot | Expected time (UTC) |
| --- | --- | --- | --- |
| HF1: own-chain claim finality + frozen finality set | {{E1}} | {{32×E1}} | {{E1 UTC}} |
| HF1: own-chain target votes | {{OT, or "not in this release"}} | | |
| HF2: canonical signatures (v2) | {{E2}} | {{32×E2}} | {{E2 UTC}} |
| HF3: optional SLH-DSA signature suite 0x0003 | {{E3}} | {{32×E3}} | {{E3 UTC}} |

The epoch number is binding. Times assume 30 s slots and 32 slots per epoch.

## What changes

**HF1, epoch {{E1}}**
- An L2 withdrawal claim is valid only against a finalized checkpoint that
  is this chain's own. Claims pause for about 2 epochs after {{E1}}.
  Deposits and settlements are unaffected.
- Finality is measured against a frozen finality set, which the inactivity
  leak cannot shrink. In a network split, at most one side can finalize.
  The set is updated only by finalized handoffs. Validators absent for 90
  epochs leave it at the next handoff and rejoin automatically once their
  votes are included again.
- {{If OT armed:}} From epoch {{OT}}, finality counts only votes whose
  source and target are this chain's own checkpoints.

**HF2, epoch {{E2}}**
- Consensus accepts only canonical (v2, suite-bound) signatures. Upgraded
  validators and wallets switch on their own. **Pre-signed transactions
  that have not been broadcast before {{E2}} become invalid. Re-sign them
  with this release.**
- Nodes apply a stricter, cheaper admission check to slashing evidence
  (relay policy, no consensus effect).
- {{If armed: activation of new funded validators is rate-limited per window.}}

**HF3, epoch {{E3}}**
- Optional signature suite 0x0003 (SLH-DSA-SHAKE-128s + Falcon-1024)
  becomes valid and is charged its own verification gas. Existing keys and
  fees do not change.

**Node-only (active on install):** signer hardening (per-key lock and
rollback guard), new RPC `getfinalitycertificate`, equivocation watcher.
Mempools refuse non-canonical signature encodings.

Nothing changes before {{E1}}. This release produces the same blocks and
state roots as the current one and replays the full history unchanged.

## Verify

    minisign -Vm SHA256SUMS -p bloch-release-20260922.pub   # key id 1A5D96A5C4955EF7
    sha256sum --check SHA256SUMS

Commit `{{COMMIT}}`. Linux x86-64 SHA-256 `{{SHA256}}`.

## Not upgrading

At {{E1}} an old node rejects the first block (`StateRootMismatch`) and
stops. An old validator stops earning, accrues inactivity penalties, and is
pruned from the finality set after 90 epochs. To recover, install this
release. If the node stored blocks after {{E1}}, restore a pre-{{E1}}
backup or a snapshot.

## Go / no-go

GO requires at least 90% of active stake on this release at
{{T−24 h}}. Otherwise a signed replacement release moves or disarms the
gates and must be installed before {{E1}}. Status is posted after every
gate on {{CHANNEL}}.
```

## Appendix B. Telegram notice (draft)

```text
MANDATORY UPGRADE: Bloch L1 hard forks 1-3

Release: bloch-pos {{VERSION}} ({{COMMIT short}}), signed, SHA-256 {{SHA256 short}}
Download and verify: {{RELEASE URL}}

Upgrade deadline: {{Fri 2026-10-23 16:11 UTC}}

Activation (epoch number is binding):
- HF1 epoch {{E1}} ≈ {{Sat 2026-10-24 16:11 UTC}}: own-chain claim finality + frozen finality set
- HF2 epoch {{E2}} ≈ {{Sun 2026-10-25 16:11 UTC}}: canonical v2 signatures (re-sign any unbroadcast transaction)
- HF3 epoch {{E3}} ≈ {{Sun 2026-10-25 19:23 UTC}}: optional SLH-DSA suite 0x0003

Nodes that do not upgrade stop following the chain at epoch {{E1}}.
Validators: never run one key on two hosts.
Exchanges: pause BLCH deposits/withdrawals from epoch {{E1−2}} and {{E2−2}} until our all-clear.

Only trust hashes from the signed release page, never from chat.
Reply with your node version to {{CONTACT}} so we count you in the readiness check.
```

## Appendix C. Exchange email (draft, Coinstore and P2B)

```text
Subject: Bloch (BLCH) mandatory node upgrade: hard forks at epochs {{E1}}, {{E2}}, {{E3}} ({{Sat 24 / Sun 25 Oct 2026}})

Dear {{Coinstore | P2B}} listing and wallet team,

Bloch L1 activates three consensus upgrades this weekend. Your BLCH node
and your BLCH signing tooling must both be upgraded.

1. Release
   bloch-pos {{VERSION}}, commit {{COMMIT}}, Linux x86-64 SHA-256 {{SHA256}}.
   Signed with our release key (minisign, key id 1A5D96A5C4955EF7).
   Download: {{RELEASE URL}}. Please verify the signature, not just this email.

2. Deadlines
   - Node upgraded by {{Fri 2026-10-23 16:11 UTC}}.
   - Wallet/signer upgraded by {{Sat 2026-10-24 16:11 UTC}}.

3. Activation epochs (the epoch number is binding; times are estimates)
   - HF1 epoch {{E1}}, about {{Sat 2026-10-24 16:11 UTC}}
   - HF2 epoch {{E2}}, about {{Sun 2026-10-25 16:11 UTC}}
   - HF3 epoch {{E3}}, about {{Sun 2026-10-25 19:23 UTC}}

4. What we ask you to do
   a. Pause BLCH deposits and withdrawals from epoch {{E1−2}}
      (about {{Sat 15:39 UTC}}) until our HF1 all-clear (expected within 3 hours),
      and again from epoch {{E2−2}} (about {{Sun 15:39 UTC}}) until the
      HF2/HF3 all-clear (expected about {{Sun 20:30 UTC}}).
   b. Do not hold pre-signed, unbroadcast BLCH withdrawals across epoch {{E2}}.
      From {{E2}} on, only signatures from the upgraded wallet are valid.
      Re-sign anything pending.
   c. Keep crediting deposits only once they are finalized on your own node.
   d. Reply to this email to confirm (i) your node is upgraded, with the output
      of `bloch-pos --version`, and (ii) your signer is upgraded. We count these
      confirmations in our go/no-go decision.

5. If a node is not upgraded
   It stops following the chain at epoch {{E1}}: deposits stop being credited
   and withdrawals stop confirming. No funds are at risk if you credit only
   finalized deposits. To recover, install the release and restart.

6. If we postpone
   We publish a signed replacement release and new epochs at least 72 hours
   ahead, and we email you directly.

Contacts: {{OPERATOR CONTACT}} (coordination), {{SECURITY CONTACT}} (private).

Best regards,
{{NAME}}, Bloch
```
