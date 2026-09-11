<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Flag day — the ADR-041 validator lifecycle (epoch **L**)

```
LIFECYCLE_EPOCH = unarmed
```

That line is machine-read. `scripts/arm-lifecycle-epoch.py --write` flips it
to the number in the same edit that sets the five constants, `--verify`
holds it to `params.rs` on every push, and `scripts/lifecycle-fleet-verify.sh`
reads it as the value every node must report. While it says `unarmed`, no
binary built from this tree admits a funded validator, accepts an
authenticated exit, pays a withdrawal, applies slashing evidence or renews a
RANDAO chain — and the legacy unauthenticated `Exit` (0x03) still applies.

Sibling of `deploy/FLAG-DAY-EPOCH-2700.md` and `docs/LEAK-RECOVERY-FLAG-DAY.md`,
under the same rule: **the constant, the tripwire and this file land in the
SAME commit.** Authority for every claim below is a file or a constant, not
this document — if a citation and the source disagree, the source wins and
this runbook is stale.

Written 2026-09-11 against `main` = `4eec48b`, the tree after PR #11
(`21a9311`, "implement unarmed validator lifecycle and state-aware
admission"). Wall clock at writing: epoch ≈ 2536.

---

## 0. Where "launching new validators" actually stands

"New validators" means public admission by `FundedDeposit` (0x0B). ADR-041's
activation plan has four steps; the honest map against `4eec48b`:

| ADR-041 step | State | Evidence |
|---|---|---|
| 1. Land the lifecycle inert on `main` | **DONE** | PR #11: `0x0A/0x0C/0x0D` decode, registry rows Released, `0x07–0x09` tombstoned (`tests/wire_tag_registry.rs:199-329`); `Withdraw` arm keyed on funded-vs-genesis backedness (`transition/lifecycle.rs`); compile-time arming-order asserts (`params.rs:1999-2006`); node-side `report_equivocation` (`engine/validator_lifecycle.rs:91`); state-aware mempool admission with head-change revalidation (`validate_lifecycle_admission`, `revalidate_lifecycle_mempool`); finality-gated activation (`activate_finalized_deposits`: `deposit_epoch < finalized`); offline `validator-lifecycle exit/withdraw` and `validator-deposit sign --genesis` bound to a trusted manifest. |
| 2. Rehearse | **PARTLY DONE** | Engine-level: `funded_validator_two_nodes_rehearsal` drives deposit → finalized → activate → attest/propose → `ExitV2` → 2,048-epoch lock → `Withdraw` → `TransferV2` spend of the payout by the credential holder, on two `Engine`s, in CI (`scripts/rehearse-validator-admission.py`). Guard mutations: `scripts/check-validator-lifecycle-mutations.py` asserts eight of eight withdrawal-guard deletions kill a test — **but no workflow ran it until this commit** (§3.2), so that verdict was nobody's until now. **NOT DONE:** the multi-process, real-transport qualification the admission review calls VAD-04 (§3.3), and a devnet soak across ≥ 3 epoch boundaries with a slashing prosecution and a post-slash withdrawal in the body. |
| 3. Founder signs L; one reproducible release; fleet rebuild audited node by node | **NOT DONE** | This runbook, `scripts/arm-lifecycle-epoch.py`, `scripts/lifecycle-fleet-verify.sh`. All five constants are `u64::MAX` (`params.rs:1345,1425,1517,1826,1971`). |
| 4. Announce external-validator opening | **NOT DONE — and gated on wall-clock time, not on code** | ADR-041 opens admission to the public only "after L is past and one full withdrawal has settled on mainnet". `WITHDRAWAL_DELAY_EPOCHS = 2,048` ≈ **22.8 days** after the first exit (§8). |

Of the six findings in `docs/audit/VALIDATOR-ADMISSION-REVIEW-2026-09-08.md`,
VAD-01/02/03/06 are closed by PR #11 as listed above; VAD-05 (20-byte padded
outputs cannot fund a deposit — migrate to a native suite-1 output first) is
an onboarding rule, restated in §8; **VAD-04 is the one still open** and is
this runbook's §3.3.

So what is left is not code on the consensus path. It is: one qualification
harness that does not exist yet, one number the founder has not signed, one
commit with a measured list of tripwires to retire, one release cut, one
64-node rollout, and then ≈ 23 days of wall clock before the sentence "open
to the public" is true. Each is below.

---

## 1. What activates at L

| constant (`crates/bloch-pos-committee/src/params.rs`) | today | at L | effect from epoch L |
|---|---|---|---|
| `FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH` | `u64::MAX` | L | `FundedDeposit` (0x0B) consensus-valid: spends real eUTXOs, dual role-separated ML-DSA-65 ‖ Falcon-1024 authorizations, names the withdrawal script. Legacy `Exit` (0x03) refused. |
| `EXIT_AUTH_ACTIVATION_EPOCH` | `u64::MAX` | L | `ExitV2` (0x0C) consensus-valid: signed by the registered key over `DS_EXIT ‖ pubkey_hash ‖ epoch`, signed epoch == inclusion epoch, `MAX_EXITS_PER_EPOCH = 4`. |
| `WITHDRAWAL_ACTIVATION_EPOCH` | `u64::MAX` | L | `Withdraw { validator }` (0x0D), unsigned crank, pays `staked_sat − unbacked principal` to the registered 32-byte credential; genesis bonds write off 25,000 BLCH each (founder's ruling, ADR-041 D4). |
| `SLASHING_EVIDENCE_ACTIVATION_EPOCH` | `u64::MAX` | L | Tag-0x05 evidence consensus-valid; a node that observes an equivocation submits it (`report_equivocation`). |
| `RANDAO_RECOMMIT_ACTIVATION_EPOCH` | `u64::MAX` | L | `RandaoRecommit` (0x0A) consensus-valid; the node renews its own chain automatically (`randao_automatic_recommit_rehearsal`). Rider — severable, but its deadline is real: first chains exhaust ≈ 2027-02-11. |
| `DEPOSIT_ACTIVATION_EPOCH` | `u64::MAX` | **`u64::MAX`** | Never moves. The unfunded legacy `Deposit`/`Delegate` era does not reopen (`docs/DEPOSIT-ACTIVATION-GATE.md` §5); the const-assert block refuses a build in which it does. |

The five arm together or not at all: `params.rs:1999-2006` is a `const _: ()`
block that fails compilation if any two differ, if `DEPOSIT` leaves
`u64::MAX`, or if `CORRELATION_WINDOW_EPOCHS < 2 × WITHDRAWAL_DELAY_EPOCHS`.
Every gate reads the block's own committed epoch as rolled by
`compute_post_state`, never a wall clock — the 2026-08-08 lesson, pinned by
the `*_is_a_function_of_the_block_epoch_alone` tests.

Below L every arm is byte-identical to what the fleet runs today, so the
rollout can be spread over days: a node on the new binary and a node on the
old one agree on every block until L. At L they do not. **A partial rebuild
forks the fleet at L**, exactly as at 2700.

---

## 2. Choosing L — the arithmetic

One epoch is `SLOTS_PER_EPOCH × slot_ms` = 32 × 30 s = **16 minutes**; 90
epochs per day. Epoch time is a pure function of the manifest clock
(`genesis_time_ms = 1786656679962`, i.e. 2026-08-13 21:31:19 UTC):

```
epoch_start_utc(E) = 2026-08-13T21:31:19.962Z + E × 16 min
```

`scripts/arm-lifecycle-epoch.py --epoch E` prints this and the lead from the
wall clock, reading both numbers from `genesis/mainnet.manifest`, so nobody
hand-computes a date. Reference points, computed 2026-09-11 (wall clock ≈
epoch 2536):

| E | begins (UTC) | lead from 2536 |
|---|---|---|
| 2700 | 2026-09-12 21:31 | `LEAK_RECOVERY` flag day — **L must be after this rollout is complete and confirmed** |
| 3240 | 2026-09-18 21:31 | 7.8 days |
| 3400 | 2026-09-20 16:11 | 9.6 days (the epoch the tripwire measurement in §4.2 used) |
| 3600 | 2026-09-22 21:31 | 11.8 days |
| 4000 | 2026-09-27 08:11 | 16.3 days |
| 4500 | 2026-10-02 21:31 | 21.8 days |

Constraints, in order of hardness:

1. **Strictly in the future at tag time.** An epoch already past arms
   silently against the whole history (`the_replay_compatibility_gates_are_inert_until_armed`'s
   own wording). The tool refuses it.
2. **After the rollout completes, with margin.** The 2700 flag day was armed
   ≈ 625 epochs ahead (≈ 6 days), 3× the demonstrated 64-validator rollout
   time; the tool's default minimum lead is 540 epochs and a shorter lead
   must be passed explicitly (`--min-lead-epochs`), which is the founder's
   call to make in writing, not the tool's to assume.
3. **After the 2700 rollout is confirmed on every node** (§3.4) — two
   rebuilds in flight at once is the failure mode ADR-041 D5 chose one
   flag day to avoid.
4. **Before the first RANDAO chain exhausts** (≈ 2027-02-11) if the rider
   stays, and well before the 2027-08-13 cohort-taper deadline.

The number itself is the founder's (ADR-041, decision 1: "fixed at release
cut, not in this document"). This runbook records it in the line at the top
once `--write` runs; nothing here proposes one.

---

## 3. Gates that must be green before `--write`

### 3.1 Tree

- `main` at or after `21a9311` (PR #11 merged).
- `cargo +1.94.1 test --locked -p bloch-pos-committee -p bloch-pos-node` green.
- `bash scripts/hardened-clippy.sh` green.
- `python3 scripts/rehearse-validator-admission.py` (default), `--audit-mempool`
  and `--randao-only` all green.
- `python3 scripts/check-validator-lifecycle-mutations.py`: eight of eight
  mutations killed, shipping source unchanged.
- `python3 scripts/arm-lifecycle-epoch.py --verify` green (unarmed).

### 3.2 CI

This commit adds the `lifecycle-flag-day-guards` job to
`.github/workflows/tests.yml`: the arming tool's selftest, `--verify`, and the
mutation run. Before it, the mutation guard existed and nothing executed it
— a withdrawal guard could have been weakened with every pipeline green.
Confirm the job is green on the branch that will ship.

### 3.3 VAD-04 — multi-process qualification (**not built; do not skip**)

The rehearsal that exists hands envelopes between two `Engine` values in one
process. The admission review requires, before release, the same lifecycle
across **separate processes and data directories over the real transport**,
covering at least:

- late joining after registrations (a node that syncs the deposit from
  history, not from gossip);
- restart of the joining node after several RANDAO reveals (the signing
  journal and slashing-protection watermark survive);
- reordered registrations on competing branches, then convergence;
- a partition longer than `ACTIVATION_DELAY_EPOCHS` (8 epochs) and finality
  recovery — `scripts/devnet-particao.sh` is the harness shape to extend;
- pending authentication after registry growth (a queued deposit whose
  registry index shifts);
- load from many independently keyed candidates, above the per-source
  mempool quota;
- ≥ 3 epoch boundaries with a slashing prosecution and a post-slash
  withdrawal in the body (ADR-041 T-6/T-8 in a live mesh).

The devnet genesis (`bloch-pos genesis`) carries no allocations, so a
funded deposit on a devnet needs coins: either a devnet manifest with
`allocations`, or an in-process fixture handing the joining node a spendable
output — the harness has to solve that before anything else. Build it on a
disposable copy armed at `L = 0` the way `rehearse-validator-admission.py`
does; never on the shipping tree. Its verdict goes into the release notes.
Until it exists and passes, **step 2 of ADR-041 is open and `--write` is
premature.**

### 3.4 Fleet

- Every one of the 64 validators past epoch 2700 on the leak-recovery
  binary, keystore sealed (`BPOSKEY2`), confirmed by the `deploy/RELEASE-INTEGRITY.md`
  §4 sweep (running-image sha256, not unit files) — the 2700 runbook's own
  exit criteria, met.
- `deploy/FLEET-INVENTORY.md` filled in: the sweep in §6 takes that
  inventory as input and a stale one is how two validators were skipped at
  epoch 800.
- Two independently operated nodes agreeing on `finalized.epoch` and
  `finalized.root` (`getchaininfo`) for at least a day before the arming
  commit is cut.

### 3.5 Founder decision record

ADR-041 is ACCEPTED with five rulings recorded 2026-09-08. The arming commit
must cite, in its message, the founder's written choice of **L** (the one
decision the ADR left open) and re-cite the write-off (D4: ≈ 1.6M BLCH of the
founder's own never-issued principal). No default is supplied here.

---

## 4. The arming commit — the ceremony, on the release engineer's workstation

Four commands, one commit. Nothing here touches a node.

### 4.1 Plan

```sh
python3 scripts/arm-lifecycle-epoch.py --epoch <L>
```

Prints the UTC start of L, the lead in epochs and days, the five edits, and
refuses (exit 1) an epoch that is past or has less lead than 540 epochs.

### 4.2 Measure the tripwires

```sh
python3 scripts/arm-lifecycle-epoch.py --rehearse --epoch <L>
```

Copies the tree (`git ls-files`) to a temporary directory, arms the copy,
compiles it (the const-assert block must accept it), runs the gate-related
test filters of both live crates and `scripts/check-comment-constants.py`,
prints every test and comment that goes red, and deletes the copy. The
checkout is never modified. It builds into `target/lifecycle-arming-rehearsal`
and there is no switch to share the shipping `target/`: on 2026-09-11 a
measurement that shared it left an armed committee rlib behind, and the
shipping tree's next `cargo test -p bloch-pos-node` linked against it and
reported the flag day armed on an unarmed checkout. A cold build is the
price of a verdict you can trust; `cargo clean -p bloch-pos-committee` is
the cure if anyone ever repeats that mistake. **Run this on the day, at the real L; the list
below is what it measured on 2026-09-11 at `4eec48b` with L = 3400, and it
rots the moment a test is added.**

Measured: **13 tests and 11 comment sites** flip meaning at L.

| goes red at L | what it guarded | what it becomes (epoch-2700 precedent: `leak_recovery_armed_epoch_matches_the_runbook`) |
|---|---|---|
| `transition::tests::exit_auth_gate_is_inert` | the constant is `u64::MAX` | one `lifecycle_armed_epoch_matches_the_runbook` asserting all five `== L` — a tripwire against a SECOND silent change |
| `transition::tests::slashing_evidence_gate_is_inert` | same | same test |
| `transition::tests::randao_recommit_gate_is_inert` | same | same test |
| `transition::tests::withdrawal_gate_is_inert` | same | same test |
| `transition::tests::the_evidence_gate_is_a_function_of_the_block_epoch_alone` | closed at 0, 1, 1766, 2700, 100 000, `MAX−1` | keep the shape: closed below L, open at L and above; `u64::MAX` is the sentinel, not an epoch |
| `transition::tests::the_withdrawal_gate_is_a_function_of_the_block_epoch_alone` | same | same |
| `transition::tests::funded_admission::funded_gate_is_closed_even_at_maximum_epoch_and_legacy_stays_closed` | `funded_validator_admission_active(u64::MAX)` false | closed below L, open at ≥ L; the "legacy stays closed" half is unchanged and must stay |
| `slashing_backed_finality_claims::evidence_decodes_and_only_the_inert_flag_day_stands_in_the_way` | `!penalty_appliable()` | the file's own instruction: "update the text first, then this file" |
| `slashing_backed_finality_claims::the_activation_constant_exists_in_one_place_and_is_not_armed` | `== u64::MAX`, one declaration | keep the one-declaration scan; the value pin becomes `== L` |
| `slashing_backed_finality_claims::observed_evidence_is_submitted_with_an_explicit_gated_outcome` | the observation hook exists AND the constant is `u64::MAX` | keep the hook assertions; drop the pin |
| `slashing_backed_finality_claims::the_retraction_is_published_wherever_the_promise_was` | 13 `RETRACTION_SITES` say slashing cannot be applied | **prose sweep**: each site (`rpc.rs`, `engine.rs`, `slashing.rs`, the committee `Cargo.toml`, two integration docs, the explorer `G4Block.tsx`, `docs/site/COPY.md`, `BLOCH-RPC-V4.md`, `SECURITY_TOOLING.md`, the CertiK dossier, `ED2-CONSENSUS.md`, the PMO plan) is rewritten to say what is true from L, and the test's site list follows |
| `slashing_backed_finality_claims::no_text_promises_a_slashing_backed_finality` | `PROMISE_PATTERNS` absent everywhere | stays; the rewritten sites must not use those phrases either — describe the mechanism, do not promise the guarantee |
| `engine::validator_admission_tests::funded_mempool_gate_source_outpoints_and_budget_are_wired` | `"activation_epoch":null` | `"activation_epoch":<L>`; the `active:false` half holds for a wall epoch below L |
| comments `transition.rs:465, 492, 3061, 3084, 3169, 3312, 3321, 3539`; `engine.rs:5916, 5936, 6685` | "`X_ACTIVATION_EPOCH` is `u64::MAX` today" | state the armed value; `check-comment-constants.py` is the judge |

Also by hand, not flagged by any guard: the `params.rs` module header
(`params.rs:14-19`) lists which constants are still `u64::MAX`; the doc blocks
above each of the five constants; the "This PR does not activate…" paragraph
of `docs/specs/BLOCH-FUNDED-VALIDATOR-ADMISSION.md` §Release boundaries; and
ADR-041's status line, which says the sentence "not for public funds" is
discharged by the ADR being LIVE.

Do not delete a test without replacing what it guarded. Do not weaken a
gate to make a test pass. Do not add `prose-guard: allow` to silence a
comment that is simply wrong now.

### 4.3 Write

```sh
python3 scripts/arm-lifecycle-epoch.py --write --epoch <L>
```

Edits exactly two files: the five constants in `params.rs` and the
`LIFECYCLE_EPOCH` line at the top of this runbook. Refuses a tree that is
already armed (a second change of the epoch is a new flag day with its own
runbook), a past epoch, a short lead, or a `DEPOSIT` off `u64::MAX`.

### 4.4 Retire the tripwires

Work the §4.2 list. Then, and only then:

```sh
python3 scripts/arm-lifecycle-epoch.py --verify --epoch <L>
cargo +1.94.1 test --locked -p bloch-pos-committee -p bloch-pos-node
python3 scripts/rehearse-validator-admission.py
python3 scripts/rehearse-validator-admission.py --audit-mempool
python3 scripts/rehearse-validator-admission.py --randao-only
python3 scripts/check-validator-lifecycle-mutations.py
bash scripts/hardened-clippy.sh
python3 scripts/check-comment-constants.py
bash scripts/ci-banned-words.sh
```

`--verify` fails on: constants differing, `DEPOSIT` moved, runbook line ≠
constant, any `*_gate_is_inert` of the four or the node's
`the_activation_constant_exists_in_one_place_and_is_not_armed` still present,
or a stale comment naming a lifecycle constant. The rehearsal script accepts
an armed tree (it sets the copy to epoch 0 whatever the tree says), so CI
keeps rehearsing after the flag day.

### 4.5 Commit

One commit. Its message names L, the UTC start, the lead, the founder's
decision record, and the count of tripwires retired. The constant, the
tripwire tests and this file move together — a reviewer who sees the
constant change without this file's line is looking at a defective commit.

---

## 5. Release cut

`deploy/RELEASE-INTEGRITY.md` §7, verbatim, plus the minor-version bump
(`docs/releases/RELEASE_PROCESS.md`: a deliberate consensus change bumps
minor):

1. Pipeline green, including `pos-release-integrity`, `lifecycle-flag-day-guards`
   and the hardened Clippy job.
2. Canonical container build at the release commit; record
   `(commit, stamp, sha256)`; a second builder on a different machine rebuilds
   and the sha256 matches bit for bit.
3. Publish binary + `SHA256SUMS` + signature. The published bytes are the
   bytes from step 2, never a box's local build.
4. Rollback package from the previous release (the 2700 binary), signed,
   staged per §5.2 of that document, exercised on a scratch host.
5. Release notes carry: L and its UTC time, the §4.2 measured list as
   retired, the VAD-04 harness verdict (§3.3), and the §6 sweep tables.

`getbuildinfo` on the shipped binary must report the release commit and a
`tree_state` of clean — those two fields are what the fleet sweep compares.

---

## 6. Fleet rollout

The shape is the 2700 rollout (`deploy/FLAG-DAY-EPOCH-2700.md` § Sequencing)
minus the keystore migration, which is already done. What is different:
there is an RPC field that says whether a node carries L.

### 6.1 Per validator, in an order that never drops attesting weight below the finality threshold

Doppelgänger protection costs each restart **32 minutes** of duties (two
epochs of observation); never restart more than a third of the active weight
concurrently, counting the observing nodes as absent.

1. Stop the node.
2. Deploy the release binary through the unit drop-in (never `pkill`+`setsid`).
3. Start it. Confirm `getbuildinfo.commit` is the release commit and
   `getvalidatoradmission.activation_epoch` is L — on this node, before
   moving on.
4. Confirm the node reaches head and attests.

### 6.2 The sweep

```sh
scripts/lifecycle-fleet-verify.sh <inventory> [--epoch <L>] [--out sweep-$(date -u +%Y%m%dT%H%M).tsv]
```

Inventory: one node per line, `<opaque-label> http://…` for a tunnelled RPC
or `<opaque-label> ssh://user@host` to run `curl` on the host against
`127.0.0.1:16310` (RPC stays loopback-bound; the sweep does not change that).
For every node it reads `getbuildinfo`, `getvalidatoradmission` and
`getchaininfo`, and prints **READY** only if: every node answered; every
node reports `activation_epoch == L`; every node runs one commit and one
`source_digest`; and nodes agreeing on a finalized epoch agree on its root.
Anything else is NOT READY with the rows named.

`activation_epoch` is one field speaking for five constants, which holds
**because** the const-assert block makes them equal in any binary built from
this tree. A binary whose `params.rs` deleted that block could report L with
the other four unarmed — which is why the sweep also requires one commit and
one digest across the fleet, and why §6.3 hashes the running image.

Run it:

- after each batch of restarts;
- once the whole fleet is on the release — **every row READY**;
- again ≥ 24 h later (catches a box that restarted onto something else);
- one final time no later than **L − 90 epochs (one day)**. A NOT READY at
  that point is an abort (§10), not a reason to hurry.

### 6.3 Running-image audit

The sweep asks the process what it is; §4 of `deploy/RELEASE-INTEGRITY.md`
asks the kernel. Do both. Per host: `sha256sum /proc/$PID/exe` must equal
the published release sha256; a ` (deleted)` suffix on
`readlink /proc/$PID/exe` means the node runs old bytes. File the table in
the release notes.

---

## 7. Crossing L

Watch, on two independently operated nodes, from L − 2 through L + 8:

- `getchaininfo`: `finalized.epoch` non-decreasing and equal across the two;
  it must advance past L on both before the flag day is called complete.
  A persistent disagreement is a fork, and takes priority over everything
  else in this document.
- `getvalidatoradmission`: `active` becomes `true` at the first head in
  epoch L; `written_off_sat` stays 0 until the first genesis withdrawal.
- `getmempoolinfo`: no lifecycle transaction should be pending before L
  (the mempool refuses them below the wall epoch); after L, lifecycle
  entries are re-validated on every head change and drop out on their own
  if state no longer supports them.
- Logs: no `StakingNotActive` refusals of a legacy `Exit` should appear
  either side of L — nothing in the fleet's tooling sends 0x03 any more; one
  appearing means someone is running an old signer.
- RANDAO: no chain is near exhaustion at L, so no `RandaoRecommit` is
  expected; one appearing is a node with a short chain, worth a look.

---

## 8. After L — the first lifecycle on mainnet, and when "open" becomes true

ADR-041 step 4: external opening is announced only after **one full
withdrawal has settled on mainnet**. That is a wall-clock sequence, and it is
the single longest item between today and a public launch:

| event | epoch | wall clock after L |
|---|---|---|
| First `FundedDeposit` included (a founder-operated candidate with real coins, spent from a **native suite-1 32-byte output** — a carried 20-byte padded output cannot fund a deposit, VAD-05; migrate the coins with a verified transfer first) | D ≥ L | minutes |
| Deposit's epoch finalized (`deposit_epoch < finalized`) and `ACTIVATION_DELAY_EPOCHS = 8` elapsed; queue cap 4 per epoch | ≥ D + 8 | ≥ 2 h 08 min, plus the finality lag |
| Candidate proposes and attests (first funded validator on mainnet) | next selection | hours |
| `ExitV2` included (offline: `bloch-pos validator-lifecycle exit --dir … --epoch <inclusion epoch>`; the signed epoch must equal the inclusion epoch, so sign close to submission) | X | — |
| Duties stop | X + `EXIT_DELAY_EPOCHS` = X + 32 | 8.5 h |
| Withdrawable | X + `WITHDRAWAL_DELAY_EPOCHS` = X + 2 048 | **22.8 days** |
| `Withdraw` cranked (each node auto-cranks its own; anyone may) — payout eUTXO exists, `written_off_sat` unchanged for a funded bond | ≥ X + 2 048 | — |
| Credential holder spends the payout with `TransferV2` | next block | — |
| **Announcement of external opening** (ADR-041 step 4) | after the above | **≥ L + ≈ 23 days**, if the exit follows activation immediately |

If the founder wants the announcement earlier, that is a change to ADR-041's
activation plan and needs its own decision — the number here is the ADR as
written. A genesis validator's withdrawal is not a substitute for this
sequence: it exercises the write-off path, not the funded one.

Onboarding text for external operators (the `docs/specs/BLOCH-FUNDED-VALIDATOR-ADMISSION.md`
§Operator workflow) is already accurate; the two additions it needs at
announcement time are the VAD-05 migration rule above and the fact that
`validator-deposit sign` now requires `--genesis <trusted manifest>` and
refuses a draft whose network domain does not match it.

---

## 9. Rollback

Same asymmetry as 2700. Before any node has produced or accepted a block at
or past L, rollback is: halt the rollout, redeploy the previous release
through the drop-in, re-sweep (expect `activation_epoch: null` everywhere),
and re-plan — the flag day has not happened and the chain has not changed.
Once a block at or past L exists under the new rules, a reverted node cannot
validate it and forks itself off; the only path forward is completing the
rebuild on every remaining node.

There is one more thing to preserve than at 2700: any `FundedDeposit` draft
signed against the release's expected L is bound to the genesis manifest and
an expiry epoch, not to L, so drafts survive a re-planned flag day; but a
signed `ExitV2` names its inclusion epoch and is dead the moment that epoch
passes.

---

## 10. Abort criteria

Do not arm, or hold the rollout and re-plan, if before L:

- the VAD-04 harness (§3.3) does not exist or does not pass;
- any of the §3.1 checks is red on the branch being rolled out, or
  `lifecycle-flag-day-guards` is red;
- `arm-lifecycle-epoch.py --rehearse` at the real L lists a tripwire that
  the arming commit did not retire (re-run it after §4.4; the list must be
  empty);
- fewer than 64 of 64 validators are READY in the §6.2 sweep with a day of
  margin before L;
- the 2700 rollout is not confirmed complete on every node;
- two independently operated nodes show a persistent `finalized` disagreement
  at any point — a fork in progress outranks the calendar;
- the release binary's `getbuildinfo` reports a dirty `tree_state` or a
  commit other than the tagged one on any node.

A missed L is a re-plan and a second lead time. A fleet forked at L, or a
bond admitted with no path out, is worse than any delay. When in doubt, do
not arm.

---

## 11. Roles

| role | does | holds |
|---|---|---|
| **Founder** | signs L in writing; reaffirms D4; owns the go/no-go at each abort criterion | the release signing key; the rollback signing key |
| **Release engineer** | §4 (arming commit), §5 (release cut) | a workstation with the pinned toolchain; no fleet keys |
| **Fleet operator(s)** | §6 rollout and sweeps, §7 watch | SSH to the hosts, read-only verify role (`deploy/SSH-ROLE-SEPARATION.md`); never the release key |
| **Second builder** | rebuilds the release commit on an unrelated machine; the sha256 must match | nothing else |
| **Second vantage** | runs the §6.2 sweep and the §7 watch from a node the fleet operator does not run | a read-only RPC path |

CI never holds fleet SSH keys; the sweep is manual or PMO-driven by design.

---

## 12. Not covered here — stated, not narrowed away

- **Delegation exit and withdrawal**: `Delegate` positions and the three
  reward ledgers still have no payout path (ADR-041 "what this does not
  solve"). Its own ADR.
- **Finality-aware exit clock**: activation now waits for a finalized
  deposit; the exit and withdrawal clocks still count epochs.
- **Network-bound exit signing** (`DS_EXIT2`): deferred to the
  `SIGHASH_NETWORK_BINDING` decision; a distinct validator key per network is
  the operator rule until then (the CLI says so).
- **Withdrawal-credential rotation**: the script named at deposit is final.
- **No independent cryptographic or consensus audit** of the combined
  lifecycle has occurred. The rehearsal evidence is internal, and this
  runbook does not change that.
- **`check-comment-constants.py` is red on `main` today** for three claims
  unrelated to the lifecycle (`kirpich/limits.rs:9`, `net.rs:505`,
  `p2p.rs:336`). `--verify` reports them as a note and judges only the
  lifecycle constants; that guard's own CI job is where they get fixed.
