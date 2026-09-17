# A3 — Consensus: staking, delegation, slashing, cohort cap, rewards, validator lifecycle

Auditor: A3. Date: 2026-09-16. Tree: `/home/user/bloch-sis-pow` working tree (main, post PR #19 lineage; `params.rs` lifecycle constants all `u64::MAX`, `LIFECYCLE_EPOCH = unarmed`). Read-only; no build/test run.

## 1. Scope & method

Read in full: `crates/bloch-pos-committee/src/{staking,delegation,slashing,genesis_cohort,rewards,tokenomics_v4}.rs`, `transition/funded.rs` (+tests), `transition/lifecycle.rs` (+tests), and in `transition.rs` (lines 1–6053 = production code): `PosTransaction` + codec, `CommittedState` fields and `compute_root`, `genesis`, `duty_roster_at`/`consensus_roster_at`, every gate predicate, `apply_transaction` (Deposit/Exit/ExitV2/RandaoRecommit/Delegate arms), `voluntary_exits_this_epoch`, `apply_exit_v2`, `apply_randao_recommit`, `apply_slashing_evidence`, `accounted_supply_sat`/`supply_conserved`, `close_epoch`, `with_leak_applied`, `compute_post_state`, `apply_block`, `process_epoch`. Node side: `validator_deposit.rs`, `validator_lifecycle.rs`, `engine/validator_lifecycle.rs`, `engine/validator_admission_tests.rs`, `tests/slashing_backed_finality_claims.rs`, plus `engine.rs` `on_transaction`, `select_transactions`, `propose`, `admissible`, `tx_source_hash`, `culprit_index`, and `genesis.rs` `state_anchored_at`/`check_bonds_are_funded`. Also `fee_market.rs` split helpers, `committees::is_supermajority`, `sample.rs` eligibility, `params.rs` gates + const-asserts, `scripts/check-validator-lifecycle-mutations.py`.

Prior material read for KNOWN/NEW labelling: VALIDATOR-ADMISSION-REVIEW-2026-09-08 (VAD-01..06), VAD-04-LIFECYCLE-SOAK-2026-09-11, ADR-037/038/041, BLOCH-FUNDED-VALIDATOR-ADMISSION, BLOCH-POS-STAKE-CHURN, BLOCH-POS-GAPS (GAP-3), deploy/FLAG-DAY-LIFECYCLE, SECURITY.md, groundstate_audit (Genesis-3, PoW; nothing in scope), tokenomics spec §3.3.1.

Method: adversarial walk of every registry/stake mutation path; for each claim in a code comment ("fixed", "closed", "inert") the callers/callees were read to verify. Arithmetic checked by hand at the boundaries (taper edges, cap truncation, `u64`/`u128` narrowing, saturating vs checked ops). Where a finding depends on a numeric consequence I show the computation.

GAP-3 status, VERIFIED: slashing is wired. `compute_post_state` step 10 routes `SlashingEvidence` to `apply_slashing_evidence` (transition.rs:5824–5842), which calls `SlashingState::process`/`process_proposer` with the registry as `KeyLookup` (both signatures re-verified against the *registered* key). It is gated by `SLASHING_EVIDENCE_ACTIVATION_EPOCH = u64::MAX` (params.rs:1425) via `epoch_gate_active` (MAX is a sentinel, never armed). Node-side `report_equivocation` (engine/validator_lifecycle.rs:91) constructs and submits evidence. GAP-3 is closed on the transition half and open only by the flag day — exactly as `slashing.rs`'s header and `slashing_backed_finality_claims.rs` say. The header sentence "Nothing constructs the transaction outside tests" is now stale (see ST-10).

Flag-day consistency, VERIFIED: the five constants are equal (`u64::MAX`) and the const-assert block (params.rs:1999–2006) pins equality, `DEPOSIT_ACTIVATION_EPOCH == u64::MAX`, and `CORRELATION_WINDOW_EPOCHS >= 2 * WITHDRAWAL_DELAY_EPOCHS`. `deploy/FLAG-DAY-LIFECYCLE.md` says `unarmed` and its §1 table matches the code, with one omission (ST-12).

---

## 2. Findings (ordered by severity)

### ST-01 — Genesis-cohort cap hands the *non-cohort* side a calendar-fixed consensus share regardless of its stake; a single 25,000 BLCH outsider reaches 1/3 (stall) at ~6 months and a 2/3 finality supermajority plus ~2/3 of all issuance at 12 months
- **Severity:** High
- **Status:** NEW (magnitude and the safety consequence). Related KNOWN: `genesis_cohort.rs` "Where this stops working" and tokenomics §3.3.1 acknowledge the cap cannot see beneficial ownership; ADR-037 item 3 lists "composition with the genesis-cohort cap" as open. Neither states that the *first* independent validator receives a finality supermajority.
- **Refs:** `genesis_cohort.rs:75–81` (`cohort_cap_bps`), `:111–127` (`cap_status`, `CAP_MEANINGFUL_AT_SAT = MIN_DEPOSIT_SAT`), `:175–193` (`cap = others*bps/(10_000-bps)`, pro-rata scale); `transition.rs:2483–2533` (`duty_roster_at` applies the cap last, before the leak); `close_epoch` step 2 (`transition.rs:4915–5000`) distributes issuance pro-rata over the *capped* `issuance_roster`; `committees.rs:550` (`is_supermajority`: `3*for >= 2*total`); `funded.rs:293–298` (deposit cap = `max(MIN_DEPOSIT, 1% of total_active)` where `total_active` is the capped effective total, `transition.rs:5803`).
- **Description.** The cap is `cohort_weight ≤ others × bps/(10000−bps)`, enforced as soon as non-cohort effective stake ≥ 25,000 BLCH (`CAP_MEANINGFUL_AT_SAT`). Once enforced, the non-cohort side's share of the capped total is exactly `1 − bps/10000` **whatever its absolute size**, because the cohort is scaled to a multiple of `others`. Consequences, computed:
  - Today (epoch ≈ 2,980; `cohort_cap_bps = 10000 − 6667·2980/32872 = 9396`): one funded validator with the minimum 25,000 BLCH makes `cap = 25,000 × 9396/604 ≈ 389,000 BLCH`; the 64-validator cohort (raw ≈ 1.6M + ~1 month of issuance ≈ 365M BLCH) is scaled to 389k. The newcomer holds 6.0% of consensus weight and 6.0% of issuance (≈ 265M BLCH/year on a 25k bond).
  - At month 6 (`bps ≈ 6667`): the newcomer alone holds ≥ 1/3 → can stall finality by not voting.
  - At month 12 and forever after (`bps = 3333`): `cap = 25,000 × 3333/6667 = 12,499`; total = 37,499; `3 × 25,000 = 75,000 ≥ 2 × 37,499 = 74,998` → **the single outsider is a finality supermajority by itself** (truncation of the cap rounds in its favour), draws ≈ 2/3 of proposer slots, and receives ≈ 2/3 of ≈ 3.9B BLCH/year issuance.
  - Because `total_active` fed to the deposit cap is the *capped* total (≈ 16× `others` today, 1.5× at the floor), the per-validator deposit cap stays at exactly `MIN_DEPOSIT` until independent stake is ~150k BLCH (today) / ~1.67M BLCH (year 1). So no outsider can bring more stake than 25k per validator, and the calendar-fixed independent share is split among independent validators **by count**, not by stake. The independent side is therefore a Sybil-count race, and the founder — who holds 93.9% of the carryover (tokenomics_v4.rs `LARGEST_CARRYOVER_ADDRESS_BLOCH`) — is best placed to win it (KNOWN direction), but any outsider who is first, or simply outnumbers others during the taper, gets a disproportionate share for a trivial bond.
- **Attack / failure scenario.** L is armed; external admission opens; the first N independent validators are one operator (25k BLCH each). During months 6–12 that operator can stall finality unilaterally; after month 12 it can finalize conflicting checkpoints alone (two branches, two 2/3 votes — slashing needs evidence *included* by a proposer, and the operator proposes ≈ 2/3 of slots), and captures ≈ 2/3 of issuance. The tokenomics spec's sentence "one third … was never what stopped anyone finalising a bad state, which needs 2/3 and is out of reach either way" (§3.3.1) is false under this cap: 2/3 is exactly what the cap hands to whoever is outside the cohort.
- **Evidence.**
  ```rust
  // genesis_cohort.rs:175-176
  let others = total - cohort_stake;
  let cap = others * bps / (10_000 - bps);
  // committees.rs:551
  total_active_stake > 0 && stake_for.saturating_mul(3) >= total_active_stake.saturating_mul(2)
  // transition.rs (close_epoch): issuance basis is the capped roster
  let total_stake: u128 = issuance_roster.iter().map(|v| v.effective_stake as u128).sum();
  ```
- **Recommendation.** Decouple "founder ≤ 1/3" from "outsiders ≥ 2/3": bound the cohort's *share* only when the non-cohort side is itself dispersed (e.g. require ≥ k independent validators or a minimum independent stake proportional to the cohort's raw stake before the cap moves past a safety threshold), or cap the cohort by share without scaling its weight below the non-cohort side's raw total; compute the deposit cap from the *uncapped* active stake so outsiders can bring real stake; and correct §3.3.1. At minimum, do not open external admission with the current formula. This is a founder-level design decision; it does not block the mixed-fleet safety of L but it does change what L opens.
- **Confidence:** High (arithmetic verified by hand at three epochs; code paths traced).

### ST-02 — Legacy unauthenticated `Exit` (0x03) is live and un-capped today: any single proposer can force-exit the entire roster in one block, killing the chain permanently at E+32
- **Severity:** High (permanent, unrecoverable network halt; precondition: one of the 64 hot validator keys, which `deploy/FLEET-INVENTORY.md` places on five servers, or one malicious operator)
- **Status:** KNOWN — VAD-01 ("admission flag day also disables unauthenticated legacy Exit … correct protection against another party forcing an exit"), `PosTransaction::Exit` docs ("a modified proposer can still put one in a block today"), `MAX_EXITS_PER_EPOCH` docs ("Enforced from EXIT_AUTH_ACTIVATION_EPOCH only — below the flag day the rule is written down and inert"). Reported here because it is the most severe *currently reachable* item in scope and the churn-cap absence compounds it.
- **Refs:** `transition.rs:3489–3520` (legacy `Exit` arm: gate check, then `rec.slashed || activation_epoch > epoch || exit_epoch != MAX`, no signature, no budget); `engine.rs:5844` (mempool refuses it — policy only); `sample.rs:75–77` (empty eligible set → no proposer); `close_epoch` step 5/6 accepts an empty `roster_next`.
- **Scenario.** A proposer builds a block whose body carries `Exit{v}` for v in 0..64. Every node applies it (mempool is bypassed by including it directly). At epoch E+32 `duty_roster_at` excludes all 64; `schedule::proposer` returns `None` for every slot; no block can ever be produced, so no `FundedDeposit` can ever be included: the chain is dead with no in-protocol recovery. Bonds are locked (no withdrawal path below L).
- **Evidence.**
  ```rust
  PosTransaction::Exit { validator } => {
      if Self::exit_auth_active(self.epoch) || crate::params::funded_validator_admission_active(self.epoch) {
          return Err(TxReject::StakingNotActive);
      }
      let Some(rec) = self.validators.get_mut(validator) else { return Err(TxReject::StakingRule) };
      if rec.slashed || rec.activation_epoch > self.epoch || rec.exit_epoch != u64::MAX { return Err(..) }
      let exit_epoch = self.epoch.saturating_add(staking::EXIT_DELAY_EPOCHS); // no MAX_EXITS_PER_EPOCH check
  ```
- **Recommendation.** Arming L closes it. Until then, consider an ungated *consensus* refusal of 0x03 is impossible without a flag day (mixed fleet), but a *node-local* defence is available now: refuse to *propose* (not validate) a body carrying 0x03, and alert on any block carrying it. Keep VAD-01's "do not accept public bonds" until L.
- **Confidence:** High.

### ST-03 — Correlated-slashing amplification mixes raw-bond penalties (numerator) with effective, capped/leaked stake (denominator): one slash of a cohort validator saturates the window, so the next unrelated offender within 4,096 epochs loses 100%
- **Severity:** Medium (post-L; precondition: slashing armed and the cohort cap enforced or a leak in progress — the expected steady state)
- **Status:** NEW
- **Refs:** `slashing.rs:349–357` (`penalty_bps = base + 3·10000·slashed_in_window/total_active_sat`), `:526–531` (window fed with `total_slashed_sat` in raw satoshis), `transition.rs:5803` (`total_active` = sum of `consensus_roster_at` effective stake, i.e. cohort-capped then leak-applied), `transition.rs:4294–4312` (`own_bond_sat = offender_rec.staked_sat`, raw).
- **Description.** The amplification is meant to price the *share of stake* already slashed. The numerator is raw satoshis burned from `staked_sat`; the denominator is the roster's *effective* stake after the cohort cap and the inactivity leak. With one independent validator today (ST-01 numbers): a cohort validator's raw bond ≈ 5.7M BLCH, 5% = 285k BLCH burned; `total_active` ≈ 414k BLCH → amplification = 3·10000·285k/414k ≈ 20,600 bps → `min(10_000)`. Every later offence in the 4,096-epoch (~45-day) window, by anyone, is priced at 100%. The same happens without the cohort cap during a long finality stall (the leak shrinks the denominator while bonds are unchanged).
- **Failure scenario.** An honest operator double-signs once after a restart (the class the slashing-protection fence exists for) six weeks after some unrelated slash and forfeits its whole bond, and its delegators' (when they exist) whole activated stake.
- **Recommendation.** Price the window against raw bonded stake (`Σ staked_sat` of the roster, or the unleaked, uncapped `duty_roster_at` sum), or feed the window with *effective* losses. Add a test with a capped cohort and a leaked roster.
- **Confidence:** High on the arithmetic; Medium on how often the precondition holds (it holds whenever the cap is enforced, which ST-01 shows is immediately upon the first independent deposit).

### ST-04 — Self-slashing is a faster, cap-free exit: ejection at E+1 bypasses `MAX_EXITS_PER_EPOCH`, withdrawability lands 32 epochs *earlier* than a voluntary exit, and a slash on a same-epoch exiter refunds the churn budget
- **Severity:** Medium (post-L; precondition: control of the keys being ejected; impact: the "empty the roster in one block" scenario `MAX_EXITS_PER_EPOCH` was written to prevent becomes available at ~12% cost, and a whole-roster ejection is an unrecoverable halt)
- **Status:** NEW (ADR-041 D5 describes the re-stamp `max(existing, slash+2048)` but not that it is shorter than a voluntary exit, nor the cap bypass)
- **Refs:** `transition.rs:4431–4443` (slash writes `exit_epoch = min(existing, E+1)`, `withdrawable = max(existing, E+2048)`), `transition.rs:3517` (legacy) / `3727–3729` (`apply_exit_v2`) (voluntary: `exit = E+32`, `withdrawable = E+32+2048`), `transition.rs:3626–3651` (`voluntary_exits_this_epoch` counts `exit_epoch == E+32` only), `slashing.rs:349–357` (amplification), `lifecycle.rs:497–539` (`withdrawal_plan` accepts any exited record at `withdrawable_epoch`).
- **Description.** A validator that signs two conflicting attestations and has any proposer include the pair is ejected at E+1 (vs E+32), becomes withdrawable at E+2048 (vs E+2080), and never touches the 4-per-epoch budget. 64 self-slashes in one block cost ≈ 5%…20% each (window grows by 1,250 BLCH per slash on 25k bonds; 3·10000·k·1250/1.6M ≈ 23k bps) — ≈ 12% on average — and empty the roster at the next boundary (ST-02's outcome) with no visibility window. Additionally, if validator A exits at E (budget 1/4) and is then slashed at E, `exit_epoch` is overwritten to E+1 and `voluntary_exits_this_epoch()` drops back to 0, freeing a budget slot.
- **Recommendation.** Make the slashed path *never* shorter than the voluntary one: `withdrawable = max(existing, E + EXIT_DELAY + WITHDRAWAL_DELAY)` (Ethereum uses a longer lock for slashed validators), keep the E+1 ejection (R1 M7 needs it) but count ejections toward a separate, also-bounded churn, or refuse evidence inclusion beyond a per-epoch ejection budget with the excess deferred to the next epoch (Ethereum defers via the exit queue). Add a test comparing the two timelines.
- **Confidence:** High.

### ST-05 — Post-L, unauthenticated lifecycle transactions cost the node 1–4 hybrid verifications each before any per-source accounting; `tx_source_hash` returns `None` for ExitV2/Withdraw/Recommit/Evidence, and a `FundedDeposit`'s "source" is a free-to-mint key
- **Severity:** Medium (post-L; single-node CPU DoS by an unauthenticated peer through gossip/RPC; transport-level rate limits are outside this scope and may mitigate — flagged for the network auditor)
- **Status:** NEW (VAD-03 was about *funding* validity, now closed; this is about verification cost ordering and quota coverage)
- **Refs:** `engine.rs:5561–5570` (`admissible` FundedDeposit: `verify_authorizations` = 2 verifies, before any state check), `engine/validator_lifecycle.rs:36–48` (`validate_lifecycle_admission` → `validate_funded_deposit`, which ends with `verify_authorizations` again = 2 more), `lifecycle.rs:584–596` (evidence: `self.clone()` + `apply_slashing_evidence` = up to 2 verifies; ExitV2: clone + 1 verify after cheap checks), `engine.rs:514–528` (`tx_source_hash` → `None` for every lifecycle variant except FundedDeposit, whose source is `funding_pubkey`, chosen by the sender).
- **Description.** A peer can send ExitV2 messages naming a real active validator's `pubkey_hash`, the current epoch and garbage signatures: each passes epoch/identity/lifecycle/budget checks and costs one hybrid verify (~150 µs) with no per-source cap. Attestation-pair evidence with distinct data and garbage signatures passes `offense()`/replay/ejection and costs one verify plus a state clone and `Registry::resolve`. A FundedDeposit with a fresh funding key per message costs 2 verifies at the door (and a valid one costs 4 in total — the second `verify_authorizations` in `validate_funded_deposit` is redundant after `admissible`).
- **Recommendation.** Skip the second verification in `validate_funded_deposit` when called from the door (or memoize by txid); key per-source quotas for ExitV2/Recommit/evidence on the named validator (`pubkey_hash`/index) and refuse more than one pending per validator; rate-limit evidence per (offender, epoch); defer to the network auditor for transport limits.
- **Confidence:** Medium-High (code paths verified; absolute cost figures from the repo's own ~145 µs estimate).

### ST-06 — `close_epoch` mints delegator issuance shares into the ledger without advancing `issued_sat`; the supply-conservation rule would then refuse every boundary block (latent; unreachable while `DEPOSIT_ACTIVATION_EPOCH == u64::MAX`)
- **Severity:** Low (latent; double-gated: `REWARDS_V2_ACTIVATION_EPOCH` must be armed *and* a `Delegate` must have applied, which the const-assert forbids forever; if a future delegation ADR reopens it, the effect is a deterministic chain halt, i.e. the invariant firing correctly on a real undercount)
- **Status:** NEW
- **Refs:** `transition.rs` `close_epoch` step 2: `issued_sat += payout.operator` and `+= dust` only; `delegator_issuance_rewards[d] += reward` has no matching `issued_sat` increment; `accounted_supply_sat` term 7 counts the ledger; `supply_conserved` (transition.rs:4741–4748); step 11b of `compute_post_state`. The test `rewards_v2_settles_delegator_issuance_share` (transition.rs:7898) calls `close_epoch` directly and asserts only that the ledger is non-zero.
- **Evidence.**
  ```rust
  if payout.operator > 0 { ... rec.staked_sat += payout.operator; if !mutation_mints_from_nothing() { st.issued_sat += payout.operator; } }
  ...
  for (delegator, reward) in shares { if reward > 0 { *st.delegator_issuance_rewards.entry(delegator).or_insert(0) += reward; } } // no issued_sat
  if dust > 0 { ... rec.staked_sat += dust; if !mutation_mints_from_nothing() { st.issued_sat += dust; } }
  ```
- **Recommendation.** `issued_sat += payout.operator + payout.delegators` (dust is inside `payout.delegators`), and add an `issued_sat`/`supply_conserved(pre, post, 0)` assertion to the rewards_v2 delegator test (route it through `process_epoch` so the existing `debug_assert!` bites).
- **Confidence:** High.

### ST-07 — Attestation and proposal signing roots carry no network/genesis binding, so a validator key reused on another network (devnet, a fork with the same slot numbering) yields *valid* slashing evidence on mainnet
- **Severity:** Low (operator-error precondition; the CLI already warns "Use a distinct validator key per network" for exits only)
- **Status:** Evidence half NEW; exit half KNOWN (ADR-041 D2 defers `DS_EXIT2`; `validator_lifecycle.rs` HELP text).
- **Refs:** `attestation.rs:42–52` (`DS_ATTEST ‖ slot ‖ head ‖ source ‖ target`), `header.rs:225–230` (`DS_PROPOSE ‖ canonical header`), `slashing.rs:381–470` (`process_proposer` deliberately checks neither schedule nor chain), `transition.rs` `SlashingEvidence` docs ("No committee-membership check … a signed conflict is hostile whether or not the signer was on duty").
- **Description.** Two headers at the same slot with different parents, or two attestations for one target epoch, signed by the same key on two networks, are indistinguishable from equivocation. The rehearsal harness (`scripts/rehearse-validator-admission.py`, `lifecycle-devnet-soak.py`) copies the tree and runs real keys; if any operator reuses a mainnet keystore on a devnet, that devnet's ordinary signatures are mainnet slashing evidence.
- **Recommendation.** Fold the genesis digest (already available as `admission_network_domain`) into `DS_ATTEST`/`DS_PROPOSE`/`DS_EXIT` under one flag day (ADR-041 already ties `DS_EXIT2` to `SIGHASH_NETWORK_BINDING`); extend the CLI warning to all signing; make the devnet harness refuse a mainnet-bound keystore.
- **Confidence:** High.

### ST-08 — Cohort-cap `Deferred` threshold is a cliff: one 5% slash, an exit, or a leak-independent effective-stake dip of the sole independent validator below 25,000 BLCH flips the cap off in one epoch (cohort back to ~100%), and back on when a new 25k deposit activates
- **Severity:** Low (post-L; consequence of ST-01's design; mostly a liveness/visibility oscillation rather than an exploit)
- **Status:** NEW (the `Deferred` escape is KNOWN — GAP-4 §4 item 4, `genesis_cohort.rs:140–160` — its discontinuity is not discussed)
- **Refs:** `genesis_cohort.rs:122–126` (`if others < CAP_MEANINGFUL_AT_SAT { Deferred }`), `MIN_DEPOSIT_SAT` = exactly the threshold, so any independent validator sits at the edge until it accrues rewards; `transition.rs:4428` (slash debits `staked_sat`, the value `sat_u64` feeds the cap).
- **Recommendation.** Hysteresis or a smooth ramp between `Deferred` and `Enforced` (e.g. scale the target share by `min(1, others/CAP_MEANINGFUL)`), and fold into the ST-01 redesign.
- **Confidence:** High.

### ST-09 — Mempool and consensus derive the funded-deposit stake cap from different totals (unleaked vs leak-applied roster)
- **Severity:** Low / Info (post-L; only matters once 1% of active stake exceeds 25,000 BLCH; effect is a deposit the mempool accepts and the proposer later drops and bars for `REJECTION_TTL_SLOTS`)
- **Status:** NEW
- **Refs:** `engine/validator_lifecycle.rs:40` (`self.state.total_active_stake_sat()` → `duty_roster()` = unleaked, `transition.rs:5405`), vs `transition.rs:5803` (`roster = consensus_roster_at`, leak-applied). Same asymmetry for `validate_lifecycle_transaction`'s evidence amplification denominator.
- **Recommendation.** Expose and use one accessor (`consensus_roster_at(self.epoch)` sum) at the door.
- **Confidence:** High.

### ST-10 — Stale/contradictory comments on the slashing path
- **Severity:** Info
- **Status:** NEW
- **Refs:** `transition.rs:≈4240` (`apply_slashing_evidence` doc block: "the record is marked slashed — duties stop immediately (the duty roster filters on the flag)") contradicts R1 M7 (`duty_roster_at` reads `exit_epoch` alone; ejection at E+1) documented 200 lines later and in `duty_roster_at`'s own docs. `slashing.rs:19` ("Nothing constructs the transaction outside tests") is false since `report_equivocation`/`observe_proposer_equivocation` landed (gated, but constructed). `transition.rs:3622` (`voluntary_exits_this_epoch` doc: "apply_slashing_evidence sets exit_epoch = self.epoch") is stale — it sets `E+1`.
- **Recommendation.** Fix the three sentences; `check-comment-constants.py` cannot catch these (no constant named).

### ST-11 — `genesis_principal_sat` and `admission_network_domain` are uncommitted, manifest-derived consensus inputs; the domain is `SHA3(manifest.encode())`, so any manifest re-encoding/format change across node versions silently forks funded-deposit validity without moving any root
- **Severity:** Info (mixed-fleet hazard to remember at L; not a present defect — every node builds state via `Manifest::state_anchored_at`, genesis.rs:1410–1436, from the same published bytes)
- **Status:** NEW
- **Refs:** `transition.rs:1466–1470,1503–1504`, `compute_root` (`ConsensusState` lists `funded_validators`, `stake_low_water`, `randao_generations`, `written_off_sat`, but neither `genesis_principal_sat` nor the domain); `genesis.rs:1424` (`Sha3_256::digest(self.encode())`), `ManifestFormat::V2Bound` (two encodings exist).
- **Recommendation.** Pin the mainnet domain as a constant test (like `leak_recovery_armed_epoch_matches_the_runbook`) and have `lifecycle-fleet-verify.sh` compare `getvalidatoradmission.network_domain` across the fleet (it already compares `source_digest`; the domain is the value that matters).

### ST-12 — Arming L also switches on gas/byte metering for ExitV2, RandaoRecommit and SlashingEvidence (`staking_tx_charge` reads `|| withdrawal_active`), which `deploy/FLAG-DAY-LIFECYCLE.md` §1 does not list
- **Severity:** Info (consistent across the fleet because all five gates arm together; worth one line in the runbook and the §4.2 rehearsal list)
- **Status:** NEW
- **Refs:** `transition.rs:3282–3314` (`if !staking_tx_metering_active(epoch) && !withdrawal_active(epoch) { free }`), `params.rs:1818` (`STAKING_TX_METERING_ACTIVATION_EPOCH = u64::MAX` — its own gate is *not* armed by L, yet the charge is).

### ST-13 — Activation queue: intra-epoch order is grindable by `pubkey_hash` and the queue is unbounded (economically bounded by 25,000 BLCH per entry locked ≥ 2,080 epochs)
- **Severity:** Info
- **Status:** KNOWN in spirit (`staking.rs:517–520` says grinding "buys at most intra-epoch ordering"); noting that 4/epoch with an earlier-epoch-first rule lets K queued entries delay honest activation by K/4 epochs.
- **Refs:** `lifecycle.rs:408–435`, `staking.rs:517–520`.

### ST-14 — Mutation guard (`scripts/check-validator-lifecycle-mutations.py`) matches the code and each of its eight mutations is killed by `transition::tests::validator_lifecycle`; gaps in what it guards
- **Severity:** Info
- **Status:** NEW (coverage assessment). Verified: all eight anchors exist exactly once in `lifecycle.rs` (activation :502, maturity :508, one-shot :509, indeterminate :502, credential :513–514, narrowing :520, collision :529, write-off-overflow :523–524) and, by reading, `withdrawal_failure_is_atomic_at_each_boundary`/`withdrawal_pays_funded_bonds_and_only_genesis_accrual` fail under each mutation.
- **Gaps:** no mutation for the `exit_epoch == u64::MAX` / `withdrawable_epoch == u64::MAX` guards; none for `unbacked_principal_sat`'s fail-closed `unwrap_or(u128::MAX)`; none for `funded_validators` keying (a `return 0` for everyone would make genesis bonds pay principal — the `funded=false` case of the payout test would catch it, but it is not in the script); the whistleblower cap (`reward.min(backed_loss)`, transition.rs:4452–4457) is outside the script's test filter. The script copies untracked files too (`--others`), so a stray local file can change the verdict.

### ST-15 — Whistleblower is always the *including proposer*; the observer who gossips evidence earns nothing, and evidence is trivially front-run
- **Severity:** Info (by design, same as Ethereum; noted because `report_equivocation` logs "admitted and broadcast" as if the reporter were paid)
- **Refs:** `transition.rs:5824–5829` (`including_proposer = header.proposer_index`).

### ST-16 — A queued funded validator whose deposit epoch is never finalized has no exit: `ExitV2` requires `activation_epoch <= epoch`, `Withdraw` requires an exit, and the only way out is a self-slash (ST-04)
- **Severity:** Info (finality stalls are recoverable by the leak; the bond is locked meanwhile)
- **Refs:** `apply_exit_v2` (transition.rs:3670–3729; `rec.activation_epoch > self.epoch` → reject), `lifecycle.rs:506`.

---

## 3. Positive observations (verified, not merely claimed)

- **Funded deposit** (`funded.rs`): both roles sign the *whole* intent (network domain, expiry, funding key, inputs, validator key, amount, RANDAO, withdrawal script, commission, change, fee budget, reserved bytes) under distinct role domains; signatures excluded from txid; input values read from committed state; exact conservation with refund to the signed change script; `AlreadyRegistered` on pubkey hash (no key reuse across validators); index = `max+1`, never reused; every fallible check precedes mutation; zero withdrawal credential and zero RANDAO refused; shape and fee bounds before the two verifications. VAD-03 is closed at the door: `validate_lifecycle_admission` runs before eviction commit and broadcast, plus `funded_mempool_conflict` and head-change revalidation.
- **Activation** is finality-gated (`deposit_epoch < finalized`), delayed 8 epochs, capped 4/epoch, deterministically ordered, and not backdated (VAD-02 closed). `resolve_activations` has differential coverage against the epoch scan.
- **ExitV2**: signature against the *registered* key over `DS_EXIT ‖ hash ‖ epoch`, signed epoch == inclusion epoch (replay-bound), churn budget derived from committed `exit_epoch` values (no new field, no root change), cheap checks before the verify.
- **Withdrawal** (`lifecycle.rs`): unsigned crank with payout fully determined by committed state; credential fixed at deposit; one-shot via `staked_sat == 0`; explicit `u64` narrowing; output collision refused; write-off column monotone and checked; conservation equality asserted in-arm; genesis principal written off exactly per ADR-041 D4; `supply_conserved` holds across a withdrawal (holdings fall by the write-off). The lifecycle metadata (`funded_validators`, `stake_low_water`, `randao_generations`, `written_off_sat`) is committed to the root and empty below L (T-9 pinned).
- **Slashing**: both header-pair and attestation-pair evidence re-verified against the registry key; order-independent anti-replay id excluding signatures; ejection set derived from `slashed`; evidence against exited-but-unwithdrawn validators still applies and *extends* the lock; whistleblower reward bounded to the operator's actually-debited, *issued* loss (R1 H4 + ADR-041/A7 cap) so self-slashing is never profitable and unissued principal never funds a reward; R1 M7 keeps the epoch's index set stable (verified: `duty_roster_at` predicate reads `exit_epoch` only). All slashing state (`applied`, `window`, delegator losses) is committed.
- **Supply**: `issued_sat` committed and clamped to headroom at the source; `SupplyCapExceeded` on the pre-state; one-sided `supply_conserved` delta rule at step 11b covers the boundary roll; genesis mint-from-nothing bounded by `GENESIS_UNFUNDED_BONDED_CEILING_SAT` with a hard error; `TOTAL_SUPPLY_SAT ≤ u64::MAX` and `> u64::MAX/2` pinned. Rounding dust in `rewards::distribute` is never minted (errs under the cap); delegator-split dust is placed explicitly.
- **Determinism**: every registry/queue/ledger is a `BTreeMap`/`BTreeSet` or chain-ordered `Vec`; sorts are on total orders; no `HashMap`; no clock; all gates read the block's committed epoch; `u64::MAX` is a sentinel in `epoch_gate_active`. No panic reachable from a block in the audited paths (all narrowing is `checked_`/`saturating_`; `MAX_EPOCH_ADVANCE` bounds the boundary walk before `first_slot + SLOTS_PER_EPOCH` could overflow).
- **Flag day**: const-asserted single lifecycle epoch; `DEPOSIT_ACTIVATION_EPOCH` pinned to `u64::MAX`; legacy `Deposit`/`Delegate` refused at every epoch by consensus.

## 4. Test-coverage gaps

1. ADR-041 T-2 partially unmet: no test that `ExitV2` is refused for a *slashed*, *already-exited* or *not-yet-active* validator (`exit_v2_*` tests cover signature, epoch binding, budget only).
2. No transition-level test of evidence against an exited-but-unwithdrawn validator (lock extension) or a withdrawn one (`staked_sat == 0`); unit test covers only the already-ejected case.
3. Nothing pins the slashed-vs-voluntary lifecycle timelines (ST-04) or the churn-budget refund on a same-epoch slash.
4. `rewards_v2_settles_delegator_issuance_share` does not check `issued_sat` or `supply_conserved` (would have caught ST-06).
5. `genesis_cohort_cap_binds_at_the_floor` and `tests/committee.rs` cohort tests use ≥ 2 outsiders or large independent stake; no test for the one-outsider supermajority (ST-01) or the `Deferred`↔`Enforced` cliff (ST-08).
6. No amplification test with a capped/leaked `total_active` (ST-03).
7. `Withdraw` is never driven through `apply_block`/`compute_post_state` with `supply_conserved` in a non-ignored test; the end-to-end lifecycle exists only in the `#[ignore]` two-engine rehearsal.
8. Mainnet genesis `withdrawal_credentials` width (must be 32 bytes for `withdrawal_plan`) is not pinned by a test reading `genesis/mainnet.manifest` (the manifest pin test checks only `validators.len() == 64`).
9. Mutation script scope (ST-14).

## 5. Residual risk / not covered

- Transport-level rate limiting and gossip scoring (ST-05 depends on it) — network auditor.
- `bloch_crypto::crypto::verify` AND-composition over the suite-1 envelope for enveloped 3,749-byte keys — crypto auditor (the committee crate's `verify_hybrid` AND is only used by the reference `staking::validate_deposit`, not by the live `FundedDeposit` path, which trusts the injected verifier's contract).
- Finality/leak/fork-choice divergence (VAD-04 §3.2–3.3: two near-equal partitions finalize different roots) — finality auditor; it interacts with ST-01 (a 2/3 outsider can also finalize alone across a partition).
- Carried-output ownership (`owns` 20-byte padded form) used by genesis withdrawal credentials — eUTXO auditor.
- `genesis/mainnet.manifest` was not decoded (binary; no build allowed): the cohort set = all 64 and 32-byte credentials are inferred from `check_bonds_are_funded`, the manifest tests and ADR-041 D4, not observed.
- Delegation (`Delegate`, cool-down, cap fixpoint, pro-rata slash) was reviewed for determinism/termination and found sound, but it is dead code by const-assert; ST-06 is the only delegation-path defect found.
