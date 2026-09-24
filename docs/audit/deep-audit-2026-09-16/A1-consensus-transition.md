# A1 — Consensus state transition audit (transition.rs and siblings)

Auditor: A1 (consensus transition / transaction execution / fee market / tokenomics)
Tree: `/home/user/bloch-sis-pow` (read-only; no build or test run by this auditor)
Date: 2026-09-16

---

## 1. Scope and method

### Read in full, line by line

| File | Lines | Notes |
|---|---|---|
| `crates/bloch-pos-committee/src/transition.rs` | 1–6055 (non-test) | codec, signing roots, txid, `CommittedState`, `EutxoSet`, genesis, `compute_post_state`, `apply_block`, `close_epoch`, every `apply_*` arm |
| `crates/bloch-pos-committee/src/transition/funded.rs` | all (397) | `FundedDeposit` (tag 0x0B) codec + validation + apply |
| `crates/bloch-pos-committee/src/transition/lifecycle.rs` | all (202) | ADR-041 withdrawal, finalized-activation, write-off accounting |
| `crates/bloch-pos-committee/src/fee_market.rs` | all (982) | controller, gas, settlement, compile-time headroom proofs |
| `crates/bloch-pos-committee/src/rewards.rs` | all (183) | fee split, issuance split |
| `crates/bloch-pos-committee/src/tokenomics_v4.rs` | all (754) | supply constants, emission curves, vesting, asserts |
| `crates/bloch-pos-committee/src/header.rs` | all (758) | header codec, `BlockId`, proposal signing root |
| `crates/bloch-pos-committee/src/params.rs` | all (2006) | every activation gate, `MAX_EPOCH_ADVANCE`, DS tags |
| `crates/bloch-pos-committee/src/interfaces.rs` | all (1128) | frozen traits, error enums |

### Skimmed (to understand coverage, or to confirm a cross-module fact)

- `transition.rs` 6055–16002: test-name inventory (about 230 tests) plus targeted reads.
- `derive.rs` (`body_root`, `attestation_root`, `merkle_root`, `attestation_leaf`), `genesis_cohort.rs` (`apply_cohort_cap`), `slashing.rs` (`process`, `process_proposer`, `offense`, outcome fields), `staking.rs` (`deposit_shape`, lifecycle constants), `attestation.rs` (`validate`), `delegation.rs` (constants), `state_root.rs` (`eutxo_leaf`, `EutxoEntry`).
- `bloch-pos-node/src/engine.rs` (block ingest → `apply_block`, `admissible`, mempool keying, proposer probe-and-bar loop, `MAX_FUTURE_SLOTS`), `codec.rs` (`decode_envelope`, `MAX_FIELD_LEN`), `net.rs` (frame budget), `genesis.rs` (duplicate-outpoint guard).
- Prior findings: `docs/audit/CERTIK-PRE-AUDIT-DOSSIER.md`, `VALIDATOR-ADMISSION-REVIEW-2026-09-08.md`, `VAD-04-LIFECYCLE-SOAK-2026-09-11.md`, `groundstate_audit.md` (Era-1, not applicable), `docs/specs/BLOCH-POS-GAPS.md`, `BLOCH-L1-FEE-MARKET.md`, `BLOCH-TOKENOMICS-V4.md`, `BLOCH-SATOSHI-ENCODING.md`, `SECURITY.md`, post-mortem 2026-08-24 (summary only; finality is another auditor's scope).

### Method

Adversarial trace from untrusted bytes (block envelope → `from_canonical_bytes` → `compute_post_state`) to committed state, checking: codec injectivity and malleability; domain separation and replay; value conservation on every path that touches the eUTXO set or a bond; arithmetic width and overflow (the crate builds with `overflow-checks = true`, so an unchecked overflow is a panic, i.e. a remote halt); double-spend inside a block; per-block DoS bounds and their placement relative to expensive work; determinism; panic reachability; header/body consistency; and spec/code divergence. Every claim below was verified by reading the code path named in the finding. Where I could not confirm, the confidence field says so.

**Labelling.** KNOWN = already recorded in the repo (code comment naming an audit ID, a gate constant's doc, a spec, or one of the audit docs); the citation is given. NEW = not found in any of those places.

**Important structural fact for all severities below.** Sixteen consensus rules ship behind `u64::MAX` gates and are inert on the live chain today (`DEPOSIT`, `EXIT_AUTH`, `FUNDED_VALIDATOR_ADMISSION`, `WITHDRAWAL`, `SLASHING_EVIDENCE`, `RANDAO_RECOMMIT`, `FEE_STAKE_DECOUPLE`, `DUST_RULE`, `TX_BYTES_BOUND`, `ATTESTATION_DEDUP`, `REWARDS_V2`, `STAKING_TX_METERING`, `SIGHASH_NETWORK_BINDING`, `FORKCHOICE_EQUIVOCATION_HORIZON`, `ANCESTRY_SEED`). Three are bound and live (`LEAKED_ROSTER` 1400, `TRANSFER_WITNESS_DEDUP` 800, `BLOCK_BYTES_V2` 800, `LEAK_RECOVERY` 2700). The live transaction set is therefore: `Transfer` (0x01), `TransferV2` (0x06), and the **unauthenticated** legacy `Exit` (0x03). Everything else is refused by consensus at every reachable epoch.

---

## 2. Findings

Ordered by severity. IDs TX-01 … TX-22.

---

### TX-01 — Legacy `Exit` (tag 0x03) is live, unauthenticated and uncapped: one block proposer can retire the entire validator set; the survivor holds 100% of consensus weight, then the chain dies when its RANDAO chain exhausts

- **Severity:** High (Critical impact; precondition = control of one of the 64 proposer keys, all founder-operated today, or one malicious operator)
- **Status:** KNOWN — `transition.rs` `PosTransaction::Exit` doc ("a modified proposer can still put one in a block today"); `params.rs` `EXIT_AUTH_ACTIVATION_EPOCH` doc ("anyone can retire any validator… Sixty-four such messages retire the whole roster"); VAD-01 (`VALIDATOR-ADMISSION-REVIEW-2026-09-08.md`). **The recorded impact is understated** (docs frame it as a bond-lock griefing); the takeover-then-death consequence below is not written down anywhere I found.
- **Refs:** `transition.rs:3489-3522` (Exit arm), `transition.rs:2492` (`duty_roster_at` exclusion `epoch >= rec.exit_epoch`), `transition.rs:3626-3648` (`voluntary_exits_this_epoch` — counted only by the `ExitV2` arm), `genesis_cohort.rs:157-160` (`Deferred` when non-cohort stake is 0), `params.rs` `RANDAO_RECOMMIT_ACTIVATION_EPOCH = u64::MAX`, `engine.rs:5844` (`admissible` refuses `Exit` — mempool policy only).
- **Description.** The arm is gated only by `exit_auth_active || funded_validator_admission_active`, both `u64::MAX`. It then requires nothing but a registered, active, not-exiting index and sets `exit_epoch = epoch + 32`, `withdrawable_epoch = +2048`. There is no signature, no churn cap (`MAX_EXITS_PER_EPOCH` is enforced only in `apply_exit_v2`), and the transaction is 5 bytes costing 0 gas and 0 bytes (`staking_tx_charge` is free while metering is inert).
- **Attack.** A proposer includes 63 `Exit` transactions (one per other index) in its own block. Every node accepts it (consensus-valid). 32 epochs (~8.5 h) later `duty_roster_at` excludes the 63; the roster is the attacker alone; `apply_cohort_cap` returns `Deferred` because non-cohort stake is zero, so the attacker keeps full weight; `finality::process_epoch` sees a 100% supermajority and finalizes the attacker's blocks alone. Exited records can never re-enter (`pubkey_index` is permanent; `FundedDeposit` is inert). After at most 8,192 further proposals (`RANDAO_CHAIN_LENGTH`, `RandaoRecommit` inert) the attacker's chain is exhausted and **no block can ever be produced again** — permanent chain death requiring a relaunch. A milder variant exits only selected victims to skew proposer share.
- **Evidence.**
  ```rust
  PosTransaction::Exit { validator } => {
      if Self::exit_auth_active(self.epoch) || crate::params::funded_validator_admission_active(self.epoch) {
          return Err(TxReject::StakingNotActive);
      }
      let Some(rec) = self.validators.get_mut(validator) else { return Err(TxReject::StakingRule) };
      if rec.slashed || rec.activation_epoch > self.epoch || rec.exit_epoch != u64::MAX { return Err(TxReject::StakingRule); }
      let exit_epoch = self.epoch.saturating_add(staking::EXIT_DELAY_EPOCHS);
      rec.exit_epoch = exit_epoch; ...
      Ok(Self::staking_tx_charge(self.epoch, 0, tx.canonical_bytes().len()))
  ```
- **Recommendation.** Do not wait for the full ADR-041 lifecycle to close this. A verdict-tightening but risk-free interim: refuse tag 0x03 in consensus unconditionally now (the chain has never applied one — the same replay argument `DEPOSIT_ACTIVATION_EPOCH`'s doc makes for 0x02 should be measured for 0x03 against the block log), or at minimum apply `MAX_EXITS_PER_EPOCH` to the legacy arm. Either is a flag day only in name if the log carries zero legacy exits. Also record the takeover/death consequence in VAD-01.
- **Confidence:** High.

---

### TX-02 — Per-block byte/gas caps are enforced only after all transactions have executed; a scheduled proposer can force ~16× a maximal block's execution work per slot before rejection

- **Severity:** Medium (privileged position: scheduled proposer; impact: multi-second CPU stall on every node per malicious slot, no state change)
- **Status:** NEW
- **Refs:** `transition.rs:5811-5886` (step 10 loop), `:5888-5893` (step 10b caps after the loop), `:3919` / `:4118` (`TxGasCeilingExceeded` bounds one tx at `MAX_TX_GAS`, i.e. up to ≈3.75 MB declared), `codec.rs:24` (`MAX_FIELD_LEN` 8 MiB), `net.rs:763` (frame ≤ `MAX_FIELD_LEN`), `codec.rs:194-196` (≤ 65,536 txs).
- **Description.** `block_gas`/`block_bytes` are summed inside the loop but compared to the caps only after every transaction has been applied (`apply_transfer` runs the hybrid verifications and inserts every output into the eUTXO SMT before the cap is consulted). The per-transaction ceiling is `MAX_TX_GAS = BLOCK_GAS_LIMIT` (60 M gas ≈ 3.75 MB of declared bytes per transfer), and the wire frame is 8 MiB. So a body of two ≈3.75 MB transfers, each with one real input and ~93 K zero-value outputs (dust rule inert, TX-06), is fully executed — two verifications, ~186 K `EutxoSet::insert` calls each rebuilding a 256-level SMT path plus the copy-on-write deep copy of the 452 K-entry map — and only then refused with `BlockByteLimitExceeded`. A maximal *valid* block carries 512 KiB. The proposer loses nothing it would otherwise have had (the block is invalid), and it can repeat this every slot it is drawn (~1/64).
- **Evidence.**
  ```rust
  for (i, tx) in transactions.iter().enumerate() {
      let applied = match tx { ... _ => st.apply_transaction(tx, total_active, base_fee, &self.verifier) };
      match applied { Ok(charge) => { block_gas = block_gas.saturating_add(charge.gas);
                                       block_bytes = block_bytes.saturating_add(charge.tx_bytes); ... }
  }
  // 10b — after the loop:
  if block_gas > fee_market::BLOCK_GAS_LIMIT { return Err(TransitionError::BlockGasLimitExceeded); }
  if block_bytes > fee_market::max_block_tx_bytes(block_epoch) { return Err(TransitionError::BlockByteLimitExceeded); }
  ```
- **Recommendation.** Check the running totals *before* executing each transaction: for `Transfer`/`TransferV2`/`FundedDeposit` the declared `tx_bytes` and `intrinsic_gas` are known before any verification (`fee_market::charge` is a pure function of class and size), so `if block_bytes + declared > cap { reject }` can precede `apply_transaction`. This is verdict-preserving (every body it refuses would have been refused at 10b), so no flag day is needed; only the reported error moves earlier, which the "frozen error order" docs should note. Also consider a consensus transaction-count cap (R7 M1's open half).
- **Confidence:** High on the mechanism; Medium on the absolute cost (per-insert SMT cost estimated, not measured).

---

### TX-03 — Single-input transfers are cross-format malleable: a relay can re-encode V1↔V2 producing a distinct, valid `canonical_bytes` with the same `txid`

- **Severity:** Low (mempool/relay churn and censorship-by-bar of the wallet's original bytes; no theft, no double spend)
- **Status:** NEW (the *intra*-V2 permutation case is KNOWN and closed by `WitnessTableNotCanonical`; the cross-format case is not addressed anywhere)
- **Refs:** `transition.rs:621-665` (`spend_signing_root` shared by V1 and V2), `:826-923` (encodings), `:3867` and `:4070` (`UnderdeclaredSize` floor only), `fee_market.rs` `TX_BYTES_DECLARE_SLACK` doc (CLI declares ≥1,024 bytes of slack), `engine.rs:3023-3024` (mempool keyed by `canonical_bytes`), `engine.rs:1936-1990` (probe-and-bar, `REJECTION_TTL_SLOTS = 128`).
- **Description.** For a transfer with one input and one owner, V1 and V2 have the same signing root, the same `txid`, the same gas (`Eutxo{inputs:1}` vs `Eutxo{inputs:keys.len()=1}`) and therefore the same fee and the same conservation equation. V2's encoding is exactly 8 bytes longer than V1's. Since `tx_bytes` need only be ≥ the encoding, and wallets over-declare by ≥1 KB, any third party holding the V1 bytes can emit a valid V2 twin (and a V2 single-input transfer always has a valid V1 twin, 8 bytes shorter). Multi-input transfers are not convertible (the class term, hence the fee, differs). Both twins are admitted by the byte-keyed mempool; the proposer includes one and bars the other for 128 slots as an "offender", which may be the wallet's own encoding.
- **Recommendation.** Key the mempool (and gossip dedup) by `txid`, not by `canonical_bytes`; treat a second encoding of a known `txid` as a duplicate, not an offender. Optionally refuse V1 for single-input transfers post-flag-day (canonical format per shape).
- **Confidence:** High.

---

### TX-04 — `network_binding()` is a compile-time label, not a genesis-derived value, so the (inert) sighash binding does not actually separate networks built from the same source

- **Severity:** Low (gate is inert; when armed it would give weaker protection than its name implies)
- **Status:** NEW (the replay hole itself is KNOWN: A2-3 / R7 M2, `SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH` docs)
- **Refs:** `transition.rs:718-735`, `funded.rs` (`network_domain` = manifest digest, the correct pattern), `params.rs` `SIGHASH_NETWORK_BINDING_ACTIVATION_EPOCH` doc ("any two networks opened from the same Genesis-3 snapshot share… identical outpoints").
- **Description.** `network_binding()` returns `b"BLCH4:GENESIS-4:MAINNET"` zero-padded. Every devnet, testnet, rehearsal fork or contentious fork built from this tree carries the same bytes unless the source is edited, which is exactly the "same source, same carryover" scenario the finding is about. `FundedDeposit` already does this correctly by binding to the genesis-manifest digest (`admission_network_domain`).
- **Recommendation.** Fold the genesis block id (or the manifest digest already held in `admission_network_domain`) into the binding instead of a constant.
- **Confidence:** High.

---

### TX-05 — Mempool and consensus compute the funded-deposit cap from different `total_active` values (leak-applied vs unleaked)

- **Severity:** Low (gate inert; when armed, the mempool may admit deposits consensus refuses and vice-versa near the cap)
- **Status:** NEW (VAD-03 asked for the check to be shared; it is shared but fed different inputs)
- **Refs:** `transition.rs:5803` (`total_active` from `consensus_roster_at`, i.e. after `with_leak_applied` since epoch 1400 and after the cohort cap), `transition.rs:5405-5407` (`StateReader::total_active_stake_sat` uses `duty_roster()`, unleaked), `funded.rs:293-297` (cap = `max(total_active × 1%, MIN_DEPOSIT)`), `lifecycle.rs:validate_lifecycle_transaction` (node passes its own `total_active_sat`).
- **Recommendation.** Expose one accessor for "the `total_active` consensus uses at this epoch" and have the node call it.
- **Confidence:** High on the divergence; Medium on practical effect (today `MIN_DEPOSIT_SAT` may dominate the 1% term).

---

### TX-06 — Zero-value and arbitrary-count outputs are valid: permanent state growth at ~6 sat per entry

- **Severity:** Medium (unauthenticated submitter; state bloat; node-local mempool refuses new dust but any proposer can include it)
- **Status:** KNOWN — H-R7-3, `params.rs` `DUST_RULE_ACTIVATION_EPOCH` (inert), `transition.rs:3141-3160`, node `admissible` dust check (policy only).
- **Refs:** as above; `apply_transfer` conservation admits `created = 0` with any number of outputs.
- **Note.** Combined with TX-02 this is the amplifier for the over-cap CPU attack; alone it is the state-growth attack. A maximal valid V2 block carries ~13 K permanent zero-value entries.
- **Confidence:** High.

---

### TX-07 — Declared `tx_bytes` may exceed the encoding by any amount; one small transfer can fill the block byte budget

- **Severity:** Low–Medium (proposer-level censorship; node policy mitigates)
- **Status:** KNOWN — H-R7-2, `params.rs` `TX_BYTES_BOUND_ACTIVATION_EPOCH` (inert), `fee_market.rs` `TX_BYTES_DECLARE_SLACK`.
- **Confidence:** High.

---

### TX-08 — Producer fee share compounds into `staked_sat` (consensus weight) with no per-block cap

- **Severity:** Medium (a proposer converts liquid coin into bonded weight at 100% via self-tips)
- **Status:** KNOWN — C-R2-2, `params.rs` `FEE_STAKE_DECOUPLE_ACTIVATION_EPOCH` (inert), `rewards.rs` `MAX_BLOCK_FEE_TO_PRODUCER_SAT`.
- **Refs:** `transition.rs:5216` (below the gate `rec.staked_sat += operator_credit`), `:5909-5925` (per-block producer credit, uncapped below the gate).
- **Confidence:** High.

---

### TX-09 — Issuance accounting below `REWARDS_V2`: delegators receive zero issuance, leak does not reduce income, credit is one unscoped bit, withheld proposals are unpriced

- **Severity:** Medium (economic/spec divergence; delegation is inert today so no live victim)
- **Status:** KNOWN — R1 M1/M3/M4, R7 M5; `params.rs` `REWARDS_V2_ACTIVATION_EPOCH`; fee-market spec §8 "Still not wired"; tokenomics spec §6.3 describes the un-shipped behaviour as adopted.
- **Refs:** `transition.rs:5054` (`(attested, 0u128, 0u128, 0u64, 0u64)` — delegated stake and commission hard-coded to zero below the gate).
- **Confidence:** High.

---

### TX-10 — Staking-class transactions are unmetered (0 gas, 0 bytes) and there is no consensus transaction-count cap

- **Severity:** Low today (the only live staking tx is `Exit`, at most 64 applicable per block; see TX-01), Medium once any lifecycle tag arms
- **Status:** KNOWN — R7 M1, `params.rs` `STAKING_TX_METERING_ACTIVATION_EPOCH` ("Not yet closed by this gate: a consensus MAX_TRANSACTIONS_PER_BLOCK").
- **Refs:** `transition.rs:3282-3310` (`staking_tx_charge` returns all-zero below the gate).
- **Confidence:** High.

---

### TX-11 — Slashing is unreachable; equivocation is free

- **Severity:** High for the protocol's safety argument (another auditor's core scope; listed here because it interacts with transaction execution)
- **Status:** KNOWN — dossier F-4 (reopened), F-02; `params.rs` `SLASHING_EVIDENCE_ACTIVATION_EPOCH` (inert); `transition.rs:5822` (`EvidenceNotActive`).
- **Verified for my scope:** the evidence path, once armed, is sound as written: `offense()` requires `first.validator == second.validator` (`slashing.rs:189`), `process_proposer` requires equal `proposer_index` (`:472`), both signatures are re-verified against the committed key, replay is refused in either order, `whistleblower_reward_sat = operator_loss_sat / 32 ≤ operator_loss_sat` (`:569-571`), losses are priced on *activated* delegated stake, and `accounted_supply_sat` subtracts the delegator-loss ledger so the block-level conservation check cannot false-red on a slash.
- **Confidence:** High.

---

### TX-12 — Every RANDAO chain is terminal; the first exhaustions (~2027-02) start removing proposers permanently

- **Severity:** High liveness (KNOWN; another auditor's scope, noted because the arm lives in `apply_transaction`)
- **Status:** KNOWN — H-R7-1, `params.rs` `RANDAO_RECOMMIT_ACTIVATION_EPOCH`.
- **Verified:** `apply_randao_recommit` is correctly ordered (epoch equality → identity → lifecycle → exhaustion precondition → signature → mutate), and self-refuses same-epoch replay via `reveals_used` reset.
- **Confidence:** High.

---

### TX-13 — `MAX_EPOCH_ADVANCE = 4096` is a hard liveness ceiling: a network-wide stall longer than ~45.5 days can only be resumed by a hard fork

- **Severity:** Low (documented trade; but a *permanent* outcome)
- **Status:** KNOWN — `params.rs` `MAX_EPOCH_ADVANCE` doc names the cost explicitly.
- **Refs:** `transition.rs:5527`, `params.rs:66-110`.
- **Note.** The node-side `MAX_FUTURE_SLOTS = 2 × SLOTS_PER_EPOCH` is the first line for gossip; the consensus bound is what holds on every other path. No recovery mechanism exists in-protocol. Worth an ADR stating the operator procedure for the >45-day case.
- **Confidence:** High.

---

### TX-14 — Genesis bonded 1,600,000 BLOCH outside `issued_sat`; the conservation invariant is a one-sided delta that can never see it, and burns are uncounted

- **Severity:** Low (accepted, documented; but it means "total burned" and "true circulating supply" are not derivable from committed state)
- **Status:** KNOWN — `tokenomics_v4.rs` `GENESIS_UNFUNDED_BONDED_CEILING_SAT`, `transition.rs` `accounted_supply_sat`/`supply_gap_sat` docs, `interfaces.rs` `SupplyNotConserved` doc.
- **Verified:** `supply_conserved` is `accounted(post) ≤ accounted(pre) + minted + unfunded_bonded`; a coin-*destroying* bug passes silently by design; `issued_sat` never decrements; `written_off_sat` exists but only for lifecycle write-offs.
- **Recommendation (Info):** commit a `burned_sat` counter alongside `issued_sat` so `issued − burned − written_off == accounted` becomes an equality auditors and explorers can check.
- **Confidence:** High.

---

### TX-15 — Duplicate `(validator, signing_root)` attestations cost one hybrid verify each and are accepted (idempotent)

- **Severity:** Low (proposer-level CPU: ≤4,096 verifies ≈ 0.6 s per block)
- **Status:** KNOWN — R3 M-2, `params.rs` `ATTESTATION_DEDUP_ACTIVATION_EPOCH`; `MAX_ATTESTATIONS_PER_BLOCK = 4096` bounds it.
- **Confidence:** High.

---

### TX-16 — Body decode, re-encode and Merkle hashing (steps 3b) run before the proposer signature (step 7); an unauthenticated peer can force ~8 MiB of hashing per message

- **Severity:** Low (linear, bounded by the 8 MiB frame; peer scoring is node policy)
- **Status:** NEW (as a note; the ordering is a documented choice: "hashes over data already in hand")
- **Refs:** `transition.rs:5495-5505`, `engine.rs:2290-2295` (`body_transactions` before verdict), `codec.rs`/`net.rs` frame limits.
- **Note.** Also a minor inefficiency: the node already holds the wire bytes but the transition re-encodes every transaction (`canonical_bytes`) to compute `body_root`, and `apply_transfer` calls `canonical_bytes()` again for the length floor. Consider passing the wire bytes alongside the typed transactions.
- **Confidence:** High.

---

### TX-17 — `FundedDeposit::decode` enforces consensus rules (`validate_shape`) inside the decoder, contrary to the stated decode/judge split

- **Severity:** Info
- **Status:** NEW
- **Refs:** `funded.rs:180-181` (`tx.validate_shape()` in `decode`), contrast `transition.rs` 0x02/0x06 arms ("the decoder reads shape, the transition judges rules").
- **Description.** A block carrying a FundedDeposit with, e.g., `amount_sat < MIN_DEPOSIT_SAT` or `max_base_fee` outside `[MIN, MAX]` fails at `body_transactions` in the node (`Verdict::Reject`) and never reaches `apply_block`. All nodes run the same decoder so there is no split, and the transition re-validates shape anyway; but the transition's own tests cannot exercise these rejects through bytes, and any future second decoder (RPC, tooling) must replicate consensus rules to agree. Harmless while the tag is inert.
- **Confidence:** High.

---

### TX-18 — `Delegate.eligible` is a wire-supplied bit that consensus records verbatim

- **Severity:** Info (gated by `DEPOSIT_ACTIVATION_EPOCH`, which the docs say must never move)
- **Status:** NEW (as a note; the taint machinery is retired per dossier §1.3)
- **Refs:** `transition.rs:3555-3580`.
- **Note.** If the legacy `Delegate` arm were ever armed, a submitter would self-certify eligibility. Also `Delegate.amount_sat` is an unbounded `u128` with only a lower bound; two `u128::MAX` delegations would overflow `accounted_supply_sat`'s sum (a panic). Both unreachable today; worth deleting the arm rather than keeping it inert.
- **Confidence:** High.

---

### TX-19 — Spec/code drift in `BLOCH-L1-FEE-MARKET.md` and `BLOCH-TOKENOMICS-V4.md`

- **Severity:** Info
- **Status:** NEW (specific items); the general "drift is inventoried" statement is KNOWN (dossier §4.10)
- **Items verified:**
  - Fee-market §5: `MAX_BLOCK_TX_BYTES = 262,144` — live cap is `524,288` since epoch 800 (`fee_market.rs:80`, `params.rs BLOCK_BYTES_V2_ACTIVATION_EPOCH = 800`).
  - Fee-market §3.2: eUTXO `verify_gas = n · HYBRID_VERIFY_GAS` with n = inputs — for `TransferV2` (live since 800) it is per witness-table entry. V2 is absent from the spec.
  - Fee-market §3.1 names `TX_FLAT_GAS` without a value (code: 5,000).
  - Fee-market §4.6 and tokenomics §6.1 quote year-1 inflation 436/435 bps; the shipped test pins 434 (`fee_market.rs` `net_inflation_stays_under_the_7_percent_target`).
  - Tokenomics §1 last line and §4: "After the 21 B is fully issued", "supply stays at 21 B" — stale (100 B / 42,853,600,000 validator emission; code asserts match §1's table).
  - Tokenomics §6.3 presents commission-on-delegated issuance as adopted; not shipped (TX-09).
  - Tokenomics §6.3.2 "50% burned": code floors the burn, so the producer receives the odd satoshi (`rewards.rs:70-75`) — a ≤1 sat/block rounding in the producer's favour, not created value.
- **Confidence:** High.

---

### TX-20 — `interfaces.rs` `StateRoots` (14 fields, "closed again at eight components") vs `state_root.rs` (~25 tags) and the frozen `StateTransition::apply_block` doc "error order is consensus-visible"

- **Severity:** Info
- **Status:** KNOWN (GAP-5, `BLOCH-POS-GAPS.md`) for the roots; NEW as a doc note for the error-order claim.
- **Note.** The error variant is never committed; only accept/reject is consensus. Two nodes reporting different rejection reasons for one invalid block is not a split. The stronger claim in the docs led to TX-02's ordering being treated as immovable; it is not.
- **Confidence:** High.

---

### TX-21 — Two block-validation stacks (`derive::validate_block` vs `transition`) still coexist

- **Severity:** Info (the live node reaches only `transition`; `derive` is documented as A1-H3 "standing, documented defect, unreachable from the live node")
- **Status:** KNOWN — GAP-2; `transition.rs:2436-2442`.
- **Confidence:** High.

---

### TX-22 — `CommittedState::genesis` silently overwrites duplicate validator indices / pubkeys from the manifest

- **Severity:** Info (node-side `Manifest::opening_balances` panics on duplicate *outpoints*; I did not find the equivalent guard for duplicate validator indices or pubkeys)
- **Status:** NEW; Low confidence that no guard exists in `genesis.rs` (not read in full).
- **Refs:** `transition.rs:2129-2155` (`registry.insert(v.index, …)`, `pubkey_index.insert(…)` — last write wins), `genesis.rs:1481-1504` (outpoint guard).
- **Confidence:** Medium.

---

## 3. Positive observations (verified, not assumed)

- **Codec injectivity holds.** Every tag uses fixed-width LE scalars, u32 length prefixes, a canonical bool (0x04), a canonical sub-discriminant (0x05), strict 304-byte header decode with no trailing bytes, and a top-level `TrailingBytes` check. `from_canonical_bytes(canonical_bytes(x)) == x` for every reachable `x`; no two byte strings decode to one transaction. Counts are never preallocated from untrusted values; every push is backed by delivered bytes. `TxReader` has no panic site (checked_add, `get`, `try_from`).
- **The ~242 `unwrap`/`expect` in transition.rs are all in the test module.** The non-test path (1–6055) contains zero (the two grep hits are doc comments).
- **No non-determinism on the consensus path**: `BTreeMap`/`BTreeSet` everywhere, `Vec` only in chain-append order, no floats, no clock, no env, no `HashMap`; `thread_local` counters are observability only; `eprintln!` is stderr only.
- **Arithmetic.** Fee products are bounded by compile-time proofs (`fee_market.rs` asserts 1/1b/1c/2) plus the two consensus ceilings (`TipAboveCeiling`, `TxGasCeilingExceeded`) checked before pricing; `part_sat` saturates; sums are `u128`; `sat_u64` saturates; `block_gas/bytes` saturate; the H1 tip×gas panic is closed (test `an_attacker_chosen_tip_cannot_panic_the_transition`).
- **Conservation is exact on every live path.** Transfer: strict equality `spent == created + fee`, fee derived never declared, txid derived never carried, `OutputExists` refuses SHA3 collisions rather than overwriting. FundedDeposit: `spent == amount + change + base(max) + tip`, refund = `base(max) − base(actual)` (monotone, `checked_sub`), `u64::try_from(change)`. Withdraw: `payout + unbacked == staked`, `checked_add` on `written_off`. Slashing: `−31/32` of the penalty is visible to the invariant.
- **Domain separation.** Fourteen distinct 16-byte tags; `DS_TXID` over `DS_SPEND`/`INTENT_DOMAIN` roots; block id ≠ proposal signing root ≠ legacy `BLOCH-BLOCK-ID-V1`; the Merkle uses MARK_LEAF/NODE/EMPTY + kind bytes and promotes odd leaves (no CVE-2012-2459 duplication).
- **Replay.** Transfers are naturally replay-proof via input consumption; `ExitV2`/`RandaoRecommit` bind the inclusion epoch exactly; `FundedDeposit` binds the manifest digest and an expiry; slashing evidence is replay-refused in either order.
- **Header/body binding.** `body_root`, `attestation_root`, `coherence_root` and `state_root` are all recomputed and compared; `parent` is compared against a locally derived id; `slot` and epoch are monotone; `EpochAdvanceTooLarge` bounds the boundary walk before the state clone.
- **Cheap-before-expensive is real**: proposer draw and RANDAO checks precede the single proposer verify, committee membership precedes each attestation verify, and every transfer rule precedes its verifications.
- **Supply cap** is enforced at the source (`close_epoch` clamps to headroom) and as an invariant (`SupplyCapExceeded` on the rolled pre-state); the emission recurrence integrates to the allocation minus a pinned 855,280 sat dust (compile-time assert).
- **Every ADR-041 gate is compile-time asserted equal** and `DEPOSIT_ACTIVATION_EPOCH` is asserted `u64::MAX`; `epoch_gate_active` treats `u64::MAX` as never-armed; the `>=` form used by other gates is equivalent because `epoch_of(u64::MAX) < u64::MAX`.

## 4. Test-coverage gaps noticed (transition.rs 6055–16002, plus `fuzz/`)

1. **No mass legacy-`Exit` test.** Only `below_the_gate_the_legacy_exit_still_applies_and_exit_v2_does_not` (one exit). Nothing pins "63 exits in one block are accepted and the survivor finalizes alone" — the TX-01 scenario — nor that the legacy arm ignores `MAX_EXITS_PER_EPOCH`.
2. **No cross-format twin test** (TX-03): `a_permuted_witness_table_is_refused_and_shares_the_txid` covers intra-V2 order only; `transfer_v2_is_refused_before_the_flag_day_and_its_v1_twin_applies` uses the gate, not the same-epoch twin.
3. **No test that the per-block caps bound execution work** (TX-02); `the_two_block_caps_are_enforced` only checks the verdict.
4. **No same-block chained spend test** (spending an output created earlier in the same block is allowed by the code and unpinned).
5. **No zero-output ("burn everything to fee") transfer test.**
6. **No KATs for `txid` / `spend_signing_root` / `canonical_bytes` vectors** (only round-trips and one fork-choice golden root); GAP-6 remains open for the transaction codec. A cross-implementation vector file would catch a symmetric encoder/decoder bug.
7. **No fuzz target exercises `PosTransaction::from_canonical_bytes`** (`fuzz/fuzz_targets/` has `pos_envelope_decode`, `pos_header_decode`, `pos_attestation_decode`; transactions inside the envelope are opaque bytes there).
8. **Withdrawal edge cases untested**: slashed-but-funded withdrawal, withdrawal after the deterministic `(txid_v, 0)` output was spent, zero-payout write-off-only withdrawal.
9. **FundedDeposit at exactly the 1% cap with a leaked roster** (TX-05) — no test of mempool/consensus agreement on `total_active`.
10. **Genesis duplicate index/pubkey** (TX-22) — no test in transition.rs.
11. `the_boundary_roll_is_judged_on_the_block_path` and `supply_is_conserved_across_*` exercise the passing side well and one mutation (`mint_from_nothing`); there is no mutation for a coin-*destroying* bug, which the one-sided rule would not catch (by design, but worth stating in a test comment).

## 5. Residual risk / not covered

- **`bloch-crypto` verifier behaviour** (another auditor): whether `verify_with_key` rejects signature/pubkey blobs with trailing bytes or non-canonical encodings. If it does not, V1 witnesses (and V2 table entries) are third-party malleable within the declared `tx_bytes` slack — same `txid`, different `canonical_bytes` — extending TX-03 to multi-input transfers. I did not verify this.
- **Epoch-close/finality/committee logic** (`finality.rs`, `committees.rs`, `forkchoice.rs`, `beacon.rs`, `genesis_cohort.rs`, `delegation.rs`, `staking.rs` internals): read only where transaction execution depends on them. The VAD-04 fork-choice-weight divergence and the F6 seed look-ahead (inert `ANCESTRY_SEED_ACTIVATION_EPOCH`) are out of scope here.
- **Node engine** (`engine.rs` 11,480 lines): read only for `apply_block` invocation, mempool admissibility, probe-and-bar, frame limits. Reorg handling, sync, RPC and clock policy are not covered.
- **Genesis manifest construction** (`genesis.rs`): only the outpoint-duplicate guard was checked.
- **Performance figures** in TX-02 are estimates from code structure, not measurements; the lead's dynamic run would settle the per-insert SMT cost.
- I did not run `cargo test`; test coverage statements are from reading test names and selected bodies.
