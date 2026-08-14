<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch — CertiK pre-audit dossier

Document: CERTIK-PRE-AUDIT-DOSSIER
Status: DRAFT for founder review — prepared before engagement, to be handed to CertiK
Prepared: 2026-08-12, against branch `integration/pos-modules` at `470b608`
Revised: 2026-08-14, against the **live Genesis-4 chain**. Every figure and
every status in this dossier was re-checked against the terminal Genesis-3
snapshot and against `crates/bloch-pos-node/src/`; corrections are marked in
place rather than folded in silently, because a dossier whose numbers move
without a record is worth nothing to an auditor.
Supersedes: the 2026-08-12 draft prepared at `84ca42a`, which predates the
100-billion redenomination, the supply-cap consensus invariant and the halt
height moving to 50,000 (which the chain never reached — see §0.0)
Repository: `gitlab.com/blochsispow-group/bloch-pos` (private at time of writing — see check 20)
License: AGPL-3.0-or-later (repo `LICENSE`; workspace `Cargo.toml:24`)

---

## 0.0 The state of the world this dossier is now written against

**Genesis-3 has halted and Genesis-4 is live.** The proof-of-work chain
stopped permanently at height **39,918** on 2026-08-13 — not at 50,000, the
value decided on 2026-08-12 and quoted throughout the original draft.
Genesis-4, proof of stake, has been producing and finalising since
**21:31:19 UTC on 2026-08-13**: 30-second slots, 32-slot epochs, Casper-style
justification and finalisation by epoch, hybrid ML-DSA-65 ‖ Falcon-1024
signatures on every consensus path
(`crates/bloch-pos-committee/src/params.rs`; `crates/bloch-pos-node/src/rpc.rs`
`Finality`). Public read RPC: `https://posternlabs.com/g4rpc`.

Three consequences an auditor should hold while reading the rest:

1. **The concentration figures moved, and the height they were measured at was
   wrong.** The original draft measured "at height 43,172". The chain was never
   at that height: 43,172 was a **block count** mislabelled as a height, and in
   a DAG the two differ by design. The terminal measurement is height
   **39,918**, **452,726** outputs, **18,146,400,000 BLOCH** carryover
   (`tokenomics_v4.rs` `CARRYOVER_MEASURED_HEIGHT`, `CARRYOVER_MEASURED_UTXOS`,
   `CARRYOVER_TOTAL_BLOCH`, whose doc comment records this exact trap). Every
   figure below is restated against the terminal snapshot. **The correction is
   not an improvement**: concentration went from 93.96% of a mismeasured set to
   **93.94%** of the real one. It is, to two decimal places, the same finding.
2. **Two open gaps in §4 closed and are marked closed**; one — the claim that
   the PoS node is a devnet skeleton — was **false by the time the chain
   launched** and is corrected rather than removed.
3. **Launching without the external audit and without the distribution gates
   is itself a finding**, and this dossier now states it as one rather than
   describing the gates as things standing between the code and a mainnet. See
   §4 item 2 and §4 item 9.

---

## 0. What this document is, and one thing it refuses to do

CertiK's Skynet **token scan** (the model given to us: the WBNB scan on BSC,
22 passed / 1 attention / 0 alerts) is a bytecode analyser for deployed EVM
contracts. It reads a contract at an address and looks for mint functions,
owner modifiers, proxy slots, tax logic.

**That scanner cannot be run against Bloch, and this dossier will not pretend
otherwise.** BLCH is the base asset of an L1, not a contract: there is no
address to scan, no owner to renounce, no proxy slot to inspect. EVM at L1 is
a design in progress (`docs/specs/BLOCH-L1-EVM-STATE-MODEL.md`), not a
deployed token, and there is no Skynet listing to apply for until that surface
exists.

What we can do — and what this dossier does — is answer, for every check the
scanner runs, whether the *property behind the check* holds on Bloch, by what
mechanism, and where the evidence is. A check that does not apply is never
answered with a bare "N/A": it gets "does not apply because X, and the thing
that plays its role here is Y" — and where nothing plays that role, the
verdict is FAIL and is written as FAIL.

What CertiK would actually audit for a chain like Bloch is the **node and
consensus code**, not a contract. Section 2 defines that surface, with
measured line counts and measured test results. Section 3 lists the findings
we found and fixed ourselves, with commits and regression tests. Section 4
lists the open gaps without softening. Section 5 flags internal
contradictions we found while preparing this document, because an auditor
would find them anyway.

Verdicts used below:

- **PASS** — the property holds, evidenced in code.
- **FAIL** — the property does not hold. No reframing.
- **N/A — substitute** — the check is meaningless for an L1 base asset; the
  row names the mechanism that plays its role and whether *that* holds.

---

## 0.1 Decisions of record — what changed on 2026-08-12

An auditor reading an earlier copy of this dossier will find different numbers.
These are the changes, and the reason each is stated here rather than quietly
folded in is that a document whose figures move without a record is worth
nothing to an auditor.

| Decision | Before | Now | Where it lives |
|---|---|---|---|
| Total supply | 21,000,000,000 (superseded) | **100,000,000,000** | `tokenomics_v4.rs` |
| Method | — | Pure redenomination, ratio `100/21` applied to every allocation. Shares unchanged, nobody diluted. Compile-time assertions prove each bucket scaled by the same ratio. | `tokenomics_v4.rs` (`SPLIT_NUMERATOR`/`SPLIT_DENOMINATOR`) |
| Supply cap | Constant respected by construction | **Consensus invariant.** Cumulative issued supply is a committed state component; a block whose pre-state exceeds the cap is rejected. | `state_root.rs` tag `0x14`; `transition.rs` (`SupplyCapExceeded`) |
| Validator bond | 100,000 BLCH (superseded) | **25,000 BLCH** — Ethereum's 32 ETH as the same fraction of supply, rounded down | `staking.rs` |
| Genesis-3 halt | height 80,000 → decided 50,000 | **the chain actually stopped at height 39,918**, 2026-08-13 | `crates/bloch-pos-committee/src/tokenomics_v4.rs` `CARRYOVER_MEASURED_HEIGHT` |

Three consequences that are costs, not details, and that an auditor should see
named rather than discover:

1. **10^19 satoshis does not fit a signed 64-bit integer.** The supply is 54.2%
   of `u64::MAX` and 108% of `i64::MAX`. Every quantity inside the consensus
   crate is `u128` and unaffected. The Go SDK types `Satoshis` as `int64` and
   **must migrate before Genesis-4 ships**; so must any exchange integration
   that made the same choice. The compile-time assertion was inverted to state
   this rather than deleted.
2. **The emission curve had to be re-derived, not scaled.** It is denominated in
   absolute satoshis, so leaving it unchanged would have cut year-one inflation
   from 4.37% to 0.91% — a monetary policy change wearing the costume of a unit
   change. Multiplying it by `100/21` instead *overshot* the allocation by
   65,042,160 sat, because integer truncation inside the per-slot division does
   not commute with scaling. The constant is now the largest value whose 40-year
   sum stays under the allocation, found by binary search over the emitter's own
   recurrence, leaving 176,880 sat unissued.
3. **Per-address conversion cannot be exact.** `100/21` never divides a power of
   ten, so no choice of decimal places makes individual balances scale exactly.
   Conversion is floor division; the remainder is absorbed by the founder's
   carried-over balance so the total closes at the cap. Bucket totals *are*
   exact — every allocation is already a multiple of 21 million.

---

## 1. The token-scan checklist, answered for an L1

The WBNB model scan evaluates the 23 checks below (scored 22 passed,
1 attention — the attention being major-holder ratio at 39.28%). File
references are to this repository at `470b608`.

| # | Check | Applies to Bloch? | Verdict | Evidence |
|---|---|---|---|---|
| **Market** | | | | |
| 1 | Buy tax | No — no contract, no tax logic on acquiring BLCH. Role played by: base-layer transaction fee under an EIP-1559-style controller; no party receives a privileged cut (the burned share is burned by never being credited). | N/A — substitute holds | `crates/bloch-pos-committee/src/fee_market.rs:193` (`next_base_fee`); `src/rewards.rs:65-75` (`split_fees_at`); `src/transition.rs:1503-1508` |
| 2 | Sell tax | No — same as check 1; disposing of BLCH pays the same fee as any transaction, to no privileged party. | N/A — substitute holds | Same as check 1 |
| 3 | Buy restrictions | No contract gate. Role played by: the closed transaction set — `Transfer` is one of exactly five `PosTransaction` variants, with no admission oracle; the provenance/taint machinery is retired-inert by consensus ("no eligibility oracle may produce `true`"). | N/A — substitute holds | `crates/bloch-pos-committee/src/transition.rs:175-220`; `src/staking.rs:172-183`, `:247` |
| 4 | Sell restrictions | No contract gate. Role played by: permissionless spend/exit/withdrawal. The only delays are stake-scoped and disclosed (`WITHDRAWAL_DELAY_EPOCHS`, delegation cool-down); withdrawal validation is a pure predicate with no approver. | N/A — substitute holds | `crates/bloch-pos-committee/src/staking.rs:106`, `:489-506`; `src/delegation.rs:110` |
| 5 | Anti-whale mechanism | No transfer/balance limits exist (in token-scan terms, none of the risk-flagged kind). Stake-side concentration bounds exist: per-validator cap of 1% of active stake, genesis-cohort declining cap, 25 bps churn. All three are honest about their limits: Sybil-bypassable by splitting, per their own doc comments. See §1.1. | N/A — substitute exists, with stated limits | `crates/bloch-pos-committee/src/delegation.rs:90`, `:103`; `src/genesis_cohort.rs:129-194`; `src/transition.rs:590`, `:857-858` |
| 6 | Anti-whale modifiability | No privileged role can modify the caps in check 5: they are compile-time constants with no setter, no governance hook, no admin path (see check-23 grep). Changing them requires a code change every operator must adopt (a hard fork). | PASS (via substitute) | `crates/bloch-pos-committee/src/delegation.rs:90-110`; §1.3 grep table |
| 7 | Honeypot (can buy, cannot sell) | No code path can block disposal: exit is self-signed, withdrawal needs no signature at all and has exactly three structural reject reasons (`NotExited`, `DelayNotElapsed`, `AlreadyWithdrawn`). Honest caveat: disposal is *market*-limited (no exchange listing, thin liquidity) — a fact for the listing conversation, not a protocol mechanism. | N/A — substitute holds | `crates/bloch-pos-committee/src/staking.rs:406-438`, `:470-479`, `:489-506` |
| 8 | Self-destruct | No `selfdestruct` analogue, and no hidden kill switch (check-23 grep). One disclosed, deliberate exception must be named, and it has now happened: Genesis-3 carried a **terminal-height consensus rule** and **stopped permanently at height 39,918 on 2026-08-13**, with Genesis-4 opening from the signed snapshot. It was public, one-time, and snapshot-preserving, not a concealed destruct path. **Genesis-4 itself carries no terminal height** — `terminal_height()` is exhaustive with no wildcard arm, so a new chain-id cannot silently inherit one. | N/A — substitute holds, with disclosure | `crates/bloch-pos-committee/src/tokenomics_v4.rs` `CARRYOVER_MEASURED_HEIGHT`; `docs/specs/BLOCH-TOKENOMICS-V4.md` §3.2; `docs/FLEET-BRIEF-2026-08-11.md` |
| 9 | **Major holder concentration** | **Applies directly — the one check that maps one-to-one, and the one that fails hardest.** Measured at the **terminal** Genesis-3 snapshot (height **39,918**, 452,726 outputs, 16 addresses): the largest single address holds **93.94%** of the carried-over supply (17,046,829,380 of 18,146,400,000 BLOCH). Carried balances are liquid **and stakeable** (founder decision 2026-08-11), so if that balance stakes the **Nakamoto coefficient is 1**. Independently of staking: all **64 live Genesis-4 validators are operated by one entity**, and of the 57,146,400,000 BLOCH issued at slot 0, **56,046,829,380 (98.08%)** is founder- or Foundation-held, leaving 1,099,570,620 (1.92%) with third parties. WBNB drew its only attention flag at 39.28%. | **FAIL** | `crates/bloch-pos-committee/src/tokenomics_v4.rs` (`LARGEST_CARRYOVER_ADDRESS_BLOCH`, `CARRYOVER_TOTAL_BLOCH`, `CARRYOVER_MEASURED_HEIGHT`, `FOUNDER_TOTAL_BLOCH`, `FOUNDATION_HELD_BLOCH`, `GENESIS_ISSUED_SAT`); `docs/specs/BLOCH-TOKENOMICS-V4.md` §4A, §4A.1. Full treatment in §1.1 |
| 10 | Mintable | No mint function, no privileged issuance: `PosTransaction` is a closed five-variant enum with no `Mint`; the only balance-increasing writes in the transition are the emission curve and fee compounding, both pure functions of slot/stake. **The block-level cap invariant that the original draft listed as an open gap has since landed**: cumulative issued supply is a committed state leaf (`state_root.rs` `TAG_ISSUED_SUPPLY = 0x14`) and a block that would carry issuance past the cap is rejected with `TransitionError::SupplyCapExceeded` (`transition.rs:2311`, test at `:5254`). See §1.2. | PASS (no privileged mint; cap now enforced as a consensus invariant) | `crates/bloch-pos-committee/src/transition.rs:175-220`, `:2307-2311`, `:5254`; `src/state_root.rs:183`; `src/tokenomics_v4.rs` (`TOTAL_SUPPLY_BLOCH` doc comment) |
| 11 | Blacklist | None. A crate-wide grep for blacklist/freeze/ban/censor machinery returns prose and retired-inert fields only (§1.3). The Genesis-3-era taint set is dismantled by named-zero constants so anything still consulting it fails loudly. (Token-level `Gate::Deny` exists in `bloch-euvm` — a regulated-asset primitive in a crate that is **not consensus-wired**; see §2.) | PASS | §1.3 grep table; `crates/bloch-pos-committee/src/staking.rs:247`; `src/tokenomics_v4.rs:106`; `crates/bloch-euvm/src/state.rs:558-575` |
| 12 | Whitelist | None at chain level — no allowlist gates participation in transfer, staking, delegation, or block production beyond the public parameter thresholds. (`MembershipList` in `bloch-euvm` is token-scoped and not consensus-wired.) | PASS | §1.3 grep table; `crates/bloch-euvm/src/state.rs:520` |
| 13 | Hidden ownership | No hidden control mechanism (§1.3 grep). Governance is explicitly **not** ownerless — the earlier "ownerless" claim was formally retracted — and the structure is disclosed: two entities, founder allocates the genesis validator cohort under a consensus-coded taper. Honest limit: beneficial ownership of the 14 non-founder carryover addresses is asserted, not provable on-chain — the tokenomics doc treats the whole non-founder remainder as "independent parties" without attribution. | PASS (disclosed, not hidden) — with the attribution caveat | `docs/adr/ADR-036-*`; `docs/specs/BLOCH-ENTITY-STRUCTURE.md`; `crates/bloch-pos-committee/src/genesis_cohort.rs:29-48` |
| 14 | Proxy contract (upgradeable logic) | No proxy slot exists. Role played by: node releases — operators choose what to run, and the release-integrity discipline (reproducible builds, published == fleet binary) is the substitute control. That discipline is specified (gate G8, `REPRO.md`) but **G8 is unmeasured** (§4). | N/A — substitute specified, not yet measured | `REPRO.md`; `repro-manifest.sh`; `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §11 (G8) |
| 15 | Balance modification (privileged) | No privileged balance write exists. Slashing is the only involuntary balance reduction and it requires structurally valid evidence validated inside the state transition — invalid evidence rejects the whole block; forged evidence slashes nobody (regression-tested). | PASS | `crates/bloch-pos-committee/src/transition.rs:1177`, `:1186-1188`, `:1482-1489`; `src/transition.rs` tests at `:2198`, `:2372` |
| 16 | Tax modification by privileged roles | The fee split constants have no setter and no role that can change them; the base fee moves only by the in-protocol controller as a function of block usage. Change requires a hard fork. | PASS (via substitute) | `crates/bloch-pos-committee/src/rewards.rs:38`, `:42`, `:65-75`; `src/fee_market.rs:193` |
| 17 | Transfer cooldown | None on transfers. The delays that exist are stake-scoped, constant, disclosed, and apply equally to everyone — including the founder (`ACTIVATION_DELAY_EPOCHS`, `EXIT_DELAY_EPOCHS`, `WITHDRAWAL_DELAY_EPOCHS`, delegation `COOLDOWN_EPOCHS`). | PASS | `crates/bloch-pos-committee/src/staking.rs:89`, `:99`, `:106`; `src/delegation.rs:110` |
| 18 | Transfer pausability | No pause authority. The only halt-shaped code is (a) the node-local `HaltForOperator` on a checkpoint conflict, which by test **cannot** override a node's own finality, and (b) the disclosed one-time terminal height (check 8). | PASS — with the terminal-height disclosure | `crates/bloch-pos-committee/src/ws.rs:602-623`, test `:1112` (`published_checkpoint_never_overrides_own_finality`) |
| 19 | Ownership renunciation | Does not apply — no owner object to renounce. Role played by: the genesis-cohort consensus rule that tapers the founder-operated cohort's combined weight from 100% to below one third within one year (a shrink-only, publish-once set that is part of chain identity). Honest limit: unlike a renounced contract, the founder retains real control today — this row does not offset check 9's FAIL. | N/A — substitute exists, control today remains with the founder | `crates/bloch-pos-committee/src/genesis_cohort.rs:58-81`, `:129-194`; `src/transition.rs:2647-2648`; test `src/transition.rs:2408` |
| 20 | **Open-source code** | Applies directly. Licensed AGPL-3.0-or-later throughout, and the decentralisation ADR rests on "code open-sourced *before* launch" — but **the repository is private at time of writing**, and no document commits to a publication date, URL, or process. The predecessor Genesis-3 repo and binaries are public; this one is not yet. | **FAIL** (today) — pass requires publication before engagement or a committed date | `LICENSE:1`; `Cargo.toml:24`; `docs/adr/ADR-039-agpl-license-pos-crates.md`; `docs/adr/ADR-033-decentralization-model.md:52` |
| 21 | External calls | No consensus-time external calls: no oracles, no cross-contract calls, no network I/O inside validation. Role played by: dependency supply chain, governed by `cargo-deny`/`cargo-audit` config and a vendored, symbol-pinned PQ stack; the Coherence prover (SP1) runs client-side — nodes verify proofs, never call out. | N/A — substitute holds | `deny.toml`; `audit.toml`; `crates/bloch-crypto/src/crypto/mod.rs:492-529` (symbol tripwire); `crates/coherence-prover/README.md:4-5,44-53` |
| 22 | Withdrawal function (owner can drain) | No contract balance and no function that drains one. Role played by: key custody for the genesis allocations — the Foundation custodies 29% of supply at genesis, and the custody plan (air-gap ceremony, sharding, exposure windows) is written but DRAFT. The original draft's line "no production key exists yet" **is no longer true**: Genesis-4 launched, so a genesis manifest and 64 validator keys exist and are in use. Whether they were produced under the DRAFT plan is not evidenced in this repository and this dossier does not assert it either way (§4 item 3). Institutional custody, not protocol code, is the real surface here. | N/A — substitute is a DRAFT plan against keys that now exist; flagged as a gap | `docs/specs/BLOCH-GENESIS-KEYS.md` (status line); `docs/specs/BLOCH-ENTITY-STRUCTURE.md` §3; `docs/research/MOFN-CUSTODY-DECISION.md` |
| 23 | Backdoor ownership recovery | None. The crate-wide grep for owner/admin/sudo/master-key/override/emergency paths (§1.3) returns no control mechanism — every hit is prose, a frozen-interface artifact, or the retired taint set. | PASS | §1.3 grep table |

Score, stated plainly: of the two checks that apply one-to-one, **both fail
today** — concentration (9) and open-source publication (20). Of the
remainder, the substitute mechanisms hold in code, with two carrying open
caveats (14: G8 unmeasured; 22: custody plan DRAFT against keys that now
exist). Check 10's caveat — the cap invariant — has closed since the earlier
draft and is now enforced in validation.

One thing the score does not capture, and an auditor should not have to infer:
**the chain launched anyway.** The distribution gates G1–G4 were written as
Go/No-Go conditions on the transition, none has ever had an observed value
above zero, and Genesis-4 went live on 2026-08-13 without them being met and
without the external audit this dossier was prepared for. That is a governance
finding, not a code finding, and it is stated here rather than left for §4.

### 1.1 Concentration — the exact numbers, and what bounds them (check 9)

This is the finding an auditor will lead with, so we lead with it.

**Which snapshot every number below comes from.** All carryover figures are the
**terminal** Genesis-3 measurement: **height 39,918**, **452,726** outputs,
**16 addresses**, re-taken 2026-08-13 from a live node and pinned in code
(`tokenomics_v4.rs` `CARRYOVER_MEASURED_HEIGHT`, `CARRYOVER_MEASURED_UTXOS`,
`CARRYOVER_TOTAL_BLOCH`, `LARGEST_CARRYOVER_ADDRESS_BLOCH`, with
`CARRYOVER_MEASURED_ROOT` and both file digests published so the measurement
is checkable rather than asserted).

The earlier draft of this dossier quoted a different set — 17,970,880,000 BLCH
across 15 addresses and 448,337 UTXOs, "at height 43,172". Two things were
wrong with it and both are stated rather than folded in. **The height label was
wrong**: the chain was never at height 43,172; that figure was a *block count*,
and in a DAG the two differ by design. **The measurement was provisional**:
Genesis-3 kept minting until it halted, so the set grew. Both figures are
restated here against the terminal snapshot, and the substantive answer does
not move:

| Measure | Earlier draft (block-count 43,172, provisional) | **Terminal (height 39,918)** |
|---|---|---|
| Carryover total | 17,970,880,000 BLOCH | **18,146,400,000 BLOCH** |
| Outputs / addresses | 448,337 / 15 | **452,726 / 16** |
| Largest single address | 16,886,549,523 BLOCH | **17,046,829,380 BLOCH** |
| **Concentration** | 93.96% | **93.94%** |

**This is not an improvement, and must not be read as one.** Two hundredths of
a percentage point on a figure of 94% is measurement noise, not distribution.
The largest single address holds essentially the same share of a slightly
larger set, and it is the founder's.

The rest of the finding, restated on the terminal numbers:

- The carryover set is **18,146,400,000 BLOCH** across **16 addresses** and
  452,726 UTXOs. The largest address holds **17,046,829,380 BLOCH — 93.94% of
  the carryover** — and is the founder's.
- The carried-over balance is liquid and therefore **stakeable** (founder
  decision 2026-08-11, pinned by
  `staking.rs::carryover_liquid_balance_is_stakeable` and
  `tests/committee.rs::carryover_liquid_balance_delegates_as_stake`). If it
  stakes and others do not, the founder holds ~94% of active stake — a
  **Nakamoto coefficient of 1**, computed at the one-third threshold.
- Founder total across carryover plus the new 10% grant (10-year cliff,
  40-year linear vest): **27.04% of eventual total supply**
  (27,046,829,380 BLOCH, compile-pinned at 2704 bps,
  `tokenomics_v4.rs::FOUNDER_TOTAL_BLOCH`). Up from the 26.89% the earlier
  draft quoted, because the re-measured carryover is larger and the founder
  holds 93.94% of it — the number moved in the unflattering direction and is
  recorded that way.
- **Of the 57,146,400,000 BLOCH issued at slot 0** (`GENESIS_ISSUED_SAT` = cap
  − validator emission), **27,046,829,380 is the founder's and 29,000,000,000
  is the Foundation's** (`FOUNDATION_HELD_BLOCH`: VC 10 B, team 10 B,
  marketing 4 B, liquidity 5 B). Together **56,046,829,380 of 57,146,400,000
  — 98.08%** — leaving **1,099,570,620 BLOCH, 1.92% of genesis supply**, in
  third-party hands. Stated precisely: this is *founder and Foundation
  together*, across six allocation buckets. It is **not** one key, and this
  dossier does not claim it is — the live genesis manifest is not committed to
  this repository, so the recipient script hashes of the five non-carryover
  buckets are not verifiable here.

**And the finding the original draft could not yet state, because the chain had
not launched: all 64 Genesis-4 validators are operated by a single entity.**
There is no independent validator on the live network. One operator can stall
finality and one operator can halt the chain. Nor can a third party join today:
the live transport is a point-to-point TCP full mesh with a fixed peer list, no
discovery and no authentication (`crates/bloch-pos-node/src/net.rs`), and
`Deposit`/`Delegate` transactions are refused at every node's mempool because
bonding is not yet funded from the UTXO set — a `Deposit` names an amount,
spends no output, and would therefore mint stake from nothing
(`crates/bloch-pos-node/src/engine.rs:1885-1907`). Until both are fixed there
is **no permissionless path to becoming a validator**, which means the
Nakamoto coefficient of the live chain is 1 by operator count regardless of
what any holder does with their coins.

The mechanisms that bound this, and — stated with equal weight — what each
does *not* reach:

| Mechanism | What it does | What it does not do |
|---|---|---|
| Genesis-cohort declining cap (`genesis_cohort.rs:75-81`, `:129-194`; enforced at `transition.rs:590`) | Consensus rule: the founder-operated genesis cohort's combined duty weight tapers 100% → 33.3% over 12 months; the cohort list is publish-once, shrink-only, part of chain identity. | Binds only the named cohort. Nothing stops funding new validators at addresses outside it; no on-chain rule sees beneficial ownership. |
| Per-validator cap: 1% of active stake (`delegation.rs:103`; fixed-point at `delegation.rs:337-349`; `transition.rs:857-858`) | No single validator identity exceeds 1% of effective stake. | Sybil-bypassable by splitting one balance across many validators — the code's own doc comment says so. |
| Churn rate 25 bps/epoch (`delegation.rs:90`, was 900; `BLOCH-POS-STAKE-CHURN.md`, ACCEPTED AND APPLIED) | Slows stake movement: a stalling third now takes ~43 hours instead of ~75 minutes — visibility time for operators. | Time, not prevention. Does not reduce anyone's holdings. |

And the arithmetic that closes the escape hatch (`BLOCH-TOKENOMICS-V4.md`
§4A.1): rewards are pro-rata to stake, so compounding preserves stake
*shares*. On the terminal snapshot, independent parties hold
1,099,570,620 / 18,146,400,000 = **6.06%** of the carryover (the earlier draft
read 6.03% against the provisional set — again, the same finding); gate G1
requires ≥ 15% of circulating in independent hands. Therefore **G1 is
unreachable by emission alone — not at year five, not at year forty. The only
thing that moves it is coins changing hands.** If the founder abstains from
staking entirely, the earliest G1 crossing under first-year emission plus
unlocks is ≈ month 9 — a bound, not a forecast.

Two facts about the live chain make even that bound theoretical today: the
64 validators are one operator's, and `Deposit`/`Delegate` are refused at the
mempool, so **independent stake cannot currently be created at all**. G1's
observed value is 0% and cannot move until bonding is funded from the UTXO set
and the transport admits strangers.

Verdict: FAIL, and it stays FAIL until the measured number changes. The
protocol constrains the founder's *validator weight*; it does not and cannot
constrain the founder's *holdings*. Any framing of the three mechanisms above
as fixing concentration would be false, and we do not offer one.

### 1.2 Mintable — what "fixed supply" is and is not, today (check 10)

Three layers, in decreasing strength:

1. **No privileged issuance path exists.** The transaction set is closed
   (`transition.rs:175-220`); the emission curve is a pure function that
   integrates to exactly the validator allocation and returns 0 after
   `EMISSION_SLOTS` (`tokenomics_v4.rs:406-421`); allocations sum to total
   supply by compile-time assertion (`tokenomics_v4.rs:217-232`).
2. **Divergence is caught indirectly.** A node minting off-curve computes a
   different `state_root` and forks itself off. Property tests pin the
   envelope (`tests/properties.rs:624`, `:665-681`).
3. **The decided direct invariant now exists — this gap is closed.** The
   decision of record (2026-08-12) was that every node refuses a block whose
   cumulative issuance would exceed the cap. The earlier draft of this dossier
   grepped for it and found nothing. It has since landed: cumulative issued
   supply is a committed component of the state root
   (`state_root.rs:183`, `TAG_ISSUED_SUPPLY = 0x14`; seeded at genesis from
   `GENESIS_ISSUED_SAT`), and `compute_post_state` rejects the block with
   `TransitionError::SupplyCapExceeded` when the committed counter would pass
   `TOTAL_SUPPLY_SAT` (`transition.rs:2307-2311`, regression test at
   `transition.rs:5254`). It is enforced in *validation*, in `u128`, against a
   counter every node commits — so two nodes cannot disagree about how much
   has been issued. The four verification points the Centralization dossier
   listed for "when it lands" are the right ones for an auditor to re-check.

The claim to make to an auditor, at its true strength and no stronger: *no
mechanism inside the protocol can raise the supply* — no vote, no key, no
governance path. A hard fork adopted by every operator can change any rule;
"impossible to change" would be false and we do not claim it.

### 1.3 The grep behind checks 6, 11, 12, 13, 18, 23

The claim "no privileged control machinery" is testable, so we tested it: a
crate-wide grep of `bloch-pos-committee/src/` for
`blacklist|whitelist|allowlist|denylist|pause|freeze|owner|admin|privileged|governance|multisig|emergency|kill-switch|sudo|authority|master key|veto|council|override|ban|censor|upgrade`
returns **no control mechanism**. Every hit is one of: doc prose
(threat-model rationale), the *interface* freeze (a frozen API surface, not
an account freeze), the node-local `ws.rs` checkpoint-conflict refusal that
by test cannot override finality (`ws.rs:1112`), or the **retired taint
set** — kept as inert, named-zero artifacts precisely so that any code still
consulting it fails loudly (`staking.rs:172-183`, `:247`;
`delegation.rs:124-130`; `tokenomics_v4.rs:106`; `state_root.rs:878`).

---

## 2. What CertiK would actually audit: the real surface

There is no contract to scan. The audit surface for Bloch is the node and
consensus code. We propose the engagement cover these four crates, in this
order:

| Crate | Role | Source LOC | Test LOC | Tests (measured) | Result |
|---|---|---:|---:|---:|---|
| `crates/bloch-pos-committee` | PoS consensus: state transition, staking, delegation, slashing, fork choice (LMD-GHOST), finality, fee market, tokenomics, state root | 15,614 | 4,088 | **334** | all pass, 0 failed |
| `crates/coherence-core` | Shielded pool (C1-frozen): SHAKE-256 commitments/nullifiers, commitment tree, sparse-Merkle nullifier set (C1.1, ratified), spend statement | 708 | 48 | **12** | all pass, 0 failed |
| `crates/bloch-crypto` | Hybrid PQ signature suite: ML-DSA-65 ‖ Falcon-1024 AND-composition, suite dispatch, Falcon constant-time `clean` pin, addresses | 9,823 | 309 | **137** | all pass, 0 failed (4 ignored) — after a one-line test-compile fix, see method note |
| `crates/bloch-euvm` | eUTXO validator VM + Ustav (PSTRN-1) charter compiler + Kirpich fail-closed audit gate — **not consensus-wired**; the base other products build on | 10,766 | 1,808 | **331** | all pass, 0 failed (4 ignored) |

Method, so the numbers are reproducible: LOC is `wc -l` over `*.rs` under
each crate's `src/` and `tests/`; test counts are the sum of `N passed` over
every `test result:` line of `cargo test --release` run per crate on
2026-08-12 at commit `84ca42a`. We did **not** run a branch/line coverage
instrument (tarpaulin/llvm-cov); the coverage statement we can make honestly
is test count and pass rate, not percentage coverage.

One measurement finding, reported because an auditor would hit it on day
one: at commit `84ca42a`, `cargo test` for `bloch-crypto` **did not
compile** — the integration test `tests/tx_under_dual_and.rs` had three
`Block` initializers stale against the `auxpow` field added to the struct
(`src/core/mod.rs:1466`). The 137-test result above was measured after a
three-line fix (`auxpow: None` in each initializer), committed alongside
this dossier. The lesson stands regardless of the fix: integration-test
targets in the Genesis-3 crates are not gating CI at present.

Context the auditor needs about the surface:

- `bloch-pos-committee` is a pure consensus crate: state in, state out, no
  I/O. The committed state is a closed 19-leaf list expressed twice — as a
  type (`state_root.rs:851-892`) and as tags (`state_root.rs:107-150`) — and
  the crate carries structural self-tests that an auditor should read first:
  `header.rs:626` (`single_derivation_path`, a source-scanning test that
  fails the build if block identity acquires a second derivation),
  `transition.rs:2518` (`every_committed_state_field_is_bound_by_the_root`),
  and `tests/one_state_root.rs` (the written statement of the
  one-derivation-path rule).
- `coherence-core` is small on purpose: it is the C1-frozen format layer.
  There is **no trusted setup** anywhere — the proof system is SP1 raw
  FRI-STARK (hash-based; the Groth16/Plonk wrappers are explicitly
  forbidden, `coherence-prover/README.md:44-53`), and the crate's only
  dependency is `sha3`.
- `bloch-crypto`'s highest-value review target is the one gate G7 already
  requires external review of: the online Falcon-1024 signing path
  (`docs/specs/BLOCH-FALCON-ONLINE-SIGNING.md`), including the symbol
  tripwire that proves the AVX2/AARCH64 non-constant-time variants are not
  linked (`crypto/mod.rs:492-529`) and the CI guard
  (`scripts/falcon-clean-guard.sh`).
- `bloch-euvm` is in scope not because it is consensus (it is not wired, and
  says so at `src/lib.rs:9-10`) but because Ustav-at-L1 is a decided
  direction (`docs/adr/ADR-040-evm-and-ustav-at-l1.md`) and two of the seven
  self-found findings (§3) live here — auditing it before promotion is the
  point of auditing it.

Supporting material the auditor receives with the code: the two PoS threat
models (`BLOCH-POS-THREAT-MODEL.md`, `-2.md`), the frozen interface contract
(`BLOCH-POS-INTERFACES.md`), the master migration design with the G1–G11
gates (`BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §11), the honest gap inventory
(`BLOCH-POS-GAPS.md`), the C1/C1.1 freeze docs, and the two prior internal
audits (`docs/audit/AUDIT-2026-04-20_ERA1.md`, `docs/audit/groundstate_audit.md`).
`docs/SECURITY_SELF_ASSESSMENT.md` states the prior-audit position plainly:
**zero external audits to date**. This engagement would be the first.

---

## 3. Findings we found and fixed ourselves

Every item below was found by our own adversarial review, fixed, and pinned
with a regression test — dates, commits, and test locations included, because
an auditor who re-derives any of these should find our fix and our test
already waiting.

**F-1. Two block identities (2026-08-11).** At integration, `interfaces` had
a public tuple `BlockId` mintable from any 32 bytes, coexisting with the
opaque `header::BlockId`; two disagreeing `BlockHeaderV4` types and three
copies of the canonical header serialisation existed — 9 construction sites
where the design allows 1. Fixed in `62ca5af` (dedup; `interfaces`
re-exports `header`; genesis lost its literal id). The guard had been built
in advance in `83cae4f`: `single_derivation_path`
(`src/header.rs:626`) scans the crate source and fails on any second
construction site, any manual trait impl, any alias, and any mention of the
legacy `pow_hash`/`block_hash` identities. This class of bug caused a real
Genesis-3 outage (block-DAG keyed by `pow_hash` while storage keyed by
`block_hash`), which is why the guard is structural, not a code review note.

**F-2. The header did not commit to the body — in the code the node actually
runs (2026-08-12).** `compute_post_state` never checked `body_root`,
`attestation_root`, or `coherence_root`; those checks lived only in a
parallel validator with no caller, and 178 green tests said nothing because
the test builder stamped zeros. One `block_id` could name two different
bodies. Fixed in `d29e3ad`: the transition now recomputes all three roots
(step 3b), and `PosTransaction::canonical_bytes` was added because the body
root was previously incomputable from typed state. Regression:
`header_must_commit_to_body_attestations_and_coherence`
(`src/transition.rs:2753`), asserting all three mismatch errors in both
directions.

**F-3. Two state-root derivations (2026-08-12).** `transition` and `derive`
committed *different* RANDAO leaf sets for the same block — two roots for one
block, each seam green on its own tests; found independently by two agents
the same day. Fixed in `4ca2646`: one function, `state_root::randao_window`
(`src/state_root.rs:924`), the stricter rule won. Regression: the five tests
of `tests/one_state_root.rs` (reverting the old rule fails 2 of 5). The file
opens with the written statement of the one-derivation-path rule.

**F-4. Slashing existed but nothing called it; then its bookkeeping was not
under the root (2026-08-11/12).** First: `slashing.rs` was implemented,
tested, sealed — and had no call site. Fixed in `8a3e0ea`: evidence became a
transaction (`PosTransaction::SlashingEvidence`) validated inside the
transition; invalid evidence rejects the whole block; 12 new tests including
`evidence_transaction_slashes_operator_and_delegators_and_pays_whistleblower`
(`src/transition.rs:2198`) and
`replayed_evidence_rejects_the_second_block_even_swapped` (`:2372`). Second:
the anti-replay set, correlation window, and delegator-loss ledger were not
committed under the `state_root`, so a state-synced node could double-slash
or reach a different verdict. Fixed in `319c7e6`: three new leaves (tags
`0x11`–`0x13`, `src/state_root.rs:148-150`). Regression:
`every_committed_state_field_is_bound_by_the_root` (`src/transition.rs:2518`)
and `ejected_set_is_exactly_the_slashed_registry` (`:2815`).

**F-5. The Ustav supply cap was not a cap (HIGH, 2026-08-11).**
`compile_supply` compared the cap against a value the *spender* wrote in the
redeemer, never against the amount actually minted: with `cap = 1,000` an
issuer minted 1,000,000,000 in one transaction. Since the program hash is the
asset's policy id, promoting Ustav to consensus would have made the chain
certify a false cap. Fixed in `0f67977`: the module reads the mint context
and asserts `prior + delta <= cap`. Regressions:
`supply_cap_cannot_be_bypassed_by_a_redeemer_supplied_amount`
(`crates/bloch-euvm/src/modules.rs:725`),
`supply_module_cap_is_enforced_over_total_supply` and
`contrast_correct_cap_policy_rejects_the_same_over_cap_mint`
(`tests/audit_modules_supply.rs:55`, `:135`).

**F-6. Redeemer padding bypass defeated the freeze control (CRITICAL,
2026-08-11).** The VM imposed no redeemer arity; compiled modules read the
`frozen` flag at a fixed top-relative offset, so padding the redeemer with
one extra value shifted every read onto attacker-controlled data — a frozen
regulated-token output became spendable with no authority signature. Fixed in
the same `0f67977`: a new `Op::ExpectDepth` opcode
(`crates/bloch-euvm/src/lib.rs:136`, executed at `:379-383`) is emitted as
the first op of every compiled module, making the expected arity part of the
program and hence of `validator_hash` — the spender cannot renegotiate it.
Regression: `transfer_policy_freeze_is_bypassed_by_padding_the_redeemer`
(`tests/audit_modules.rs:55`), which deliberately keeps its bug-era name with
the assertion inverted, plus an honest-arity-still-runs assertion.

**F-7. The shielded pool did not cross the genesis seam (2026-08-11), and its
nullifier set had no canonical root (fixed 2026-08-12).** The Genesis-3→4
carryover pipeline moved only transparent `(addr, value)` balances; the
ceremony stamped `coherence_root = [0u8; 32]` ("empty pool") with nothing
carrying the tree or the nullifier set — a pool that does not cross as
ordered leaves plus the complete nullifier set either burns every unspent
note or revives every spent one. Worse, the header's coherence mirror was
copied from the parent verbatim, validating nothing. Fixed in `eacddd9`
(merged `c59a175`): the ceremony requires a fail-closed Coherence artifact,
replays leaves in exact position order, carries the nullifier set whole, and
"empty" became an attested artifact, never an assumption; the mirror now
derives from committed state. Follow-up `c6fe0c1` ratified C1.1: the
nullifier set is a sparse Merkle tree over the 256-bit nullifier space in
`coherence-core` (order-independent root, provable non-membership), removing
the interim commitment the PoS crate had been computing on the pool's behalf.
Regressions: `expected_coherence_derives_from_committed_state_not_the_parent_header`
(`src/derive.rs:699`), `empty_pool_commits_a_real_root_never_the_zero_sentinel`,
`leaf_order_is_consensus`, `dropping_a_nullifier_is_a_different_chain`,
`shield_before_spend_after_crosses_the_seam`
(`tools/genesis4-ceremony/src/lib.rs:1675-1735`), and the seven C1.1 set
tests in `coherence-core/src/lib.rs:599-702`.

A pattern worth handing the auditor: F-2, F-3, and F-4b are one class — *a
consensus value with two derivation paths, or none* — and the codebase now
carries structural tests against the class itself
(`single_derivation_path`, `one_state_root.rs`,
`every_committed_state_field_is_bound_by_the_root`), not just the instances.

---

## 4. Open gaps — the list we would not want CertiK to discover first

1. **The node is no longer a skeleton — but its network layer is, and that is
   the gap.** The earlier draft of this dossier said "the PoS node is a devnet
   skeleton … no transactions, no libp2p, no RPC, 2,313 lines of scaffolding."
   **That statement is false as of the Genesis-4 launch and is corrected, not
   deleted.** `crates/bloch-pos-node/src/` is now ~9,900 lines and carries a
   JSON-RPC server (`rpc.rs`, 1,498 lines — `sendrawtransaction`,
   `getmempoolinfo`, finality and chain reads), a mempool with a bounded
   admission path (`engine.rs`, `MEMPOOL_MAX = 4_096`), transfers that execute
   on the live chain, a libp2p stack with gossipsub and directed paginated
   sync (`p2p.rs`, 1,657 lines), and persistence (`store.rs`). What is
   genuinely missing, stated exactly:
   - **The live transport is still `Transport::Devnet` and it is still the
     default** (`engine.rs:104-107`, `main.rs:765`). It is a point-to-point
     TCP full mesh with a fixed peer list, **no discovery and no
     authentication** (`net.rs`), which is the mechanical reason a third
     party cannot join the network today. `Transport::Libp2p` exists in the
     tree; it is not what the fleet runs, and this dossier does not describe
     a production network layer as existing.
   - **`Deposit` and `Delegate` are refused at every node's mempool**
     (`engine.rs:1900-1907`), because a deposit registers bonded stake
     without spending any output — measured on 2026-08-13 at 25,000 BLOCH of
     stake per unauthenticated request. The refusal is node-side policy, not
     a consensus rule: a block that already carries a deposit still applies
     it. Closing it properly means giving deposits and withdrawals eUTXO
     inputs and outputs — a wire-format change needing a flag day. **Until
     then there is no permissionless way to become a validator.**
   - **Persistence is an append-only block log, not RocksDB**
     (`store.rs:3-21`): restart is O(chain length) deterministic replay
     through the same `Transition`. Deliberate and documented; a scaling
     item, not a correctness one.
   - No slashing-evidence detection/packaging pipeline in the node (the
     rules and the evidence transaction exist in the committee crate).
   - No weak-subjectivity fresh-sync path (format and verification exist).
2. **G1–G11: the chain launched without them, and none has an observed value
   above zero.** The go/no-go gates (`BLOCH-POS-SHA3-LATTICE-MIGRATION.md`
   §11) were written as conditions on the transition. Genesis-4 launched on
   2026-08-13 regardless. Their observed values today are not "unmeasured" in
   the sense the earlier draft meant — they are measurably failed: G1
   (independent stake ≥ 15% of circulating) is **0%**, because independent
   stake cannot be created while `Deposit`/`Delegate` are refused; G2 (no
   entity above 25% of active stake), G3 (Nakamoto coefficient ≥ 7) and G4
   (≥ 200 validators, ≥ 50 unaffiliated) all fail against a set of **64
   validators operated by one entity**. G1 additionally has an arithmetic
   proof that it cannot be reached by emission alone (§1.1). The measurement
   functions for G2/G3 exist in code (`delegation.rs`) but their semantics are
   specified in no document (`BLOCH-POS-GAPS.md` §4 item 1). **An auditor
   should treat "launched without meeting the launch gates" as the headline
   governance finding of this dossier.**
3. **Genesis keys now exist; the custody plan they were supposed to be
   produced under is still DRAFT.** The earlier draft said "NO production key
   exists yet." Genesis-4 is live, so a genesis manifest and 64 validator keys
   necessarily exist and are signing. `BLOCH-GENESIS-KEYS.md`'s custody plan
   (air-gap, sharding, exposure windows, T−2-week validator keygen) is DRAFT,
   and **this repository contains no evidence about how the live keys were
   actually produced or are held** — the live genesis manifest is not
   committed here. This dossier states that as an unresolved question rather
   than assuming either answer. The carryover exception is named in the doc
   itself and is unchanged: the Genesis-3 keys guarding the liquid carryover
   already existed, were generated long ago under unknown conditions, and sit
   outside the plan, inside the risk.
4. **EVM at L1 is a design.** Only the state-root leaf
   (`TAG_EVM_COMMITMENT`, `state_root.rs:136`) is implemented. There is no
   execution crate, no deposit/withdrawal transaction kinds, no gas limits
   fixed, and — decisive for an auditor — **the authorisation model
   (secp256k1 vs PQ-only vs dual) is an undecided founder decision**
   (`BLOCH-L1-EVM-AUTHORIZATION.md`, recommendation recorded, nothing
   ratified). Ustav/Kirpich promotion to L1 is likewise a proposal with no
   code (`BLOCH-USTAV-L1.md`; `bloch-euvm` is not consensus-wired).
5. ~~**The decided supply-cap consensus invariant is unimplemented.**~~
   **CLOSED** (§1.2). The block-level check now exists in validation:
   `TransitionError::SupplyCapExceeded`, `transition.rs:2307-2311`, against
   the committed `TAG_ISSUED_SUPPLY` leaf. Left on the list, struck through,
   so an auditor comparing drafts can see what moved.
6. **Fee-era boundary wiring is incomplete.** `distribute_producer_fees`
   (`fee_market.rs:267-282`) — the fix that lets delegators keep earning
   once fees are the whole budget — is implemented and tested but **not yet
   called from the transition**, which still credits the raw producer share
   (`fee_market.rs:261` says so itself).
7. **SPDX headers are not universal.** 59 of 115 `.rs` files under `crates/`
   lack the per-file SPDX line — including all seven `bloch-euvm` source
   files and `coherence-core/src/lib.rs`. Manifests all declare
   AGPL-3.0-or-later (two deliberate vendored exceptions);
   `bloch-pos-committee` and `bloch-pos-node` are 100% clean.
8. **Repository publication is asserted, not scheduled** (check 20): the
   repo is private, and no document commits to a date, URL, or process for
   opening it, while ADR-033 rests its decentralisation claim on "open-sourced
   before launch".
9. **Zero external audits to date** (`SECURITY_SELF_ASSESSMENT.md`), one
   primary developer, and a fleet operated by the founder — **and the chain
   launched in that state.** Genesis-4 has been live since 2026-08-13 with no
   third-party audit of the consensus crate, the node, or the hybrid
   signature composition. The prior internal audits (ERA-1, GroundState)
   cover a predecessor codebase, and `audit/CONSOLIDATED-SECURITY-REPORT.md`
   covers the proof-of-work tree, not this one. Sixty-four of sixty-four
   validators are the founder's.
10. **Known spec-vs-code drift is inventoried** in `BLOCH-POS-GAPS.md` —
    including the `CapStatus::Deferred` consensus behaviour absent from the
    spec, the stale §7A tables in the tokenomics doc, and the frozen
    interface amended by the EVM leaf. We hand the auditor that inventory
    rather than a claim of alignment.

---

## 5. Contradictions flagged while preparing this dossier

These were internal inconsistencies between decisions of record, documents,
and code, found while preparing the 2026-08-12 draft. Their dispositions are
recorded rather than the entries deleted, because the point of the section is
that an auditor can see what was flagged and what happened to it.

1. ~~**Total supply: 21 B in code and docs vs 100 B decision of record.**~~
   **RESOLVED.** `tokenomics_v4.rs` now pins
   `TOTAL_SUPPLY_BLOCH = 100_000_000_000` with per-bucket compile-time
   assertions proving `new × 21 == old × 100` for every allocation — a pure
   split, no dilution. The headroom cost the contradiction warned about was
   **accepted and pinned, not deleted**: 10¹⁹ sat is ~54.2% of `u64::MAX` and
   ~108% of `i64::MAX`, every consensus quantity is `u128`, and the
   assertions were inverted to state the hazard rather than removed. The
   consequence for integrators stands: **any SDK or exchange integration that
   types satoshis as a signed 64-bit integer will overflow and must migrate.**
   Concentration percentages in §1.1 are denomination-independent and were
   unaffected either way.
2. ~~**Genesis-3 terminal height: 50,000 decided.**~~ **OVERTAKEN BY EVENTS.**
   The chain did not reach 50,000. It stopped permanently at height **39,918**
   on 2026-08-13, and the terminal snapshot taken there is what pins the
   carryover constants (§0.0, §1.1). Any document in this repository still
   saying the halt is at 50,000, or that a halt is forthcoming, is stale. The
   original entry's advice was right for a reason worth keeping: the snapshot
   height should be reasoned about as "the terminal height", and the number
   attached to it should always be quoted with the artifact it came from.
3. **Validator bond.** Unchanged and still true: the bond is 25,000 BLCH
   (Ethereum's fraction of supply under 100 B), down from 100,000. It widens
   who *may* validate; it does nothing about who *does*, and this dossier does
   not describe it as a concentration fix. On the live chain it does neither
   yet, because deposits are refused at the mempool (§4 item 1).
4. **New, and the sharpest one: the launch preceded the gates and the audit.**
   The migration design classifies G1–G4 (distribution) and G7 (external
   review of the Falcon online-signing path) as conditions on activation.
   Genesis-4 activated without any of them. Documents in this repository that
   describe the gates as standing between the code and a mainnet are
   describing a plan that was not followed, and this dossier says so rather
   than letting an auditor discover the mismatch.

---

## 6. What this dossier does not claim

- It does not claim the scanner's checklist was "passed". Two applicable
  checks fail today (9, 20), and the substitutes for three more carry open
  caveats (10, 14, 22).
- It does not claim percentage test coverage — not measured, only test
  counts and pass rates (§2 method note).
- It does not claim the supply cap is unchangeable — only that no mechanism
  inside the protocol can change it, which is the strongest true statement.
- It does not claim decentralisation. The chain started centralised, by
  construction, and **is centralised today**: 64 of 64 validators are one
  operator's, no third party can join, and the gates that were supposed to
  measure the distance from there were not met before launch.
- It does not claim that the numbers in §1.1 improved. They were re-measured
  at the terminal snapshot and they are, to two decimal places, what they
  were.

---

## Annex A — document inventory for the engagement

| Document | One line |
|---|---|
| `docs/specs/BLOCH-POS-SHA3-LATTICE-MIGRATION.md` | Master Genesis-4 PoS design; §11 = G1–G11 gates. DRAFT. |
| `docs/specs/BLOCH-TOKENOMICS-V4.md` | Supply, allocation, §4A/§4A.1 concentration analysis. DRAFT, parameters not frozen. |
| `docs/specs/BLOCH-POS-INTERFACES.md` | Frozen consensus interface contract (with recorded amendments). |
| `docs/specs/BLOCH-POS-GAPS.md` | The honest implemented/specified/neither inventory. |
| `docs/specs/BLOCH-POS-THREAT-MODEL.md`, `-2.md` | Two adversarial passes over the PoS design. |
| `docs/specs/COHERENCE-C1.md`, `COHERENCE-C1.1.md` | Shielded-pool format freeze; C1.1 is the only RATIFIED spec. |
| `docs/specs/COHERENCE-G11-SHADOW-FORKS.md` | G11 acceptance-evidence plan (three shadow forks). |
| `docs/specs/BLOCH-FALCON-ONLINE-SIGNING.md` | The path G7 requires externally reviewed — a natural CertiK work item. |
| `docs/specs/BLOCH-GENESIS-KEYS.md` | Key ceremony and custody plan. DRAFT; no production key exists. |
| `docs/specs/BLOCH-ENTITY-STRUCTURE.md` | Two-entity governance structure. DRAFT, jurisdiction open. |
| `docs/specs/BLOCH-L1-EVM-*.md` (5 docs) | EVM-at-L1 design set; authorisation undecided. |
| `docs/specs/BLOCH-USTAV-L1.md`, `BLOCH-KIRPICH-UNDER-POS.md` | Charter-at-consensus proposals; no code. |
| `docs/adr/` (ADR-023…040) | Decision record: governance, custody, licence (ADR-039), EVM/Ustav at L1 (ADR-040), churn (ADR-038), ownerless-claim retraction (ADR-036). |
| `docs/audit/AUDIT-2026-04-20_ERA1.md`, `docs/audit/groundstate_audit.md` | Prior internal audits of the predecessor codebase. |
| `docs/SECURITY_SELF_ASSESSMENT.md` | Self-assessment vs Bitcoin Core; records zero external audits. |
| `audit/CONSOLIDATED-SECURITY-REPORT.md` | Roll-up of every internal security review to date. |
| `legacy/INTERNAL-AUDIT-PLAN.md` | The internal review plan that names CertiK among candidate firms. |
| `REPRO.md`, `repro-manifest.sh`, `scripts/falcon-clean-guard.sh`, `deny.toml`, `audit.toml` | Build-integrity and supply-chain tooling. |
