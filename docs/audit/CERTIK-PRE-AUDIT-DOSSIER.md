<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Bloch — CertiK pre-audit dossier

Document: CERTIK-PRE-AUDIT-DOSSIER
Status: DRAFT for founder review — prepared before engagement, to be handed to CertiK
Prepared: 2026-08-12, against branch `integration/pos-modules` at `470b608`
Supersedes: the 2026-08-12 draft prepared at `84ca42a`, which predates the
100-billion redenomination, the supply-cap consensus invariant and the halt
height moving to 50,000
Repository: `gitlab.com/blochsispow-group/bloch-pos` (private at time of writing — see check 20)
License: AGPL-3.0-or-later (repo `LICENSE`; workspace `Cargo.toml:24`)

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
| Genesis-3 halt | height 80,000 | **height 50,000** | `crates/bloch-crypto/src/core/mod.rs` |

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
| 8 | Self-destruct | No `selfdestruct` analogue, and no hidden kill switch (check-23 grep). One disclosed, deliberate exception must be named: Genesis-3 carries a **terminal-height consensus rule** — the chain halts at a fixed height for the Genesis-4 migration. It is public, one-time, and snapshot-preserving, not a concealed destruct path. See §5 for the height contradiction. | N/A — substitute holds, with disclosure | `docs/specs/BLOCH-TOKENOMICS-V4.md` §3.2; `docs/FLEET-BRIEF-2026-08-11.md` |
| 9 | **Major holder concentration** | **Applies directly — the one check that maps one-to-one.** Measured: the largest single address holds **93.96%** of the carried-over supply (16,886,549,523 of 17,970,850,000 BLCH, snapshot at height 43,172, 15 addresses); **70.4%** of circulating at slot 0; if staked (it is stakeable, founder decision 2026-08-11), **94.0% of active stake — Nakamoto coefficient 1**. WBNB drew its only attention flag at 39.28%. | **FAIL** | `docs/specs/BLOCH-TOKENOMICS-V4.md` §2 (snapshot root `280d604b32525f03…`), §4A, §4A.1; `crates/bloch-pos-committee/src/tokenomics_v4.rs:236` (`LARGEST_CARRYOVER_ADDRESS_BLOCH`). Full treatment in §1.1 |
| 10 | Mintable | No mint function, no privileged issuance: `PosTransaction` is a closed five-variant enum with no `Mint`; the only balance-increasing writes in the transition are the emission curve and fee compounding, both pure functions of slot/stake. Open gap: the decided block-level cap invariant is **not yet implemented** — see §1.2. | PASS (no privileged mint) — with an open gap on the cap invariant | `crates/bloch-pos-committee/src/transition.rs:175-220`, `:1152`, `:1177`, `:1186-1188`; `src/tokenomics_v4.rs:406-421` |
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
| 22 | Withdrawal function (owner can drain) | No contract balance and no function that drains one. Role played by: key custody for the genesis allocations — the Foundation custodies 29% of supply at genesis, and the custody plan (air-gap ceremony, sharding, exposure windows) is written but DRAFT, and **no production key exists yet** (§4). Institutional custody, not protocol code, is the real surface here. | N/A — substitute is a DRAFT plan, flagged as a gap | `docs/specs/BLOCH-GENESIS-KEYS.md` (status line); `docs/specs/BLOCH-ENTITY-STRUCTURE.md` §3; `docs/research/MOFN-CUSTODY-DECISION.md` |
| 23 | Backdoor ownership recovery | None. The crate-wide grep for owner/admin/sudo/master-key/override/emergency paths (§1.3) returns no control mechanism — every hit is prose, a frozen-interface artifact, or the retired taint set. | PASS | §1.3 grep table |

Score, stated plainly: of the two checks that apply one-to-one, **both fail
today** — concentration (9) and open-source publication (20). Of the
remainder, the substitute mechanisms hold in code, with three carrying open
caveats (10: cap invariant unimplemented; 14: G8 unmeasured; 22: custody plan
DRAFT).

### 1.1 Concentration — the exact numbers, and what bounds them (check 9)

This is the finding an auditor will lead with, so we lead with it.

Measured, not estimated (snapshot at Genesis-3 height 43,172 via
`bloch-snapshot-utxo`, snapshot root SHAKE-256 `280d604b32525f03…`, carryover
digest `92918209a106f297…` — `BLOCH-TOKENOMICS-V4.md` §2):

- The carryover set is 17,970,850,000 BLCH across **15 addresses** and 448,337
  UTXOs. The largest address holds 16,886,549,523 BLCH — **93.96% of the
  carryover** — and is the founder's.
- At Genesis-4 slot 0, circulating supply is carryover + liquidity +
  marketing TGE; the founder's liquid balance is **70.4% of circulating**.
- The carried-over balance is liquid and therefore **stakeable** (founder
  decision 2026-08-11, pinned by
  `staking.rs::carryover_liquid_balance_is_stakeable` and
  `tests/committee.rs::carryover_liquid_balance_delegates_as_stake`). If it
  stakes and others do not, the founder holds **94.0% of active stake — a
  Nakamoto coefficient of 1**, computed at the one-third threshold.
- Founder total across carryover plus the new 10% grant (10-year cliff,
  40-year linear vest): **26.89% of eventual total supply**.

The mechanisms that bound this, and — stated with equal weight — what each
does *not* reach:

| Mechanism | What it does | What it does not do |
|---|---|---|
| Genesis-cohort declining cap (`genesis_cohort.rs:75-81`, `:129-194`; enforced at `transition.rs:590`) | Consensus rule: the founder-operated genesis cohort's combined duty weight tapers 100% → 33.3% over 12 months; the cohort list is publish-once, shrink-only, part of chain identity. | Binds only the named cohort. Nothing stops funding new validators at addresses outside it; no on-chain rule sees beneficial ownership. |
| Per-validator cap: 1% of active stake (`delegation.rs:103`; fixed-point at `delegation.rs:337-349`; `transition.rs:857-858`) | No single validator identity exceeds 1% of effective stake. | Sybil-bypassable by splitting one balance across many validators — the code's own doc comment says so. |
| Churn rate 25 bps/epoch (`delegation.rs:90`, was 900; `BLOCH-POS-STAKE-CHURN.md`, ACCEPTED AND APPLIED) | Slows stake movement: a stalling third now takes ~43 hours instead of ~75 minutes — visibility time for operators. | Time, not prevention. Does not reduce anyone's holdings. |

And the arithmetic that closes the escape hatch (`BLOCH-TOKENOMICS-V4.md`
§4A.1): rewards are pro-rata to stake, so compounding preserves stake
*shares*. Independent parties hold 227,709,400 / 17,970,850,000 = **6.03%** of
the carryover; gate G1 requires ≥ 15% of circulating in independent hands.
Therefore **G1 is unreachable by emission alone — not at year five, not at
year forty. The only thing that moves it is coins changing hands.** If the
founder abstains from staking entirely, the earliest G1 crossing under
first-year emission plus unlocks is ≈ month 9 — a bound, not a forecast.

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
3. **The decided direct invariant does not exist yet.** The decision of
   record (2026-08-12) is that every node refuses a block whose cumulative
   issuance would exceed the cap. We grepped for it: there is **no
   block-level cumulative-issuance check** in `tokenomics_v4.rs`,
   `transition.rs`, or `produce.rs`. This is an open implementation gap (§4,
   item 5).

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

1. **The PoS node is a devnet skeleton.** `crates/bloch-pos-node` runs real
   validators with real hybrid signatures over a localhost TCP mesh — and
   that is all. **No transactions** (`engine.rs:95` `NO_TXS`; non-empty
   bodies fail-closed rejected at `engine.rs:344-347`), **no libp2p**
   (`std::net::TcpListener` bound to `127.0.0.1`, `net.rs:147`), **no RPC**
   (no HTTP listener of any kind). The crate's own header lists the rest:
   no RocksDB store, no slashing-evidence pipeline, no weak-subjectivity
   sync, no fork choice beyond a linear chain, no mainnet genesis manifest
   (`main.rs:10-15`). The consensus *crate* is substantially built; the
   *node* around it is 2,313 lines of scaffolding.
2. **G1–G11 are defined and none is measured.** The go/no-go gates
   (`BLOCH-POS-SHA3-LATTICE-MIGRATION.md` §11) attach to a transition height
   that is only reached after a hybrid phase that has not started; Genesis-4
   has not launched, so no gate has an observed value. G1 additionally has an
   arithmetic proof that it cannot be reached by emission alone (§1.1). The
   measurement functions for G2/G3 exist in code
   (`delegation.rs:279-307`) but their semantics are specified in no
   document (`BLOCH-POS-GAPS.md` §4 item 1).
3. **Genesis keys do not exist.** `BLOCH-GENESIS-KEYS.md` is explicit:
   "NO production key exists yet." The custody plan (air-gap, sharding,
   exposure windows, T−2-week validator keygen) is DRAFT. The carryover
   exception is named in the doc itself: the Genesis-3 keys guarding the
   3.77 B liquid carryover already exist, were generated long ago under
   unknown conditions, and sit outside the plan, inside the risk.
4. **EVM at L1 is a design.** Only the state-root leaf
   (`TAG_EVM_COMMITMENT`, `state_root.rs:136`) is implemented. There is no
   execution crate, no deposit/withdrawal transaction kinds, no gas limits
   fixed, and — decisive for an auditor — **the authorisation model
   (secp256k1 vs PQ-only vs dual) is an undecided founder decision**
   (`BLOCH-L1-EVM-AUTHORIZATION.md`, recommendation recorded, nothing
   ratified). Ustav/Kirpich promotion to L1 is likewise a proposal with no
   code (`BLOCH-USTAV-L1.md`; `bloch-euvm` is not consensus-wired).
5. **The decided supply-cap consensus invariant is unimplemented** (§1.2):
   no block-level check rejects over-cap cumulative issuance; the cap holds
   by construction and by state-root divergence only.
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
   primary developer, and a fleet operated by the founder. The prior internal
   audits (ERA-1, GroundState) cover a predecessor codebase.
10. **Known spec-vs-code drift is inventoried** in `BLOCH-POS-GAPS.md` —
    including the `CapStatus::Deferred` consensus behaviour absent from the
    spec, the stale §7A tables in the tokenomics doc, and the frozen
    interface amended by the EVM leaf. We hand the auditor that inventory
    rather than a claim of alignment.

---

## 5. Contradictions flagged while preparing this dossier

These are internal inconsistencies between decisions of record, documents,
and code, found during preparation. They must be resolved before the dossier
is sent, or sent with this section intact — an auditor will find them within
hours.

1. **Total supply: 21 B in code and docs vs 100 B decision of record.**
   `tokenomics_v4.rs:33` pins `TOTAL_SUPPLY_BLOCH = 21_000_000_000`, with a
   doc comment recording the founder's 2026-08-11 decision as a *revert* of
   a 100 B draft; `BLOCH-TOKENOMICS-V4.md` §1 says the same. The 2026-08-12
   decision of record reverses this again: 100 B as a pure split
   (×4.7619, every percentage unchanged — a redenomination, not "more supply
   for holders"). **The redenomination as specified cannot land in the
   current representation**: at 8 decimal places, 100 B is 1.0 × 10¹⁹ sat,
   which violates both compile-time assertions at `tokenomics_v4.rs:254-255`
   (the 8× `u64` headroom bound and the `i64::MAX` bound that exists because
   the Go SDK's `Satoshis` is a signed int64 — the very overflow the 21 B
   revert was recorded as fixing). Landing 100 B requires reducing decimal
   places, changing the satoshi representation, or accepting the loss of
   headroom — a decision, not a find-and-replace. Concentration percentages
   in §1.1 are denomination-independent and unaffected either way.
2. **Genesis-3 terminal height: 50,000 decided, 50,000 everywhere.** The
   2026-08-12 decision lowers the halt to height 50,000 (~4 days out at
   decision time). Every committed artifact says 50,000 — `BLOCH-TOKENOMICS-V4.md`
   §3.1/§3.2, the migration spec, the node-integration plan, the interfaces
   doc, and five public portal pages; the value 50,000 appears in no height
   context anywhere in `docs/`. §3.1's notice-period argument was also
   written for 50,000. Until code and fleet actually enforce 50,000, the
   snapshot height in this dossier's §1.1 measurements should be treated as
   "the terminal height", not a number.
3. **Validator bond.** The decision of record sets the bond near 25,000 BLCH
   (Ethereum's fraction of supply under 100 B), down from 100,000. This
   follows the supply decision and inherits contradiction 1. It widens who
   *may* validate; it does nothing about who *does*, and this dossier does
   not describe it as a concentration fix.

---

## 6. What this dossier does not claim

- It does not claim the scanner's checklist was "passed". Two applicable
  checks fail today (9, 20), and the substitutes for three more carry open
  caveats (10, 14, 22).
- It does not claim percentage test coverage — not measured, only test
  counts and pass rates (§2 method note).
- It does not claim the supply cap is unchangeable — only that no mechanism
  inside the protocol can change it, which is the strongest true statement.
- It does not claim decentralisation. The chain starts centralised, by
  construction; the gates measure the distance from there, and none has been
  measured.

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
| `docs/INTERNAL-AUDIT-PLAN.md` | The internal review plan that names CertiK among candidate firms. |
| `REPRO.md`, `repro-manifest.sh`, `scripts/falcon-clean-guard.sh`, `deny.toml`, `audit.toml` | Build-integrity and supply-chain tooling. |
