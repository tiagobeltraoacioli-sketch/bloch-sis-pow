<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# CertiK pre-audit dossier — Market Risks, Transparency, General

**Scope:** the *Market*, *Transparency* and *General* categories of CertiK's
Skynet token scan, answered for Bloch Genesis-4 (PoS) with file:line evidence.
Companion dossiers cover Rugpull and Centralization. Written 2026-08-12
against branch `integration/pos-modules`, worktree commit `84ca42a`.

**The framing caveat, stated once and up front** (from
`docs/FLEET-BRIEF-CERTIK-2026-08-12.md`): Skynet's token scan is a bytecode
analyser for deployed EVM contracts. BLCH is the base asset of an L1 — there
is no contract address to scan, no `owner()` to renounce, no proxy slot to
inspect. This document therefore answers, for each check, whether the
*property behind it* holds on Bloch, by what mechanism, and where the
evidence is. A check that does not apply gets "does not apply, and here is
what plays its role instead" — never a blank pass. Section 5 states exactly
which checks become literally runnable once EVM at L1 ships.

**Evidence discipline.** Every number below is a constant or a measurement
with a path. Where something was measured, the command or test is named.
Where something is not implemented, it says "not implemented". The test
suite backing the cited tests is `crates/bloch-pos-committee` (its own
workspace; run `cargo test` from inside the crate directory) — the run
performed for this dossier is reported in §6.

---

## 1. Market Risks

### 1.1 Buy tax / sell tax — **does not apply; what exists instead is a
resource fee plus a scheduled burn, and neither is value-proportional**

There is no token contract, therefore no transfer hook, therefore no place a
buy or sell tax could exist. Skynet's tax check detects a percentage skimmed
from the *transfer amount*, conditionally on trade direction. Bloch has no
mechanism with either property:

- **The fee is resource-proportional, not value-proportional.** A
  transaction pays `intrinsic_gas = TX_FLAT_GAS + tx_bytes · GAS_PER_BYTE +
  verify_gas(class)` (`crates/bloch-pos-committee/src/fee_market.rs:145`),
  priced by a protocol-computed base fee in millisatoshi per gas
  (`fee_market.rs:159`, floor `MIN_BASE_FEE_MILLISAT_PER_GAS = 10`). At the
  genesis floor, a minimal one-input eUTXO transfer costs 155,268 gas =
  1,553 satoshis ≈ 1.6 × 10⁻⁵ BLCH — the same whether it moves 10 BLCH or
  3 billion. A tax scales with value; this does not.
- **The fee is direction-blind.** Consensus cannot see "buy" or "sell":
  `PosTransaction::Transfer` is opaque to the committee crate by design —
  it carries only `base_fee_sat` and `priority_fee_sat`
  (`crates/bloch-pos-committee/src/transition.rs:177`). There is no
  address-conditional or counterparty-conditional branch anywhere in the fee
  path (verified by reading `fee_market.rs` and `rewards.rs` end to end —
  the split functions take amounts and a slot, nothing else:
  `rewards.rs:65`, `fee_market.rs:235`).
- **The burn is a fee-split policy, not a tax.** During the 40-year emission
  era, half of the **base fee** is burned (`BASE_FEE_BURN_BPS = 5_000`,
  `crates/bloch-pos-committee/src/rewards.rs:38`) and the tip goes entirely
  to the producer (`PRIORITY_FEE_PRODUCER_BPS = 10_000`, `rewards.rs:42`).
  After `EMISSION_SLOTS` the burn drops to zero and 100% of fees go to the
  producer — the switch is `split_fees_at` (`rewards.rs:65`), a `const fn`
  of the slot number alone. The burn destroys part of the *fee*, never part
  of the *principal*. Spec: `docs/specs/BLOCH-L1-FEE-MARKET.md` §4.5, which
  also corrects the shorthand "fees burn during emission" — only half the
  base fee burns.

**Verdict for the scan's purposes: buy tax 0%, sell tax 0%, by absence of
any mechanism, not by a parameter currently set to zero.** There is no
parameter to raise.

### 1.2 Tax modification by privileged roles — **no in-protocol path; the
honest statement of the out-of-protocol path follows**

Two things about the fee can change, and neither is a privileged-role
action:

1. **The base fee moves every block — algorithmically.** `next_base_fee`
   (`fee_market.rs:193`) is EIP-1559's ±1/8 controller over the max of the
   gas and byte utilisation axes, computed from parent-committed usage only.
   No role sets it; a block whose transactions were priced against anything
   else is invalid (`BLOCH-L1-FEE-MARKET.md` §4.4: the base fee is a
   committed state leaf, recomputed and checked by every validator). Calling
   this "tax modification" would be like calling Ethereum's base fee an
   owner-settable tax — it is a posted price every node derives identically.
2. **The constants can change — only by hard fork.** `BASE_FEE_BURN_BPS`,
   `GAS_PER_BYTE`, `MIN_BASE_FEE_MILLISAT_PER_GAS`, the era boundary
   `EMISSION_SLOTS` — all are compile-time constants, several pinned by
   compile-time assertions (`fee_market.rs:289–322`). There is no on-chain
   parameter store, no setter, no admin key, no governance vote: measured by
   `grep -rni 'governance|admin|owner_|privileged|superuser|master.?key'`
   over `crates/bloch-pos-committee/src/` — zero hits that denote a
   privileged role (the matches are doc references to the founder's
   *inability* to act and to finality recovery, §3.3). Changing a fee
   constant means shipping a new binary that every operator chooses to run.

**The claim an auditor should check, stated at its true strength** (per the
fleet brief): *no mechanism inside the protocol* can change the fee split or
the fee schedule. "Impossible to change" would be false — a hard fork
adopted by every operator can change any rule. And the honest corollary,
which the Centralization dossier owns in full: while the validator set is
the founder-operated genesis cohort and the founder authors the reference
implementation, a hard fork is unilateral *in practice*. The fee rules are
exactly as immutable as the operator set is diverse. That is a
centralization finding, not a hidden tax function — there is no code path to
find.

The scheduled change that *is* in the code — burn → no burn at
`EMISSION_SLOTS` (year 40) — is fixed at genesis, moves in the
fee-receivers' favour only after issuance ends, and is not actionable by
anyone (`rewards.rs:52–64` states the rationale; the
`net_inflation_stays_under_the_7_percent_target` test pins both eras).

### 1.3 Buy restrictions / sell restrictions — **none on liquid coins; the
three real illiquidity mechanisms, and where each is legitimate**

Nothing in consensus restricts transferring a liquid balance. There is no
blacklist, no whitelist, no transfer pause, no per-address transfer limit:
measured by `grep -rni 'blacklist|whitelist|pause|freeze'` over
`crates/bloch-pos-committee/src/` — the only hits are documentation of the
founder's *loss* of the ability to freeze (`genesis_cohort.rs:21`) and the
interface-freeze vocabulary. The one origin-based exclusion Bloch ever
designed — the §4.1 taint set — was **retired** on 2026-08-11: the set is
empty by rule, `DepositReject::TaintedInput` is documented as never produced
(`crates/bloch-pos-committee/src/staking.rs:243`), and the retired holder
cap survives only as a named zero that fails loudly if consulted
(`tokenomics_v4.rs:106`, `HOLDER_CARRYOVER_CAP_BLOCH = 0`).

Three mechanisms do make coins temporarily non-transferable, and an auditor
will (correctly) list them. Each is scoped and none touches an ordinary
holder's liquid balance:

1. **Staking exit friction — opt-in, consensus-security, the legitimate
   kind.** A validator bond activates after `ACTIVATION_DELAY_EPOCHS = 8`
   (~2.1 h, `staking.rs:89`), stops duties `EXIT_DELAY_EPOCHS = 32` (~8.5 h,
   `staking.rs:99`) after a voluntary exit, and is withdrawable only after
   `WITHDRAWAL_DELAY_EPOCHS = 2048` (~22.8 days, `staking.rs:106`). The
   22.8-day delay is the weak-subjectivity margin: an exited validator with
   its principal returned can sign conflicting history at zero cost, so the
   delay must exceed the window in which any client could believe such a
   history (`staking.rs:28–34`). Delegations similarly: `COOLDOWN_EPOCHS =
   32` (`delegation.rs:110`), and both activation and deactivation are
   rate-limited to `WARMUP_RATE_BPS = 25` (0.25%) of active stake per epoch
   with a floor of one validator's deposit (`delegation.rs:90,100`) — so a
   coordinated drain of one third of stake takes ~43 hours, symmetric with
   the takeover it defends against (the F3 symmetry, `delegation.rs:70–79`).
   These are the same devices Ethereum and Solana use, they bind only coins
   their owner voluntarily bonded, and every parameter is a public constant.
   **Legitimate.**
2. **Vesting — restricts allocation recipients, not holders.** Founder
   grant: 10-year cliff + 40-year per-slot linear vest
   (`tokenomics_v4.rs:137–139`); VC 12-month cliff + 24 linear
   (`tokenomics_v4.rs:269`); team 18 + 36 (`tokenomics_v4.rs:276`);
   marketing 25% at TGE + 24 months (`tokenomics_v4.rs:282`); liquidity
   fully liquid. In token-scan vocabulary this is "locked team tokens" — the
   thing the scan rewards, not a restriction it flags. The carryover — every
   pre-existing holder, the founder's carried balance included — is fully
   liquid at slot 0 with no cap (`tokenomics_v4.rs:100`). **Legitimate, and
   disclosure-positive.**
3. **Deposit-boundary rules — restrict what may become a *bond*, not what
   may move.** Stake must be funded from transparent (non-shielded) inputs
   (`staking.rs::validate_deposit`, `DepositReject::ShieldedInput`,
   `staking.rs:283`) so every bond is attributable for slashing. A shielded
   coin remains fully transferable inside and out of the Coherence pool; it
   just cannot *be a validator bond* while shielded. **Legitimate —
   attributability, not exclusion.**

**Where a restriction would NOT have been legitimate, and what happened to
it:** a rule that made coins non-transferable or non-stakeable *by origin* —
the taint set and the 300 M holder cap were exactly that shape, and both
were dissolved rather than shipped
(`tokenomics_v4.rs:88–99`). The decision is pinned by tests so it cannot be
reverted silently: `staking.rs::carryover_liquid_balance_is_stakeable`
(`staking.rs:601`) proves a carryover-funded deposit is rejected only by
**size** (the per-validator cap), never by origin, and
`tests/committee.rs::carryover_liquid_balance_delegates_as_stake` proves the
same for delegation. One caveat belongs in the open: the retained-inert
`tainted` bit and `TaintedInput` variant still exist in the frozen interface
(`staking.rs:176–184`). They are documented as never-produced and exist so
the fail-closed direction stays testable — but they are the door a future
rule change would re-open, and an auditor should verify at integration time
that no oracle implementation can return `Tainted` (`interfaces.rs:397–405`
requires answers to derive from the committed `taint_root`, whose set is
empty).

**Verdict: no buy restrictions, no sell restrictions, no transfer cooldown
on liquid balances. Cooldowns exist only inside the staking lifecycle, are
opt-in, and are security-load-bearing.**

### 1.4 Anti-whale mechanism — **two real ones, both stake-scoped; and the
honest statement of what neither reaches**

Skynet's anti-whale check looks for max-wallet / max-tx caps. Bloch has
**no cap on holding or transferring** — deliberately (the holder cap was
retired, §1.3). What it has are two caps on *consensus weight*:

1. **Per-validator cap: 1% of active stake.** `MAX_VALIDATOR_STAKE_BPS =
   100` (`crates/bloch-pos-committee/src/delegation.rs:103`), enforced two
   ways: at the deposit boundary (`DepositReject::AboveMaximum`,
   `staking.rs:292`) and continuously on effective stake, resolved by
   bounded fixed-point iteration against the *capped* total
   (`delegation.rs::Registry::cap_sat`, `delegation.rs:356` — the naive
   1%-of-uncapped version degrades exactly as concentration rises; the
   fixed-point version clamps a 90%-of-raw-stake operator to 1.0% effective,
   documented at `delegation.rs:340–355`). Delegated stake counts toward the
   cap (`delegation.rs:20–23`), so delegation is not a bypass. Over-cap
   stake earns nothing and carries no weight; it is not confiscated.
2. **Genesis-cohort declining cap.** The founder-operated genesis validator
   set is a fixed list published in the genesis block — shrink-only, nothing
   can be added (`crates/bloch-pos-committee/src/genesis_cohort.rs:30–35`).
   Its *combined* effective stake is capped, declining linearly from 100% at
   genesis to one third at one year and holding there
   (`COHORT_CAP_FLOOR_BPS = 3_333`, `COHORT_TAPER_EPOCHS =
   EPOCHS_PER_YEAR`, `genesis_cohort.rs:58–64`; closed-form `s/(1−s)·O`
   scaling at `genesis_cohort.rs:175`). One third is chosen because it is
   the finality-stall threshold: below it the founder cannot halt the chain
   alone (`genesis_cohort.rs:16–27`).
3. (Supporting) the 25 bps churn limit (§1.3) is an anti-whale *velocity*
   device: even unlimited eligible coins cannot re-shape the validator set
   faster than ~43 hours of publicly visible queue traffic.

**Modifiability — who can change these caps?** Nobody, in-protocol. All
three are compile-time constants; `cohort_cap_bps` is a `const fn`; there is
no runtime parameter, setter, or vote (same grep evidence as §1.2). The
change path is a hard fork — with the same honesty note as §1.2 about what
a hard fork means while the operator set is a monoculture. One integration
seam deserves audit attention: `validate_deposit` takes the cap as a
*parameter* (`max_stake_sat`, `staking.rs:271`) because the true cap lives
in parent-committed state; a wrong caller could pass a weaker cap. The crate
documents the required derivation (`staking.rs:258–266`); the node-side
wiring does not exist yet and should be a named audit item.

**What neither cap reaches — stated plainly, because the modules themselves
state it.** Both caps bind *operators*, not *owners*. One holder can split
stake across many validators and keep economic control; beneficial ownership
is invisible on-chain (`delegation.rs:80–84`, `genesis_cohort.rs:41–48`).
The cohort cap binds only the genesis addresses — nothing prevents funding
new validators outside the cohort. And the concentration these caps operate
against is severe: the largest carried-over address holds 16,886,549,523 of
17,970,850,000 BLCH — 93.97% of the carryover — and if staked would be ~94%
of active stake, Nakamoto coefficient 1
(`docs/specs/BLOCH-TOKENOMICS-V4.md` §4A/§4A.1;
`tokenomics_v4.rs::LARGEST_CARRYOVER_ADDRESS_BLOCH`, line 236). §4A.1's
conserved-share arithmetic shows gate G1 (independent stake ≥ 15%) is
unreachable by emission alone if that balance stakes and compounds. That
number is the Centralization dossier's headline; it is repeated here because
an anti-whale section that omitted the whale would be the softening the
fleet brief forbids. The caps bound *how fast* and *through how many
validators* the position acts; they do not and cannot bound the position.

---

## 2. Transparency

### 2.1 Open-source code — **FAIL today, by measurement; here is exactly
what is and is not public**

Skynet's check: is the token's source public and verified? The L1 analog:
can anyone read, build, and verify the code the network runs?

**Measured 2026-08-12, unauthenticated (no session, plain HTTPS):**

| Repository | Probe | Result |
|---|---|---|
| `gitlab.com/blochsispow-group/bloch-pos` (THIS repo — the Genesis-4 PoS code under audit) | `GET /api/v4/projects/blochsispow-group%2Fbloch-pos` | **404** — not visible to the public (private or hidden; indistinguishable from absent, which is the point) |
| `gitlab.com/blochsispow-group/BlochSISPoW-project` (Genesis-1..3 lineage) | same API | **200**, `visibility: public`, last activity 2026-08-10 |
| `github.com/tiagobeltraoacioli-sketch/bloch-sis-pow` (mirror) | `GET /repos/...` | **200** — public |

**The code this dossier cites — the fee market, the staking lifecycle, the
anti-whale caps, the tokenomics constants — is not publicly readable. Until
`bloch-pos` is published, the open-source check is a FAIL, and every claim
in this dossier is verifiable only by parties given access.** That is not a
nuance to manage; it is the first thing CertiK will observe, and it gates
everything else: a consensus rule nobody outside can read is, for
transparency purposes, a closed-source contract. The Genesis-3 chain being
public does not cure it — Genesis-4 is a different consensus.

Licensing, measured inside the repo:

- Root `LICENSE` is the full AGPL-3.0 text; workspace `Cargo.toml:24`
  declares `AGPL-3.0-or-later`.
- Per-crate manifests: 11 of 13 crates declare `AGPL-3.0-or-later`
  (`bloch-btc-wallet`, `bloch-crypto`, `bloch-euvm`, `bloch-ffg`,
  `bloch-pos-committee`, `bloch-pos-node`, `bloch-pq-vault`,
  `coherence-core`, `services/pq-shield-api`, `tools/genesis4-ceremony`,
  root). Two still declare `MIT OR Apache-2.0` (the norm until 2026-08-11):
  `crates/bloch-sis-pow` and `crates/pqcrypto-internals`. For the latter
  (vendored PQClean-adjacent material) permissive licensing is appropriate;
  for the former, confirm whether it should be superseded by AGPL like the
  other PoS-era crates. Nine `Cargo.toml` files have **no** license
  field: `fuzz/`, `spikes/prover-cost/` (×5), and the three
  `crates/coherence-prover/{script,program,service}` subcrates.
- SPDX header coverage, counted per `.rs` file: `bloch-pos-committee`
  **29/29**, `bloch-pos-node` **8/8**, `bloch-sis-pow` 18/23 — and then
  `bloch-crypto` 1/19, `bloch-euvm` 0/22, `bloch-pq-vault` 0/5,
  `coherence-core` 0/2, `coherence-prover` 0/3, `bloch-ffg` 0/1,
  `bloch-btc-wallet` 0/1, `pqcrypto-internals` 0/2. The new PoS work is
  clean; the inherited crates are not. Mechanical fix, worth doing before
  hand-off.
- Reproducible-build tooling exists (`REPRO.md`, `repro-manifest.sh`,
  `repro-compare.sh`) — the right substrate for "verify the binary you
  run" — but it is moot for outsiders while the repo is private.

**Remediation is one action: publish the repository.** Everything else in
this section is polish on top of that.

---

## 3. General

### 3.1 External calls — **consensus makes none; the two injection seams,
named**

In a token contract, "external calls" means calls into other contracts —
upgradable dependencies whose behaviour the token does not control. The L1
mapping: does any consensus rule reach outside committed state?

Measured: `crates/bloch-pos-committee` has no network I/O, no process
spawning, no FFI (`grep -rn 'extern|std::process|Command::'` over `src/` —
zero code hits), and no dependency on the PQClean C stack — deliberately.
What it has instead are **two injected capability traits**, which are the
audit-relevant analog:

1. **Signature verification** — `HybridKeyVerifier` (`staking.rs:120`) and
   `KeyVerifier` (`interfaces.rs:391`). The crate deliberately keeps the
   security-critical composition on its own side of the boundary: the
   AND-of-both-halves rule and the fixed split points live in
   `staking.rs::verify_hybrid` (`staking.rs:134`), so no injected
   implementation can weaken the hybrid to an OR. Tests
   `pop_requires_both_halves` and `truncated_pop_rejected_before_verifier_runs`
   pin it.
2. **The stake-eligibility oracle** — `StakeEligibility`
   (`interfaces.rs:403`). This is the "external call" the task brief asks
   about, and its contract is purity: implementations must answer from the
   taint-set state committed at the parent block (`taint_root`), never from
   a live index, and two nodes at the same parent must answer
   byte-identically (`interfaces.rs:400–402`). In Genesis-4 the taint set is
   empty by rule, so the oracle has no discretionary power to exercise
   (§1.3).

Both seams are *implemented by the node*, which is not written yet. The
audit item is not this crate — it is verifying, at integration, that the
node's implementations honour the purity contracts. There are no price
oracles, no cross-chain calls, and no other outward dependency in the
consensus rules.

### 3.2 Withdrawal function — **exists, and is provably inert as an attack
surface**

The scan's fear: a withdrawal function an owner can point at the contract's
balance. Bloch's only "withdrawal function" is
`staking.rs::validate_withdrawal` (`staking.rs:489`), and its shape is the
opposite of the feared one — **it takes no destination, no amount, and no
signature, because everything is already committed**:

- The payout address is fixed at deposit time and can never be supplied
  later (`DepositTx::withdrawal_addr`, `staking.rs:164`: the validator key
  is hot, and compromising it must not redirect the principal).
- The amount is the committed record's, already reduced by any slashing
  (`staking.rs:487`).
- Preconditions, each with a distinct reject and a test: an exit on record
  (`NotExited`; `withdrawal_without_exit_rejected`), the 2,048-epoch
  weak-subjectivity delay elapsed (`DelayNotElapsed`;
  `withdrawal_before_delay_rejected`), and single-shot payment
  (`AlreadyWithdrawn`; `double_withdrawal_rejected`).
- No signature is verified at withdrawal — and that is correct, not an
  omission: after the delay, the transfer of the recorded amount to the
  pre-committed address is *the only thing that can happen* to these coins
  (`staking.rs:484–488`). A function with no free parameters needs no
  authorisation.

There is no path in the crate by which a withdrawal reaches anyone else's
balance: the function is `fn(record, epoch) → (record.withdrawal_addr,
record.amount_sat)`, and nothing else in `src/` constructs a payout
(verified by reading every value-moving site; the only other value flows are
reward distribution — pro-rata arithmetic in `rewards.rs::distribute` and
`fee_market.rs::distribute_producer_fees`, both conservation-checked by
test — and slashing, §3.3).

### 3.3 Backdoor ownership recovery — **none found; here is the search, and
the two things an auditor might mistake for one**

Expected answer: no key recovers anyone else's funds. Evidence, not
assertion:

- **Vocabulary sweep.** `grep -rni
  'backdoor|recover|owner_|admin|privileged|superuser|master.?key|blacklist|whitelist'`
  over `crates/bloch-pos-committee/src/`: every hit is documentation or one
  of the two protocol mechanisms below. No role, no key, no
  reserved-address branch exists in any value path.
- **Value-path enumeration.** The complete set of operations that change a
  balance in this crate: reward payout (pro-rata, `rewards.rs:128`),
  producer-fee payout (`fee_market.rs:267`), withdrawal (§3.2, address
  fixed at deposit), and slashing (`delegation.rs::apply_slash`,
  `delegation.rs:484` — burns a rule-defined penalty from the offender and
  its delegators pro-rata, on cryptographic evidence of equivocation
  validated by `interfaces.rs::EvidenceReject` rules; nothing is paid *to*
  anyone discretionary). None takes an arbitrary destination. None takes an
  arbitrary source.

Two mechanisms will show up in an auditor's grep for "recover" and deserve
pre-emptive classification:

1. **The inactivity leak** (`finality.rs:322`, test
   `inactivity_leak_recovers_finality`): when finality stalls, offline
   validators' stake decays until the online set regains a quorum. It
   reduces balances by rule — Ethereum's identical device — and pays nobody.
   It is a liveness mechanism, not a recovery backdoor.
2. **The weak-subjectivity checkpoint multisig** (`ws.rs:295–309`): 2-of-3
   at launch (Foundation, Postern Labs, one external auditor), 3-of-5 with
   two external by first review. It signs *checkpoints for bootstrapping
   clients*. It cannot move funds, mint, or alter state — but it is a trust
   point: a colluding quorum could point a fresh, long-offline node at a
   wrong history. That is a centralization finding (cross-referenced to that
   dossier), not an ownership backdoor, and its honest bound is already
   documented in `ws.rs`.

**Conclusion: no backdoor ownership recovery, demonstrated by exhaustive
enumeration of value paths in the committee crate.** Standing caveat, same
as §3.1: the crate is the consensus authority but not the whole node; the
Genesis-4 node integration (transaction execution, state object) does not
exist yet, and this conclusion must be re-verified against it — put it on
the integration audit checklist rather than letting this dossier's answer
be quoted past its scope.

---

## 4. Contradictions found while writing this dossier (flagged, not fixed)

The fleet brief (2026-08-12) instructs building against the 100 B
redenomination and flagging contradictions. Found:

1. **The code says 21 B and frames it as final.**
   `tokenomics_v4.rs:26–33` reads "Back to the V2 nominal of 100 billion
   (founder decision, 2026-08-11), after a draft at 100 billion" — the
   brief's 2026-08-12 decision reverses this again. The doc comment's
   framing ("the revert removes two hazards for free") will be stale the
   moment the split lands.
2. **The int64 assertion will fail the build at 100 B — and it is right to.**
   `tokenomics_v4.rs:255`: `assert!(TOTAL_SUPPLY_SAT < i64::MAX as u128,
   "nao cabe no int64 do SDK Go")`. At 100 B, `TOTAL_SUPPLY_SAT` = 10¹⁹ >
   `i64::MAX` (9.22 × 10¹⁸), and is back at the old 54.21% of `u64::MAX` —
   the wrap hazard the revert to the 21 B V2 nominal had removed (both
   verified by arithmetic this session). The redenomination is *not* free
   as the brief states: the Go SDK's signed-64 `Satoshis` type breaks, and
   the assertion at line 254 (`< u64::MAX / 8`) fails too. Whoever lands the
   split must change the SDK type (or the decimals), not just delete the
   assertions.
3. **Snapshot height.** Brief says Genesis-3 halts at 50,000 (lowered
   2026-08-12); `docs/specs/BLOCH-TOKENOMICS-V4.md` §3.1 still says
   "decided: 50,000", and §2 measures the carryover "at height 43,172".
   The carryover constants will need re-measuring at the actual halt.
4. **Minimum deposit.** Brief decision 3 puts the validator bond near
   25,000 BLCH under the 100 B supply; `staking.rs:83` still says 100,000
   BLCH. All duration/threshold arithmetic in §1.3–1.4 uses the current
   constants and must be re-checked when that lands (the *fractions* —
   25 bps, 1%, one third — are supply-invariant; the floors in BLCH are
   not).

None of these change a §1–§3 verdict: no verdict above depends on the
denomination.

---

## 5. What changes when the EVM at L1 exists

Design docs: `docs/specs/BLOCH-L1-EVM-{AUTHORIZATION,STATE-MODEL,
RPC-SURFACE,THREAT-MODEL,REUSE-AUDIT}.md`, all status *proposed* — nothing
below is deployed.

**The category error dissolves — for contracts, not for BLCH.** With EVM at
L1 there are deployed contracts at addresses, and Skynet's token scan
becomes *literally runnable* against any of them, exactly as it runs against
BSC contracts today. Native BLCH itself remains unscannable for the same
reason native ETH is: it is not a contract. The first scannable object will
be whatever wrapped-BLCH contract gets deployed — and WBNB, the model the
founder pointed at, is precisely the pattern to copy: no owner, no mint
beyond deposit/withdraw, no tax hooks, no proxy. That contract's scan result
is a deliverable someone must own at deployment time.

Per check, what becomes literally applicable to contracts on Bloch:

| Skynet check | Status once EVM-L1 ships |
|---|---|
| buy/sell tax, tax modification | Literally applicable per token contract. The *chain's* fee layer stays as §1.1–1.2 — and becomes externally visible as `baseFeePerGas` over standard `eth_*` RPC (`BLOCH-L1-EVM-RPC-SURFACE.md` §2.4), auditable with unmodified Ethereum tooling. |
| buy/sell restrictions, transfer cooldown/pausability, blacklist/whitelist | Literally applicable per contract (these are `_transfer`-hook properties). |
| anti-whale, max wallet/tx | Literally applicable per contract. |
| honeypot, self-destruct, proxy, hidden owner, mintable, balance modification | Literally applicable per contract. |
| external calls | Literally applicable per contract; at chain level, §3.1's answer gains one entry — the EVM engine itself becomes a consensus dependency, with its version and gas schedule as fork surface (`BLOCH-L1-EVM-THREAT-MODEL.md` E1) and Keccak-256 entering consensus (E2). |
| withdrawal function / backdoor recovery | Literally applicable per contract; the chain-level answers (§3.2–3.3) are unchanged but gain the eUTXO↔EVM boundary as a new value path — deposit/withdraw between the transparent set and the account leaf, with a conservation invariant specified in `BLOCH-L1-EVM-STATE-MODEL.md` §4.5 that must be tested like `validate_withdrawal` is. |
| open source | Unchanged in kind, sharper in consequence: token-scan verification requires **verified source on a public explorer**. That infrastructure (explorer + verifier) is a prerequisite for anyone's contract passing anything — and it inherits §2.1's FAIL until the repo and the explorer exist publicly. |

Three Bloch-specific items that will shape scan results and have no BSC
analog:

1. **The authorisation decision decides the chain's security story.**
   Whether secp256k1 accounts exist at L1 (Options 1/3 of
   `BLOCH-L1-EVM-AUTHORIZATION.md`) decides whether a quantum-vulnerable
   spend path exists on the PQ chain (threat model E7/E8: recoverable
   pubkeys on-chain; stolen secp value is fungible and stakeable). GATED on
   the founder; every scan-facing security narrative depends on it.
2. **The PQ fee gap is visible to users.** A PQ-account EVM transaction
   pays ~12× the intrinsic gas of a secp256k1 one (~36× on authorisation
   alone) — pinned by `fee_market.rs::intrinsic_gas_prices_the_pq_byte_reality`
   and stated in `BLOCH-L1-FEE-MARKET.md` §3.2. Any subsidy is a GATED
   founder decision.
3. **Ustav at L1** (charter-as-consensus, per the 2026-08-11 brief) would
   give Bloch something the scan cannot express: token rules a contract
   *cannot* bypass because every node validates them. If it ships, the
   right framing for auditors is "the charter is the scan, enforced" — with
   the cost (charter bugs become chain bugs) stated alongside, as the brief
   requires.

---

## 6. Test evidence

Test run for this dossier: `cargo test` from
`crates/bloch-pos-committee/` (own workspace), 2026-08-12, at worktree
commit `84ca42a`. **Result: 297 passed, 0 failed** — lib 179, `tests/committee.rs`
101, `tests/e2e.rs` 15, doc-tests 2; exit code 0. Tests cited by name
in this document and what each pins:

| Test | Pins |
|---|---|
| `staking.rs::carryover_liquid_balance_is_stakeable` | rejection of a carryover deposit is by size only, never origin (§1.3) |
| `staking.rs::withdrawal_before_delay_rejected`, `withdrawal_without_exit_rejected`, `double_withdrawal_rejected` | the three withdrawal preconditions (§3.2) |
| `staking.rs::pop_requires_both_halves`, `truncated_pop_rejected_before_verifier_runs` | injected verifiers cannot weaken the hybrid AND (§3.1) |
| `fee_market.rs::net_inflation_stays_under_the_7_percent_target` | both fee eras and the burn direction (§1.1–1.2) |
| `fee_market.rs::delegation_survives_fee_only_era` | fee revenue conservation through the commission split (§3.3 value-path claim) |
| `fee_market.rs::intrinsic_gas_prices_the_pq_byte_reality` | the ~12× PQ/secp intrinsic gap (§5) |
| `finality.rs::inactivity_leak_recovers_finality` | the leak is bounded recovery, not discretion (§3.3) |

---

## 7. What this dossier did NOT do

- **Did not run the Skynet scanner** — it cannot run against a chain
  (§ preamble), and no wrapped-BLCH contract exists to point it at.
- **Did not audit the node/execution layer** — the Genesis-4 node
  integration does not exist; §3.1–3.3 conclusions are scoped to
  `bloch-pos-committee` and flagged for re-verification at integration.
- **Did not verify GitLab visibility from more than one vantage point** —
  the 404-vs-200 probes ran once, unauthenticated, from one network.
- **Did not fix** the missing SPDX headers, the nine license-less
  `Cargo.toml` files, the stale 21 B/50,000/100,000-BLCH values flagged in
  §4, or the `bloch-sis-pow` MIT-vs-AGPL question — flagged, owner
  decisions or other agents' surface.
- **Did not re-measure the carryover** at the new halt height (50,000); all
  concentration figures are the height-43,172 measurement the constants
  encode.
- **Did not cover** Rugpull or Centralization checks beyond the
  cross-references — other agents' categories.
