# ADR-041 — Validator exit and withdrawal lifecycle

Status: **ACCEPTED — founder decisions recorded 2026-09-08. ARMED 2026-09-09:
`L = 2700`** (≈2026-09-12 21:31 UTC), runbook `docs/VALIDATOR-LIFECYCLE-FLAG-DAY.md`.
The `= u64::MAX` values quoted below describe main as measured on `6e4b5323`,
when this ADR was written; the five constants now carry `2_700`.
(1) epoch **L**: best technical choice, targeted THIS WEEK — the concrete epoch is
fixed at release cut, not in this document; (2) the genesis principal write-off
(~1.6M BLCH, the founder's own never-issued principal) is explicitly reaffirmed;
(3) the RandaoRecommit rider ships at L; (4) `MAX_EXITS_PER_EPOCH = 4` stands,
revisit at roster >256; (5) crank policy: each node auto-cranks its own matured
withdrawal.

Originally: Nothing in this document changes a
running node. Every constant it names ships inert until the founder signs the
activation epoch, and every wire byte it assigns is unreleased until the
registry rows in `tests/wire_tag_registry.rs` are edited in the same commit
that adds the decoder arms.

Date: 2026-09-08. Written against `github/main` = `6e4b5323` (funded
validator admission merged, wire tag `0x0B`, inert behind
`FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH = u64::MAX`).

## Context — what exists, measured on `6e4b5323`

The lifecycle is four gates, and main already carries three of them further
than the audit folklore says:

1. **Admission** — `FundedDeposit` (0x0B) is complete: consumes real eUTXOs,
   dual role-separated hybrid-PQ authorizations, and **names a 32-byte
   withdrawal script in the signed intent**, stored into
   `ValidatorRecord::withdrawal_credentials` (`transition/funded.rs:370`,
   all-zero refused). Its spec forbids opening it for public funds before an
   exit/withdrawal path exists, and its flag day already refuses the
   unauthenticated legacy `Exit` (0x03).
2. **Exit** — `PosTransaction::ExitV2 { pubkey_hash, epoch, signature }` is
   implemented, tested and wired into the production dispatcher behind
   `EXIT_AUTH_ACTIVATION_EPOCH = u64::MAX` (hybrid signature against the
   *registered* key over `DS_EXIT`, signed epoch must equal inclusion epoch,
   churn cap `MAX_EXITS_PER_EPOCH = 4` derived from committed state, no new
   field). It is **encode-and-apply only**: `canonical_bytes` writes `0x08`,
   the decoder deliberately has no `0x08` arm because that byte is contested
   three ways across live lineages (`SignedExit` / `Withdraw` / `ExitV2`).
   The missing piece is one founder ruling on the byte plus a one-line
   decoder arm.
3. **Withdrawal** — `WITHDRAWAL_ACTIVATION_EPOCH = u64::MAX` exists and gates
   **nothing**: there is no `PosTransaction::Withdraw` variant on main, and
   `interfaces::ValidatorRecord` has no paid-out marker. `Exit`/`ExitV2` set
   `withdrawable_epoch`, the root commits it, and nothing has ever read it.
   Every genesis bond (1,600,000 BLCH) and all validator emission (minted
   directly into `staked_sat`, never into an eUTXO) is illiquid.
4. **Slashing evidence** — 0x05 decodes on main since F02 (`a8d289cf`),
   `apply_slashing_evidence` burns, ejects (`exit_epoch = epoch+1`), pays the
   1/32 whistleblower and **re-stamps
   `withdrawable_epoch = max(existing, slash_epoch + WITHDRAWAL_DELAY_EPOCHS)`**
   — all behind `SLASHING_EVIDENCE_ACTIVATION_EPOCH = u64::MAX`. What is
   missing is the node-side whistleblower path: a node that *observes* an
   equivocation still only logs it.

Constants that constrain the design, verified in source:
`EXIT_DELAY_EPOCHS = 32` (duties stop 32 epochs after exit),
`WITHDRAWAL_DELAY_EPOCHS = 2,048` (≈ 22.8 days),
`CORRELATION_WINDOW_EPOCHS = 4,096` (= 2× the withdrawal delay — the 2× rule
must survive this ADR), `MAX_EXITS_PER_EPOCH = 4`,
`GENESIS_UNFUNDED_BONDED_CEILING_SAT = 1,600,000 BLCH` (the frozen record
that the 64 genesis bonds sit **outside** `GENESIS_ISSUED_SAT`).

The supply trap this ADR must not fall into: `accounted_supply_sat` counts
`staked_sat`, so paying a genesis bond into an eUTXO **does not trip
`supply_conserved`** — the offset cancels in the delta. Full payout would
nonetheless convert 1.6M BLCH that `issued_sat` never counted into spendable
coin. The invariant cannot see this failure; only the payout rule can prevent
it.

## Branch survey (moved-main discipline: old branches are re-derived, never force-merged)

| Branch (+commits) | Lifecycle piece | Quality | Rot vs main `6e4b5323` | Verdict |
|---|---|---|---|---|
| `port/validator-withdrawal-release` (+1, 2026-09-02) | Pull-style `Withdraw { validator }` crank: pays `staked_sat − unbacked principal` (low-water floored) to the registered 32-byte credential as a fresh eUTXO, books the remainder as `written_off_sat`, refuses the indeterminate class, priced-but-fee-free, replay-safe via `staked_sat == 0`. Also ports the A7 whistleblower cap. Itself a survey-and-port of six earlier withdrawal branches (reference `dev1/transition-merge`). | High — violation tests both directions, 10 mutations run, conservation equality explicit | Base `7a83ca89` (pre-funded-admission); merge-tree: **4 conflicts**. Its rule "every deposit is written off in full" predates `FundedDeposit` and is now WRONG for funded validators | **REUSE AS BASE** — re-port onto main; re-key backedness: `FundedDeposit` bonds are fully backed (unbacked = 0), genesis/legacy bonds keep the write-off |
| `rescue/wt-exitcarrier-final` (+52) | Signed-exit wire carrier at **tag 0x09** + §11.1, plus a large non-consensus payload (VALIDATOR-RUNBOOK, observability, slashing-protection spec, ops scripts) | Mixed; carrier is sound but duplicates main's ExitV2 | Base 2026-09-01; **20 conflicts**; its 0x09 choice violates the contested-space ruling this ADR adopts | **SUPERSEDED** for consensus (main's ExitV2 survives). **MINE** the docs/runbooks/ops scripts as separate non-consensus salvage |
| `slashing/evidence-reachable-gated` (+4) | (a) evidence decodable+gated — already re-derived on main as F02; (b) node-side `report_equivocation`: observe → construct evidence → mempool → broadcast | Good, focused | **2 conflicts**; half superseded | **RE-DERIVE (b) only** — the whistleblower submission path in `engine.rs`/`p2p.rs` |
| `safety/slashing-protection` (+5) | Durable local double-sign fence (node-local, not consensus) + staking-cli/ops tooling | Good idea, node-local | 2026-09-02 base; mostly tooling atop wip commits | **RE-DERIVE the fence** separately; not part of this consensus decision |
| `rescue/wt-wdexec-final` (+5) | staking-cli / validator-ops tooling; no consensus withdrawal execution despite the name | Tooling-grade | Shares the wip base | **SALVAGE tooling later**; nothing consensus-bearing to take |
| `rescue/genesis-bond-issuance-hole` (+20) | `DepositV2` at 0x07 / `Withdraw` at 0x08 (dead wire choices), exit throughput gate (now on main as the churn cap), **compile-time gate-ordering asserts**, and the pinned test "the hole the flag-day ordering cannot reach" | Uneven; wire choices dead | **13 conflicts**; deposit shape superseded by 0x0B | **RE-DERIVE two ideas**: the compile-time arming-order asserts and the ordering-hole pin test |
| `wip/funded-stake-a7` / `wip/funded-stake-flagday` (+3/+1, 2026-08-21) | Pre-ratchet funded-stake attempt + whistleblower cap | Historical | Superseded by merged 0x0B admission; cap already carried by the port branch | **DISCARD** (history only) |

## Decision

Open the full lifecycle as **one flag day** (the *lifecycle epoch* `L`), with
these five rulings:

### D1 — Wire bytes: fresh assignments, contested space retired forever

Follow the `0x0B` precedent exactly. **`0x07`–`0x09` are permanently
poisoned** — no tree may ever decode them; the registry keeps them as
tombstones. Assign:

- **`0x0C` = `ExitV2`** (change the encoder's byte from `0x08` to `0x0C` —
  safe, nothing has ever decoded either; the txid folds the tag, so the byte
  is fixed in the same release that arms the gate, never after);
- **`0x0D` = `Withdraw`** (replaces the port's `WITHDRAW_WIRE_TAG = None`
  sentinel);
- **`0x0A` = `RandaoRecommit`** released as-is (sole claimant in the
  2026-09-02 sweep; already what `canonical_bytes` writes).

Rejected: ruling `0x08 = ExitV2`. Live lineages hold binaries where `0x08`
decodes to a semantically incompatible `Withdraw`; releasing it invites a
decode-split with any resurrected branch binary, and the fresh-byte
discipline already has a working precedent.

### D2 — Exit: main's `ExitV2` is the exit, unchanged

Hybrid signature verified in consensus against the registered pubkey over
`DS_EXIT ‖ pubkey_hash ‖ epoch`; signed epoch must **equal** the inclusion
epoch (replay-bound); `MAX_EXITS_PER_EPOCH = 4` churn budget derived from
committed `exit_epoch` values (no new field, no root movement); legacy `Exit`
(0x03) consensus-invalid at `L`. Genesis-digest binding: `DS_EXIT` does not
fold the genesis manifest digest today; because the signed epoch must equal
the inclusion epoch and registries diverge across networks, cross-network
replay requires an identical registry at an identical epoch — accept for now,
and fold the network domain into `DS_EXIT2` **only if** the
`SIGHASH_NETWORK_BINDING` flag day is armed for transfers (do both under one
announcement; do not invent a second signing-root migration alone).

The only new consensus code for exit is the `0x0C` decoder arm plus the
registry edit.

### D3 — Withdrawal: a pull-style unsigned crank, paying the backed part to the deposit-named script

Re-port `port/validator-withdrawal-release` onto main:

- **Shape**: `Withdraw { validator: u32 }`, five canonical bytes, unsigned.
  Anyone may crank it; it cannot be stolen because the payout is fully
  determined by committed state: one eUTXO
  `{ txid, vout: 0, value: payout, script_hash: withdrawal_credentials }`.
  The credential must already be the 32-byte script form (genesis
  credentials are `founder H160 ‖ 12 zero bytes`, which the transfer
  ownership check opens; `FundedDeposit` credentials are the signed script).
- **Guards, in order**: gate (`WITHDRAWAL_ACTIVATION_EPOCH`), indeterminate
  write-off class refused, `epoch ≥ withdrawable_epoch` (which is also the
  must-have-exited rule, since the field is `u64::MAX` until exit or slash),
  32-byte credential, `staked_sat > 0` (the replay/one-shot rule — zeroing
  the bond IS the paid marker, so **no new `withdrawn` field and no record
  encoding migration**), explicit `u64` narrowing (never saturating), output
  collision refused.
- **Amount**: `payout = staked_sat − min(unbacked_principal, staked_sat)`;
  the remainder is booked to a committed, monotone `written_off_sat` audit
  column. **Re-keyed for funded admission** (the one place the port is
  stale): `unbacked_principal = 0` for validators admitted by
  `FundedDeposit`; for the 64 genesis records it is the seeded principal
  (25,000 BLCH each), floored by the bond's low-water mark so slashing burns
  unbacked principal first. Legacy `Deposit`/`Delegate` gates stay
  `u64::MAX` forever, so no third class ever appears — assert that in the
  arming-order module (D5).
- **Fees**: priced but fee-free — bytes and gas count against both block
  caps (no free-stuffing vector), settled fee zero, so fully-slashed and
  pure-write-off bonds can still be closed and their write-off recorded.
  One per validator per lifetime; not a spam surface.
- **Conservation equality enforced in the arm**:
  `staked_before − staked_after == payout + written_off`, `issued_sat`
  untouched — correct **only because** the payout excludes unissued
  principal.

**Push (automatic payout in `close_epoch`) is rejected**: it does unmetered,
unbounded work at the epoch boundary — the single most fork-prone code path
in this chain's history (leak/roster incidents of 2026-08) — outside the
block caps and outside the one audited transaction pipeline where the
supply-conservation check runs per block. **A signed `WithdrawalClaim` is
rejected**: a ~4.6 KB hybrid witness buys no authority (the destination was
fixed and signed at deposit; a signature can change nothing) and adds a
griefing surface — a lost validator key would strand funds that belong to
the withdrawal-credential holder.

### D4 — Genesis validators: exit normally, withdraw accrual only

The 64 genesis records hold registered hybrid keys, so `ExitV2` works for
them unchanged, inside the same churn budget. Their withdrawal pays
`staked_sat − 25,000 BLCH` — i.e. accrued issuance only; the never-issued
principal is written off. All 64 credentials are the founder's, so the
economic weight of this ruling falls entirely on the founder: **the founder
forfeits 1.6M BLCH of nominal principal to keep spendable supply ≤ issued
supply.** (This re-affirms the ruling already recorded on the
`demo/final-writeoff-ruled` lineage; it is restated here because ADRs, not
branch names, are where rulings live.) A genesis operator who wants a backed
bond exits, withdraws the accrual, and re-registers with real coins via
`FundedDeposit` — voluntary, never forced: forcing re-registration would
churn the roster inside the cohort-taper security window (external share of
finality is scheduled regardless of turnout; deadline 2027-08-13).

Rejected: paying genesis principal in full (mints 1.6M invisible to
`issued_sat`); excluding genesis validators from exit until re-registration
(no supply reason once the write-off exists, and it would make the founder's
own de-risking impossible).

### D5 — Slashing interaction and packaging: one lifecycle flag day

A slashed validator withdraws through the **same** `Withdraw` arm: the
penalty was already burned from `staked_sat` at prosecution, and
`apply_slashing_evidence` re-stamps
`withdrawable_epoch = max(existing, slash_epoch + WITHDRAWAL_DELAY_EPOCHS)`,
so the residue stays reachable for late correlated evidence. The 2× rule is
promoted from a comment to code:
`const _: () = assert!(CORRELATION_WINDOW_EPOCHS >= 2 * WITHDRAWAL_DELAY_EPOCHS);`
The A7 whistleblower cap rides along: a slashing reward may never be paid out
of unbacked principal.

**Packaging: one combined flag day.** Set, in one release:

```
FUNDED_VALIDATOR_ADMISSION_ACTIVATION_EPOCH = L
EXIT_AUTH_ACTIVATION_EPOCH                  = L
WITHDRAWAL_ACTIVATION_EPOCH                 = L
SLASHING_EVIDENCE_ACTIVATION_EPOCH          = L
RANDAO_RECOMMIT_ACTIVATION_EPOCH            = L   (rider — see below)
```

The constants stay **separate** (independently revocable before release),
pinned by a compile-time arming-order module (re-derived from
`rescue/genesis-bond-issuance-hole`):

```
ADMISSION == EXIT_AUTH           // the Exit arm already refuses legacy 0x03 when
                                 // EITHER gate is live: admission without a
                                 // decodable ExitV2 abolishes voluntary exit
WITHDRAWAL >= EXIT_AUTH          // nothing is withdrawable before exits exist
EVIDENCE   <= WITHDRAWAL         // stake must be slashable no later than it is liquid
DEPOSIT_ACTIVATION_EPOCH == u64::MAX  // the unfunded era never reopens
```

Why combined and not staged: every flag day costs a coordinated fleet
rebuild plus ~21 minutes of mute RPC and 40–198 slots of gap per node
restart, run fleet-wide — the dominant operational risk on this network is
the rollout, not the code. The admission spec itself forbids opening
deposits before the lifecycle exists, and the code already hard-couples
legacy-Exit refusal to the admission gate, so staging admission after
exit/withdrawal buys a second rebuild for no decoupling that the code does
not already deny. Blast radius is bought down with rehearsal, not with
stages: extend `scripts/rehearse-validator-admission.py` to drive the full
cycle (deposit → activate → attest → exit → wait → withdraw → **spend the
payout eUTXO with the withdrawal key**) on a source copy with `L = 0`,
plus a multi-epoch devnet soak before the epoch is announced.

`RandaoRecommit` at `L` is the default (its deadline is real: first chains
exhaust ~2027-02-11, and a later separate flag day is a whole second fleet
rebuild), but it is severable — dropping it changes nothing else in this ADR.

## Activation plan

1. **Land inert on main** (order within one PR series, no behavior change at
   any reachable epoch): (a) `0x0C`/`0x0D`/`0x0A` decoder arms + registry
   rows flipped to Released, 0x07–0x09 tombstoned; (b) the re-ported
   `Withdraw` arm keyed on funded-vs-genesis backedness + `written_off_sat` +
   low-water recorder (ungated, empty on today's chain — see test T-9); (c)
   the arming-order assert module; (d) node-side `report_equivocation`
   re-derived from `slashing/evidence-reachable-gated`; (e) mempool
   `admissible` arms for 0x0C/0x0D (policy, gated on the same constants).
2. **Rehearse**: full-lifecycle rehearsal script + two-node engine run +
   devnet soak across ≥ 3 epoch boundaries with a slashing prosecution and a
   post-slash withdrawal in the body.
3. **Founder signs `L`**, one reproducible release, fleet rebuild audited
   node-by-node (the E=1400 rollout runbook is the template: enumerate by
   RPC, verify the binary digest, zero blocks with two roots during soak).
4. Only after `L` is past and one full withdrawal has settled on mainnet:
   announce external-validator opening (the admission spec's "not for public
   funds" sentence is discharged by this ADR being LIVE, not by it being
   merged).

## Test obligations (violation tests, FundedDeposit coverage style)

- **T-1 wire**: full single-byte decode sweep before/after assignment;
  0x07–0x09 refuse forever; txid stability pinned to the assigned byte.
- **T-2 exit**: future epoch, stale epoch (replay one epoch later), wrong
  `pubkey_hash`, each hybrid half failing independently, exit of
  slashed/exited/not-yet-active validator, 5th exit in an epoch refused,
  legacy 0x03 refused **by consensus** at ≥ L with the mempool bypassed.
- **T-3 withdraw guards**: each guard deleted in turn must kill a test
  (mutation pass, as the port did — re-run it on the re-port): early crank,
  double crank, indeterminate class, malformed credential, output collision,
  saturating-cast regression.
- **T-4 conservation**: `staked_before − staked_after == payout +
  written_off` asserted in-arm and end-to-end; `issued_sat` unmoved;
  `supply_conserved` holds across a block containing a withdrawal; a
  deliberately full-principal payout must be shown to violate the
  spendable ≤ issued audit even though `supply_conserved` cannot see it.
- **T-5 backedness keying**: FundedDeposit validator withdraws in full;
  genesis validator withdraws exactly `staked_sat − 25,000 BLCH`; a
  slashed-below-principal genesis bond pays zero and still closes.
- **T-6 slashing**: post-slash withdrawal only after the re-stamped lock; a
  second correlated prosecution inside `CORRELATION_WINDOW_EPOCHS` still
  reaches the unwithdrawn residue; whistleblower cap: reward never exceeds
  backed stake; the 2× static assert.
- **T-7 mixed fleet**: below `L`, every arm byte-identical to today
  (control); every gate reads the committed epoch rolled by
  `compute_post_state`, never node-local (the 2026-08-08 lesson).
- **T-8 rehearsal**: two-node engine, full lifecycle, ending in a real
  `TransferV2` spend of the withdrawal eUTXO by the credential holder.
- **T-9 low-water recorder**: pin that nothing on today's chain writes it —
  in particular that the inactivity leak (armed at epoch 2,700) adjusts
  roster weight only and never `staked_sat`; if that ever changes, the
  ungated recorder becomes a mixed-fleet root split and this pin must fire.

## Founder decision points (defaults, not settled facts)

1. **The epoch `L`** — must precede RANDAO exhaustion (~2027-02-11) if the
   rider stays, and comfortably precede the 2027-08-13 cohort-taper
   deadline. Business choice; no default named here.
2. **The genesis write-off** (D4) — technically forced if spendable ≤ issued
   is to hold, but it is the founder's 1.6M BLCH: reaffirm explicitly.
3. **RandaoRecommit rider** — default YES at `L`; severable.
4. **Churn cap value** — default keep `MAX_EXITS_PER_EPOCH = 4`; revisit
   when the roster exceeds ~256 (full-roster drain time scales linearly).
5. **Crank policy** — default: each node auto-cranks its own validator's
   matured withdrawal (mempool convenience; consensus is permissionless
   either way).

## What this does not solve

- **Delegation exit/withdrawal**: `Delegate` positions and the
  `delegator_fee_rewards` / `validator_fee_rewards` /
  `delegator_issuance_rewards` ledgers still have no payout path — the same
  shape of hole, one layer out. Needs its own ADR.
- **Deposit-and-mint audit closure**: the genesis offset stays committed
  history; this ADR stops it becoming spendable, it does not erase it.
- **Withdrawal-credential rotation**: the script named at deposit is final;
  a compromised withdrawal key has no recovery path.
- **Finality-aware activation/exit**: the 8-epoch queue delay and the exit
  clock count epochs, not finalized checkpoints (the admission spec's own
  caveat stands).
- **Network-bound exit signing** (`DS_EXIT2`): deferred to the
  `SIGHASH_NETWORK_BINDING` decision (D2).
- **Non-consensus salvage**: the runbooks, observability, staking-cli,
  double-sign fence and ops scripts on the rescue/safety branches are worth
  mining but are outside this consensus decision.
- **No independent cryptographic or consensus audit** of the combined
  lifecycle has occurred; the rehearsal evidence is internal.
