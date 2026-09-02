// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The supply surface: the constants Genesis-4 was built from, the emission
// curves that are still a decision, and the client for `getsupply`.
//
// EVERY CONSTANT HERE IS MIRRORED FROM `crates/bloch-pos-committee/src/
// tokenomics_v4.rs`. It is a mirror and not a source: if the two disagree, the
// crate is right and this file is a bug. `supplyMirrorSelfCheck()` below
// re-derives the two figures the crate pins with compile-time assertions
// (`VALIDATOR_EMISSION_BLOCH == 42_853_600_000` and the 40-year decay residual
// `EMISSION_DUST_SAT == 855_280`), so a mistyped digit here fails visibly on
// the page instead of being rendered as fact.
//
// Arithmetic is bigint throughout. The cap is 1e19 sat, ~1110x JavaScript's
// exact-integer limit; a satoshi routed through a Number is silently wrong.

export const SAT = 100_000_000n;

// ── Buckets, exactly as tokenomics_v4.rs declares them ──────────────────────

export const TOTAL_SUPPLY_BLOCH = 100_000_000_000n;
export const TOTAL_SUPPLY_SAT = TOTAL_SUPPLY_BLOCH * SAT;

export const FOUNDER_BLOCH = 10_000_000_000n;
export const VC_BLOCH = 10_000_000_000n;
export const TEAM_BLOCH = 10_000_000_000n;
export const MARKETING_BLOCH = 4_000_000_000n;
export const LIQUIDITY_BLOCH = 5_000_000_000n;

/** The pinned carryover. Disputed — see `CARRYOVER_DISPUTE`. */
export const CARRYOVER_TOTAL_BLOCH = 18_146_400_000n;

export const ALLOCATIONS_TOTAL_BLOCH =
  FOUNDER_BLOCH + VC_BLOCH + TEAM_BLOCH + MARKETING_BLOCH + LIQUIDITY_BLOCH;

/**
 * The remainder of a fixed total. This is the definition, not a measurement:
 * `TOTAL − carryover − the five buckets`.
 */
export const VALIDATOR_EMISSION_BLOCH =
  TOTAL_SUPPLY_BLOCH - CARRYOVER_TOTAL_BLOCH - ALLOCATIONS_TOTAL_BLOCH;
export const VALIDATOR_EMISSION_SAT = VALIDATOR_EMISSION_BLOCH * SAT;

/**
 * Everything that exists at slot 0 — and it is defined as the total minus the
 * emission, which is why `check_supply()` cannot corroborate it. See
 * `TAUTOLOGY` below.
 */
export const GENESIS_ISSUED_SAT = TOTAL_SUPPLY_SAT - VALIDATOR_EMISSION_SAT;
export const GENESIS_ISSUED_BLOCH = GENESIS_ISSUED_SAT / SAT;

// ── Time grid ───────────────────────────────────────────────────────────────

export const SLOTS_PER_YEAR = 1_051_920n;
export const EMISSION_YEARS = 40n;
export const EMISSION_SLOTS = SLOTS_PER_YEAR * EMISSION_YEARS;
export const SLOT_SECS = 30;

// ── Concentration ───────────────────────────────────────────────────────────

/**
 * The 20-byte hash-160 every allocation is paid to, zero-extended to the
 * 32-byte script hash the ledger is keyed by. `main.rs:605-612` builds all five
 * `GenesisAllocation` rows from this one constant — there is no second address
 * in the allocation set.
 */
export const FOUNDER_H160 = "e986db5149cff7499b282a048272a09aff0af4ff";
export const FOUNDER_SCRIPT_HASH = FOUNDER_H160 + "0".repeat(24);

/**
 * The same address's carried balance — `LARGEST_CARRYOVER_ADDRESS_BLOCH`,
 * pinned in the crate against the Genesis-3 satoshi measurement under the
 * x100/21 split.
 */
export const LARGEST_CARRYOVER_BLOCH = 17_046_829_380n;

/** Distinct addresses in the carried balance set. */
export const CARRYOVER_ADDRESSES = 16;
/** Unspent outputs carried across; the heaviest address holds 426,194 of them. */
export const CARRYOVER_UTXOS = 452_726;
export const LARGEST_CARRYOVER_UTXOS = 426_194;

/** Allocations plus carried balance, at one script hash. */
export const CONCENTRATED_BLOCH = ALLOCATIONS_TOTAL_BLOCH + LARGEST_CARRYOVER_BLOCH;

// ── The launch cohort ───────────────────────────────────────────────────────

export const COHORT_VALIDATORS = 64n;
/** `staking.rs::MIN_DEPOSIT_SAT` — 25,000 BLOCH. */
export const MIN_DEPOSIT_BLOCH = 25_000n;
/** 64 x the minimum deposit. Outside `GENESIS_ISSUED_SAT`; see the page. */
export const COHORT_BOND_BLOCH = COHORT_VALIDATORS * MIN_DEPOSIT_BLOCH;

// ── The two artefacts that disagree ─────────────────────────────────────────

/**
 * `tokenomics_v4.rs:CARRYOVER_TOTAL_BLOCH` says one thing and the ceremony tool
 * (`tools/genesis4-ceremony/src/lib.rs:1234`) asserts another. Both are in the
 * repository, both are load-bearing, and they cannot both be right.
 */
export const CARRYOVER_DISPUTE = {
  pinned: 18_146_400_000n,
  pinnedSource: "crates/bloch-pos-committee/src/tokenomics_v4.rs",
  pinnedHeight: 39_918,
  pinnedUtxos: 452_726,
  measured: 17_970_880_000n,
  measuredSource: "tools/genesis4-ceremony/src/lib.rs:1234",
  measuredUtxos: 448_337,
  get differenceBloch() {
    return this.pinned - this.measured;
  },
} as const;

// ── Emission curves ─────────────────────────────────────────────────────────
//
// Three are defined in the crate and NONE is aliased as "the" reward. The
// comment there is explicit about why: "picking one here would make a founder
// decision look like an implementation detail." So the page shows three, and
// says the choice is open. Each function below is a transcription of its Rust
// counterpart including the integer truncation, which is load-bearing — the
// residual under the cap is a consequence of it.

/** `validator_reward_flat_sat` — constant for 40 years, then fee-only. */
export function rewardFlatSat(slot: bigint): bigint {
  if (slot >= EMISSION_SLOTS) return 0n;
  return VALIDATOR_EMISSION_SAT / EMISSION_SLOTS;
}

export const HALVING_PERIOD_SLOTS = 4n * SLOTS_PER_YEAR;
export const HALVINGS = 10n;
/** `INITIAL_REWARD_SAT`, derived so ten periods sum to the allocation. */
export const INITIAL_REWARD_SAT =
  (VALIDATOR_EMISSION_SAT * 1024n) / (HALVING_PERIOD_SLOTS * 2046n);

export function rewardHalvingSat(slot: bigint): bigint {
  if (slot >= EMISSION_SLOTS) return 0n;
  const era = slot / HALVING_PERIOD_SLOTS;
  if (era >= HALVINGS) return 0n;
  return INITIAL_REWARD_SAT >> era;
}

export const DECAY_NUM = 9n;
export const DECAY_DEN = 10n;
/** `INITIAL_ANNUAL_SAT`, solved for under exactly this truncating arithmetic. */
export const INITIAL_ANNUAL_SAT = 434_965_169_252_191_762n;

export function rewardDecaySat(slot: bigint): bigint {
  if (slot >= EMISSION_SLOTS) return 0n;
  const year = slot / SLOTS_PER_YEAR;
  let annual = INITIAL_ANNUAL_SAT;
  for (let n = 0n; n < year; n++) annual = (annual * DECAY_NUM) / DECAY_DEN;
  return annual / SLOTS_PER_YEAR;
}

function emittedBy(slot: bigint, reward: (s: bigint) => bigint): bigint {
  // Year-granular accumulation: every curve here is constant within a year
  // (flat trivially, halving because 4 | 1 year, decay by construction), so
  // this is exact and not a sample.
  const end = slot > EMISSION_SLOTS ? EMISSION_SLOTS : slot;
  let total = 0n;
  for (let y = 0n; y < EMISSION_YEARS; y++) {
    const start = y * SLOTS_PER_YEAR;
    if (end <= start) break;
    const inYear = end - start;
    const span = inYear > SLOTS_PER_YEAR ? SLOTS_PER_YEAR : inYear;
    total += reward(start) * span;
  }
  return total;
}

export const emittedFlatBy = (s: bigint) => emittedBy(s, rewardFlatSat);
export const emittedHalvingBy = (s: bigint) => emittedBy(s, rewardHalvingSat);
export const emittedDecayBy = (s: bigint) => emittedBy(s, rewardDecaySat);

/**
 * `EMISSION_DUST_SAT` — satoshis of the validator allocation the decay curve can
 * never emit, because the 40-year sum is a multiple of `SLOTS_PER_YEAR` and the
 * allocation is not. Permanently unissued: it errs under the cap, never over.
 */
export const EMISSION_DUST_SAT = 855_280n;

/** Annual issuance as basis points of TOTAL supply — the way Solana and Ethereum quote it. */
export function annualInflationBps(year: bigint): bigint {
  let annual = INITIAL_ANNUAL_SAT;
  for (let n = 0n; n < year; n++) annual = (annual * DECAY_NUM) / DECAY_DEN;
  return (annual * 10_000n) / TOTAL_SUPPLY_SAT;
}

// ── Self-check ──────────────────────────────────────────────────────────────

export interface MirrorCheck {
  ok: boolean;
  failures: string[];
}

/**
 * Re-derive what the crate pins with `const _: () = assert!(…)`. This is the
 * only thing standing between a typo in this file and a wrong number rendered
 * as a fact, so the page shows the result rather than trusting it silently.
 */
export function supplyMirrorSelfCheck(): MirrorCheck {
  const failures: string[] = [];
  if (VALIDATOR_EMISSION_BLOCH !== 42_853_600_000n)
    failures.push(
      `VALIDATOR_EMISSION_BLOCH is ${VALIDATOR_EMISSION_BLOCH}, crate asserts 42,853,600,000`,
    );
  if (
    CARRYOVER_TOTAL_BLOCH +
      ALLOCATIONS_TOTAL_BLOCH +
      VALIDATOR_EMISSION_BLOCH !==
    TOTAL_SUPPLY_BLOCH
  )
    failures.push("buckets do not sum to the cap");
  const residual = VALIDATOR_EMISSION_SAT - emittedDecayBy(EMISSION_SLOTS);
  if (residual !== EMISSION_DUST_SAT)
    failures.push(
      `decay 40-year residual is ${residual} sat, crate asserts ${EMISSION_DUST_SAT}`,
    );
  if (GENESIS_ISSUED_SAT + VALIDATOR_EMISSION_SAT !== TOTAL_SUPPLY_SAT)
    failures.push("genesis issuance plus emission does not equal the cap");
  return { ok: failures.length === 0, failures };
}

// ── getsupply ───────────────────────────────────────────────────────────────

/**
 * The response shape proposed in `docs/specs/BLOCH-RPC-STABILITY-V4.md` §5.1 —
 * an O(1) read of the committed `issued_sat` counter (`TAG_ISSUED_SUPPLY`).
 *
 * It does not exist on the node yet. `rpc.rs:RPC_ABSENT` carries the name with
 * the reason, and the public proxy answers `-32601` for it. This interface is
 * written against the spec so that when the sibling change lands, the page
 * starts showing live figures with no further work — and so that the shape it
 * lands with is the shape a reader was already promised.
 */
export interface G4Supply {
  issued_sat: string;
  cap_sat: string;
  remaining_sat: string;
  genesis_issued_sat: string;
  emitted_since_genesis_sat: string;
  at_slot: number;
  at_epoch: number;
  finalized: boolean;
  note?: string;
}

/** Circulating supply is deliberately not in `getsupply` — §5.1. */
export const CIRCULATING_NOT_SERVED =
  "Circulating supply requires a full scan of the unspent-output set. The spec " +
  "refuses to compute it per request on the consensus thread; if it is served " +
  "at all it must be memoised per finalised epoch and report the epoch it was " +
  "computed at. No endpoint offers it today.";

// ───────────────────────────────────────────────────────────────────────────
// The founder's position, with every denominator named
// ───────────────────────────────────────────────────────────────────────────
//
// Four figures for "founder concentration" circulate and they describe four
// different things. Published together or not at all: a reader given one
// number and no denominator cannot tell which question it answers, and the
// three that are real move in OPPOSITE directions depending on the denominator
// chosen.
//
// The genesis row is the one that must never be dropped. Without it
// "27.04% -> 37.92%" reads as growth, when the position has in fact SHRUNK
// from 56.05%.
//
// MEASURED vs STATED is the distinction that gives this table its value.
// Everything marked `measured` is reproducible from the chain by anyone. The
// `sold` row is NOT: the founder states the outflow was private sales to third
// parties, and the chain cannot attribute control of an address to anyone,
// ever. An auditor re-running this must reproduce every measured row and must
// FAIL to reproduce that one. If they can reproduce it, something is wrong
// with the claim, not with the auditor.

/** Total supply cap, BLCH. */
export const CAP_BLOCH = 100_000_000_000;

/** Issued so far — the denominator that is not the cap. */
export const ISSUED_BLOCH = 57_146_400;

/** Issued so far, to the satoshi scale used in the table below. */
export const ISSUED_FOR_TABLE_BLOCH = 57_146_400_000 / 1000; // 57,146,400 BLCH

export type Provenance = "measured" | "stated";

export interface FounderRow {
  key: string;
  label: string;
  /** BLCH, as measured/stated. Decimal string — it exceeds a JS integer. */
  bloch: string;
  /** Percent of the 100B cap. */
  ofCap: string;
  /** Percent of what has been issued so far. */
  ofIssued: string;
  provenance: Provenance;
  note: string;
}

/**
 * The three rows that are real, in the order that makes the movement legible.
 *
 * Measured against the chain on 2026-09-01. The outflow spans epochs 184-1618
 * to 14 addresses.
 */
export const FOUNDER_POSITION: FounderRow[] = [
  {
    key: "genesis",
    label: "At genesis",
    bloch: "56,046,829,380.86",
    ofCap: "56.05%",
    ofIssued: "98.08%",
    provenance: "measured",
    note: "Five buckets at one script hash. This is the row that makes the other two readable: leave it out and a rising percentage looks like accumulation.",
  },
  {
    key: "today",
    label: "Today",
    bloch: "37,918,473,235.79",
    ofCap: "37.92%",
    ofIssued: "66.35%",
    provenance: "measured",
    note: "The same address, now. Lower than genesis against both denominators.",
  },
  {
    key: "sold",
    label: "Left the address",
    bloch: "18,128,356,145.07",
    ofCap: "18.13%",
    ofIssued: "31.72%",
    provenance: "stated",
    note: "Epochs 184-1618, to 14 addresses. That it MOVED is measured. That it was sold to third parties is the founder's statement, and the chain cannot confirm or refute it — an address is not an identity.",
  },
];

/**
 * The number published on the site today, which is none of the above.
 *
 * `FOUNDER_TOTAL_BLOCH` = largest carryover + the founder grant, and it OMITS
 * the other four buckets (VC, TEAM, MARKETING, LIQUIDITY = 29B) which
 * `main.rs:605-622` writes to the SAME script hash. It has understated from
 * genesis onward. It is pinned by a compile-time assert
 * (`tokenomics_v4.rs:446`), which froze the arithmetic without making it
 * correct — the assert proves the constant has not drifted, not that it
 * measures what its name says.
 */
export const PUBLISHED_UNDERSTATEMENT = {
  percent: "27.04%",
  omittedBuckets: "VC, TEAM, MARKETING, LIQUIDITY",
  omittedBloch: "29,000,000,000",
};

/**
 * There is no on-chain lockup on ANY of it — sold or retained.
 *
 * `unlock_epoch` is 0 on all five buckets, no node reads the field, and all
 * five were spent between epochs 1052 and 1167. Documented and tested on
 * `main` at commit fa4ad9be. This belongs beside the concentration figures
 * rather than in a footnote: a reader who sees a vesting schedule in the
 * tokenomics and no lockup here should learn that from this page.
 */
export const NO_ONCHAIN_LOCKUP = {
  unlockEpoch: 0,
  bucketsSpentFrom: 1052,
  bucketsSpentTo: 1167,
  evidenceCommit: "fa4ad9be",
  /**
   * The two tests that make this checkable rather than our word.
   *
   * `vesting_is_not_enforced` greps the SPENDING-AUTHORISATION crate
   * (`bloch-pos-committee`) for `unlock_epoch` and asserts ZERO occurrences —
   * so it fails the moment anyone adds a read, which is the only way a claim
   * about absence can be maintained. `the_shipped_buckets_are_all_liquid_at_slot_zero`
   * asserts every bucket in `genesis-mainnet` carries `unlock_epoch: 0`.
   *
   * Both are verified by violation: they were made to fail before being
   * trusted to pass.
   */
  tests: ["vesting_is_not_enforced", "the_shipped_buckets_are_all_liquid_at_slot_zero"],
  crateChecked: "bloch-pos-committee",
};
