// Emission schedule — V2 curve below the Emission V3 fork, V3 curve at/above it.
//
// TWO THINGS THAT ARE EASY TO GET WRONG:
//
// 1. Bloch's subsidy is NOT a function of the local block height you see in the
//    explorer. Genesis-3 restarted the local chain at height 0 but deliberately
//    CONTINUES emission from where the carried Genesis-1 ledger stopped, so the
//    node offsets the height before computing the subsidy:
//
//      emission_height(local) = local + CARRYOVER_SOURCE_HEIGHT     (413,743)
//
// 2. Emission V3 (flag-day hard fork at emission height 453,743 = LOCAL 40,000)
//    replaces the curve at/above the fork, NON-retroactively:
//
//      below the fork:  subsidy(h) = max(8400 >> (h / 1,036,800), 100)   — V2, verbatim
//      at/above it:     epoch  = (h − 453,743) / 1,555,200               — counter RESTARTS
//                       subsidy = max(2600 >> epoch, 60)                 — V3-only 60 floor (PISO-60)
//
//    The first V3 halving is therefore counted FROM THE FORK, not from any
//    absolute-height multiple.
//
// Source of truth, all consensus-critical (commit c21e09d):
//   crates/bloch-crypto/src/core/mod.rs            → emission_height(), CARRYOVER_SOURCE_HEIGHT
//   crates/bloch-crypto/src/core/tokenomics_v2.rs  → block_subsidy_sat(), EMISSION_V3_* constants

/** Absolute emission height the carried ledger stopped at. */
export const CARRYOVER_SOURCE_HEIGHT = 413_743;
export const TARGET_BLOCK_SECS = 30;
/** V2 tail floor — legacy PRE-fork branch only. Never applies to the V3 curve. */
export const TAIL_FLOOR_BLOCH = 100;
/**
 * V3 perpetual tail floor (PISO-60): post-fork the subsidy never falls below
 * this, so emission never ends. Deliberately its own constant — reusing the
 * V2 floor in the V3 branch (or vice versa) is exactly the drift the node
 * guards against with `EMISSION_V3_TAIL_FLOOR_*` in tokenomics_v2.rs.
 */
export const EMISSION_V3_TAIL_FLOOR_BLOCH = 60;

// ── Legacy V2 curve (governs emission heights BELOW the V3 fork) ──────────
export const V2_HALVING_INTERVAL = 1_036_800; // ~1 year @ 30 s (360 × 2880)
export const V2_INITIAL_REWARD_BLOCH = 8_400;

// ── Emission V3 (flag-day hard fork) ──────────────────────────────────────
/** V3 fork in EMISSION-height space: 453,743 = local 40,000 + carryover offset. */
export const EMISSION_V3_FORK_EMISSION_HEIGHT = 453_743;
/** The same fork expressed in node-LOCAL height (what the explorer shows). */
export const EMISSION_V3_FORK_LOCAL_HEIGHT = 40_000;
export const EMISSION_V3_INITIAL_REWARD_BLOCH = 2_600;
/** Blocks per V3 halving epoch — ~1.5 years at the 30 s target (1.5 × 1,036,800). */
export const EMISSION_V3_HALVING_INTERVAL = 1_555_200;
/** First V3 epoch on the floor: 2600 >> 5 = 81 ≥ 60 but 2600 >> 6 = 40 < 60. */
export const EMISSION_V3_TAIL_ACTIVATION_EPOCH = 6;

// Backwards-compatible aliases (post-fork era values).
export const HALVING_INTERVAL = EMISSION_V3_HALVING_INTERVAL;
export const INITIAL_REWARD_BLOCH = EMISSION_V3_INITIAL_REWARD_BLOCH;

/** Absolute emission height for a local Genesis-3 height. */
export function emissionHeight(localHeight: number): number {
  return localHeight + CARRYOVER_SOURCE_HEIGHT;
}

/**
 * Block subsidy in whole BLOCH at an ABSOLUTE emission height.
 * Mirrors `block_subsidy_sat` (tokenomics_v2.rs) exactly, including the V3 gate.
 */
export function subsidyBloch(absHeight: number): number {
  if (absHeight >= EMISSION_V3_FORK_EMISSION_HEIGHT) {
    const epoch = Math.floor(
      (absHeight - EMISSION_V3_FORK_EMISSION_HEIGHT) / EMISSION_V3_HALVING_INTERVAL,
    );
    const geometric =
      epoch >= 64 ? 0 : Math.floor(EMISSION_V3_INITIAL_REWARD_BLOCH / 2 ** epoch);
    return Math.max(geometric, EMISSION_V3_TAIL_FLOOR_BLOCH); // V3 floor, never the V2 100
  }
  const epoch = Math.floor(absHeight / V2_HALVING_INTERVAL);
  const geometric = epoch >= 64 ? 0 : Math.floor(V2_INITIAL_REWARD_BLOCH / 2 ** epoch);
  return Math.max(geometric, TAIL_FLOOR_BLOCH);
}

export interface Halving {
  /**
   * What the next reward change IS: the one-off V3 fork step (8,400 → 2,600),
   * or an ordinary V3 halving after it.
   */
  kind: "fork" | "halving";
  /** V3 epoch index (0 = the 2,600 BLOCH era). −1 while still pre-fork. */
  epoch: number;
  /** Absolute emission height right now. */
  absHeight: number;
  /** LOCAL height at which the next reward change lands — what the explorer shows. */
  nextLocalHeight: number;
  /** Absolute height of the next reward change. */
  nextAbsHeight: number;
  blocksRemaining: number;
  /** 0..1 through the current era (pre-fork: Genesis-3 → fork). */
  progress: number;
  /** Total blocks in the current era (denominator of `progress`). */
  eraBlocks: number;
  rewardNow: number;
  rewardNext: number;
  /** True once the tail floor holds and no further halving changes the reward. */
  tailReached: boolean;
}

export function halvingAt(localHeight: number): Halving {
  const absHeight = emissionHeight(localHeight);

  if (absHeight < EMISSION_V3_FORK_EMISSION_HEIGHT) {
    // Pre-fork: the next reward change is the Emission V3 flag-day itself.
    // (The fork lands before the V2 curve's first halving, so the whole
    // pre-fork era is the flat 8,400 BLOCH epoch — const-asserted in the node.)
    return {
      kind: "fork",
      epoch: -1,
      absHeight,
      nextLocalHeight: EMISSION_V3_FORK_LOCAL_HEIGHT,
      nextAbsHeight: EMISSION_V3_FORK_EMISSION_HEIGHT,
      blocksRemaining: Math.max(0, EMISSION_V3_FORK_LOCAL_HEIGHT - localHeight),
      progress: Math.min(1, Math.max(0, localHeight / EMISSION_V3_FORK_LOCAL_HEIGHT)),
      eraBlocks: EMISSION_V3_FORK_LOCAL_HEIGHT,
      rewardNow: subsidyBloch(absHeight),
      rewardNext: EMISSION_V3_INITIAL_REWARD_BLOCH,
      tailReached: false,
    };
  }

  // Post-fork: epochs are counted FROM THE FORK.
  const sinceFork = absHeight - EMISSION_V3_FORK_EMISSION_HEIGHT;
  const epoch = Math.floor(sinceFork / EMISSION_V3_HALVING_INTERVAL);
  const nextAbsHeight =
    EMISSION_V3_FORK_EMISSION_HEIGHT + (epoch + 1) * EMISSION_V3_HALVING_INTERVAL;
  const nextLocalHeight = nextAbsHeight - CARRYOVER_SOURCE_HEIGHT;
  const rewardNow = subsidyBloch(absHeight);
  const rewardNext = subsidyBloch(nextAbsHeight);
  return {
    kind: "halving",
    epoch,
    absHeight,
    nextLocalHeight,
    nextAbsHeight,
    blocksRemaining: Math.max(0, nextLocalHeight - localHeight),
    progress:
      (sinceFork - epoch * EMISSION_V3_HALVING_INTERVAL) / EMISSION_V3_HALVING_INTERVAL,
    eraBlocks: EMISSION_V3_HALVING_INTERVAL,
    rewardNow,
    rewardNext,
    // Tail is only reachable post-fork, so it is the V3 floor by definition.
    tailReached:
      rewardNow === EMISSION_V3_TAIL_FLOOR_BLOCH && rewardNext === EMISSION_V3_TAIL_FLOOR_BLOCH,
  };
}

/** "4d 07:12:44" — a countdown, not a duration prose string. */
export function fmtCountdown(secs: number): string {
  if (!isFinite(secs) || secs <= 0) return "00:00:00";
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = Math.floor(secs % 60);
  const hhmmss = [h, m, s].map((n) => String(n).padStart(2, "0")).join(":");
  return d > 0 ? `${d}d ${hhmmss}` : hhmmss;
}

/** Coarse human horizon for a long wait: "~6.8 months". */
export function fmtHorizon(secs: number): string {
  if (!isFinite(secs) || secs <= 0) return "—";
  const days = secs / 86400;
  if (days < 1) return `~${(secs / 3600).toFixed(1)} hours`;
  if (days < 60) return `~${days.toFixed(1)} days`;
  if (days < 730) return `~${(days / 30.44).toFixed(1)} months`;
  return `~${(days / 365.25).toFixed(1)} years`;
}

/** UTC calendar day of an estimated arrival. */
export function fmtEtaDate(atMs: number): string {
  return new Date(atMs).toISOString().slice(0, 10);
}
