// Halving schedule.
//
// THE THING THAT IS EASY TO GET WRONG: Bloch's subsidy is NOT a function of the
// local block height you see in the explorer. Genesis-3 restarted the local
// chain at height 0 but deliberately CONTINUES emission from where the carried
// Genesis-1 ledger stopped, so the node offsets the height before computing the
// subsidy:
//
//   emission_height(local) = local + CARRYOVER_SOURCE_HEIGHT     (413,743)
//   subsidy(h)            = max(8400 >> (h / HALVING_INTERVAL), 100) BLOCH
//
// Source of truth, both consensus-critical:
//   crates/bloch-crypto/src/core/mod.rs            → emission_height(), CARRYOVER_SOURCE_HEIGHT
//   crates/bloch-crypto/src/core/tokenomics_v2.rs  → block_subsidy_sat(), HALVING_INTERVAL
//
// Reading the halving off the raw local height would put the first one at local
// 1,036,800 — roughly 413,743 blocks (~5 months) later than it actually lands.

/** Absolute emission height the carried ledger stopped at. */
export const CARRYOVER_SOURCE_HEIGHT = 413_743;
/** Blocks per halving epoch — ~1 year at the 30 s target (360 × 2880). */
export const HALVING_INTERVAL = 1_036_800;
export const INITIAL_REWARD_BLOCH = 8_400;
/** Perpetual tail: the subsidy never falls below this, so emission never ends. */
export const TAIL_FLOOR_BLOCH = 100;
/** Epoch at which `8400 >> n` drops under the tail floor and the floor takes over. */
export const TAIL_ACTIVATION_EPOCH = 7;
export const TARGET_BLOCK_SECS = 30;

/** Absolute emission height for a local Genesis-3 height. */
export function emissionHeight(localHeight: number): number {
  return localHeight + CARRYOVER_SOURCE_HEIGHT;
}

/** Block subsidy in whole BLOCH at an ABSOLUTE emission height. */
export function subsidyBloch(absHeight: number): number {
  const epoch = Math.floor(absHeight / HALVING_INTERVAL);
  const geometric = epoch >= 64 ? 0 : Math.floor(INITIAL_REWARD_BLOCH / 2 ** epoch);
  return Math.max(geometric, TAIL_FLOOR_BLOCH);
}

export interface Halving {
  /** Current epoch index (0 = the 8,400 BLOCH era). */
  epoch: number;
  /** Absolute emission height right now. */
  absHeight: number;
  /** LOCAL height at which the next halving lands — what the explorer shows. */
  nextLocalHeight: number;
  /** Absolute height of the next halving. */
  nextAbsHeight: number;
  blocksRemaining: number;
  /** 0..1 through the current epoch. */
  progress: number;
  rewardNow: number;
  rewardNext: number;
  /** True once the tail floor holds and no further halving changes the reward. */
  tailReached: boolean;
}

export function halvingAt(localHeight: number): Halving {
  const absHeight = emissionHeight(localHeight);
  const epoch = Math.floor(absHeight / HALVING_INTERVAL);
  const nextAbsHeight = (epoch + 1) * HALVING_INTERVAL;
  const nextLocalHeight = nextAbsHeight - CARRYOVER_SOURCE_HEIGHT;
  const rewardNow = subsidyBloch(absHeight);
  const rewardNext = subsidyBloch(nextAbsHeight);
  return {
    epoch,
    absHeight,
    nextLocalHeight,
    nextAbsHeight,
    blocksRemaining: Math.max(0, nextLocalHeight - localHeight),
    progress: (absHeight - epoch * HALVING_INTERVAL) / HALVING_INTERVAL,
    rewardNow,
    rewardNext,
    tailReached: rewardNow === TAIL_FLOOR_BLOCH && rewardNext === TAIL_FLOOR_BLOCH,
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
