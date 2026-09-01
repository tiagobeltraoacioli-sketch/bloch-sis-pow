// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Genesis-4 staking and committee parameters, as consensus actually holds them.
//
// EVERY VALUE HERE IS CITED TO THE LINE THAT DEFINES IT. That is not decoration.
// Three wrong figures reached our public documentation in one week because they
// were written from memory and never run, so the rule for this file is: a
// number may be added only with the file and line it was read from, and if the
// citation cannot be produced the number does not go on the site.
//
// These are CONSTANTS OF THE PROTOCOL, not readings from a node. They belong in
// the bundle because they cannot change without a release; anything that can
// change while the chain runs is fetched, never listed here.

/** Where each constant came from, rendered in the UI so a reader can check it. */
export interface Cited<T> {
  value: T;
  /** repo-relative path and line */
  src: string;
}

const cite = <T,>(value: T, src: string): Cited<T> => ({ value, src });

export const PARAMS = {
  // ── Timing ───────────────────────────────────────────────────────────────
  slotSecs: cite(30, "crates/bloch-pos-committee/src/params.rs:34"),
  slotsPerEpoch: cite(32, "crates/bloch-pos-committee/src/params.rs:30"),
  slotsPerYear: cite(1_051_920, "crates/bloch-pos-committee/src/tokenomics_v4.rs:258"),
  /** Genesis slot 0, from the manifest's `genesis_time_ms`. */
  genesisTimeMs: cite(1_786_656_679_962, "genesis/mainnet.manifest (genesis_time_ms)"),

  // ── The set ──────────────────────────────────────────────────────────────
  genesisValidators: cite(64, "crates/bloch-pos-node/src/genesis.rs:1877"),
  /** Per-validator genesis bond. Identical for all 64. */
  minDepositSat: cite(2_500_000_000_000n, "crates/bloch-pos-committee/src/staking.rs:97"),
  /**
   * The one withdrawal address behind all 64 validators.
   *
   * This is `FOUNDER_WITHDRAWAL_H160` zero-extended to 32 bytes, and it is
   * also the script hash of all five genesis allocation buckets — founder, VC,
   * team, marketing and liquidity — so the same 32 bytes occur 69 times in the
   * genesis manifest. It was a deliberate decision, not an oversight.
   */
  withdrawalScriptHash: cite(
    "e986db5149cff7499b282a048272a09aff0af4ff000000000000000000000000",
    "crates/bloch-pos-committee/src/tokenomics_v4.rs:418 · docs/specs/BLOCH-GENESIS-KEYS.md:159",
  ),

  // ── Queues ───────────────────────────────────────────────────────────────
  maxActivationsPerEpoch: cite(4, "crates/bloch-pos-committee/src/staking.rs:108"),
  activationDelayEpochs: cite(8, "crates/bloch-pos-committee/src/staking.rs:103"),
  exitDelayEpochs: cite(32, "crates/bloch-pos-committee/src/staking.rs:113"),
  withdrawalDelayEpochs: cite(2048, "crates/bloch-pos-committee/src/staking.rs:120"),

  // ── The cohort cap ───────────────────────────────────────────────────────
  cohortCapStartBps: cite(10_000, "crates/bloch-pos-committee/src/genesis_cohort.rs:58"),
  cohortCapFloorBps: cite(3_333, "crates/bloch-pos-committee/src/genesis_cohort.rs:61"),
  cohortTaperEpochs: cite(32_872, "crates/bloch-pos-committee/src/genesis_cohort.rs:64"),

  // ── Finality and the leak ────────────────────────────────────────────────
  inactivityLeakThresholdEpochs: cite(4, "crates/bloch-pos-committee/src/params.rs:59"),
  inactivityLeakQuotient: cite(64, "crates/bloch-pos-committee/src/params.rs:67"),
  /** `u64::MAX` — inert. Leaked weight does not come back. */
  leakRecoveryActivationEpoch: cite(null, "crates/bloch-pos-committee/src/params.rs:597"),
  leakedRosterActivationEpoch: cite(1400, "crates/bloch-pos-committee/src/params.rs:244"),
  /** Casper k=1: epoch E finalises only once E+1 justifies. */
  finalityLagEpochs: cite(2, "crates/bloch-pos-committee/src/finality.rs:458"),
} as const;

/** Seconds in one epoch. */
export const EPOCH_SECS = PARAMS.slotsPerEpoch.value * PARAMS.slotSecs.value;

/** Wall-clock time an epoch boundary falls at. */
export function epochStartMs(epoch: number): number {
  return PARAMS.genesisTimeMs.value + epoch * EPOCH_SECS * 1000;
}

/**
 * The cap on the genesis cohort's combined weight at `epoch`, in basis points.
 *
 * A direct transcription of `cohort_cap_bps` — including the integer division,
 * which is not incidental. Reproducing the truncation is the difference
 * between showing the rule and showing a smooth line that resembles it.
 */
export function cohortCapBps(epoch: number): number {
  const { cohortCapStartBps: start, cohortCapFloorBps: floor, cohortTaperEpochs: span } = PARAMS;
  if (epoch >= span.value) return floor.value;
  const range = start.value - floor.value;
  return start.value - Math.floor((range * epoch) / span.value);
}

/**
 * The share of total weight left to everyone outside the cohort, at `epoch`.
 *
 * The complement of the cap, and the number that actually describes the
 * commitment: independent operators are guaranteed at least this much of
 * finality weight — 66.67% once the taper completes.
 */
export function independentFloorBps(epoch: number): number {
  return 10_000 - cohortCapBps(epoch);
}

/** Unix ms at which the taper reaches its floor and stops moving. */
export const TAPER_COMPLETE_MS = epochStartMs(PARAMS.cohortTaperEpochs.value);

/**
 * Is the cap actually binding, given how much independent stake exists?
 *
 * Mirrors `cap_status`. The third case is the one everybody misses: with less
 * than one validator's worth of non-cohort stake the rule is DEFERRED, not
 * enforced — because the closed form is a share of non-cohort stake, so with
 * none of it the cap is zero, the whole cohort drops to zero weight, and the
 * chain stops. Adversarial review found that this would have bitten at epoch 5,
 * about 1.3 hours after genesis. The cap cannot manufacture decentralisation
 * out of nothing; when nobody has arrived it says so instead of halting.
 */
export type CapStatus =
  | { kind: "not-tapering" }
  | { kind: "deferred"; independentSat: bigint }
  | { kind: "enforced"; capSat: bigint };

export function capStatus(epoch: number, totalSat: bigint, cohortSat: bigint): CapStatus {
  const bps = BigInt(cohortCapBps(epoch));
  if (bps >= 10_000n) return { kind: "not-tapering" };
  const others = totalSat - cohortSat;
  if (others < PARAMS.minDepositSat.value) return { kind: "deferred", independentSat: others };
  return { kind: "enforced", capSat: (others * bps) / (10_000n - bps) };
}

/**
 * The five words `getvalidator` can return in `state`, in the order consensus
 * decides them — `slashed` outranks everything, and the chain reports it on a
 * SEPARATE boolean as well.
 *
 * Listed here because a live operator script alarmed on every healthy
 * validator by reading a `status` field that does not exist on this RPC. The
 * field is `state`; there is no `status`.
 */
export const VALIDATOR_STATES = ["active", "queued", "exiting", "exited", "slashed"] as const;
export type ValidatorState = (typeof VALIDATOR_STATES)[number];

/** How a state should read: neutral, good, or a problem. */
export function stateTone(state: string, slashed: boolean): "ok" | "warn" | "bad" | "quiet" {
  if (slashed || state === "slashed") return "bad";
  if (state === "active") return "ok";
  if (state === "exiting" || state === "exited") return "warn";
  return "quiet";
}
