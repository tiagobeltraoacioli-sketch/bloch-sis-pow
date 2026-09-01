// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Genesis-4 fee market, ported from the crate that IS consensus:
// `crates/bloch-pos-committee/src/fee_market.rs`.
//
// ── Why this file is allowed to exist at all ────────────────────────────────
//
// A second implementation of a consensus rule is normally a bug waiting to
// happen, and this one is the exact shape of bug that already bit this
// project: the published integrator formula (exchange book §6.2) took the
// BYTE term from the V2 transfer format and the VERIFICATION term from V1,
// and printed a confident ceiling of "815 inputs" for a transaction that
// cannot exist. The arithmetic was right. The model was not.
//
// So this port is bound to the original by a test, not by care:
// `crates/bloch-pos-committee/tests/explorer_fee_surface.rs` asserts every
// number this page renders against `fee_market` itself, including the two
// worked examples below. When a constant here drifts from the crate, that
// test fails — which is the only reason a reader should believe this page.
// (Writing that test caught two figures in this page's first draft: a
// downward controller walk and a tip-rounding example, both computed by hand
// and both wrong. They are corrected here.)
//
// ── Units ───────────────────────────────────────────────────────────────────
//
// Price is millisatoshi per gas (1 msat = 1e-3 sat = 1e-11 BLOCH). Fees
// settle in whole satoshis, rounded UP. Everything is bigint: block gas times
// the maximum representable price does not fit a JS number, and this is a
// page about exact equality — a rounded number here would be a lie of exactly
// the kind the chain rejects transactions for.

/** Gas per payload byte. Ethereum's non-zero-calldata price. */
export const GAS_PER_BYTE = 16n;

/** Flat per-transaction overhead. */
export const TX_FLAT_GAS = 5_000n;

/**
 * Gas for one hybrid ML-DSA-65 ‖ Falcon-1024 verification: 72,748.
 * Derived in the crate from 7,274,849 measured RV32IM instructions at
 * 100 instructions/gas, and pinned there by a compile-time assertion.
 */
export const HYBRID_VERIFY_GAS = 72_748n;

/** Gas ceiling and EIP-1559 target per block. Era-independent. */
export const BLOCK_GAS_LIMIT = 60_000_000n;
export const BLOCK_GAS_TARGET = 30_000_000n;

/** The payload cap before and after the flag day. */
export const MAX_BLOCK_TX_BYTES_V1 = 262_144n;
export const MAX_BLOCK_TX_BYTES_V2 = 524_288n;

/** The epoch both the cap raise and the V2 witness dedup activated at. */
export const BLOCK_BYTES_V2_ACTIVATION_EPOCH = 800;

export const MILLISAT_PER_SAT = 1_000n;
export const MIN_BASE_FEE_MILLISAT_PER_GAS = 10n;
export const BASE_FEE_CHANGE_DENOMINATOR = 8n;

/**
 * The payload cap in force at `epoch` — asked as a function, never read as a
 * constant, for the same reason the crate insists on it: a cap taken from
 * anywhere but the block's own epoch is how a fleet on one binary splits.
 */
export function maxBlockTxBytes(epoch: number): bigint {
  return epoch < BLOCK_BYTES_V2_ACTIVATION_EPOCH ? MAX_BLOCK_TX_BYTES_V1 : MAX_BLOCK_TX_BYTES_V2;
}

/** The byte target: always exactly half the cap of the same era. */
export function blockTxBytesTarget(epoch: number): bigint {
  return maxBlockTxBytes(epoch) / 2n;
}

/**
 * Intrinsic gas — what a transfer owes before a single opcode runs.
 *
 *     gas = 5,000 + tx_bytes x 16 + 72,748 x verifications
 *
 * `verifications` is **the number of hybrid checks the node will actually
 * run**, and that count is what the two transfer formats differ on:
 *
 *   V1 (tag 0x01)  one per INPUT — every input carries its own witness.
 *   V2 (tag 0x06)  one per WITNESS-TABLE ENTRY, i.e. per distinct owner key:
 *                  one signature over the shared signing root authorises all
 *                  of that owner's inputs.
 *
 * Neither count is ever declared by the transaction. The transition derives
 * it from the lists (`inputs.len()` in `apply_transfer`, `keys.len()` in
 * `apply_transfer_v2`), because gas buys node CPU and the CPU spent is not a
 * number the sender gets to assert.
 */
export function intrinsicGas(txBytes: bigint, verifications: bigint): bigint {
  return TX_FLAT_GAS + txBytes * GAS_PER_BYTE + HYBRID_VERIFY_GAS * verifications;
}

function ceilDiv(n: bigint, d: bigint): bigint {
  return n / d + (n % d !== 0n ? 1n : 0n);
}

/**
 * Settle a fee in whole satoshis: `[base, tip]`, each rounded UP **on its
 * own**.
 *
 * The separate rounding is not a detail. A wallet that folds the two prices
 * together and divides once — `ceil(gas x (base + tip) / 1000)` — can come
 * out one satoshi short, and under strict equality one satoshi short is a
 * hard rejection. See `foldedFeeSat` for the wrong version, kept so the page
 * can show the gap rather than assert it.
 */
export function feePartsSat(gas: bigint, baseMsat: bigint, tipMsat: bigint): [bigint, bigint] {
  return [ceilDiv(gas * baseMsat, MILLISAT_PER_SAT), ceilDiv(gas * tipMsat, MILLISAT_PER_SAT)];
}

/** The wallet bug, so the page can display it. Never larger than the truth. */
export function foldedFeeSat(gas: bigint, baseMsat: bigint, tipMsat: bigint): bigint {
  return ceilDiv(gas * (baseMsat + tipMsat), MILLISAT_PER_SAT);
}

/** What the parent block used, on both axes. */
export interface BlockUsage {
  gasUsed: bigint;
  txBytes: bigint;
}

/**
 * Next block's base fee, from the parent's price and usage.
 *
 * EIP-1559 with one change: utilisation is the **maximum of the gas axis and
 * the byte axis**, compared by cross-multiplication so it stays in integers.
 * A gas-only controller would misprice this chain — a block full of eUTXO
 * transfers saturates the byte cap while using under a tenth of the gas cap,
 * and would be read as slack.
 *
 * `epoch` is the epoch the price will be CHARGED in, not the parent's.
 */
export function nextBaseFee(parentBaseFee: bigint, parent: BlockUsage, epoch: number): bigint {
  const byteTarget = blockTxBytesTarget(epoch);
  const gasCross = parent.gasUsed * byteTarget;
  const bytesCross = parent.txBytes * BLOCK_GAS_TARGET;
  const [used, target] =
    gasCross >= bytesCross ? [parent.gasUsed, BLOCK_GAS_TARGET] : [parent.txBytes, byteTarget];

  const base = clampBaseFee(parentBaseFee);
  if (used === target) return base;
  if (used > target) {
    let delta = (base * (used - target)) / target / BASE_FEE_CHANGE_DENOMINATOR;
    // A congested block must always move the price.
    if (delta === 0n) delta = 1n;
    return clampBaseFee(base + delta);
  }
  const delta = (base * (target - used)) / target / BASE_FEE_CHANGE_DENOMINATOR;
  return clampBaseFee(base - delta);
}

function clampBaseFee(v: bigint): bigint {
  return v < MIN_BASE_FEE_MILLISAT_PER_GAS ? MIN_BASE_FEE_MILLISAT_PER_GAS : v;
}

/**
 * The one figure this page exists to make usable: what one transfer costs.
 *
 * Returns the whole derivation, not just the total, because a reader who
 * cannot see which term dominates cannot plan around it — and for every
 * realistic transfer the byte term dominates, which is the design.
 */
export interface Quote {
  gas: bigint;
  flatGas: bigint;
  byteGas: bigint;
  verifyGas: bigint;
  baseFeeSat: bigint;
  priorityFeeSat: bigint;
  totalSat: bigint;
  /** The one-satoshi trap: what a fold-and-divide-once wallet would compute. */
  foldedSat: bigint;
  overByteCap: boolean;
  overGasCap: boolean;
}

export function quote(
  txBytes: bigint,
  verifications: bigint,
  baseMsat: bigint,
  tipMsat: bigint,
  epoch: number,
): Quote {
  const flatGas = TX_FLAT_GAS;
  const byteGas = txBytes * GAS_PER_BYTE;
  const verifyGas = HYBRID_VERIFY_GAS * verifications;
  const gas = flatGas + byteGas + verifyGas;
  const [baseFeeSat, priorityFeeSat] = feePartsSat(gas, baseMsat, tipMsat);
  return {
    gas,
    flatGas,
    byteGas,
    verifyGas,
    baseFeeSat,
    priorityFeeSat,
    totalSat: baseFeeSat + priorityFeeSat,
    foldedSat: foldedFeeSat(gas, baseMsat, tipMsat),
    overByteCap: txBytes > maxBlockTxBytes(epoch),
    overGasCap: gas > BLOCK_GAS_LIMIT,
  };
}

/**
 * An ILLUSTRATIVE encoded size for a one-input, one-owner, two-output
 * transfer. Not a constant of the protocol and not safe to plan with:
 * Falcon-1024 signatures are variable length, so the encoded size of a
 * transfer is not a function of its input count. The book's instruction is
 * to build the transaction, measure the bytes you actually produced, and
 * check both caps against that. The page says so where it uses this.
 */
export const ILLUSTRATIVE_TRANSFER_BYTES = 8_689n;

/** Satoshis to a BLOCH display string. 1 BLOCH = 1e8 sat. */
export function satToBloch(sat: bigint, frac = 8): string {
  const whole = sat / 100_000_000n;
  const rest = (sat % 100_000_000n).toString().padStart(8, "0").slice(0, frac).replace(/0+$/, "");
  return whole.toString() + (rest ? "." + rest : "");
}
