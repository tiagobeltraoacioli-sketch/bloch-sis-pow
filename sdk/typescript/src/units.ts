// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Bloch community contributors
//
// Unit helpers: satoshis <-> BLOCH display.
//
// The integer satoshi value is the ONLY source of truth on-chain
// (1 BLOCH = 100_000_000 satoshis). The float `bloch` fields the node returns
// are display-only and MUST NOT be used for accounting. These helpers keep the
// truth in `bigint` so no precision is lost.

/** Satoshis per whole BLOCH. */
export const SATS_PER_BLOCH = 100_000_000n;

/** Number of decimal places in a BLOCH display value. */
export const BLOCH_DECIMALS = 8;

/**
 * Parse a human BLOCH string (e.g. "1.5", "0.00000001") into integer satoshis.
 * Rejects more than 8 decimal places and non-numeric input.
 */
export function blochToSats(bloch: string | number): bigint {
  const s = typeof bloch === "number" ? formatNumberLossless(bloch) : bloch.trim();
  if (!/^-?\d+(\.\d+)?$/.test(s)) {
    throw new RangeError(`invalid BLOCH amount: ${JSON.stringify(bloch)}`);
  }
  const negative = s.startsWith("-");
  const unsigned = negative ? s.slice(1) : s;
  const [whole, frac = ""] = unsigned.split(".");
  if (frac.length > BLOCH_DECIMALS) {
    throw new RangeError(
      `too many decimal places (max ${BLOCH_DECIMALS}): ${JSON.stringify(bloch)}`,
    );
  }
  const fracPadded = frac.padEnd(BLOCH_DECIMALS, "0");
  const sats = BigInt(whole || "0") * SATS_PER_BLOCH + BigInt(fracPadded || "0");
  return negative ? -sats : sats;
}

/**
 * Format integer satoshis as a BLOCH display string with 8 decimals.
 * Trailing zeros are preserved for readability unless `trim` is set.
 */
export function satsToBloch(
  sats: bigint | number,
  opts: { trim?: boolean } = {},
): string {
  const v = typeof sats === "number" ? BigInt(Math.trunc(sats)) : sats;
  const negative = v < 0n;
  const abs = negative ? -v : v;
  const whole = abs / SATS_PER_BLOCH;
  const frac = abs % SATS_PER_BLOCH;
  let fracStr = frac.toString().padStart(BLOCH_DECIMALS, "0");
  if (opts.trim) {
    fracStr = fracStr.replace(/0+$/, "");
  }
  const body = fracStr.length > 0 ? `${whole}.${fracStr}` : `${whole}`;
  return negative ? `-${body}` : body;
}

/** Convenience: format satoshis as e.g. "1.50000000 BLOCH". */
export function formatBloch(sats: bigint | number): string {
  return `${satsToBloch(sats)} BLOCH`;
}

function formatNumberLossless(n: number): string {
  if (!Number.isFinite(n)) throw new RangeError(`non-finite BLOCH amount: ${n}`);
  // Avoid exponential notation for small/large numbers.
  if (Number.isInteger(n)) return n.toString();
  return n.toFixed(BLOCH_DECIMALS);
}
