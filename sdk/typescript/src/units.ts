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
 * Genesis-4 total supply, in satoshis: 100,000,000,000 BLCH x 1e8 = 10^19 sat.
 *
 * This is a hard cap, so no legitimate satoshi field can ever exceed it and a
 * value above it is a decode error, not a big number. Two measured facts follow
 * from it, and they are the whole reason this module exists:
 *   * 10^19 > i64::MAX (9,223,372,036,854,775,807) — ~108% of it.
 *   * 10^19 / (2^53 - 1) ~= 1110 — a satoshi value that reaches a JS `number`
 *     is corrupt roughly a thousand-fold before the cap is even in sight.
 */
export const MAX_SATS = 10_000_000_000_000_000_000n;

/**
 * Parse a wire satoshi value into an exact `bigint`.
 *
 * Accepts all three forms a caller can hold:
 *   * `string`  — the canonical V4 decimal encoding (R3), e.g. "10000000000000000000".
 *   * `number`  — the LEGACY bare-JSON-number form still emitted by live
 *     Genesis-3 nodes. Accepted only up to `Number.MAX_SAFE_INTEGER`.
 *   * `bigint`  — already exact; range-checked and passed through.
 *
 * REJECTS (throws `RangeError`) on:
 *   * negative values — satoshi amounts on the wire are unsigned;
 *   * non-integers (`1.5`, `"1.5"`) — satoshis are the indivisible unit;
 *   * anything above {@link MAX_SATS} — above the supply cap, so it is a bug;
 *   * a `number` above `Number.MAX_SAFE_INTEGER`.
 *
 * That last rule is the deliberate one. Such a `number` is NOT merely risky, it
 * is ALREADY WRONG: by the time `JSON.parse` produced it the nearest-double
 * rounding has happened and the original digits are gone (9007199254740993
 * parses to 9007199254740992). Silently returning `BigInt(v)` would launder a
 * corrupted amount into an exact-looking type, so this function refuses. The
 * fix belongs upstream: have the node send the decimal string.
 */
export function parseSats(v: string | number | bigint): bigint {
  if (typeof v === "bigint") return checkRange(v, v.toString());

  if (typeof v === "number") {
    if (!Number.isFinite(v)) {
      throw new RangeError(`non-finite satoshi value: ${v}`);
    }
    if (!Number.isInteger(v)) {
      throw new RangeError(`satoshi value is not an integer: ${v}`);
    }
    if (!Number.isSafeInteger(v)) {
      throw new RangeError(
        `satoshi value ${v} exceeds Number.MAX_SAFE_INTEGER (${Number.MAX_SAFE_INTEGER}) ` +
          `and is therefore already corrupted by IEEE-754 rounding; the node must ` +
          `send this amount as a decimal string (BLOCH-RPC-V4 R3)`,
      );
    }
    return checkRange(BigInt(v), String(v));
  }

  const s = v.trim();
  if (!/^-?\d+$/.test(s)) {
    throw new RangeError(`invalid satoshi string: ${JSON.stringify(v)}`);
  }
  return checkRange(BigInt(s), s);
}

function checkRange(sats: bigint, shown: string): bigint {
  if (sats < 0n) {
    throw new RangeError(`negative satoshi value: ${shown}`);
  }
  if (sats > MAX_SATS) {
    throw new RangeError(
      `satoshi value ${shown} exceeds the Genesis-4 supply cap ${MAX_SATS}`,
    );
  }
  return sats;
}

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
 *
 * Accepts the wire `string` form directly so a caller can format an amount
 * without it ever touching a `number`. Signed values are allowed here (unlike
 * {@link parseSats}) because callers format deltas and change with this too.
 */
export function satsToBloch(
  sats: bigint | number | string,
  opts: { trim?: boolean } = {},
): string {
  const v =
    typeof sats === "string"
      ? parseSigned(sats)
      : typeof sats === "number"
        ? BigInt(Math.trunc(sats))
        : sats;
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
export function formatBloch(sats: bigint | number | string): string {
  return `${satsToBloch(sats)} BLOCH`;
}

/** Like the string branch of parseSats, but tolerates a leading `-`. */
function parseSigned(s: string): bigint {
  const t = s.trim();
  if (!/^-?\d+$/.test(t)) {
    throw new RangeError(`invalid satoshi string: ${JSON.stringify(s)}`);
  }
  return BigInt(t);
}

function formatNumberLossless(n: number): string {
  if (!Number.isFinite(n)) throw new RangeError(`non-finite BLOCH amount: ${n}`);
  // Avoid exponential notation for small/large numbers.
  if (Number.isInteger(n)) return n.toString();
  return n.toFixed(BLOCH_DECIMALS);
}
