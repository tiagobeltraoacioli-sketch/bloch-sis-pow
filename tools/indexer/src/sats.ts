// SPDX-License-Identifier: MIT OR Apache-2.0
// Satoshi encoding for the indexer — the single place amounts cross the border
// between JSON and memory.
//
// The rule (docs/specs/BLOCH-SATOSHI-ENCODING.md, normative for Genesis-4):
// a satoshi amount is a DECIMAL STRING on the JSON wire and an unsigned 64-bit
// integer in memory — `bigint` in TypeScript, never a `number`.
//
// Why this file exists rather than a cast at each call site: JSON has no integer
// type, so `JSON.parse` turns every JSON number into an IEEE-754 double, exact
// only to 2^53-1 = 9,007,199,254,740,991 sat. Genesis-4's total supply is 10^19
// sat (1,110x that limit) and the largest single carried-over address already
// holds 354,617,540,000,000,000 sat — 39x past it. Measured on node v22.16.0:
//
//   JSON.parse('{"v":354617540000000001}')  ->  354617540000000000   (1 sat gone)
//   JSON.parse('{"v":"354617540000000001"}')->  "354617540000000001" (exact)
//
// Readers are dual-tolerant (rule 5): live Genesis-3 nodes still emit bare JSON
// numbers, so `parseSats` accepts both forms. Writers emit only the string form.

/**
 * Upper bound for a satoshi amount: Genesis-4 total supply, 10^19 sat
 * (100,000,000,000 BLCH). Authority is `TOTAL_SUPPLY_SAT` in
 * `crates/bloch-pos-committee/src/tokenomics_v4.rs`; this is a mirrored copy
 * because TypeScript cannot link the Rust crate. Do not restate it elsewhere.
 */
export const MAX_SATS = 10_000_000_000_000_000_000n;

/** Canonical wire form: no sign, no leading zeros, no point, no exponent. */
const CANONICAL_SATS = /^(0|[1-9][0-9]{0,19})$/;

/**
 * Parse a satoshi amount from the wire (or from a persisted state file) into an
 * exact `bigint`.
 *
 * Accepts:
 *   - the canonical Genesis-4 form: a decimal string, e.g. `"354617540000000000"`
 *   - a `bigint` (already parsed / constructed in memory)
 *   - the legacy Genesis-3 form: a bare JSON number, ONLY when the value is an
 *     exact integer that survived the parser (see below)
 *
 * Rejects negatives, non-integers, and anything above `MAX_SATS`.
 *
 * The legacy branch never reconstructs digits through a float: a JSON number
 * above 2^53 has ALREADY lost precision by the time it reaches this function, so
 * rather than launder a wrong value into a confident-looking `bigint` we refuse
 * it. The transport avoids ever getting here with a large number by reading such
 * literals from their raw source text (`parseJsonExactIntegers` below).
 */
export function parseSats(raw: unknown, context = "amount"): bigint {
  let v: bigint;

  if (typeof raw === "bigint") {
    v = raw;
  } else if (typeof raw === "string") {
    if (!CANONICAL_SATS.test(raw)) {
      throw new Error(
        `${context}: not a canonical satoshi string (expected base-10 digits, no sign/point/exponent/leading zeros): ${JSON.stringify(raw)}`,
      );
    }
    v = BigInt(raw); // exact: BigInt() on the digit string, never via Number()
  } else if (typeof raw === "number") {
    if (!Number.isInteger(raw)) {
      throw new Error(`${context}: satoshi amount is not an integer: ${raw}`);
    }
    if (!Number.isSafeInteger(raw)) {
      throw new Error(
        `${context}: legacy numeric satoshi amount ${raw} exceeds Number.MAX_SAFE_INTEGER ` +
          `(${Number.MAX_SAFE_INTEGER}); its digits were already lost by JSON.parse. ` +
          `The node must emit this field as a decimal string ` +
          `(docs/specs/BLOCH-SATOSHI-ENCODING.md).`,
      );
    }
    v = BigInt(raw); // safe integer -> exact
  } else {
    throw new Error(`${context}: expected a satoshi string, number or bigint, got ${typeof raw}`);
  }

  if (v < 0n) throw new Error(`${context}: negative satoshi amount: ${v}`);
  if (v > MAX_SATS) throw new Error(`${context}: satoshi amount ${v} exceeds total supply ${MAX_SATS}`);
  return v;
}

/** Canonical wire/persistence form of an amount. The only way amounts leave. */
export function formatSats(v: bigint): string {
  return v.toString(10);
}

/**
 * Display-only BLCH rendering. Lossy by construction (IEEE-754), documented as
 * such by the spec (rule 6), and MUST NOT be used for accounting or comparison.
 */
export function satsToBlochDisplay(v: bigint): number {
  return Number(v) / 1e8;
}

/**
 * `JSON.parse` that preserves integer literals too large for a double by handing
 * them back as strings, so `parseSats` can read the exact digits.
 *
 * Uses the JSON.parse source-access reviver (`context.source`, available on node
 * >= 21; verified on v22.16.0). Only integer literals that are NOT safe integers
 * are converted — heights, indices and timestamps stay `number`. On a runtime
 * without source access the reviver degrades to plain `JSON.parse`, and a large
 * amount then fails loudly in `parseSats` instead of corrupting silently.
 */
export function parseJsonExactIntegers(text: string): unknown {
  const reviver = function (
    this: unknown,
    _key: string,
    value: unknown,
    context?: { source?: string },
  ): unknown {
    if (
      typeof value === "number" &&
      !Number.isSafeInteger(value) &&
      context !== undefined &&
      typeof context.source === "string" &&
      /^-?[0-9]+$/.test(context.source)
    ) {
      return context.source;
    }
    return value;
  } as (key: string, value: unknown) => unknown;
  return JSON.parse(text, reviver);
}

/** `JSON.stringify` replacer that renders any stray `bigint` as a decimal string. */
export function bigintReplacer(_key: string, value: unknown): unknown {
  return typeof value === "bigint" ? value.toString(10) : value;
}
