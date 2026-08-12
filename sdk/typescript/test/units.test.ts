// SPDX-License-Identifier: MIT OR Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  blochToSats,
  satsToBloch,
  formatBloch,
  parseSats,
  SATS_PER_BLOCH,
  MAX_SATS,
} from "../src/index.js";

test("SATS_PER_BLOCH is 1e8", () => {
  assert.equal(SATS_PER_BLOCH, 100_000_000n);
});

test("blochToSats parses whole and fractional amounts", () => {
  assert.equal(blochToSats("1"), 100_000_000n);
  assert.equal(blochToSats("1.5"), 150_000_000n);
  assert.equal(blochToSats("0.00000001"), 1n);
  assert.equal(blochToSats("0"), 0n);
  assert.equal(blochToSats(2), 200_000_000n);
});

test("blochToSats rejects >8 decimals and junk", () => {
  assert.throws(() => blochToSats("0.000000001"), RangeError);
  assert.throws(() => blochToSats("abc"), RangeError);
  assert.throws(() => blochToSats("1.2.3"), RangeError);
});

test("satsToBloch formats with 8 decimals", () => {
  assert.equal(satsToBloch(150_000_000n), "1.50000000");
  assert.equal(satsToBloch(1n), "0.00000001");
  assert.equal(satsToBloch(0n), "0.00000000");
  assert.equal(satsToBloch(150_000_000n, { trim: true }), "1.5");
});

test("round-trips losslessly", () => {
  for (const s of ["0.00000001", "12345.67891011", "999999999.99999999"]) {
    assert.equal(satsToBloch(blochToSats(s)), s.padEnd(s.indexOf(".") + 9, "0"));
  }
});

test("formatBloch adds the unit", () => {
  assert.equal(formatBloch(150_000_000n), "1.50000000 BLOCH");
});

// ── parseSats / the 2^53 wire problem ──────────────────────────────────────

test("MAX_SATS is the Genesis-4 cap: 100e9 BLCH = 1e19 sat", () => {
  assert.equal(MAX_SATS, 10_000_000_000_000_000_000n);
  assert.equal(MAX_SATS, 100_000_000_000n * SATS_PER_BLOCH);
  // Measured: the cap does not fit an i64, and is ~1110x past JS's safe range.
  assert.ok(MAX_SATS > 9_223_372_036_854_775_807n, "cap exceeds i64::MAX");
  assert.ok(MAX_SATS / BigInt(Number.MAX_SAFE_INTEGER) === 1110n);
});

test("parseSats round-trips the supply cap through the canonical string", () => {
  const wire = "10000000000000000000";
  const sats = parseSats(wire);
  assert.equal(sats, MAX_SATS);
  assert.equal(sats.toString(), wire);
  // And through a real JSON envelope, the way it arrives off the wire.
  const decoded = JSON.parse(`{"satoshis":"${wire}"}`) as { satoshis: string };
  assert.equal(parseSats(decoded.satoshis), MAX_SATS);
});

test("parseSats accepts the legacy bare-number form below 2^53", () => {
  assert.equal(parseSats(0), 0n);
  assert.equal(parseSats(8_400_00000000), 840_000_000_000n);
  assert.equal(parseSats(Number.MAX_SAFE_INTEGER), 9_007_199_254_740_991n);
});

test("parseSats accepts bigint and plain strings", () => {
  assert.equal(parseSats(1n), 1n);
  assert.equal(parseSats("0"), 0n);
  assert.equal(parseSats(" 42 "), 42n);
});

test("parseSats rejects negatives", () => {
  assert.throws(() => parseSats(-1), RangeError);
  assert.throws(() => parseSats("-1"), RangeError);
  assert.throws(() => parseSats(-1n), RangeError);
});

test("parseSats rejects values above the supply cap", () => {
  assert.throws(() => parseSats(MAX_SATS + 1n), RangeError);
  assert.throws(() => parseSats("10000000000000000001"), RangeError);
  assert.throws(() => parseSats("99999999999999999999999"), RangeError);
});

test("parseSats rejects non-integers and junk", () => {
  assert.throws(() => parseSats(1.5), RangeError);
  assert.throws(() => parseSats("1.5"), RangeError);
  assert.throws(() => parseSats("abc"), RangeError);
  assert.throws(() => parseSats(""), RangeError);
  assert.throws(() => parseSats(NaN), RangeError);
  assert.throws(() => parseSats(Infinity), RangeError);
});

test("parseSats REJECTS a number past 2^53 because it is already corrupt", () => {
  // Not a policy choice about risk — the damage is already done, see below.
  assert.throws(() => parseSats(9_007_199_254_740_993), RangeError);
  assert.throws(() => parseSats(1e19), RangeError);
});

// The fixed vector that justifies rule R3. Everything here is MEASURED by the
// assertions themselves, not asserted from memory.
test("JSON round-trip: the string form survives, the number form corrupts", () => {
  // 2^53 + 1 — the smallest integer a double cannot represent.
  const numberWire = '{"v":9007199254740993}';
  const roundTripped = JSON.stringify(JSON.parse(numberWire));
  assert.equal(roundTripped, '{"v":9007199254740992}'); // ← lost a satoshi
  assert.notEqual(roundTripped, numberWire);

  // The same value as a decimal string is byte-identical after a round trip.
  const stringWire = '{"v":"9007199254740993"}';
  assert.equal(JSON.stringify(JSON.parse(stringWire)), stringWire);
  assert.equal(parseSats((JSON.parse(stringWire) as { v: string }).v), 9_007_199_254_740_993n);

  // At Genesis-4 scale the loss is bigger than one satoshi. Measured:
  const bigWire = '{"v":1234567890123456789}';
  assert.equal(BigInt(JSON.parse(bigWire).v as number), 1_234_567_890_123_456_768n);
  assert.equal(parseSats("1234567890123456789"), 1_234_567_890_123_456_789n);
  // 21 satoshis evaporate on a value well inside the supply cap.
  assert.equal(1_234_567_890_123_456_789n - 1_234_567_890_123_456_768n, 21n);

  // And the worst case: one satoshi BELOW the cap rounds UP, inventing supply
  // that lands exactly on the cap — a number-based reader cannot even tell.
  assert.equal(BigInt(JSON.parse('{"v":9999999999999999999}').v as number), MAX_SATS);
  assert.equal(parseSats("9999999999999999999"), MAX_SATS - 1n);
});

test("satsToBloch formats the wire string form without touching a number", () => {
  assert.equal(satsToBloch(MAX_SATS), "100000000000.00000000");
  assert.equal(satsToBloch("10000000000000000000"), "100000000000.00000000");
  assert.equal(formatBloch("354617540000000000"), "3546175400.00000000 BLOCH");
});
