// SPDX-License-Identifier: MIT OR Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import { blochToSats, satsToBloch, formatBloch, SATS_PER_BLOCH } from "../src/index.js";

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
