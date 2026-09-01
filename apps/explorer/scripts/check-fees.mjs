// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Guard: `src/lib/fees.ts` must agree with the consensus crate.
//
//   npm run check:fees
//
// The page renders numbers that decide whether a transaction is accepted, and
// it computes them in the browser from a hand-port of
// `crates/bloch-pos-committee/src/fee_market.rs`. A port is a second
// implementation of a consensus rule, and the project has already shipped one
// wrong fee formula in public (the "815 inputs" ceiling in the exchange book,
// which mixed a V2 byte term with a V1 verification term).
//
// So the port is bound to the original in both directions:
//
//   * `crates/bloch-pos-committee/tests/explorer_fee_surface.rs` asserts these
//     same cases against `fee_market` itself, in Rust. That is the authority.
//   * This script asserts them against the TypeScript. Same inputs, same
//     expected outputs, transcribed from that test.
//
// If a constant moves in the crate, the Rust test fails. If the port drifts
// from the crate, this fails. Neither on its own is enough; run both.
//
// No test runner is needed or wanted here — the explorer has none, and adding
// one to check nine numbers would be the larger change. `esbuild` is already
// present as a Vite dependency.
import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const out = await build({
  entryPoints: [join(here, "..", "src", "lib", "fees.ts")],
  bundle: true,
  format: "esm",
  write: false,
  logLevel: "error",
});
const F = await import(
  "data:text/javascript;base64," + Buffer.from(out.outputFiles[0].text).toString("base64")
);

let fails = 0;
const eq = (got, want, what) => {
  const g = String(got), w = String(want);
  if (g !== w) { console.log(`FAIL ${what}: got ${g}, want ${w}`); fails++; }
};
const E = 1704; // the live epoch the Rust test pins against

// the_page_is_describing_the_post_flag_day_era
eq(F.BLOCK_BYTES_V2_ACTIVATION_EPOCH, 800, "activation epoch");
eq(F.maxBlockTxBytes(E), 524288n, "cap @1704");
eq(F.blockTxBytesTarget(E), 262144n, "target @1704");
eq(F.maxBlockTxBytes(799), 262144n, "cap @799");
eq(F.blockTxBytesTarget(799), 131072n, "target @799");

// the_gas_formula_the_page_prints
for (const keys of [1n, 2n, 7n, 62n])
  for (const bytes of [8689n, 20000n, 262144n, 524288n])
    eq(F.intrinsicGas(bytes, keys), 5000n + bytes * 16n + 72748n * keys, `gas ${keys}/${bytes}`);

// the_worked_example_the_page_shows
eq(F.intrinsicGas(8689n, 1n), 216772n, "worked gas");
const q = F.quote(8689n, 1n, 10n, 0n, E);
eq(q.gas, 216772n, "quote gas"); eq(q.baseFeeSat, 2168n, "quote base"); eq(q.priorityFeeSat, 0n, "quote tip");

// base_and_tip_round_up_separately_and_the_difference_is_real
let firstGap = null;
for (let bytes = 8000n; bytes < 30000n; bytes++) {
  const g = F.intrinsicGas(bytes, 1n);
  for (const tip of [1n, 2n, 3n, 5n, 10n]) {
    const [b, t] = F.feePartsSat(g, 10n, tip);
    const folded = F.foldedFeeSat(g, 10n, tip);
    if (folded > b + t) { console.log(`FAIL folding overpaid at ${bytes}/${tip}`); fails++; }
    if (b + t - folded > 1n) { console.log(`FAIL gap > 1 at ${bytes}/${tip}`); fails++; }
    if (b + t - folded === 1n && !firstGap) firstGap = [bytes, tip, g, b + t, folded];
  }
}
eq(firstGap[0], 8000n, "gap bytes"); eq(firstGap[1], 2n, "gap tip");
eq(firstGap[2], 205748n, "gap gas"); eq(firstGap[3], 2470n, "gap separate"); eq(firstGap[4], 2469n, "gap folded");
const [gb, gt] = F.feePartsSat(205748n, 10n, 2n);
eq(gb, 2058n, "gap base part"); eq(gt, 412n, "gap tip part");

// the_floor_is_absorbing_which_is_why_the_chart_is_flat
const empty = { gasUsed: 0n, txBytes: 0n };
let price = 10n;
for (let i = 0; i < 10000; i++) { price = F.nextBaseFee(price, empty, E); if (price !== 10n) { console.log("FAIL floor let go"); fails++; break; } }
let p = 1000000n;
for (let i = 0; i < 2000; i++) p = F.nextBaseFee(p, empty, E);
eq(p, 10n, "walks down to the floor");

// what_it_would_actually_take_to_lift_the_price
const T = F.blockTxBytesTarget(E);
eq(F.nextBaseFee(10n, { gasUsed: 0n, txBytes: T }, E), 10n, "at target");
eq(F.nextBaseFee(10n, { gasUsed: 0n, txBytes: T + 1n }, E), 11n, "one over target");
eq(F.nextBaseFee(8000n, { gasUsed: 0n, txBytes: F.maxBlockTxBytes(E) }, E), 9000n, "saturated +1/8");
eq(T / 8689n, 30n, "transfers to target");
eq(F.maxBlockTxBytes(E) / 8689n, 60n, "transfers to cap");

// staleness_is_bounded_at_one_eighth_per_block_in_both_directions
let up = 8000n;
for (let i = 0; i < 3; i++) up = F.nextBaseFee(up, { gasUsed: F.BLOCK_GAS_LIMIT, txBytes: 0n }, E);
eq(up, 11390n, "three full blocks up");
let down = 8000n;
for (let i = 0; i < 3; i++) down = F.nextBaseFee(down, empty, E);
eq(down, 5360n, "three empty blocks down");

// the_caps_the_page_prints_as_planning_limits
eq(F.BLOCK_GAS_LIMIT, 60000000n, "gas limit");
eq(F.BLOCK_GAS_TARGET, 30000000n, "gas target");
eq(F.MIN_BASE_FEE_MILLISAT_PER_GAS, 10n, "floor");
const sat62 = F.intrinsicGas(524288n, 62n);
if (sat62 >= F.BLOCK_GAS_LIMIT) { console.log("FAIL bytes must bind before gas"); fails++; }
eq(sat62, 5000n + 524288n * 16n + 72748n * 62n, "saturated 62-owner gas");

console.log(fails === 0 ? "PORT OK — every figure matches the Rust test" : `${fails} MISMATCHES`);
process.exit(fails ? 1 : 0);
