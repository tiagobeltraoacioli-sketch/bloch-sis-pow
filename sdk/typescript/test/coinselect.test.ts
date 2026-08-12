// SPDX-License-Identifier: MIT OR Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  selectCoins,
  InsufficientFundsError,
  buildTransaction,
  encodeAddress,
  type SelectableUtxo,
} from "../src/index.js";

function utxo(txid: string, index: number, value: number): SelectableUtxo {
  return { txid, index, value, script_pubkey: "00".repeat(20) };
}

const UTXOS: SelectableUtxo[] = [
  utxo("aa".repeat(32), 0, 50_000),
  utxo("bb".repeat(32), 1, 200_000),
  utxo("cc".repeat(32), 0, 10_000),
];

test("selects largest-first and returns change", () => {
  const r = selectCoins(UTXOS, { target: 100_000n, fee: 1_000n });
  assert.equal(r.inputs.length, 1);
  assert.equal(r.inputs[0]!.value, 200_000);
  assert.equal(r.inputTotal, 200_000n);
  assert.equal(r.change, 200_000n - 100_000n - 1_000n);
  assert.equal(r.fee, 1_000n);
});

test("accumulates multiple inputs when needed", () => {
  const r = selectCoins(UTXOS, { target: 230_000n, fee: 1_000n });
  assert.equal(r.inputs.length, 2);
  assert.equal(r.inputTotal, 250_000n);
});

test("folds dust change into the fee", () => {
  const r = selectCoins(UTXOS, { target: 199_000n, fee: 500n, dustThreshold: 1_000n });
  assert.equal(r.change, 0n);
  assert.equal(r.fee, 500n + (200_000n - 199_000n - 500n));
});

test("throws InsufficientFundsError", () => {
  assert.throws(
    () => selectCoins(UTXOS, { target: 10_000_000n, fee: 1_000n }),
    InsufficientFundsError,
  );
});

test("buildTransaction assembles unsigned tx with change output", () => {
  const to = encodeAddress("11".repeat(20), "mainnet");
  const change = encodeAddress("22".repeat(20), "mainnet");
  const built = buildTransaction({
    utxos: UTXOS,
    to,
    amount: 100_000,
    fee: 1_000,
    changeAddress: change,
  });
  assert.equal(built.tx.inputs.length, 1);
  assert.equal(built.tx.outputs.length, 2); // recipient + change
  // Output values are bigint: this is the amount a signature commits to.
  assert.equal(built.tx.outputs[0]!.value, 100_000n);
  assert.equal(built.tx.inputs[0]!.value, 200_000n);
  assert.equal(built.sent, 100_000n);
  assert.equal(built.change, 99_000n);
  assert.equal(built.tx.version, 1);
});

test("selection and building work on the decimal-string wire form", () => {
  // A V4 node sends satoshis as strings; selection must not care.
  const strUtxos: SelectableUtxo[] = [
    { txid: "dd".repeat(32), index: 0, value: "9007199254740993", script_pubkey: "00".repeat(20) },
    { txid: "ee".repeat(32), index: 0, value: "1000", script_pubkey: "00".repeat(20) },
  ];
  const r = selectCoins(strUtxos, { target: 9_007_199_254_740_000n, fee: 0n });
  assert.equal(r.inputs.length, 1);
  // Exact to the satoshi — a number path would have made this ...992.
  assert.equal(r.inputTotal, 9_007_199_254_740_993n);
  assert.equal(r.change, 993n);
});

test("buildTransaction refuses an already-corrupted number amount", () => {
  const to = encodeAddress("11".repeat(20), "mainnet");
  assert.throws(
    () =>
      buildTransaction({
        utxos: UTXOS,
        to,
        amount: 9_007_199_254_740_993, // > 2^53, silently rounded by JS already
        fee: 1_000,
        changeAddress: to,
      }),
    RangeError,
  );
});
