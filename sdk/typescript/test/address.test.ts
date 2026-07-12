// SPDX-License-Identifier: MIT OR Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  encodeAddress,
  parseAddress,
  isValidAddress,
  addressNetwork,
  addressToHashHex,
  addressToScriptPubkey,
  MAINNET_PREFIX,
  TESTNET_PREFIX,
} from "../src/index.js";

const HASH = "0102030405060708090a0b0c0d0e0f1011121314"; // 20 bytes

test("encode + parse round-trips (mainnet)", () => {
  const addr = encodeAddress(HASH, "mainnet");
  assert.ok(addr.startsWith(MAINNET_PREFIX));
  assert.equal(addr.length, 55);
  const p = parseAddress(addr);
  assert.equal(p.valid, true);
  assert.equal(p.network, "mainnet");
  assert.equal(p.checksum, true);
  assert.equal(p.hashHex, HASH);
});

test("encode + parse round-trips (testnet)", () => {
  const addr = encodeAddress(HASH, "testnet");
  assert.ok(addr.startsWith(TESTNET_PREFIX));
  assert.equal(addressNetwork(addr), "testnet");
  assert.equal(addressToHashHex(addr), HASH);
});

test("scriptPubkey equals the 20-byte hash (no script system)", () => {
  const addr = encodeAddress(HASH, "mainnet");
  assert.equal(addressToScriptPubkey(addr), HASH);
});

test("rejects a corrupted checksum", () => {
  const addr = encodeAddress(HASH, "mainnet");
  const bad = addr.slice(0, -1) + (addr.endsWith("0") ? "1" : "0");
  assert.equal(isValidAddress(bad), false);
  assert.equal(parseAddress(bad).reason, "checksum mismatch");
});

test("rejects bad prefix and bad length", () => {
  assert.equal(isValidAddress("btc1qwhatever"), false);
  assert.equal(parseAddress("bloch1qshort").reason, "wrong length (expected 48 hex chars after prefix)");
});

test("addressToHashHex throws on invalid address", () => {
  assert.throws(() => addressToHashHex("nonsense"), RangeError);
});
