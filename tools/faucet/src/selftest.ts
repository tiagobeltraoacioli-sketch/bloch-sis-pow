// SPDX-License-Identifier: MIT OR Apache-2.0
// Offline self-test: drives the faucet pipeline end-to-end with the stub
// transport + stub signer (no node, no keys, no broadcast). Exits non-zero on
// failure. Run with: npm run selftest
//
// This is NOT a test against a live network. It only proves the wiring builds
// and the getutxos -> select -> sign -> (dry-run) path returns a txid, and that
// rate limiting + address validation behave.

import { loadConfig } from "./config.js";
import { RpcClient, StubTransport } from "./rpc.js";
import { StubSigner } from "./signer.js";
import { Faucet } from "./faucet.js";
import { RateLimiter } from "./ratelimit.js";
import { encodeAddress, parseAddress } from "./address.js";
import { randomBytes } from "node:crypto";

function assert(cond: boolean, msg: string): void {
  if (!cond) {
    console.error("FAIL:", msg);
    process.exit(1);
  }
  console.log("ok:", msg);
}

async function run(): Promise<void> {
  // A valid, checksummed testnet address generated locally.
  const hash = randomBytes(20);
  const testAddr = encodeAddress(hash, "testnet");
  assert(parseAddress(testAddr)?.network === "testnet", "generated address round-trips as testnet");

  const cfg = { ...loadConfig(), dryRun: true, fundingAddress: encodeAddress(randomBytes(20), "testnet") };
  const rpc = new RpcClient(new StubTransport(cfg.fundingAddress));
  const faucet = new Faucet(cfg, rpc, new StubSigner());
  const limiter = new RateLimiter(cfg.perAddressWindowMs, cfg.perIpWindowMs, cfg.perIpMax);

  // Happy path (dry-run).
  const d1 = await faucet.drip(testAddr);
  assert(d1.ok === true, "drip to valid testnet address succeeds in dry-run");
  if (d1.ok) {
    assert(d1.dryRun === true, "result is flagged dry-run");
    assert(/^[0-9a-f]{64}$/.test(d1.txid), "returns a 64-hex txid");
  }

  // Reject a mainnet address.
  const mainAddr = encodeAddress(randomBytes(20), "mainnet");
  const d2 = await faucet.drip(mainAddr);
  assert(d2.ok === false && d2.code === "not_testnet", "mainnet address rejected as not_testnet");

  // Reject garbage.
  const d3 = await faucet.drip("bloch1tZZZ");
  assert(d3.ok === false && d3.code === "bad_address", "malformed address rejected");

  // Rate limiter: one drip per address per window.
  const ip = "203.0.113.7";
  const ok = limiter.check(testAddr, ip);
  assert(ok.allowed, "first request allowed");
  limiter.record(testAddr, ip);
  const blocked = limiter.check(testAddr, ip);
  assert(!blocked.allowed, "second request for same address blocked by cooldown");

  console.log("\nAll self-tests passed (offline, dry-run, no network).");
}

run().catch((e) => {
  console.error("selftest crashed:", e);
  process.exit(1);
});
