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

  // A bare 64-hex script_hash is the primary recipient form: it is what
  // `bloch-pos spendkey` prints, and a native Genesis-4 key has no address.
  {
    const sh = randomBytes(32).toString("hex");
    const d = await faucet.drip(sh);
    assert(d.ok === true && d.scriptHash === sh, "drip accepts a bare 64-hex script_hash");
  }

  // A bloch1t address is zero-extended to 32 bytes the way the chain does it.
  {
    const p2 = parseAddress(testAddr)!;
    const d = await faucet.drip(testAddr);
    assert(
      d.ok === true && d.scriptHash === p2.hashHex + "00".repeat(12),
      "an address is zero-extended to its script_hash",
    );
  }

  // ── Rate limiter ─────────────────────────────────────────────────────────
  // Each of these pins a bypass that was live in the previous limiter.
  const AMT = 100_000_000;

  // One drip per address per window.
  const ip = "203.0.113.7";
  const first = limiter.reserve(testAddr, ip, AMT);
  assert(first.allowed, "first request allowed");
  limiter.commit(first.ticket!);
  const blocked = limiter.reserve(testAddr, ip, AMT);
  assert(!blocked.allowed, "second request for same address blocked by cooldown");

  // The concurrency race: reserving twice WITHOUT settling in between must
  // fail the second time. This is the drain that paid out 47x.
  {
    const lim = new RateLimiter(86_400_000, 3_600_000, 100, 86_400_000, 0);
    const a = lim.reserve(testAddr, "198.51.100.1", AMT);
    const b = lim.reserve(testAddr, "198.51.100.2", AMT);
    assert(a.allowed && !b.allowed, "an in-flight reservation blocks a concurrent one");
  }

  // Case-mangling must not open a fresh quota: Bloch addresses are
  // checksum-case-insensitive, so one address has ~2^40 spellings.
  {
    const lim = new RateLimiter(86_400_000, 3_600_000, 100, 86_400_000, 0);
    const a = lim.reserve(testAddr.toLowerCase(), "198.51.100.3", AMT);
    lim.commit(a.ticket!);
    const b = lim.reserve(testAddr.toUpperCase(), "198.51.100.4", AMT);
    assert(a.allowed && !b.allowed, "upper-case spelling of one address shares its cooldown");
  }

  // A failed drip returns the address cooldown but NOT the per-IP budget:
  // failures used to be free, which made them an unbounded DoS.
  {
    const lim = new RateLimiter(86_400_000, 3_600_000, 2, 86_400_000, 0);
    const r1 = lim.reserve(testAddr, "198.51.100.5", AMT);
    lim.release(r1.ticket!);
    const r2 = lim.reserve(testAddr, "198.51.100.5", AMT);
    assert(r2.allowed, "a released address may try again immediately");
    lim.release(r2.ticket!);
    const r3 = lim.reserve(testAddr, "198.51.100.5", AMT);
    assert(!r3.allowed, "but the per-IP budget is spent by the attempts, not the payouts");
  }

  // The global ceiling bounds the sum across all clients, which no per-client
  // limit can do.
  {
    const lim = new RateLimiter(0, 3_600_000, 100, 86_400_000, 2 * AMT);
    const a = lim.reserve(testAddr, "198.51.100.6", AMT);
    lim.commit(a.ticket!);
    const b = lim.reserve(testAddr, "198.51.100.7", AMT);
    lim.commit(b.ticket!);
    const c = lim.reserve(testAddr, "198.51.100.8", AMT);
    assert(!c.allowed, "the global ceiling refuses the drip that would exceed it");
    assert(lim.spentSats() === 2 * AMT, "spend ledger totals the committed drips");
  }

  console.log("\nAll self-tests passed (offline, dry-run, no network).");
}

run().catch((e) => {
  console.error("selftest crashed:", e);
  process.exit(1);
});
