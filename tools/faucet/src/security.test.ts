// SPDX-License-Identifier: MIT OR Apache-2.0
// node:test regression suite for the T-3/T-4/T-5 audit findings.
// Run: `tsc && node --test dist/security.test.js` (see package.json "test:node").

import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { loadConfig } from "./config.js";
import { RpcClient, StubTransport, parseSats } from "./rpc.js";
import { StubSigner } from "./signer.js";
import { Faucet } from "./faucet.js";
import { RateLimiter } from "./ratelimit.js";
import { createFaucetServer } from "./server.js";
import { encodeAddress } from "./address.js";
import { parseJsonExactIntegers, assertJsonSourceAccessAvailable, MAX_SATS } from "./sats.js";

function baseCfg() {
  const cfg = loadConfig();
  return { ...cfg, dryRun: true, fundingAddress: encodeAddress(randomBytes(20), "testnet") };
}

async function withServer(
  fn: (base: string) => Promise<void>,
  opts?: { perIpMax?: number },
): Promise<void> {
  const cfg = baseCfg();
  const rpc = new RpcClient(new StubTransport(cfg.fundingAddress));
  const faucet = new Faucet(cfg, rpc, new StubSigner());
  const limiter = new RateLimiter(
    cfg.perAddressWindowMs,
    cfg.perIpWindowMs,
    opts?.perIpMax ?? cfg.perIpMax,
  );
  const server = createFaucetServer(cfg, faucet, limiter);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("expected an AddressInfo");
  try {
    await fn(`http://127.0.0.1:${addr.port}`);
  } finally {
    server.close();
  }
}

// ── T-3: reserve-then-confirm closes the concurrent-drip race ──────────────

test("T-3: two concurrent POST /api/faucet for the SAME address dispatch at most once", async () => {
  await withServer(async (base) => {
    const hash = randomBytes(20);
    const address = encodeAddress(hash, "testnet");

    // Fire both requests essentially simultaneously — before the fix,
    // `check()` (a pure read) let both observe "no prior drip" because
    // NEITHER had called `record()` yet (that only happened after `await
    // faucet.drip(...)` resolved). The fix's `reserve()` is synchronous, so
    // whichever request's JS runs first (Node is single-threaded; only one
    // callback body executes at a time) reserves the address before the
    // second request's `reserve()` call is even invoked.
    const [r1, r2] = await Promise.all([
      fetch(`${base}/api/faucet`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ address }),
      }),
      fetch(`${base}/api/faucet`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ address }),
      }),
    ]);

    const statuses = [r1.status, r2.status].sort();
    // Exactly one 200 (dispatched) and one 429 (rate limited) — never two
    // 200s, which is what the TOCTOU used to allow.
    assert.deepEqual(statuses, [200, 429], `expected [200, 429], got [${statuses.join(", ")}]`);
  });
});

test("T-3: ten concurrent requests for the same address yield exactly one success", async () => {
  await withServer(async (base) => {
    const address = encodeAddress(randomBytes(20), "testnet");
    const responses = await Promise.all(
      Array.from({ length: 10 }, () =>
        fetch(`${base}/api/faucet`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ address }),
        }),
      ),
    );
    const okCount = responses.filter((r) => r.status === 200).length;
    const rateLimitedCount = responses.filter((r) => r.status === 429).length;
    assert.equal(okCount, 1, `expected exactly 1 success among 10 concurrent requests, got ${okCount}`);
    assert.equal(rateLimitedCount, 9);
  });
});

test("T-3: a failed drip releases the reservation so the SAME address can retry", async () => {
  // Use a bad address that faucet.drip() will reject (not the rate limiter,
  // the address validator) — this proves reserve/release around a failing
  // drip does not permanently strand the address.
  await withServer(async (base) => {
    const mainnetAddr = encodeAddress(randomBytes(20), "mainnet");
    const r1 = await fetch(`${base}/api/faucet`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ address: mainnetAddr }),
    });
    assert.equal(r1.status, 400); // not_testnet — the reservation must have been released
    const r2 = await fetch(`${base}/api/faucet`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ address: mainnetAddr }),
    });
    assert.equal(r2.status, 400, "second attempt must reach the SAME validation error, not a stale 429");
  });
});

// ── T-4: the transport does not round large amounts through res.json() ─────

test("T-4: parseJsonExactIntegers preserves a satoshi literal above Number.MAX_SAFE_INTEGER", () => {
  const text = '{"result":{"satoshis":354617540000000001}}';
  const parsed = parseJsonExactIntegers(text) as { result: { satoshis: unknown } };
  assert.equal(typeof parsed.result.satoshis, "string", "oversized literal must survive as a string, not a rounded number");
  assert.equal(parseSats(parsed.result.satoshis, "test"), 354617540000000001n);
});

// ── T-5: faucet and indexer share one canonical sats implementation ────────

test("T-5: the faucet's parseSats enforces the canonical (no leading zeros, bounded) form", () => {
  // The faucet's OLD local parseSats accepted "007" (leading zeros) and had
  // no MAX_SATS bound. The shared/vendored implementation must reject both.
  assert.throws(() => parseSats("007", "test"), /canonical/);
  assert.throws(() => parseSats((MAX_SATS + 1n).toString(10), "test"), /exceeds total supply/);
  assert.equal(parseSats("7", "test"), 7n);
  assert.equal(parseSats(MAX_SATS.toString(10), "test"), MAX_SATS);
});

// ── T-6: key-filtered exact-integer reviver + startup probe ────────────────

test("T-6: an oversized integer under a recognized amount key is preserved exactly", () => {
  const parsed = parseJsonExactIntegers('{"result":{"satoshis":354617540000000001}}') as {
    result: { satoshis: unknown };
  };
  assert.equal(typeof parsed.result.satoshis, "string");
  assert.equal(parsed.result.satoshis, "354617540000000001");
});

test("T-6: an oversized integer under an UNRECOGNIZED key is left as a (rounded) number, never retyped", () => {
  const parsed = parseJsonExactIntegers('{"blocks":99999999999999999999}') as { blocks: unknown };
  assert.equal(typeof parsed.blocks, "number", "an unlisted key must stay a number, never silently retyped");
});

test("T-6: assertJsonSourceAccessAvailable does not throw on this test runtime (node >= 21 required for exact amounts)", () => {
  assert.doesNotThrow(() => assertJsonSourceAccessAvailable());
});
