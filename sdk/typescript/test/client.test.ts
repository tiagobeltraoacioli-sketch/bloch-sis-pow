// SPDX-License-Identifier: MIT OR Apache-2.0
import { test } from "node:test";
import assert from "node:assert/strict";
import { BlochClient, BlochRpcError, type FetchLike } from "../src/index.js";

/** Build a mock fetch that returns a fixed JSON body + status. */
function mockFetch(body: unknown, status = 200): { fetch: FetchLike; calls: any[] } {
  const calls: any[] = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, init, parsed: JSON.parse(init.body) });
    const text = JSON.stringify(body);
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => JSON.parse(text),
      text: async () => text,
    };
  };
  return { fetch, calls };
}

test("getBlockCount returns a bare number result", async () => {
  const { fetch, calls } = mockFetch({ jsonrpc: "2.0", result: 42, id: 1 });
  const c = new BlochClient({ fetch });
  assert.equal(await c.getBlockCount(), 42);
  assert.equal(calls[0].parsed.method, "getblockcount");
  assert.deepEqual(calls[0].parsed.params, []);
});

test("getBalance passes the address and returns the typed shape", async () => {
  const { fetch, calls } = mockFetch({
    jsonrpc: "2.0",
    result: { satoshis: 150000000, bloch: 1.5, utxo_count: 2, address: "bloch1q..." },
    id: 1,
  });
  const c = new BlochClient({ fetch });
  const bal = await c.getBalance("bloch1qexample");
  assert.equal(bal.satoshis, 150000000);
  assert.equal(bal.utxo_count, 2);
  assert.equal(calls[0].parsed.params[0], "bloch1qexample");
});

test("handles the non-standard result.error quirk", async () => {
  const { fetch } = mockFetch({ jsonrpc: "2.0", result: { error: "invalid hash" }, id: 1 });
  const c = new BlochClient({ fetch });
  await assert.rejects(
    () => c.getBlock("deadbeef"),
    (err: unknown) => {
      assert.ok(err instanceof BlochRpcError);
      assert.equal(err.source, "result-error");
      assert.equal(err.message, "invalid hash");
      return true;
    },
  );
});

test("handles the standard JSON-RPC error object (Sprint-M auth)", async () => {
  const { fetch } = mockFetch(
    { jsonrpc: "2.0", error: { code: -32001, message: "unauthorized" }, id: 1 },
    401,
  );
  const c = new BlochClient({ fetch });
  await assert.rejects(
    () => c.sendRawTransaction("00"),
    (err: unknown) => {
      assert.ok(err instanceof BlochRpcError);
      assert.equal(err.source, "jsonrpc-error");
      assert.equal(err.code, -32001);
      assert.equal(err.isUnauthorized, true);
      return true;
    },
  );
});

test("sends X-API-Key header when configured", async () => {
  const { fetch, calls } = mockFetch({ jsonrpc: "2.0", result: { txid: "ab" }, id: 1 });
  const c = new BlochClient({ fetch, apiKey: "secret" });
  await c.sendRawTransaction("00ff");
  assert.equal(calls[0].init.headers["X-API-Key"], "secret");
});

test("sends Bearer auth when bearer=true", async () => {
  const { fetch, calls } = mockFetch({ jsonrpc: "2.0", result: 0, id: 1 });
  const c = new BlochClient({ fetch, apiKey: "secret", bearer: true });
  await c.getBlockCount();
  assert.equal(calls[0].init.headers["Authorization"], "Bearer secret");
});
