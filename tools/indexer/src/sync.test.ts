// SPDX-License-Identifier: MIT OR Apache-2.0
import test from "node:test";
import assert from "node:assert/strict";
import { loadConfig } from "./config.js";
import { Indexer, MAX_BLOCKS_PER_PASS, MAX_FORK_SEARCH } from "./indexer.js";
import { JsonStore } from "./store.js";
import { RpcClient, RpcError, HttpTransport } from "./rpc.js";
import { StubChainTransport, buildScenario, coinbase, type StubBlock } from "./stubchain.js";
const storeForTest = () => JsonStore.ephemeral(s => s);
const blocks = (prefix: string, count: number): StubBlock[] => Array.from({ length: count }, (_, i) => ({
  hash: `${prefix}${i}`, parents: i ? [`${prefix}${i - 1}`] : [], timestamp: i,
  transactions: [coinbase(`${prefix}-tx-${i}`, prefix, 1n)],
}));

test("branch shift between verbose reads cannot publish a mixed batch", async () => {
  const transport = new StubChainTransport(blocks("a", 3));
  const store = storeForTest();
  let switched = false;
  const rpc = new RpcClient({ async call(method, params) {
    if (!switched && method === "getblockbyheight" && params[0] === 1) {
      switched = true;
      transport.reorgFrom(0, blocks("b", 3));
    }
    return transport.call(method, params);
  } });
  const indexer = new Indexer(rpc, store);
  await assert.rejects(indexer.syncOnce(), /branch linkage changed/);
  assert.equal(store.getTip(), null);
  assert.equal(store.getBalance("a"), 0n);
  assert.equal((await indexer.syncOnce()).applied, 3);
  assert.equal(store.getBalance("b"), 3n);
});

test("failed replacement fetch does not roll back the previously published state", async () => {
  const { transport, doReorg } = buildScenario();
  const store = storeForTest();
  await new Indexer(new RpcClient(transport), store).syncOnce();
  const tip = store.getTip();
  const revision = store.getSnapshotId();
  doReorg();
  const rpc = new RpcClient({ async call(method, params) {
    if (method === "getblockbyheight") throw new Error("upstream unavailable");
    return transport.call(method, params);
  } });
  await assert.rejects(new Indexer(rpc, store).syncOnce(), /upstream unavailable/);
  assert.deepEqual(store.getTip(), tip);
  assert.equal(store.getSnapshotId(), revision);
  assert.equal(store.state.blocksRolledBack, 0);
  const recovered = await new Indexer(new RpcClient(transport), store).syncOnce();
  assert.equal(recovered.rolledBack, 2);
  assert.equal(recovered.applied, 2);
});

test("final tip recheck refuses a branch replaced after its body was fetched", async () => {
  const transport = new StubChainTransport(blocks("a", 1));
  const store = storeForTest();
  let hashes = 0;
  const rpc = new RpcClient({ async call(method, params) {
    if (method === "getblockhash" && ++hashes === 2) transport.reorgFrom(0, blocks("b", 1));
    return transport.call(method, params);
  } });
  await assert.rejects(new Indexer(rpc, store).syncOnce(), /batch tip changed/);
  assert.equal(store.state.blocksApplied, 0);
});

test("sync work is bounded and concurrent calls share one publication", async () => {
  const transport = new StubChainTransport(blocks("a", MAX_BLOCKS_PER_PASS + 2));
  const store = storeForTest();
  const indexer = new Indexer(new RpcClient(transport), store);
  const first = indexer.syncOnce();
  assert.equal(indexer.syncOnce(), first);
  assert.equal((await first).applied, MAX_BLOCKS_PER_PASS);
  assert.equal(store.getBalance("a"), BigInt(MAX_BLOCKS_PER_PASS));
  assert.equal((await indexer.syncOnce()).applied, 2);
  assert.equal((await indexer.syncOnce()).applied, 0);
});

test("deep fork search refuses without deleting indexed balances", async () => {
  const store = storeForTest();
  for (let i = 0; i <= MAX_FORK_SEARCH + 1; i++) store.applyBlock(i, `a${i}`, []);
  const revision = store.getSnapshotId();
  let calls = 0;
  const rpc = new RpcClient({ async call(method) {
    assert.equal(method, "getblockhash"); calls++; return "unrelated";
  } });
  await assert.rejects(new Indexer(rpc, store).syncOnce(), /bounded fork search/);
  assert.equal(calls, MAX_FORK_SEARCH + 1);
  assert.equal(store.getSnapshotId(), revision);
});

test("missing stored block data is an error, not a caught-up height", async () => {
  const rpc = new RpcClient({ async call(method) { throw new RpcError("block data not found", method); } });
  await assert.rejects(rpc.getBlockByHeight(3), /block data not found/);
});

test("verbose transaction and parent fields cannot silently default to empty", async () => {
  for (const raw of [{ hash: "h", height: 0, parents: [] }, { hash: "h", height: 0, transactions: [] }]) {
    const rpc = new RpcClient({ async call() { return raw; } });
    await assert.rejects(rpc.getBlockByHeight(0), /invalid verbose block shape/);
  }
});


test("fork-anchor recheck catches changes after a linked body fetch", async () => {
  const old = blocks("a", 1);
  const transport = new StubChainTransport(old);
  const store = storeForTest();
  await new Indexer(new RpcClient(transport), store).syncOnce();
  transport.reorgFrom(1, [{ ...blocks("b", 1)[0]!, hash: "b1", parents: ["a0"] }]);
  let anchorReads = 0;
  const rpc = new RpcClient({ async call(method, params) {
    if (method === "getblockhash" && params[0] === 0 && ++anchorReads === 2) return "changed-anchor";
    return transport.call(method, params);
  } });
  const revision = store.getSnapshotId();
  await assert.rejects(new Indexer(rpc, store).syncOnce(), /fork anchor changed/);
  assert.equal(store.getSnapshotId(), revision);
  assert.equal(store.getChainHashAt(1), undefined);
});

test("RPC envelope IDs and mutually exclusive result/error fields are validated", async (t) => {
  let body: unknown;
  t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify(body)));
  const transport = new HttpTransport("http://localhost:1");
  for (body of [null, [], { jsonrpc: "2.0", id: 2, result: 0 },
    { jsonrpc: "2.0", id: 1, result: 0, error: {} }, { jsonrpc: "2.0", id: 1, error: "bad" }]) {
    await assert.rejects(transport.call("getblockcount", []), /invalid JSON-RPC response envelope/);
  }
  body = { jsonrpc: "2.0", id: 1, result: 3 };
  assert.equal(await transport.call("getblockcount", []), 3);
});


test("malformed selected hashes do not masquerade as chain truncation", async () => {
  for (const hash of [null, {}, 3, ""]) {
    const rpc = new RpcClient({ async call() { return hash; } });
    await assert.rejects(rpc.getBlockHash(0), /invalid block hash response/);
  }
});


test("truncated or coerced transaction fields fail before balance publication", async () => {
  const valid = { txid: "tx", coinbase: false, inputs: [{ prev_txid: "prev", prev_index: 0 }],
    outputs: [{ index: 0, value: "1", script_pubkey: "address" }] };
  const malformed = [
    { ...valid, inputs: undefined }, { ...valid, outputs: undefined }, { ...valid, txid: 42 },
    { ...valid, inputs: [{ prev_txid: "prev" }] },
    ...[-1, 2 ** 32, "0", NaN].map(prev_index => ({ ...valid, inputs: [{ prev_txid: "prev", prev_index }] })),
    { ...valid, outputs: [{ ...valid.outputs[0], index: 1 }] },
  ];
  for (const tx of malformed) {
    const rpc = new RpcClient({ async call() { return { hash: "h", height: 0, parents: [], transactions: [tx] }; } });
    const store = storeForTest();
    await assert.rejects(new Indexer(rpc, store).syncOnce());
    assert.equal(store.getTip(), null);
    assert.equal(store.state.blocksApplied, 0);
  }
});


test("pass deadline aborts a stalled read without mutating or accepting a late result", async () => {
  const store = storeForTest();
  let release: (value: unknown) => void = () => {};
  let observed: AbortSignal | undefined;
  const rpc = new RpcClient({ call(_method, _params, signal) {
    observed = signal;
    return new Promise(resolve => { release = resolve; });
  } });
  const indexer = new Indexer(rpc, store, undefined, 15);
  await assert.rejects(indexer.syncOnce(), /deadline exceeded/);
  assert.equal(observed?.aborted, true);
  release({ hash: "late", height: 0, parents: [], transactions: [] });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(store.getTip(), null);
  assert.equal(store.state.blocksApplied, 0);
});

test("shutdown cancels both active reads and long poll sleeps", async () => {
  for (const pendingRead of [true, false]) {
    const stop = new AbortController();
    const store = storeForTest();
    const rpc = new RpcClient({ async call(method) {
      if (pendingRead) return new Promise(() => {});
      throw new RpcError("height not found", method);
    } });
    const indexer = new Indexer(rpc, store);
    const running = indexer.run(60_000, undefined, stop.signal);
    await new Promise(resolve => setTimeout(resolve, 10));
    stop.abort();
    await running;
    assert.equal(store.getTip(), null);
  }
});

test("HTTP transport propagates the pass cancellation through body consumption", async (t) => {
  let signal: AbortSignal | undefined;
  t.mock.method(globalThis, "fetch", async (_url: unknown, init: RequestInit) => {
    signal = init.signal ?? undefined;
    return new Response(new ReadableStream({ start(controller) {
      signal?.addEventListener("abort", () => controller.error(signal!.reason), { once: true });
    } }));
  });
  const stop = new AbortController();
  const call = new HttpTransport("http://localhost:1").call("getblockhash", [0], stop.signal);
  await new Promise(resolve => setImmediate(resolve));
  stop.abort(new Error("operator stop"));
  await assert.rejects(call, /operator stop/);
  assert.equal(signal?.aborted, true);
});

test("slow responsive reads publish a shorter checked batch instead of starving", async () => {
  const transport = new StubChainTransport(blocks("slow", 16));
  const rpc = new RpcClient({ async call(method, params) {
    await new Promise(resolve => setTimeout(resolve, 15));
    return transport.call(method, params);
  } });
  const store = storeForTest();
  const result = await new Indexer(rpc, store, undefined, 180).syncOnce();
  assert.ok(result.applied >= 1 && result.applied < 16);
  assert.equal(store.getBalance("slow"), BigInt(result.applied));
});


test("RPC transport refuses remote plaintext and embedded credentials", () => {
  for (const url of ["http://node.example.org", "ftp://localhost", "https://user:secret@example.org", "https://node.example.org/#secret"]) {
    assert.throws(() => new HttpTransport(url, "token"), /RPC requires HTTPS/);
  }
  for (const url of ["http://127.0.0.1:16210", "http://[::1]:16210", "https://node.example.org"]) {
    assert.doesNotThrow(() => new HttpTransport(url));
  }
});

test("invalid operational configuration fails instead of silently changing network or timing", () => {
  const names = ["INDEXER_NETWORK", "INDEXER_STUB", "INDEXER_POLL_MS", "INDEXER_API_PORT", "INDEXER_SYNC_TIMEOUT_MS"];
  const before = Object.fromEntries(names.map(name => [name, process.env[name]]));
  try {
    for (const name of names) delete process.env[name];
    assert.equal(loadConfig().syncTimeoutMs, 30_000);
    for (const [name, value] of [["INDEXER_NETWORK", "mainent"], ["INDEXER_STUB", "maybe"],
      ["INDEXER_POLL_MS", "-1"], ["INDEXER_POLL_MS", "1.1"], ["INDEXER_POLL_MS", "NaN"],
      ["INDEXER_API_PORT", "65536"], ["INDEXER_SYNC_TIMEOUT_MS", "300001"], ["INDEXER_SYNC_TIMEOUT_MS", "0"]]) {
      process.env[name!] = value;
      assert.throws(loadConfig, new RegExp(name!));
      delete process.env[name!];
    }
  } finally {
    for (const name of names) {
      if (before[name] === undefined) delete process.env[name];
      else process.env[name] = before[name];
    }
  }
});


test("elapsed read deadlines are checked even while the event loop delays timers", async () => {
  const store = storeForTest();
  let signal: AbortSignal | undefined;
  const rpc = new RpcClient({ async call(_method, _params, passedSignal) {
    signal = passedSignal;
    const until = performance.now() + 30;
    while (performance.now() < until) { /* Model synchronous response parsing. */ }
    return { hash: "too-late", height: 0, parents: [], transactions: [] };
  } });
  await assert.rejects(new Indexer(rpc, store, undefined, 10).syncOnce(), /deadline exceeded/);
  assert.equal(signal?.aborted, true);
  assert.equal(store.getTip(), null);
});
