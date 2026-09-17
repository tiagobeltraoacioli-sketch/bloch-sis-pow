// SPDX-License-Identifier: MIT OR Apache-2.0
// Small read-only HTTP API over the index store (Node stdlib http, no framework).
//
// Amounts leave here in exactly the form the node's Genesis-4 RPC uses: a
// decimal STRING (`"balanceSats": "354617540000000000"`), never a JSON number —
// see docs/specs/BLOCH-SATOSHI-ENCODING.md. The `*Bloch` companions are floats,
// display-only and lossy by construction; they must not be used for accounting.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { IndexStore } from "./store.js";
import type { IndexerConfig } from "./config.js";
import { formatSats, satsToBlochDisplay, bigintReplacer } from "./sats.js";
import { parseAddress, encodeAddress } from "./address.js";

export const MAX_API_RESPONSE_BYTES = 1024 * 1024;
export const MAX_PAGE_SIZE = 500;
const DEFAULT_PAGE_SIZE = 100;

function json(res: ServerResponse, status: number, body: unknown): void {
  // bigintReplacer is a backstop: every amount below is already formatted, but
  // a stray bigint would otherwise make JSON.stringify throw at request time.
  let s: string;
  try {
    s = JSON.stringify(body, (key, value: unknown) => {
      if (typeof value === "string" && value.length > 8192) throw new RangeError("oversized response field");
      return bigintReplacer(key, value);
    });
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
    status = 503;
    s = JSON.stringify({ error: "response field exceeds byte limit" });
  }
  if (Buffer.byteLength(s) > MAX_API_RESPONSE_BYTES) {
    status = 503;
    s = JSON.stringify({ error: "response exceeds byte limit; request a smaller page" });
  }
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(s) });
  res.end(s);
}

export function createReadApi(cfg: IndexerConfig, store: IndexStore) {
  const server = createServer((req, res) => {
    // T-1 fix (audit finding): the whole handler used to have NO try/catch.
    // A synchronous throw inside a `createServer` callback is an uncaught
    // exception, and Node's default behaviour is to log it and EXIT THE
    // PROCESS — so any bug reachable from an unauthenticated GET (the
    // `__proto__` case below among them) took the whole indexer down. This
    // wrapper is the second, independent layer: even a future accessor that
    // reintroduces an unguarded lookup degrades to a 500, not a process exit.
    try {
      handleRequest(cfg, store, req, res);
    } catch (e) {
      console.error(`[bloch-indexer] unhandled API error: ${e instanceof Error ? e.stack ?? e.message : String(e)}`);
      if (!res.headersSent) {
        json(res, 500, { error: "internal error" });
      } else {
        res.end();
      }
    }
  });
  // Bound HTTP resource lifetimes without process-wide exception handlers.
  server.headersTimeout = 5_000;
  server.requestTimeout = 10_000;
  server.keepAliveTimeout = 2_000;
  server.maxHeadersCount = 32;
  server.maxRequestsPerSocket = 100;
  server.maxConnections = 64;
  server.setTimeout(10_000, (socket) => socket.destroy());
  return server;
}

function handleRequest(
  cfg: IndexerConfig,
  store: IndexStore,
  req: IncomingMessage,
  res: ServerResponse,
): void {
  {
    if ((req.url?.length ?? 0) > 2048) { json(res, 414, { error: "request URL too long" }); return; }
    if (req.headers["transfer-encoding"] || (req.headers["content-length"] && req.headers["content-length"] !== "0")) {
      res.setHeader("connection", "close");
      json(res, 400, { error: "read API requests cannot have a body" }); return;
    }
    const url = new URL(req.url ?? "/", "http://localhost");
    const parts = url.pathname.split("/").filter(Boolean);

    if (req.method !== "GET") {
      json(res, 405, { error: "method not allowed" });
      return;
    }

    // GET /health
    if (url.pathname === "/health") {
      // T-7 fix: a corrupt-load-then-silent-empty-state used to report
      // healthy here too. `indexOk: false` is the externally visible signal
      // that this instance's answers are not authoritative.
      const ok = store.indexOk();
      json(res, ok ? 200 : 503, { ok, indexOk: ok, service: "bloch-reorg-safe-indexer" });
      return;
    }

    // GET /status
    if (url.pathname === "/status") {
      const s = store.state;
      const indexOk = store.indexOk();
      json(res, indexOk ? 200 : 503, {
        service: "bloch-reorg-safe-indexer",
        network: cfg.network,
        // T-7 fix: surfaced explicitly rather than letting a corrupt load
        // masquerade as a genuinely empty, healthy chain.
        indexOk,
        indexedTip: s.indexedTip,
        blocksApplied: s.blocksApplied,
        blocksRolledBack: s.blocksRolledBack,
        reorgsHandled: s.reorgsHandled,
        utxoCount: Object.keys(s.utxos).length,
        addressCount: Object.keys(s.balances).length,
        rails:
          "SCAFFOLD/reference indexer, unaudited, testnet-only reference; reorg-safe by design; BLCH not a security, test BLCH has no value.",
      });
      return;
    }

    if (!store.indexOk()) {
      json(res, 503, { error: "index snapshot is unreadable; data is not authoritative" });
      return;
    }

    // GET /address/:addr/(balance|utxos|history)
    if (parts[0] === "address" && parts[1]) {
      let rawAddress: string;
      try { rawAddress = decodeURIComponent(parts[1]); }
      catch { json(res, 400, { error: "malformed address encoding" }); return; }
      const parsedAddress = parseAddress(rawAddress);
      // T-1 fix: validate the path segment BEFORE it ever reaches the
      // store. `parseAddress` already existed (address.ts) and was unused
      // by the API; a malformed value (including "__proto__" and friends)
      // now gets a clean 400 instead of a store lookup at all — the
      // null-prototype maps + Object.hasOwn guards in store.ts are the
      // second, independent layer if this one is ever bypassed.
      if (parsedAddress === null || parsedAddress.network !== cfg.network) {
        json(res, 400, { error: "malformed address" });
        return;
      }
      const addr = encodeAddress(parsedAddress.hashHex, parsedAddress.network);
      const sub = parts[2] ?? "balance";
      if (sub === "balance") {
        const bal = store.getBalance(addr);
        json(res, 200, {
          address: addr,
          balanceSats: formatSats(bal), // canonical: decimal string
          balanceBloch: satsToBlochDisplay(bal), // display only, lossy
          utxoCount: store.getUtxoCount(addr),
        });
        return;
      }
      if (sub === "utxos" || sub === "history") {
        const page = parsePage(url, store, addr, sub, res);
        if (!page) return;
        const items = sub === "utxos"
          ? store.getUtxoPage(addr, page.offset, page.limit + 1).map(({ key, utxo }) => {
              const [txid, index] = key.split(":");
              return { txid, index: Number(index), value: formatSats(utxo.value), height: utxo.height };
            })
          : store.getHistoryPage(addr, page.offset, page.limit + 1).map((entry) => ({
              txid: entry.txid, height: entry.height, direction: entry.direction,
              amountSats: formatSats(entry.amountSats),
            }));
        const more = items.length > page.limit;
        if (more) items.pop();
        const nextCursor = more ? Buffer.from(JSON.stringify({ version: 1, address: addr,
          kind: sub, snapshot: store.getSnapshotId(), offset: page.offset + items.length })).toString("base64url") : null;
        json(res, 200, { address: addr, [sub]: items, limit: page.limit,
          nextCursor, snapshot: store.getSnapshotId(), indexedTip: store.getTip() });
        return;
      }
    }

    // GET /utxo/:txid/:index
    if (parts[0] === "utxo" && parts[1] && parts[2] !== undefined) {
      const utxo = store.getUtxo(parts[1], Number(parts[2]));
      if (!utxo) {
        json(res, 404, { error: "utxo not found or already spent" });
        return;
      }
      json(res, 200, {
        txid: parts[1],
        index: Number(parts[2]),
        address: utxo.address,
        value: formatSats(utxo.value),
        height: utxo.height,
      });
      return;
    }

    // GET /block/:height  -> our indexed hash at that height
    if (parts[0] === "block" && parts[1] !== undefined) {
      const h = Number(parts[1]);
      const hash = store.getChainHashAt(h);
      if (hash === undefined) {
        json(res, 404, { error: "height not indexed" });
        return;
      }
      json(res, 200, { height: h, hash });
      return;
    }

    json(res, 404, { error: "not found" });
  }
}

function parsePage(url: URL, store: IndexStore, address: string, kind: string, res: ServerResponse): { limit: number; offset: number } | null {
  const bad = (message: string, status = 400): null => { json(res, status, { error: message }); return null; };
  if ([...url.searchParams.keys()].some((key) => !["limit", "cursor"].includes(key))
      || url.searchParams.getAll("limit").length > 1 || url.searchParams.getAll("cursor").length > 1) {
    return bad("expected only one limit and cursor");
  }
  const rawLimit = url.searchParams.get("limit") ?? String(DEFAULT_PAGE_SIZE);
  if (!/^[1-9][0-9]{0,2}$/.test(rawLimit) || Number(rawLimit) > MAX_PAGE_SIZE) return bad(`limit must be 1..${MAX_PAGE_SIZE}`);
  const limit = Number(rawLimit);
  const rawCursor = url.searchParams.get("cursor");
  if (rawCursor === null) return { limit, offset: 0 };
  if (rawCursor.length > 1024 || !/^[A-Za-z0-9_-]+$/.test(rawCursor)) return bad("invalid cursor");
  let cursor: { version?: unknown; address?: unknown; kind?: unknown; snapshot?: unknown; offset?: unknown };
  try { cursor = JSON.parse(Buffer.from(rawCursor, "base64url").toString("utf8")); }
  catch { return bad("invalid cursor"); }
  if (!cursor || cursor.version !== 1 || cursor.address !== address || cursor.kind !== kind
      || !Number.isSafeInteger(cursor.offset) || (cursor.offset as number) < 0) return bad("invalid cursor");
  if (cursor.snapshot !== store.getSnapshotId()) return bad("index changed; restart pagination", 409);
  return { limit, offset: cursor.offset as number };
}
