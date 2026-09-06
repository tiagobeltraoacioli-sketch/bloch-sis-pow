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
import { parseAddress } from "./address.js";

function json(res: ServerResponse, status: number, body: unknown): void {
  // bigintReplacer is a backstop: every amount below is already formatted, but
  // a stray bigint would otherwise make JSON.stringify throw at request time.
  const s = JSON.stringify(body, bigintReplacer);
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
  // T-1 fix: a throw from an async event handler elsewhere in the process
  // would otherwise still crash Node by default; this is not a substitute
  // for the try/catch above (which is the actual fix for THIS server's
  // synchronous handlers) but a last-resort backstop so a slip anywhere
  // degrades to a logged error instead of taking the whole process down.
  process.on("uncaughtException", (e) => {
    console.error(`[bloch-indexer] uncaughtException (process kept alive): ${e instanceof Error ? e.stack ?? e.message : String(e)}`);
  });
  return server;
}

function handleRequest(
  cfg: IndexerConfig,
  store: IndexStore,
  req: IncomingMessage,
  res: ServerResponse,
): void {
  {
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

    // GET /address/:addr/(balance|utxos|history)
    if (parts[0] === "address" && parts[1]) {
      const addr = decodeURIComponent(parts[1]);
      // T-1 fix: validate the path segment BEFORE it ever reaches the
      // store. `parseAddress` already existed (address.ts) and was unused
      // by the API; a malformed value (including "__proto__" and friends)
      // now gets a clean 400 instead of a store lookup at all — the
      // null-prototype maps + Object.hasOwn guards in store.ts are the
      // second, independent layer if this one is ever bypassed.
      if (parseAddress(addr) === null) {
        json(res, 400, { error: "malformed address" });
        return;
      }
      const sub = parts[2] ?? "balance";
      if (sub === "balance") {
        const bal = store.getBalance(addr);
        json(res, 200, {
          address: addr,
          balanceSats: formatSats(bal), // canonical: decimal string
          balanceBloch: satsToBlochDisplay(bal), // display only, lossy
          utxoCount: store.getUtxosForAddress(addr).length,
        });
        return;
      }
      if (sub === "utxos") {
        json(res, 200, {
          address: addr,
          utxos: store.getUtxosForAddress(addr).map(({ key, utxo }) => {
            const [txid, index] = key.split(":");
            return { txid, index: Number(index), value: formatSats(utxo.value), height: utxo.height };
          }),
        });
        return;
      }
      if (sub === "history") {
        json(res, 200, {
          address: addr,
          history: store.getHistory(addr).map((e) => ({
            txid: e.txid,
            height: e.height,
            direction: e.direction,
            amountSats: formatSats(e.amountSats),
          })),
        });
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
