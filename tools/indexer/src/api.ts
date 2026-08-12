// SPDX-License-Identifier: MIT OR Apache-2.0
// Small read-only HTTP API over the index store (Node stdlib http, no framework).
//
// Amounts leave here in exactly the form the node's Genesis-4 RPC uses: a
// decimal STRING (`"balanceSats": "354617540000000000"`), never a JSON number —
// see docs/specs/BLOCH-SATOSHI-ENCODING.md. The `*Bloch` companions are floats,
// display-only and lossy by construction; they must not be used for accounting.

import { createServer, type ServerResponse } from "node:http";
import type { IndexStore } from "./store.js";
import type { IndexerConfig } from "./config.js";
import { formatSats, satsToBlochDisplay, bigintReplacer } from "./sats.js";

function json(res: ServerResponse, status: number, body: unknown): void {
  // bigintReplacer is a backstop: every amount below is already formatted, but
  // a stray bigint would otherwise make JSON.stringify throw at request time.
  const s = JSON.stringify(body, bigintReplacer);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(s) });
  res.end(s);
}

export function createReadApi(cfg: IndexerConfig, store: IndexStore) {
  return createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const parts = url.pathname.split("/").filter(Boolean);

    if (req.method !== "GET") {
      json(res, 405, { error: "method not allowed" });
      return;
    }

    // GET /health
    if (url.pathname === "/health") {
      json(res, 200, { ok: true, service: "bloch-reorg-safe-indexer" });
      return;
    }

    // GET /status
    if (url.pathname === "/status") {
      const s = store.state;
      json(res, 200, {
        service: "bloch-reorg-safe-indexer",
        network: cfg.network,
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
  });
}
