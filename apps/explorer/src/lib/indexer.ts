// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The indexer client — and, until the indexer exists, the written contract for
// what it must serve.
//
// ── Why there has to be one ─────────────────────────────────────────────────
//
// Two things the node RPC cannot do, measured against the live chain on
// 2026-09-01 from the archival at 139.180.166.5:8080:
//
//   1. PAGING. `getutxos` takes `(script_hash, limit)` and nothing else. No
//      cursor, no offset. `UTXO_PAGE_DEFAULT` is 100, `UTXO_PAGE_MAX` is 1,000
//      and the clamp is server-side (asking for 5,000 returns 1,000 with
//      `truncated: true`). The founder's carried hash
//      `e986db51…af4ff‖0×12` held 45,149 unspent outputs at slot 54,535, so
//      44,149 of them are unreachable: the same first thousand come back every
//      time. At genesis that same hash held 426,194 of the chain's 452,726
//      carryover outputs.
//
//   2. HISTORY. There are no transaction ids at this layer. `gettransaction`
//      refuses BY DESIGN, in those words ("this is a permanent answer for this
//      build, not a transient failure — do not retry"), because
//      `PosTransaction::Transfer` encodes only fee-market terms and the block
//      store keeps no txid index. Nothing maps a script hash to the blocks
//      that touched it, and `getblockbyslot` reports `tx_count` — a number —
//      not the transactions themselves.
//
// Everything in this file is therefore OPTIONAL by construction. The address
// page must render, completely and honestly, with `available === false`; the
// indexer only ever ADDS rows. That is not politeness, it is the failure mode
// we are designing against: a page that silently shows a partial set as if it
// were the whole one is the same bug as a silent zero balance.
//
// ── The contract (for the sibling task building it) ─────────────────────────
//
// Base URL from `VITE_BLOCH_INDEXER` at build time, else same-origin
// `/indexer`. All responses JSON, all satoshi amounts DECIMAL STRINGS (supply
// is 1e19 sat, ~1110× Number.MAX_SAFE_INTEGER — a satoshi value that passes
// through a JS number is silently rounded). All hashes lowercase hex, no `0x`.
//
//   GET /indexer/health
//     -> { ok, indexed_to_slot, indexed_to_height, finalized_height,
//          source: "139.180.166.5:8080" | …, lag_slots }
//     `indexed_to_slot` is load-bearing: every other answer is AS OF that
//     slot, and the page prints it. An indexer that does not say how far
//     behind it is cannot be trusted to say anything else.
//
//   GET /indexer/utxos/:script_hash?cursor=&limit=
//     -> { script_hash, total, utxos: [{ txid, vout, value_sat,
//                                        created_slot, created_height }],
//          next_cursor: string | null, as_of_slot }
//     THE reason the indexer exists. `created_slot` is the second reason:
//     `getutxos` does not carry it and `gettxout`'s `at_slot` is NOT it (see
//     below), so the slot an output landed in exists nowhere on the RPC.
//     Opaque cursor, please — offset-into-a-changing-set is a paging bug
//     waiting to duplicate and skip rows under reorg.
//
//   GET /indexer/outpoint/:txid/:vout
//     -> { txid, vout, value_sat, script_hash,
//          created_slot, created_height,
//          spent_slot: number | null, spent_height: number | null,
//          as_of_slot }
//     The honest unit of history on this chain. Not a transaction: an
//     outpoint, the slot that created it, and the slot that spent it.
//
//   GET /indexer/history/:script_hash?cursor=&limit=
//     -> { script_hash, events: [{ kind: "created" | "spent", txid, vout,
//                                  value_sat, slot, height }],
//          next_cursor: string | null, as_of_slot }
//     "Transaction history", as far as this chain permits one. An event is an
//     outpoint appearing or disappearing under this hash — never a "payment",
//     because nothing on the wire says who paid whom.
//
// The indexer MUST read from the archivals (139.180.166.5 / 139.180.173.231,
// port 8080) and never from a validator: that RPC has no auth, no rate limit,
// and is served by the consensus thread itself (`EngineBackend` hands each
// call to the engine's event loop — a burst of reads competes with block
// production).

/** Where the indexer lives, if it lives anywhere. */
export const INDEXER_BASE: string =
  (import.meta as { env?: Record<string, string> }).env?.VITE_BLOCH_INDEXER ?? "/indexer";

export interface IndexerHealth {
  ok: boolean;
  indexed_to_slot: number;
  indexed_to_height: number;
  finalized_height: number;
  source: string;
  lag_slots: number;
}

export interface IndexedUtxo {
  txid: string;
  vout: number;
  value_sat: string;
  created_slot: number;
  created_height: number;
}

export interface IndexedUtxoPage {
  script_hash: string;
  total: number;
  utxos: IndexedUtxo[];
  next_cursor: string | null;
  as_of_slot: number;
}

export interface IndexedOutpoint {
  txid: string;
  vout: number;
  value_sat: string;
  script_hash: string;
  created_slot: number;
  created_height: number;
  spent_slot: number | null;
  spent_height: number | null;
  as_of_slot: number;
}

export interface IndexedEvent {
  kind: "created" | "spent";
  txid: string;
  vout: number;
  value_sat: string;
  slot: number;
  height: number;
}

export interface IndexedHistoryPage {
  script_hash: string;
  events: IndexedEvent[];
  next_cursor: string | null;
  as_of_slot: number;
}

const TIMEOUT_MS = 8000;

async function get<T>(path: string): Promise<T> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(INDEXER_BASE + path, { signal: ac.signal });
    if (!res.ok) throw new Error(`indexer ${res.status}`);
    return (await res.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Is there an indexer at all?
 *
 * Probed once per page load and cached, including the negative. A page that
 * re-probes a missing service on every render turns "the indexer is not
 * deployed yet" into a stream of failed requests, and the console noise is
 * how a real outage gets missed later.
 */
let probe: Promise<IndexerHealth | null> | null = null;

export function indexerHealth(): Promise<IndexerHealth | null> {
  if (!probe) {
    probe = get<IndexerHealth>("/health")
      .then((h) => (h && h.ok ? h : null))
      .catch(() => null);
  }
  return probe;
}

export function indexedUtxos(
  scriptHash: string,
  cursor?: string | null,
  limit = 100,
): Promise<IndexedUtxoPage> {
  const q = new URLSearchParams({ limit: String(limit) });
  if (cursor) q.set("cursor", cursor);
  return get<IndexedUtxoPage>(`/utxos/${scriptHash}?${q}`);
}

export function indexedOutpoint(txid: string, vout: number): Promise<IndexedOutpoint> {
  return get<IndexedOutpoint>(`/outpoint/${txid}/${vout}`);
}

export function indexedHistory(
  scriptHash: string,
  cursor?: string | null,
  limit = 50,
): Promise<IndexedHistoryPage> {
  const q = new URLSearchParams({ limit: String(limit) });
  if (cursor) q.set("cursor", cursor);
  return get<IndexedHistoryPage>(`/history/${scriptHash}?${q}`);
}
