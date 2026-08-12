// SPDX-License-Identifier: MIT OR Apache-2.0
// Embedded index store (JSON-backed) with a per-block UNDO journal — the
// mechanism that makes the indexer reorg-safe.
//
// For every applied block we record enough information to exactly reverse it:
//   * `created`  — UTXO keys this block created (delete them on rollback)
//   * `spent`    — UTXOs this block consumed, with their prior value (re-add)
//   * `deltas`   — net per-address balance change (subtract on rollback)
// Address-history entries carry their block height, so rollback simply drops
// every entry at heights above the fork point. No re-scan of the whole chain is
// needed — rollback is O(work done by the orphaned blocks).
//
// The store is an interface (`IndexStore`); `JsonStore` is the reference
// implementation. Swapping in SQLite/sled later only requires implementing the
// same interface.
//
// Every satoshi quantity in here is a `bigint` (see sats.ts). Balance deltas are
// signed, so they are the one place a satoshi value may legitimately be
// negative; they are never `parseSats`-validated as amounts, only serialized as
// signed decimal strings.
//
// Persistence note: `bigint` is not JSON-serializable — `JSON.stringify` throws
// `TypeError: Do not know how to serialize a BigInt`. So the state is converted
// to/from a plain wire shape (`serializeState`/`deserializeState`) where amounts
// are decimal strings. Load is dual-tolerant: a state file written by the old
// `number`-typed build still reads back exactly.

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import { parseSats, formatSats, parseJsonExactIntegers } from "./sats.js";

export interface Utxo {
  address: string;
  value: bigint; // satoshis
  height: number;
}

export interface HistoryEntry {
  txid: string;
  height: number;
  direction: "in" | "out";
  amountSats: bigint;
}

export interface UndoRecord {
  height: number;
  hash: string;
  created: string[]; // utxo keys created
  spent: Array<{ key: string; utxo: Utxo }>; // utxos consumed
  deltas: Record<string, bigint>; // address -> net balance change (signed)
}

export interface Tip {
  height: number;
  hash: string;
}

export interface StoreState {
  indexedTip: Tip | null;
  reorgsHandled: number;
  blocksApplied: number;
  blocksRolledBack: number;
  chain: Record<number, string>; // height -> hash (our applied selected chain)
  utxos: Record<string, Utxo>; // "txid:index" -> utxo
  balances: Record<string, bigint>; // address -> satoshis
  history: Record<string, HistoryEntry[]>; // address -> entries
  undo: Record<number, UndoRecord>; // height -> undo record
}

export interface IndexStore {
  state: StoreState;
  getTip(): Tip | null;
  getChainHashAt(height: number): string | undefined;
  applyBlock(height: number, hash: string, txs: import("./rpc.js").Tx[]): void;
  rollbackTo(forkHeight: number): void; // keep <= forkHeight, drop above
  getBalance(address: string): bigint;
  getUtxosForAddress(address: string): Array<{ key: string; utxo: Utxo }>;
  getHistory(address: string): HistoryEntry[];
  getUtxo(txid: string, index: number): Utxo | undefined;
  persist(): void;
}

function emptyState(): StoreState {
  return {
    indexedTip: null,
    reorgsHandled: 0,
    blocksApplied: 0,
    blocksRolledBack: 0,
    chain: {},
    utxos: {},
    balances: {},
    history: {},
    undo: {},
  };
}

// ── Persistence shape (amounts as decimal strings) ────────────────────────────
//
// A signed decimal string, for undo deltas. `parseSats` rejects negatives (an
// amount may not be negative), so deltas get their own narrow parser.
function parseSignedSats(raw: unknown, context: string): bigint {
  if (typeof raw === "bigint") return raw;
  if (typeof raw === "string") {
    if (!/^-?(0|[1-9][0-9]{0,19})$/.test(raw)) {
      throw new Error(`${context}: not a signed decimal satoshi string: ${JSON.stringify(raw)}`);
    }
    return BigInt(raw);
  }
  if (typeof raw === "number") {
    // Legacy on-disk form. Mirrors parseSats: refuse values whose digits are
    // already gone rather than launder them into a confident bigint.
    if (!Number.isInteger(raw)) throw new Error(`${context}: not an integer: ${raw}`);
    if (!Number.isSafeInteger(raw)) {
      throw new Error(
        `${context}: legacy numeric delta ${raw} exceeds Number.MAX_SAFE_INTEGER; its digits were lost before load`,
      );
    }
    return BigInt(raw);
  }
  throw new Error(`${context}: expected string/number/bigint, got ${typeof raw}`);
}

function serializeUtxo(u: Utxo): Record<string, unknown> {
  return { address: u.address, value: formatSats(u.value), height: u.height };
}
function deserializeUtxo(raw: unknown, context: string): Utxo {
  const o = raw as { address?: unknown; value?: unknown; height?: unknown };
  return {
    address: String(o.address ?? ""),
    value: parseSats(o.value, `${context}.value`),
    height: Number(o.height ?? 0),
  };
}

/** State -> plain JSON-safe object. Amounts become decimal strings. */
export function serializeState(s: StoreState): unknown {
  const utxos: Record<string, unknown> = {};
  for (const [k, u] of Object.entries(s.utxos)) utxos[k] = serializeUtxo(u);

  const balances: Record<string, string> = {};
  for (const [a, v] of Object.entries(s.balances)) balances[a] = formatSats(v);

  const history: Record<string, unknown[]> = {};
  for (const [a, entries] of Object.entries(s.history)) {
    history[a] = entries.map((e) => ({
      txid: e.txid,
      height: e.height,
      direction: e.direction,
      amountSats: formatSats(e.amountSats),
    }));
  }

  const undo: Record<string, unknown> = {};
  for (const [h, u] of Object.entries(s.undo)) {
    const deltas: Record<string, string> = {};
    for (const [a, d] of Object.entries(u.deltas)) deltas[a] = d.toString(10); // signed
    undo[h] = {
      height: u.height,
      hash: u.hash,
      created: u.created,
      spent: u.spent.map((sp) => ({ key: sp.key, utxo: serializeUtxo(sp.utxo) })),
      deltas,
    };
  }

  return {
    indexedTip: s.indexedTip,
    reorgsHandled: s.reorgsHandled,
    blocksApplied: s.blocksApplied,
    blocksRolledBack: s.blocksRolledBack,
    chain: s.chain,
    utxos,
    balances,
    history,
    undo,
  };
}

/**
 * Plain JSON object -> state. Amounts may be decimal strings (current form) or
 * bare numbers (a state file written by the pre-bigint build) — both parse to
 * the same exact `bigint`.
 */
export function deserializeState(raw: unknown): StoreState {
  const r = (raw ?? {}) as Record<string, unknown>;
  const s = emptyState();

  s.indexedTip = (r.indexedTip as Tip | null) ?? null;
  s.reorgsHandled = Number(r.reorgsHandled ?? 0);
  s.blocksApplied = Number(r.blocksApplied ?? 0);
  s.blocksRolledBack = Number(r.blocksRolledBack ?? 0);
  s.chain = (r.chain as Record<number, string>) ?? {};

  for (const [k, u] of Object.entries((r.utxos as Record<string, unknown>) ?? {})) {
    s.utxos[k] = deserializeUtxo(u, `utxo ${k}`);
  }
  for (const [a, v] of Object.entries((r.balances as Record<string, unknown>) ?? {})) {
    s.balances[a] = parseSats(v, `balance ${a}`);
  }
  for (const [a, entries] of Object.entries((r.history as Record<string, unknown[]>) ?? {})) {
    s.history[a] = (entries ?? []).map((e) => {
      const h = e as { txid?: unknown; height?: unknown; direction?: unknown; amountSats?: unknown };
      return {
        txid: String(h.txid ?? ""),
        height: Number(h.height ?? 0),
        direction: h.direction === "out" ? "out" : "in",
        amountSats: parseSats(h.amountSats, `history ${a}.amountSats`),
      };
    });
  }
  for (const [h, u] of Object.entries((r.undo as Record<string, unknown>) ?? {})) {
    const rec = (u ?? {}) as {
      height?: unknown;
      hash?: unknown;
      created?: unknown;
      spent?: Array<{ key?: unknown; utxo?: unknown }>;
      deltas?: Record<string, unknown>;
    };
    const deltas: Record<string, bigint> = {};
    for (const [a, d] of Object.entries(rec.deltas ?? {})) {
      deltas[a] = parseSignedSats(d, `undo ${h} delta ${a}`);
    }
    s.undo[Number(h)] = {
      height: Number(rec.height ?? Number(h)),
      hash: String(rec.hash ?? ""),
      created: (rec.created as string[]) ?? [],
      spent: (rec.spent ?? []).map((sp) => ({
        key: String(sp.key ?? ""),
        utxo: deserializeUtxo(sp.utxo, `undo ${h} spent ${String(sp.key)}`),
      })),
      deltas,
    };
  }
  return s;
}

export class JsonStore implements IndexStore {
  state: StoreState;

  private constructor(
    private readonly filePath: string,
    private readonly encodeAddress: (scriptPubkeyHex: string) => string,
    state: StoreState,
  ) {
    this.state = state;
  }

  static open(
    filePath: string,
    encodeAddress: (scriptPubkeyHex: string) => string,
  ): JsonStore {
    let state = emptyState();
    if (existsSync(filePath)) {
      try {
        // parseJsonExactIntegers, not plain JSON.parse: a state file written by
        // the old number-typed build can hold amounts above 2^53, and those must
        // be read from their raw digits rather than through a double.
        state = deserializeState(parseJsonExactIntegers(readFileSync(filePath, "utf8")));
      } catch (e) {
        // Corrupt/partial file — start fresh rather than crash, but say so: a
        // silently discarded index looks identical to an empty chain.
        console.error(
          `[bloch-indexer] state file ${filePath} unreadable (${e instanceof Error ? e.message : String(e)}); starting from empty state`,
        );
        state = emptyState();
      }
    }
    return new JsonStore(filePath, encodeAddress, state);
  }

  /** In-memory only, for tests. */
  static ephemeral(encodeAddress: (scriptPubkeyHex: string) => string): JsonStore {
    return new JsonStore("", encodeAddress, emptyState());
  }

  getTip(): Tip | null {
    return this.state.indexedTip;
  }

  getChainHashAt(height: number): string | undefined {
    return this.state.chain[height];
  }

  getUtxo(txid: string, index: number): Utxo | undefined {
    return this.state.utxos[`${txid}:${index}`];
  }

  private addHistory(address: string, entry: HistoryEntry): void {
    (this.state.history[address] ??= []).push(entry);
  }

  private bump(deltas: Record<string, bigint>, address: string, amount: bigint): void {
    this.state.balances[address] = (this.state.balances[address] ?? 0n) + amount;
    deltas[address] = (deltas[address] ?? 0n) + amount;
  }

  applyBlock(height: number, hash: string, txs: import("./rpc.js").Tx[]): void {
    if (this.state.chain[height] !== undefined) {
      throw new Error(`refusing to apply height ${height}: already indexed (should roll back first)`);
    }
    const undo: UndoRecord = { height, hash, created: [], spent: [], deltas: {} };

    for (const tx of txs) {
      // Spend inputs (coinbase has none / references we don't track).
      if (!tx.coinbase) {
        for (const inp of tx.inputs) {
          const key = `${inp.prev_txid}:${inp.prev_index}`;
          const utxo = this.state.utxos[key];
          if (!utxo) continue; // input we never indexed (e.g. pre-genesis); skip defensively
          undo.spent.push({ key, utxo });
          delete this.state.utxos[key];
          this.bump(undo.deltas, utxo.address, -utxo.value);
          this.addHistory(utxo.address, { txid: tx.txid, height, direction: "out", amountSats: utxo.value });
        }
      }
      // Create outputs.
      for (const out of tx.outputs) {
        const address = this.encodeAddress(out.script_pubkey);
        const key = `${tx.txid}:${out.index}`;
        this.state.utxos[key] = { address, value: out.value, height };
        undo.created.push(key);
        this.bump(undo.deltas, address, out.value);
        this.addHistory(address, { txid: tx.txid, height, direction: "in", amountSats: out.value });
      }
    }

    this.state.chain[height] = hash;
    this.state.undo[height] = undo;
    this.state.indexedTip = { height, hash };
    this.state.blocksApplied += 1;
  }

  /** Reverse exactly one block using its undo record. */
  private rollbackBlock(height: number): void {
    const undo = this.state.undo[height];
    if (!undo) throw new Error(`no undo record for height ${height}`);
    const affected = new Set<string>();

    // Delete UTXOs this block created.
    for (const key of undo.created) delete this.state.utxos[key];
    // Restore UTXOs this block spent.
    for (const { key, utxo } of undo.spent) this.state.utxos[key] = utxo;
    // Reverse balance deltas.
    for (const [addr, delta] of Object.entries(undo.deltas)) {
      this.state.balances[addr] = (this.state.balances[addr] ?? 0n) - delta;
      affected.add(addr);
      if (this.state.balances[addr] === 0n) delete this.state.balances[addr];
    }
    // Drop history entries recorded at this height for affected addresses.
    for (const addr of affected) {
      const list = this.state.history[addr];
      if (!list) continue;
      const kept = list.filter((e) => e.height !== height);
      if (kept.length === 0) delete this.state.history[addr];
      else this.state.history[addr] = kept;
    }

    delete this.state.chain[height];
    delete this.state.undo[height];
    this.state.blocksRolledBack += 1;
  }

  /** Roll back every block ABOVE forkHeight (keep heights <= forkHeight). */
  rollbackTo(forkHeight: number): void {
    const tip = this.state.indexedTip;
    if (!tip) return;
    for (let h = tip.height; h > forkHeight; h--) {
      if (this.state.chain[h] !== undefined) this.rollbackBlock(h);
    }
    if (forkHeight < 0) {
      this.state.indexedTip = null;
    } else {
      const hash = this.state.chain[forkHeight];
      this.state.indexedTip = hash !== undefined ? { height: forkHeight, hash } : null;
    }
    this.state.reorgsHandled += 1;
  }

  getBalance(address: string): bigint {
    return this.state.balances[address] ?? 0n;
  }

  getUtxosForAddress(address: string): Array<{ key: string; utxo: Utxo }> {
    const out: Array<{ key: string; utxo: Utxo }> = [];
    for (const [key, utxo] of Object.entries(this.state.utxos)) {
      if (utxo.address === address) out.push({ key, utxo });
    }
    return out;
  }

  getHistory(address: string): HistoryEntry[] {
    return this.state.history[address] ?? [];
  }

  persist(): void {
    if (!this.filePath) return; // ephemeral
    mkdirSync(dirname(this.filePath), { recursive: true });
    // JSON.stringify(this.state) would THROW here: the state holds bigints.
    writeFileSync(this.filePath, JSON.stringify(serializeState(this.state)));
  }
}
