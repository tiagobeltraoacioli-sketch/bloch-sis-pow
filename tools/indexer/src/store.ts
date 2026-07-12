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

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname } from "node:path";

export interface Utxo {
  address: string;
  value: number;
  height: number;
}

export interface HistoryEntry {
  txid: string;
  height: number;
  direction: "in" | "out";
  amountSats: number;
}

export interface UndoRecord {
  height: number;
  hash: string;
  created: string[]; // utxo keys created
  spent: Array<{ key: string; utxo: Utxo }>; // utxos consumed
  deltas: Record<string, number>; // address -> net balance change
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
  balances: Record<string, number>; // address -> satoshis
  history: Record<string, HistoryEntry[]>; // address -> entries
  undo: Record<number, UndoRecord>; // height -> undo record
}

export interface IndexStore {
  state: StoreState;
  getTip(): Tip | null;
  getChainHashAt(height: number): string | undefined;
  applyBlock(height: number, hash: string, txs: import("./rpc.js").Tx[]): void;
  rollbackTo(forkHeight: number): void; // keep <= forkHeight, drop above
  getBalance(address: string): number;
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
        state = { ...emptyState(), ...(JSON.parse(readFileSync(filePath, "utf8")) as StoreState) };
      } catch {
        // Corrupt/partial file — start fresh rather than crash.
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

  private bump(deltas: Record<string, number>, address: string, amount: number): void {
    this.state.balances[address] = (this.state.balances[address] ?? 0) + amount;
    deltas[address] = (deltas[address] ?? 0) + amount;
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
      this.state.balances[addr] = (this.state.balances[addr] ?? 0) - delta;
      affected.add(addr);
      if (this.state.balances[addr] === 0) delete this.state.balances[addr];
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

  getBalance(address: string): number {
    return this.state.balances[address] ?? 0;
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
    writeFileSync(this.filePath, JSON.stringify(this.state));
  }
}
