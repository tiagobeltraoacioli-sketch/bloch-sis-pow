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

import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync, openSync, closeSync, fsyncSync, unlinkSync } from "node:fs";
import { randomUUID } from "node:crypto";
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
  getSnapshotId(): string;
  getUtxoCount(address: string): number;
  getUtxoPage(address: string, offset: number, limit: number): Array<{ key: string; utxo: Utxo }>;
  getHistoryPage(address: string, offset: number, limit: number): HistoryEntry[];
  getUtxo(txid: string, index: number): Utxo | undefined;
  persist(): void;
  /** T-7 fix: `false` iff the on-disk state file existed but failed to load
   * (parse error / corruption), in which case this store fell back to an
   * EMPTY state that must not be presented as an authoritative "zero
   * balance for every address" answer. Always `true` for a fresh index
   * (no file yet) or an in-memory/ephemeral store. */
  indexOk(): boolean;
}

// T-1 fix (audit finding): every one of these maps is keyed, directly or
// indirectly, by an ADDRESS — and `address` reaches here straight from an
// HTTP path segment (`api.ts`'s `req.url` parsing), fully attacker-chosen.
// A plain `{}` object literal inherits from `Object.prototype`, so a key
// like `"__proto__"`, `"constructor"`, or `"toString"` resolves to an
// INHERITED property instead of `undefined` — which is not nullish, so a
// `?? []`/`?? 0n` default never fires, and the caller gets back a function
// object where it expected `HistoryEntry[]`/`bigint`/`Utxo`. `Object.create
// (null)` makes each of these maps have NO prototype at all, so every one
// of those keys is a plain, ordinary miss (`undefined`) like any other
// absent key — this is the structural fix; `Object.hasOwn` at each read
// site (below) is the second, independent layer.
function emptyState(): StoreState {
  return {
    indexedTip: null,
    reorgsHandled: 0,
    blocksApplied: 0,
    blocksRolledBack: 0,
    chain: Object.create(null),
    utxos: Object.create(null),
    balances: Object.create(null),
    history: Object.create(null),
    undo: Object.create(null),
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
function record(raw: unknown, context: string): Record<string, unknown> {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`${context}: expected object`);
  return raw as Record<string, unknown>;
}
function counter(raw: unknown, context: string): number {
  if (typeof raw !== "number" || !Number.isSafeInteger(raw) || raw < 0) throw new Error(`${context}: expected nonnegative safe integer`);
  return raw;
}
function text(raw: unknown, context: string): string {
  if (typeof raw !== "string" || raw.length === 0) throw new Error(`${context}: expected nonempty string`);
  return raw;
}
function heightKey(raw: string): number {
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) throw new Error("invalid height key");
  return counter(Number(raw), "height key");
}
function deserializeUtxo(raw: unknown, context: string): Utxo {
  const value = record(raw, context);
  return { address: text(value.address, `${context}.address`),
    value: parseSats(value.value, `${context}.value`), height: counter(value.height, `${context}.height`) };
}

/** State -> plain JSON-safe object. Amounts become decimal strings. */
export function serializeState(s: StoreState): unknown {
  const utxos: Record<string, unknown> = Object.create(null);
  for (const [k, u] of Object.entries(s.utxos)) utxos[k] = serializeUtxo(u);

  const balances: Record<string, string> = Object.create(null);
  for (const [a, v] of Object.entries(s.balances)) balances[a] = formatSats(v);

  const history: Record<string, unknown[]> = Object.create(null);
  for (const [a, entries] of Object.entries(s.history)) {
    history[a] = entries.map((e) => ({
      txid: e.txid,
      height: e.height,
      direction: e.direction,
      amountSats: formatSats(e.amountSats),
    }));
  }

  const undo: Record<string, unknown> = Object.create(null);
  for (const [h, u] of Object.entries(s.undo)) {
    const deltas: Record<string, string> = Object.create(null);
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
  const r = record(raw, "snapshot");
  const s = emptyState();
  if (r.indexedTip !== null) {
    const tip = record(r.indexedTip, "indexedTip");
    s.indexedTip = { height: counter(tip.height, "indexedTip.height"), hash: text(tip.hash, "indexedTip.hash") };
  }
  s.reorgsHandled = counter(r.reorgsHandled, "reorgsHandled");
  s.blocksApplied = counter(r.blocksApplied, "blocksApplied");
  s.blocksRolledBack = counter(r.blocksRolledBack, "blocksRolledBack");
  let maximumHeight = -1;
  for (const [key, hash] of Object.entries(record(r.chain, "chain"))) {
    const height = heightKey(key);
    s.chain[height] = text(hash, `chain ${key}`);
    maximumHeight = Math.max(maximumHeight, height);
  }
  if (s.indexedTip === null ? maximumHeight !== -1
      : maximumHeight !== s.indexedTip.height || s.chain[s.indexedTip.height] !== s.indexedTip.hash) {
    throw new Error("indexedTip does not match indexed chain");
  }
  for (const [key, value] of Object.entries(record(r.utxos, "utxos"))) {
    const utxo = deserializeUtxo(value, `utxo ${key}`);
    if (utxo.height > maximumHeight) throw new Error("UTXO above indexed tip");
    s.utxos[key] = utxo;
  }
  for (const [address, value] of Object.entries(record(r.balances, "balances"))) {
    s.balances[address] = parseSats(value, `balance ${address}`);
  }
  for (const [address, entries] of Object.entries(record(r.history, "history"))) {
    if (!Array.isArray(entries)) throw new Error("history must contain arrays");
    s.history[address] = entries.map((entry) => {
      const value = record(entry, "history entry");
      if (value.direction !== "in" && value.direction !== "out") throw new Error("invalid history direction");
      const height = counter(value.height, "history height");
      if (height > maximumHeight) throw new Error("history above indexed tip");
      return { txid: text(value.txid, "history txid"), height, direction: value.direction,
        amountSats: parseSats(value.amountSats, `history ${address}.amountSats`) };
    });
  }
  for (const [key, value] of Object.entries(record(r.undo, "undo"))) {
    const height = heightKey(key);
    const undo = record(value, `undo ${key}`);
    const hash = text(undo.hash, "undo hash");
    if (counter(undo.height, "undo height") !== height || s.chain[height] !== hash) throw new Error("undo does not match indexed chain");
    if (!Array.isArray(undo.created) || !Array.isArray(undo.spent)) throw new Error("invalid undo arrays");
    const deltas: Record<string, bigint> = Object.create(null);
    for (const [address, delta] of Object.entries(record(undo.deltas, "undo deltas"))) {
      deltas[address] = parseSignedSats(delta, `undo ${key} delta ${address}`);
    }
    s.undo[height] = { height, hash, created: undo.created.map((entry) => text(entry, "created key")),
      spent: undo.spent.map((entry) => {
        const spent = record(entry, "spent entry");
        return { key: text(spent.key, "spent key"), utxo: deserializeUtxo(spent.utxo, "spent utxo") };
      }), deltas };
  }
  return s;
}

export class JsonStore implements IndexStore {
  state: StoreState;
  // Address -> dense UTXO-key array and positions, maintained in O(1).
  // Pages are O(page size); swap-removal is safe because cursors bind a revision.
  // The previous Set required scanning all preceding keys for an offset page.
  // The derived index is maintained
  // incrementally alongside `state.utxos` (applyBlock / rollbackBlock).
  // NOT part of `StoreState` / the persisted format — it is fully derivable
  // from `state.utxos` and is rebuilt from it on every load, so this adds
  // no on-disk compatibility surface.
  private readonly utxosByAddress = new Map<string, { keys: string[]; positions: Map<string, number> }>();
  private readonly generation = randomUUID();
  private revision = 0n;
  private persistedSnapshot: string | null = null;
  // T-7 fix: false iff the state file existed but failed to parse/load.
  private loadOk = true;

  private constructor(
    private readonly filePath: string,
    private readonly encodeAddress: (scriptPubkeyHex: string) => string,
    state: StoreState,
  ) {
    this.state = state;
    for (const [key, utxo] of Object.entries(state.utxos)) {
      this.indexUtxo(key, utxo.address);
    }
  }

  private indexUtxo(key: string, address: string): void {
    let index = this.utxosByAddress.get(address);
    if (!index) {
      index = { keys: [], positions: new Map() };
      this.utxosByAddress.set(address, index);
    }
    if (index.positions.has(key)) return;
    index.positions.set(key, index.keys.length);
    index.keys.push(key);
  }

  private unindexUtxo(key: string, address: string): void {
    const index = this.utxosByAddress.get(address);
    const position = index?.positions.get(key);
    if (!index || position === undefined) return;
    const last = index.keys.pop()!;
    index.positions.delete(key);
    if (position < index.keys.length) {
      index.keys[position] = last;
      index.positions.set(last, position);
    }
    if (index.keys.length === 0) this.utxosByAddress.delete(address);
  }

  getSnapshotId(): string {
    return `${this.generation}:${this.revision}`;
  }

  getUtxoCount(address: string): number {
    return this.utxosByAddress.get(address)?.keys.length ?? 0;
  }

  getUtxoPage(address: string, offset: number, limit: number): Array<{ key: string; utxo: Utxo }> {
    const keys = this.utxosByAddress.get(address)?.keys ?? [];
    return keys.slice(offset, offset + limit).map((key) => ({ key, utxo: this.state.utxos[key]! }));
  }

  getHistoryPage(address: string, offset: number, limit: number): HistoryEntry[] {
    return this.getHistory(address).slice(offset, offset + limit);
  }

  indexOk(): boolean {
    return this.loadOk;
  }

  static open(
    filePath: string,
    encodeAddress: (scriptPubkeyHex: string) => string,
  ): JsonStore {
    let state = emptyState();
    let loadOk = true;
    if (existsSync(filePath)) {
      try {
        // parseJsonExactIntegers, not plain JSON.parse: a state file written by
        // the old number-typed build can hold amounts above 2^53, and those must
        // be read from their raw digits rather than through a double.
        state = deserializeState(parseJsonExactIntegers(readFileSync(filePath, "utf8")));
      } catch (e) {
        // T-7 fix: this used to silently fall back to an empty state that
        // is indistinguishable, over the API, from a genuinely empty chain
        // — "a silently discarded index looks identical to an empty chain".
        // Still start from empty state (refusing to start at all would turn
        // one corrupt file into a full outage), but the store now KNOWS and
        // REPORTS (`indexOk()`) that its answers are not authoritative,
        // instead of confidently serving zero balances for every address.
        console.error(
          `[bloch-indexer] state file ${filePath} unreadable (${e instanceof Error ? e.message : String(e)}); starting from empty state — indexOk() will report false`,
        );
        state = emptyState();
        loadOk = false;
      }
    }
    const store = new JsonStore(filePath, encodeAddress, state);
    store.loadOk = loadOk;
    return store;
  }

  /** In-memory only, for tests. */
  static ephemeral(encodeAddress: (scriptPubkeyHex: string) => string): JsonStore {
    return new JsonStore("", encodeAddress, emptyState());
  }

  getTip(): Tip | null {
    return this.state.indexedTip;
  }

  getChainHashAt(height: number): string | undefined {
    // T-1 fix: `Object.hasOwn` first — belt-and-suspenders alongside the
    // null-prototype maps (see emptyState's comment): even if some future
    // caller reconstructs `chain` as an ordinary `{}`, a lookup here can
    // never resolve to an inherited (non-own) property.
    return Object.hasOwn(this.state.chain, height) ? this.state.chain[height] : undefined;
  }

  getUtxo(txid: string, index: number): Utxo | undefined {
    const key = `${txid}:${index}`;
    return Object.hasOwn(this.state.utxos, key) ? this.state.utxos[key] : undefined;
  }

  private addHistory(address: string, entry: HistoryEntry): void {
    (this.state.history[address] ??= []).push(entry);
  }

  private bump(deltas: Record<string, bigint>, address: string, amount: bigint): void {
    this.state.balances[address] = (this.state.balances[address] ?? 0n) + amount;
    deltas[address] = (deltas[address] ?? 0n) + amount;
  }

  // T-2 fix (audit finding): `applyBlock` is now two-phase.
  //
  // PHASE 1 (plan) touches `this.state` READ-ONLY and does everything that
  // can throw (`this.encodeAddress`, previously — see below, no longer
  // throws either, but the phase split is kept as the structural guarantee
  // regardless of what a future `encodeAddress` implementation does).
  // PHASE 2 (apply) replays the plan; nothing in it can throw (delete /
  // assign / bigint arithmetic / array push on already-validated data).
  //
  // Before this fix the two were interleaved: `delete this.state.utxos[key]`
  // and `this.bump(...)` ran DURING the same loop that could throw on a
  // later output (`this.encodeAddress` rejects any non-P2PKH-shaped
  // `script_pubkey`). A throw left the store with partially-applied
  // balances, spent UTXOs deleted, and history written — but with NEITHER
  // `chain[height]` NOR an undo record, so nothing could roll it back, and
  // the linkage guard in `indexer.ts` would not stop `applyBlock` from
  // running the SAME height again from scratch on the next poll — silently
  // re-crediting every already-applied output, forever.
  applyBlock(height: number, hash: string, txs: import("./rpc.js").Tx[]): void {
    if (this.state.chain[height] !== undefined) {
      throw new Error(`refusing to apply height ${height}: already indexed (should roll back first)`);
    }

    if (!Number.isSafeInteger(this.state.blocksApplied + 1)) throw new Error("blocksApplied counter exhausted");

    type PlannedSpend = { kind: "spend"; key: string; utxo: Utxo; txid: string; restoreOnUndo: boolean };
    type PlannedCreate = { kind: "create"; key: string; address: string; value: bigint; txid: string };
    const plan: Array<PlannedSpend | PlannedCreate> = [];

    // The overlay models preceding transactions in this block without touching
    // committed state. A null entry is a spend tombstone, not a missing lookup.
    const overlay = new Map<string, Utxo | null>();
    const consumed = new Set<string>();
    const created = new Set<string>();

    // PHASE 1 — plan against the overlay; committed state stays unchanged.
    for (const tx of txs) {
      if (!tx.coinbase) {
        for (const inp of tx.inputs) {
          const key = `${inp.prev_txid}:${inp.prev_index}`;
          if (consumed.has(key)) throw new Error(`duplicate spend of outpoint ${key} in block ${height}`);
          consumed.add(key);
          const utxo = overlay.has(key) ? overlay.get(key)
            : Object.hasOwn(this.state.utxos, key) ? this.state.utxos[key] : undefined;
          overlay.set(key, null);
          if (!utxo) continue; // preserve compatibility for inputs outside indexed history
          plan.push({ kind: "spend", key, utxo, txid: tx.txid, restoreOnUndo: !created.has(key) });
        }
      }
      for (const out of tx.outputs) {
        const key = `${tx.txid}:${out.index}`;
        if (created.has(key) || Object.hasOwn(this.state.utxos, key)) {
          throw new Error(`duplicate created outpoint ${key} in block ${height}`);
        }
        if (consumed.has(key)) throw new Error(`outpoint ${key} is spent before creation in block ${height}`);
        if (typeof out.value !== "bigint" || out.value < 0n) {
          throw new Error(`invalid value for outpoint ${key}`);
        }
        // T-2 fix: an unrecognised script_pubkey (anything not exactly
        // 20 bytes — an OP_RETURN-style output, an eUVM validator output,
        // an empty script, an RPC schema change) used to make
        // `encodeAddress` throw and abort the WHOLE block mid-application.
        // Indexing a synthetic address instead means one non-P2PKH output
        // degrades gracefully (that output is tracked under an address no
        // real key can ever produce) instead of either corrupting the store
        // (the old interleaved behaviour) or permanently wedging indexing
        // at this exact height (a purely two-phase fix with a still-
        // throwing encodeAddress would retry-and-fail this same height
        // forever, since the block's content does not change between polls).
        let address: string;
        try {
          address = this.encodeAddress(out.script_pubkey);
        } catch (e) {
          address = `unknown:${out.script_pubkey}`;
          console.error(
            `[bloch-indexer] height ${height} tx ${tx.txid} output ${out.index}: ` +
              `unrecognised script_pubkey (${e instanceof Error ? e.message : String(e)}); ` +
              `indexed as ${address}`,
          );
        }
        created.add(key);
        overlay.set(key, { address, value: out.value, height });
        plan.push({ kind: "create", key, address, value: out.value, txid: tx.txid });
      }
    }

    // PHASE 2 — apply. Every value here was already validated in phase 1.
    const undo: UndoRecord = { height, hash, created: [], spent: [], deltas: Object.create(null) };
    for (const op of plan) {
      if (op.kind === "spend") {
        // A same-block intermediate output did not exist before this block.
        // Restoring it on rollback would create an unbacked UTXO.
        if (op.restoreOnUndo) undo.spent.push({ key: op.key, utxo: op.utxo });
        delete this.state.utxos[op.key];
        this.unindexUtxo(op.key, op.utxo.address); // T-8: keep the secondary index in sync
        this.bump(undo.deltas, op.utxo.address, -op.utxo.value);
        this.addHistory(op.utxo.address, { txid: op.txid, height, direction: "out", amountSats: op.utxo.value });
      } else {
        this.state.utxos[op.key] = { address: op.address, value: op.value, height };
        this.indexUtxo(op.key, op.address); // T-8: keep the secondary index in sync
        undo.created.push(op.key);
        this.bump(undo.deltas, op.address, op.value);
        this.addHistory(op.address, { txid: op.txid, height, direction: "in", amountSats: op.value });
      }
    }

    this.state.chain[height] = hash;
    this.state.undo[height] = undo;
    this.state.indexedTip = { height, hash };
    this.state.blocksApplied += 1;
    this.revision += 1n;
  }

  /** Reverse exactly one block using its undo record. */
  private rollbackBlock(height: number): void {
    const undo = this.state.undo[height];
    if (!undo) throw new Error(`no undo record for height ${height}`);
    const affected = new Set<string>();

    // Delete UTXOs this block created.
    for (const key of undo.created) {
      const utxo = this.state.utxos[key];
      delete this.state.utxos[key];
      if (utxo) this.unindexUtxo(key, utxo.address); // T-8: keep the secondary index in sync
    }
    // Restore UTXOs this block spent.
    for (const { key, utxo } of undo.spent) {
      this.state.utxos[key] = utxo;
      this.indexUtxo(key, utxo.address); // T-8: keep the secondary index in sync
    }
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
    this.revision += 1n;
  }

  /** Roll back every block ABOVE forkHeight (keep heights <= forkHeight). */
  rollbackTo(forkHeight: number): void {
    const tip = this.state.indexedTip;
    if (!tip) return;
    if (!Number.isSafeInteger(forkHeight) || forkHeight < -1 || forkHeight > tip.height) throw new Error("invalid rollback height");
    if (!Number.isSafeInteger(this.state.reorgsHandled + 1)
        || !Number.isSafeInteger(this.state.blocksRolledBack + tip.height - forkHeight)) {
      throw new Error("rollback counter exhausted");
    }
    for (let h = tip.height; h > forkHeight; h--) {
      if (this.state.chain[h] !== undefined && !Object.hasOwn(this.state.undo, h)) {
        throw new Error(`no undo record for height ${h}`);
      }
    }
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
    this.revision += 1n;
  }

  getBalance(address: string): bigint {
    // T-1 fix: see getChainHashAt's comment. `address` reaches here straight
    // from an HTTP path segment (api.ts).
    const v = Object.hasOwn(this.state.balances, address) ? this.state.balances[address] : undefined;
    return v ?? 0n;
  }

  getUtxosForAddress(address: string): Array<{ key: string; utxo: Utxo }> {
    // T-8 fix (audit finding): this used to iterate EVERY utxo in the store
    // on every call — a cheap unauthenticated CPU DoS against
    // `/address/:addr/utxos` and `/address/:addr/balance` (which calls this
    // too, for `utxoCount`) once the UTXO set is realistically large. The
    // secondary `utxosByAddress` index turns this compatibility helper into an O(this address's
    // own UTXO count) lookup, maintained incrementally in applyBlock /
    // rollbackBlock rather than rebuilt per request.
    return this.getUtxoPage(address, 0, this.getUtxoCount(address));
  }

  getHistory(address: string): HistoryEntry[] {
    // T-1 fix: this is the exact site the finding's PoC hits
    // (`GET /address/__proto__/history`) — see getChainHashAt's comment.
    const v = Object.hasOwn(this.state.history, address) ? this.state.history[address] : undefined;
    return v ?? [];
  }

  persist(): void {
    if (!this.filePath) return;
    if (!this.loadOk) throw new Error("refusing to overwrite an unreadable index snapshot");
    // Mutations must use applyBlock/rollbackTo; state is exposed for inspection.
    const snapshot = this.getSnapshotId();
    if (snapshot === this.persistedSnapshot) return; // polling without changes must not rewrite the index
    mkdirSync(dirname(this.filePath), { recursive: true });
    const bytes = JSON.stringify(serializeState(this.state));
    const tmpPath = `${this.filePath}.tmp-${randomUUID()}`;
    let fd: number | undefined;
    try {
      fd = openSync(tmpPath, "wx", 0o600);
      writeFileSync(fd, bytes);
      fsyncSync(fd);
      closeSync(fd);
      fd = undefined;
      renameSync(tmpPath, this.filePath);
      const directory = openSync(dirname(this.filePath), "r");
      try { fsyncSync(directory); } finally { closeSync(directory); }
      this.persistedSnapshot = snapshot;
    } finally {
      if (fd !== undefined) closeSync(fd);
      if (existsSync(tmpPath)) unlinkSync(tmpPath);
    }
  }
}
