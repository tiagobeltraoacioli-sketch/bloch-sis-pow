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

import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync } from "node:fs";
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
  // T-1 fix: do not adopt the raw parsed object as-is (it inherits from
  // Object.prototype like any JSON.parse result) — copy its OWN keys onto a
  // null-prototype object instead.
  s.chain = Object.assign(Object.create(null), (r.chain as Record<number, string>) ?? {});

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
  // T-8 fix: address -> Set of "txid:index" utxo keys, maintained
  // incrementally alongside `state.utxos` (applyBlock / rollbackBlock).
  // NOT part of `StoreState` / the persisted format — it is fully derivable
  // from `state.utxos` and is rebuilt from it on every load, so this adds
  // no on-disk compatibility surface.
  private readonly utxosByAddress: Map<string, Set<string>> = new Map();
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
    let set = this.utxosByAddress.get(address);
    if (!set) {
      set = new Set();
      this.utxosByAddress.set(address, set);
    }
    set.add(key);
  }

  private unindexUtxo(key: string, address: string): void {
    const set = this.utxosByAddress.get(address);
    if (!set) return;
    set.delete(key);
    if (set.size === 0) this.utxosByAddress.delete(address);
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

    type PlannedSpend = { kind: "spend"; key: string; utxo: Utxo; txid: string };
    type PlannedCreate = { kind: "create"; key: string; address: string; value: bigint; txid: string };
    const plan: Array<PlannedSpend | PlannedCreate> = [];

    // PHASE 1 — plan. Reads `this.state.utxos` but never mutates anything.
    for (const tx of txs) {
      if (!tx.coinbase) {
        for (const inp of tx.inputs) {
          const key = `${inp.prev_txid}:${inp.prev_index}`;
          const utxo = Object.hasOwn(this.state.utxos, key) ? this.state.utxos[key] : undefined;
          if (!utxo) continue; // input we never indexed (e.g. pre-genesis); skip defensively
          plan.push({ kind: "spend", key, utxo, txid: tx.txid });
        }
      }
      for (const out of tx.outputs) {
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
        plan.push({ kind: "create", key: `${tx.txid}:${out.index}`, address, value: out.value, txid: tx.txid });
      }
    }

    // PHASE 2 — apply. Every value here was already validated in phase 1.
    const undo: UndoRecord = { height, hash, created: [], spent: [], deltas: {} };
    for (const op of plan) {
      if (op.kind === "spend") {
        undo.spent.push({ key: op.key, utxo: op.utxo });
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
    // secondary `utxosByAddress` index turns this into an O(this address's
    // own UTXO count) lookup, maintained incrementally in applyBlock /
    // rollbackBlock rather than rebuilt per request.
    const keys = this.utxosByAddress.get(address);
    if (!keys) return [];
    const out: Array<{ key: string; utxo: Utxo }> = [];
    for (const key of keys) {
      const utxo = this.state.utxos[key];
      if (utxo) out.push({ key, utxo });
    }
    return out;
  }

  getHistory(address: string): HistoryEntry[] {
    // T-1 fix: this is the exact site the finding's PoC hits
    // (`GET /address/__proto__/history`) — see getChainHashAt's comment.
    const v = Object.hasOwn(this.state.history, address) ? this.state.history[address] : undefined;
    return v ?? [];
  }

  persist(): void {
    if (!this.filePath) return; // ephemeral
    mkdirSync(dirname(this.filePath), { recursive: true });
    // JSON.stringify(this.state) would THROW here: the state holds bigints.
    const bytes = JSON.stringify(serializeState(this.state));
    // T-7 fix (audit finding): write-then-rename instead of a bare
    // writeFileSync onto the live path. A crash or a full disk mid-write
    // used to leave a TRUNCATED file at the real path — which `open()`
    // then reads on next start, hits a JSON parse error, and (before the
    // T-7 `indexOk` fix above) silently substituted an empty state with no
    // externally visible sign the index was gone. `rename(2)` on the same
    // filesystem is atomic: the live path either still holds the last
    // complete write, or holds the new complete write — never a partial
    // one, regardless of when a crash lands.
    const tmpPath = `${this.filePath}.tmp`;
    writeFileSync(tmpPath, bytes);
    renameSync(tmpPath, this.filePath);
  }
}
