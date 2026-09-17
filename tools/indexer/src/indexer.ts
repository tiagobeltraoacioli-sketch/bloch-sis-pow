// SPDX-License-Identifier: MIT OR Apache-2.0
// Stage a bounded, linked batch before mutating indexed balances. RPC reads are
// not an atomic chain snapshot; observed branch shifts defer the pass unchanged.
// A reorg after the final observation is detected on a subsequent pass.
import { setTimeout as sleep } from "node:timers/promises";
import type { Block, RpcClient } from "./rpc.js";
import type { IndexStore } from "./store.js";

export interface SyncResult {
  reorgDetected: boolean;
  forkHeight: number | null;
  rolledBack: number;
  applied: number;
  tipHeight: number | null;
}
export const MAX_BLOCKS_PER_PASS = 16;
export const MAX_FORK_SEARCH = 2048;
export const DEFAULT_SYNC_TIMEOUT_MS = 30_000;

// Abort each pending read as well as the overall pass. A transport ignoring the
// signal may finish later, but its result cannot resume this pass or publish it.
async function readWithAbort<T>(signal: AbortSignal, read: () => Promise<T>, check: () => void): Promise<T> {
  check();
  let onAbort: () => void = () => {};
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    const result = await Promise.race([read(), aborted]);
    check();
    return result;
  } finally { signal.removeEventListener("abort", onAbort); }
}

export class Indexer {
  private running: Promise<SyncResult> | undefined;
  constructor(
    private readonly rpc: RpcClient,
    private readonly store: IndexStore,
    private readonly log: (msg: string) => void = () => {},
    private readonly timeoutMs = DEFAULT_SYNC_TIMEOUT_MS,
  ) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) {
      throw new Error("sync timeout must be an integer from 1 through 300000 ms");
    }
  }

  /** Concurrent callers share one pass; they must not interleave mutations. */
  syncOnce(stop?: AbortSignal): Promise<SyncResult> {
    if (!this.running) {
      const deadline = new AbortController();
      const expiresAt = performance.now() + this.timeoutMs;
      const expire = () => deadline.abort(new Error("index sync deadline exceeded"));
      const timer = setTimeout(expire, this.timeoutMs);
      const signal = stop ? AbortSignal.any([stop, deadline.signal]) : deadline.signal;
      const check = () => {
        // Timers cannot run while parsing blocks the event loop. Check elapsed
        // monotonic time too, so a late synchronous read cannot publish anyway.
        if (performance.now() >= expiresAt && !deadline.signal.aborted) expire();
        signal.throwIfAborted();
      };
      this.running = this.syncPass(signal, check).finally(() => {
        clearTimeout(timer);
        this.running = undefined;
      });
    }
    return this.running;
  }

  private async syncPass(signal: AbortSignal, check: () => void): Promise<SyncResult> {
    check();
    const hashAt = (height: number) => readWithAbort(signal, () => this.rpc.getBlockHash(height, signal), check);
    const blockAt = (height: number) => readWithAbort(signal, () => this.rpc.getBlockByHeight(height, signal), check);
    if (!this.store.indexOk()) throw new Error("refusing to sync an unreadable index snapshot");
    // Stop collecting early enough to reserve most of the RPC deadline for
    // anchor/tip rechecks. Slow but responsive sources can publish short batches.
    const collectUntil = performance.now() + this.timeoutMs / 3;
    const revision = this.store.getSnapshotId();
    const tip = this.store.getTip();
    let fork = tip?.height ?? -1;
    let reorgDetected = false;
    const rolledBackBefore = this.store.state.blocksRolledBack;
    const appliedBefore = this.store.state.blocksApplied;
    if (tip && await hashAt(tip.height) !== tip.hash) {
      reorgDetected = true;
      let searched = 0;
      for (fork = tip.height - 1; fork >= 0; fork--) {
        if (++searched > MAX_FORK_SEARCH) {
          throw new Error("reorg exceeds bounded fork search; operator reconciliation required");
        }
        const local = this.store.getChainHashAt(fork);
        if (local !== undefined && await hashAt(fork) === local) break;
      }
    }
    const anchor = fork >= 0 ? this.store.getChainHashAt(fork) : undefined;
    const staged: Block[] = [];
    let previous = anchor;
    let caughtUp = false;
    for (let height = fork + 1; staged.length < MAX_BLOCKS_PER_PASS; height++) {
      if (staged.length > 0 && performance.now() >= collectUntil) break;
      const block = await blockAt(height);
      if (!block) { caughtUp = true; break; }
      if (block.height !== height) {
        throw new Error(`RPC returned height ${block.height} for requested height ${height}`);
      }
      if (previous !== undefined && !block.parents.includes(previous)) {
        throw new Error(`RPC branch linkage changed at height ${height}; pass deferred`);
      }
      if (await hashAt(height) !== block.hash) {
        throw new Error(`RPC height hash changed at height ${height}; pass deferred`);
      }
      staged.push(block);
      previous = block.hash;
    }
    // Recheck both ends after fetching bodies. No balances have changed yet.
    if (anchor !== undefined && await hashAt(fork) !== anchor) {
      throw new Error("RPC fork anchor changed during sync; pass deferred");
    }
    const last = staged[staged.length - 1];
    if (last && await hashAt(last.height) !== last.hash) {
      throw new Error("RPC batch tip changed during sync; pass deferred");
    }
    if (caughtUp && !last && await hashAt(fork + 1) !== null) {
      throw new Error("RPC height/body disagreement; pass deferred");
    }
    check();
    if (this.store.getSnapshotId() !== revision) {
      throw new Error("index changed during RPC reads; pass deferred");
    }
    // No awaits inside publication: HTTP readers cannot observe a half-applied
    // batch. A malformed block can still fail store validation, leaving an
    // earlier prefix; persist that prefix before propagating the failure.
    try {
      if (reorgDetected) {
        this.log(`reorg: rolling back to checked fork height ${fork}`);
        this.store.rollbackTo(fork);
      }
      for (const block of staged) this.store.applyBlock(block.height, block.hash, block.transactions);
    } finally { this.store.persist(); }
    return {
      reorgDetected,
      forkHeight: reorgDetected ? fork : null,
      rolledBack: this.store.state.blocksRolledBack - rolledBackBefore,
      applied: this.store.state.blocksApplied - appliedBefore,
      tipHeight: this.store.getTip()?.height ?? null,
    };
  }

  /** Run forever, polling every pollMs. */
  async run(pollMs: number, stop?: () => boolean, signal?: AbortSignal): Promise<void> {
    for (;;) {
      if (signal?.aborted || stop?.()) return;
      try {
        const r = await this.syncOnce(signal);
        if (r.reorgDetected) {
          this.log(`REORG handled: fork=${r.forkHeight} rolledBack=${r.rolledBack} reapplied=${r.applied} tip=${r.tipHeight}`);
        } else if (r.applied > 0) {
          this.log(`applied ${r.applied} block(s); tip=${r.tipHeight}`);
        }
      } catch (e) {
        if (signal?.aborted) return;
        this.log(`sync error: ${e instanceof Error ? e.message : String(e)}`);
      }
      try { await sleep(pollMs, undefined, { signal }); }
      catch (error) { if (signal?.aborted) return; throw error; }
    }
  }
}
