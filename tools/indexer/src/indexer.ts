// SPDX-License-Identifier: MIT OR Apache-2.0
// Stage a bounded, linked batch before mutating indexed balances. RPC reads are
// not an atomic chain snapshot; observed branch shifts defer the pass unchanged.
// A reorg after the final observation is detected on a subsequent pass.
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

export class Indexer {
  private running: Promise<SyncResult> | undefined;
  constructor(
    private readonly rpc: RpcClient,
    private readonly store: IndexStore,
    private readonly log: (msg: string) => void = () => {},
  ) {}

  /** Concurrent callers share one pass; they must not interleave mutations. */
  syncOnce(): Promise<SyncResult> {
    if (!this.running) {
      this.running = this.syncPass().finally(() => { this.running = undefined; });
    }
    return this.running;
  }

  private async syncPass(): Promise<SyncResult> {
    if (!this.store.indexOk()) throw new Error("refusing to sync an unreadable index snapshot");
    const revision = this.store.getSnapshotId();
    const tip = this.store.getTip();
    let fork = tip?.height ?? -1;
    let reorgDetected = false;
    const rolledBackBefore = this.store.state.blocksRolledBack;
    const appliedBefore = this.store.state.blocksApplied;
    if (tip && await this.rpc.getBlockHash(tip.height) !== tip.hash) {
      reorgDetected = true;
      let searched = 0;
      for (fork = tip.height - 1; fork >= 0; fork--) {
        if (++searched > MAX_FORK_SEARCH) {
          throw new Error("reorg exceeds bounded fork search; operator reconciliation required");
        }
        const local = this.store.getChainHashAt(fork);
        if (local !== undefined && await this.rpc.getBlockHash(fork) === local) break;
      }
    }
    const anchor = fork >= 0 ? this.store.getChainHashAt(fork) : undefined;
    const staged: Block[] = [];
    let previous = anchor;
    let caughtUp = false;
    for (let height = fork + 1; staged.length < MAX_BLOCKS_PER_PASS; height++) {
      const block = await this.rpc.getBlockByHeight(height);
      if (!block) { caughtUp = true; break; }
      if (block.height !== height) {
        throw new Error(`RPC returned height ${block.height} for requested height ${height}`);
      }
      if (previous !== undefined && !block.parents.includes(previous)) {
        throw new Error(`RPC branch linkage changed at height ${height}; pass deferred`);
      }
      if (await this.rpc.getBlockHash(height) !== block.hash) {
        throw new Error(`RPC height hash changed at height ${height}; pass deferred`);
      }
      staged.push(block);
      previous = block.hash;
    }
    // Recheck both ends after fetching bodies. No balances have changed yet.
    if (anchor !== undefined && await this.rpc.getBlockHash(fork) !== anchor) {
      throw new Error("RPC fork anchor changed during sync; pass deferred");
    }
    const last = staged[staged.length - 1];
    if (last && await this.rpc.getBlockHash(last.height) !== last.hash) {
      throw new Error("RPC batch tip changed during sync; pass deferred");
    }
    if (caughtUp && !last && await this.rpc.getBlockHash(fork + 1) !== null) {
      throw new Error("RPC height/body disagreement; pass deferred");
    }
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
  async run(pollMs: number, stop?: () => boolean): Promise<void> {
    for (;;) {
      if (stop?.()) return;
      try {
        const r = await this.syncOnce();
        if (r.reorgDetected) {
          this.log(`REORG handled: fork=${r.forkHeight} rolledBack=${r.rolledBack} reapplied=${r.applied} tip=${r.tipHeight}`);
        } else if (r.applied > 0) {
          this.log(`applied ${r.applied} block(s); tip=${r.tipHeight}`);
        }
      } catch (e) {
        this.log(`sync error: ${e instanceof Error ? e.message : String(e)}`);
      }
      await new Promise((res) => setTimeout(res, pollMs));
    }
  }
}
