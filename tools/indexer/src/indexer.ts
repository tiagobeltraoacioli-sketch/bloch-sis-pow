// SPDX-License-Identifier: MIT OR Apache-2.0
// Reorg-safe sync loop.
//
// The invariant we maintain: our applied `chain[height] -> hash` must always be
// a prefix of the node's current selected chain. Each tick:
//
//   1. DETECT: if we have a tip, re-fetch the node's hash at our tip height. If
//      it differs, a reorg replaced blocks at or below our tip. Walk backwards
//      comparing our stored hash vs the node's hash at each height until they
//      agree — that agreement height is the fork point.
//   2. ROLLBACK: undo every block above the fork point (store.rollbackTo), which
//      deletes the UTXOs those blocks created, restores the UTXOs they spent,
//      and drops their address-history entries. Address balances/history are now
//      correct as of the fork point.
//   3. RE-APPLY: walk forward from fork point + 1, fetching each block by height
//      (verbose) and applying it, until the node has no block at the next height.
//
// This is exactly the fix called out in the roadmap (§2.1 / Phase 0): the
// existing address-history indexer does NOT roll back on reorg; this one does.

import type { RpcClient } from "./rpc.js";
import type { IndexStore } from "./store.js";

export interface SyncResult {
  reorgDetected: boolean;
  forkHeight: number | null;
  rolledBack: number;
  applied: number;
  tipHeight: number | null;
}

export class Indexer {
  constructor(
    private readonly rpc: RpcClient,
    private readonly store: IndexStore,
    private readonly log: (msg: string) => void = () => {},
  ) {}

  /** One reorg-safe sync pass. Returns what happened this tick. */
  async syncOnce(): Promise<SyncResult> {
    let reorgDetected = false;
    let forkHeight: number | null = null;
    const rolledBackBefore = this.store.state.blocksRolledBack;
    const appliedBefore = this.store.state.blocksApplied;

    // ── 1 + 2: detect + roll back ────────────────────────────────────────────
    const tip = this.store.getTip();
    if (tip) {
      const nodeHashAtTip = await this.rpc.getBlockHash(tip.height);
      if (nodeHashAtTip === null || nodeHashAtTip !== tip.hash) {
        reorgDetected = true;
        // Walk back to find the fork point (deepest height where hashes agree).
        let fork = tip.height - 1;
        for (; fork >= 0; fork--) {
          const localHash = this.store.getChainHashAt(fork);
          const nodeHash = await this.rpc.getBlockHash(fork);
          if (localHash !== undefined && nodeHash !== null && nodeHash === localHash) break;
        }
        forkHeight = fork; // may be -1 (whole chain replaced)
        this.log(
          `reorg: node hash at tip height ${tip.height} changed; rolling back to fork height ${fork}`,
        );
        this.store.rollbackTo(fork);
      }
    }

    // ── 3: re-apply / extend forward ─────────────────────────────────────────
    const startTip = this.store.getTip();
    let nextHeight = startTip ? startTip.height + 1 : 0;
    for (;;) {
      const block = await this.rpc.getBlockByHeight(nextHeight);
      if (!block) break; // caught up

      // Linkage guard: if the node's selected chain shifted mid-apply such that
      // this height is already indexed under a different hash, bail and let the
      // next tick's detect/rollback handle it (keeps the prefix invariant).
      const existing = this.store.getChainHashAt(nextHeight);
      if (existing !== undefined) {
        if (existing === block.hash) {
          nextHeight++;
          continue;
        }
        this.log(`linkage shift at height ${nextHeight}; deferring to next tick`);
        break;
      }

      this.store.applyBlock(nextHeight, block.hash, block.transactions);
      nextHeight++;
    }

    this.store.persist();
    const newTip = this.store.getTip();
    return {
      reorgDetected,
      forkHeight,
      rolledBack: this.store.state.blocksRolledBack - rolledBackBefore,
      applied: this.store.state.blocksApplied - appliedBefore,
      tipHeight: newTip ? newTip.height : null,
    };
  }

  /** Run forever, polling every `pollMs`. */
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
