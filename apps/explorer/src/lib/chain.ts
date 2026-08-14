// SPDX-License-Identifier: AGPL-3.0-or-later
import { rpc } from "./rpc";
import { toSats } from "./format";
import type { DagBlock } from "../components/dag";

/**
 * Genesis-1 carry-over opening balances, baked into Genesis-3 at height 0.
 *
 * `getsupplydistribution` walks the live UTXO set and does NOT see these — the
 * snapshot is loaded separately at genesis (see `CARRYOVER_TOTAL_SAT` /
 * `CARRYOVER_UTXO_COUNT` in `crates/bloch-crypto/src/core/mod.rs`). Reporting the
 * RPC figure on its own understates total supply by this whole amount, so every
 * supply readout must add it back.
 */
export const CARRYOVER_TOTAL_SAT = 347_544_120_000_000_000n; // 3,475,441,200 BLOCH
export const CARRYOVER_UTXO_COUNT = 413_743;

/**
 * Total supply = UTXO-set supply reported by the RPC + the carry-over set.
 *
 * Accepts the decimal-string wire form (RPC-V4 R3) and the legacy bare number;
 * the whole computation stays in bigint because this figure is the one most
 * certain to exceed 2^53 sat (Genesis-4 supply is 1e19 sat, ~1110x that).
 */
export function totalSupplySat(rpcTotalSats: number | string | bigint | undefined): bigint {
  return toSats(rpcTotalSats) + CARRYOVER_TOTAL_SAT;
}

export interface NetworkInfo {
  blocks: number;
  blue_score: number;
  peers: number;
  mempool: number;
  syncing: boolean;
  chain: string;
  version: string;
  network: string;
}

export interface DagInfo {
  tip: string | null;
  tip_blue_score: number;
  tip_height: number;
  block_count: number;
  tip_count: number;
  tips: string[];
  chain_length: number;
  k: number;
}

// Fetch a DAG window: the selected-chain backbone over the last `depth` heights
// PLUS every current tip. A tip that has a block BODY renders as a real coloured
// branch; a header-only tip (body never arrived — common while the chain is
// stalled) has no getblock data, so it becomes a "ghost tip" we still surface as
// a labelled fan. Each real entry carries parents + blue_score for edge drawing.
export async function fetchDagWindow(depth: number): Promise<{
  blocks: DagBlock[];
  tips: Set<string>;
  ghostTips: string[];
  selectedTip: string | null;
  dag: DagInfo;
}> {
  const dag = await rpc<DagInfo>("getdaginfo", []);
  const tipHeight = dag.tip_height || 0;
  const startH = Math.max(0, tipHeight - depth + 1);

  const heightCalls: Promise<any>[] = [];
  for (let h = startH; h <= tipHeight; h++) heightCalls.push(rpc("getblockbyheight", [h, false]).catch(() => null));

  // cap tips fetched to keep it snappy
  const tipHashes = (dag.tips || []).slice(0, 60);
  const tipCalls = tipHashes.map((h) => rpc("getblock", [h, false]).catch(() => null));

  const [backbone, tipBlocks] = await Promise.all([Promise.all(heightCalls), Promise.all(tipCalls)]);

  const byHash = new Map<string, DagBlock>();
  const bodied = (b: any) => b && b.hash && !b.error;
  const add = (b: any) => {
    if (!bodied(b)) return;
    byHash.set(b.hash, {
      hash: b.hash,
      height: b.height,
      blue_score: b.blue_score ?? 0,
      parents: Array.isArray(b.parents) ? b.parents : [],
      timestamp: b.timestamp ?? 0,
    });
  };
  backbone.forEach(add);
  tipBlocks.forEach(add);

  // tips whose body is present are real branches; the rest are ghosts.
  const bodiedTipSet = new Set<string>();
  tipBlocks.forEach((b, i) => {
    if (bodied(b)) bodiedTipSet.add(tipHashes[i]);
  });
  const ghostTips = tipHashes.filter((h) => !bodiedTipSet.has(h));

  // Selected tip to highlight gold: prefer the DAG's own selected tip if it has
  // a body; otherwise the highest-height bodied block we rendered (the bodied
  // selected-chain tip).
  let selectedTip: string | null = dag.tip && byHash.has(dag.tip) ? dag.tip : null;
  if (!selectedTip && byHash.size) {
    selectedTip = [...byHash.values()].sort((a, b) => b.height - a.height || b.blue_score - a.blue_score)[0].hash;
  }

  return {
    blocks: [...byHash.values()],
    tips: bodiedTipSet,
    ghostTips,
    selectedTip,
    dag,
  };
}

// A block whose freshest tip timestamp is older than this is treated as quiet
// (no recent production) while the chain is still below the halt height.
export const STALL_THRESHOLD_SECS = 20 * 60;

/**
 * The height Genesis-3 actually ended at.
 *
 * The rule was written for 50,000 and the chain was stopped at 39,918 instead:
 * hashrate was falling and waiting out 10,082 more blocks bought nothing the
 * snapshot did not already have. The terminal state was taken here, verified on
 * two independent nodes, and carried into Genesis-4 — so this, not 50,000, is
 * the number every balance in the carryover was measured at.
 *
 * Reaching it was the PLAN, not a failure — the UI must never present it as an
 * error state.
 */
export const HALT_HEIGHT = 39_918;

/** Poll cadence once the chain is complete: history doesn't change every 15 s. */
export const COMPLETE_POLL_MS = 10 * 60 * 1000;

/**
 * The three presentation states of the chain:
 *   producing — blocks are arriving, height below the halt
 *   quiet     — below the halt but nothing recent (factual, amber, not red)
 *   complete  — tip reached HALT_HEIGHT: Genesis-3 finished as designed
 */
export type ChainPhase = "producing" | "quiet" | "complete";

export function chainPhase(tipHeight: number, freshestTs: number): ChainPhase {
  if (tipHeight >= HALT_HEIGHT) return "complete";
  const age = freshestTs ? Date.now() / 1000 - freshestTs : Infinity;
  return age > STALL_THRESHOLD_SECS ? "quiet" : "producing";
}

// Sticky "Genesis-3 is complete" flag so every page (even ones that don't fetch
// a tip height) can start on the slow poll after a reload. localStorage is a
// cache, never the source of truth — the RPC tip height is.
const COMPLETE_LS_KEY = "bloch:g3:complete";

export function isChainComplete(): boolean {
  try {
    return localStorage.getItem(COMPLETE_LS_KEY) === "1";
  } catch {
    return false;
  }
}

/** Record an observed tip height; marks the chain complete once ≥ HALT_HEIGHT. */
export function noteTipHeight(h: number | null | undefined): void {
  if (typeof h === "number" && isFinite(h) && h >= HALT_HEIGHT) {
    try {
      localStorage.setItem(COMPLETE_LS_KEY, "1");
    } catch {
      /* private mode etc. — polling just stays fast */
    }
  }
}
