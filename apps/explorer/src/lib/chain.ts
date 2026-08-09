import { rpc } from "./rpc";
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

/** Total supply = UTXO-set supply reported by the RPC + the carry-over set. */
export function totalSupplySat(rpcTotalSats: number | string | bigint | undefined): bigint {
  let live: bigint;
  try {
    live = BigInt(typeof rpcTotalSats === "number" ? Math.round(rpcTotalSats) : (rpcTotalSats ?? 0));
  } catch {
    live = 0n;
  }
  return live + CARRYOVER_TOTAL_SAT;
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

// A block whose freshest tip timestamp is older than this is treated as stalled.
export const STALL_THRESHOLD_SECS = 20 * 60;
