// SPDX-License-Identifier: AGPL-3.0-or-later
// Mining data layer — reuses the existing /rpc client + allowlisted read methods.
// Nothing here fabricates data: every number traces to a live RPC response, and
// callers surface a stalled/empty state honestly when the chain isn't advancing.

import { rpc, rpcAllSettled } from "./rpc";
import { addressFromHashHex } from "./sha3";

// The Postern reference pool (Stratum). Bare address as the username — the pool
// rejects `address.worker`, so NEVER append a worker suffix.
export const POOL = {
  host: "stratum.posternpool.com",
  port: 3336,
  stratum: "stratum+tcp://stratum.posternpool.com:3336",
};

export const TARGET_BLOCK_TIME = 30; // seconds (network target)
export const STALL_SECS = 20 * 60;

export interface NetParams {
  networkHs: number;
  difficulty: number;
  blockTimeSecs: number; // effective value used for estimates
  blockTimeSource: "measured" | "target";
  subsidySats: number;
  minerRewardSats: number; // miner's share of the subsidy
  freshestTs: number;
  tipHeight: number; // highest recent block seen (0 when unknown)
  stalled: boolean;
  ok: boolean; // did any live source answer
}

export async function fetchNetParams(): Promise<NetParams> {
  const r = await rpcAllSettled({
    chain: rpc<any>("getchainstats"),
    hash: rpc<any>("gethashrate"),
    pools: rpc<any>("getpools"),
    recent: rpc<any[]>("getrecentblocks", [12]),
  });
  const chain = r.chain || {};
  const hash = r.hash || {};
  const pools = r.pools || {};
  const recent = r.recent || [];

  const networkHs = num(chain.hashrate_hs) || num(hash.hashrate_hs) || 0;
  const difficulty = num(chain.current_difficulty) || num(hash.current_difficulty) || 0;
  // avg_block_time_secs is documented to go wild when the DAG has out-of-order
  // timestamps — clamp to a sane window, else fall back to the network target.
  const measured = num(chain.avg_block_time_secs) || num(hash.avg_block_time_secs) || 0;
  const usable = measured > 0.5 && measured < 3600;
  const blockTimeSecs = usable ? measured : TARGET_BLOCK_TIME;

  const subsidySats = num(pools.subsidy_per_block_sat) || 0;
  const minerRewardSats = num(pools.miner_share_sat) || subsidySats;

  const freshestTs = recent.length ? Math.max(...recent.map((b: any) => num(b.timestamp))) : 0;
  const tipHeight = recent.length ? Math.max(...recent.map((b: any) => num(b.height))) : 0;
  const ageSecs = freshestTs ? Date.now() / 1000 - freshestTs : Infinity;
  const stalled = ageSecs > STALL_SECS;
  const ok = !!(r.chain || r.hash || r.pools || r.recent);

  return {
    networkHs,
    difficulty,
    blockTimeSecs,
    blockTimeSource: usable ? "measured" : "target",
    subsidySats,
    minerRewardSats,
    freshestTs,
    tipHeight,
    stalled,
    ok,
  };
}

// The known protocol pool addresses (validator / oracle / founder). A coinbase
// output paying one of these is NOT the miner's reward — we use this set to pick
// the true miner output when the coinbase splits the subsidy.
export interface PoolAddresses {
  set: Set<string>;
  founder: string | null;
  validator: string | null;
  oracle: string | null;
  minerShareSats: number;
  subsidySats: number;
}

export async function fetchPoolAddresses(): Promise<PoolAddresses> {
  const pools = await rpc<any>("getpools").catch(() => null);
  const p = pools?.pools || {};
  const founder = norm(p.founder?.address);
  const validator = norm(p.validator_pool?.address);
  const oracle = norm(p.oracle_pool?.address);
  const set = new Set<string>();
  [founder, validator, oracle].forEach((a) => a && set.add(a));
  return {
    set,
    founder,
    validator,
    oracle,
    minerShareSats: num(pools?.miner_share_sat),
    subsidySats: num(pools?.subsidy_per_block_sat),
  };
}

export interface MinerBlock {
  hash: string;
  height: number;
  timestamp: number;
  miner: string | null; // derived bloch1q… address of the coinbase miner output
  rewardSats: number; // value of the miner output
  txCount: number;
}

// Scan the most recent bodied blocks and derive each block's miner address from
// its coinbase output(s). Heavy (one getblock/verbose per block) so callers run
// it on demand / at a slow cadence, not on every poll.
export async function scanMinerBlocks(limit: number, pools: PoolAddresses): Promise<MinerBlock[]> {
  const recent = (await rpc<any[]>("getrecentblocks", [Math.min(limit, 50)]).catch(() => [])) || [];
  const detailed = await Promise.all(
    recent.map((b: any) => rpc<any>("getblock", [b.hash, true]).catch(() => null))
  );

  const out: MinerBlock[] = [];
  detailed.forEach((blk: any, i: number) => {
    const meta = recent[i] || {};
    if (!blk || blk.error) {
      out.push({
        hash: meta.hash,
        height: num(meta.height),
        timestamp: num(meta.timestamp),
        miner: null,
        rewardSats: 0,
        txCount: num(meta.tx_count),
      });
      return;
    }
    const txs = blk.transactions || [];
    const cb = txs.find((t: any) => t.coinbase) || txs[0];
    let miner: string | null = null;
    let rewardSats = 0;
    if (cb && Array.isArray(cb.outputs)) {
      const candidates = cb.outputs
        .map((o: any) => ({ addr: addressFromHashHex(o.script_pubkey), value: num(o.value) }))
        .filter((c: any) => !!c.addr) as { addr: string; value: number }[];
      const unknown = candidates.filter((c) => !pools.set.has(c.addr.toLowerCase()));
      const pool = unknown.length ? unknown : candidates;
      const pick = pool.sort((a, b) => b.value - a.value)[0];
      if (pick) {
        miner = pick.addr;
        rewardSats = pick.value;
      }
    }
    out.push({
      hash: blk.hash,
      height: num(blk.height),
      timestamp: num(blk.timestamp),
      miner,
      rewardSats,
      txCount: blk.tx_count ?? txs.length,
    });
  });
  return out;
}

export interface MinerRank {
  miner: string;
  blocks: number;
  rewardSats: number;
  lastHeight: number;
  lastTs: number;
  isFounder: boolean;
  isValidator: boolean;
  isOracle: boolean;
}

export function rankMiners(blocks: MinerBlock[], pools: PoolAddresses): MinerRank[] {
  const map = new Map<string, MinerRank>();
  for (const b of blocks) {
    if (!b.miner) continue;
    const key = b.miner.toLowerCase();
    const cur =
      map.get(key) ||
      ({
        miner: b.miner,
        blocks: 0,
        rewardSats: 0,
        lastHeight: 0,
        lastTs: 0,
        isFounder: key === pools.founder,
        isValidator: key === pools.validator,
        isOracle: key === pools.oracle,
      } as MinerRank);
    cur.blocks += 1;
    cur.rewardSats += b.rewardSats;
    if (b.height >= cur.lastHeight) {
      cur.lastHeight = b.height;
      cur.lastTs = b.timestamp;
    }
    map.set(key, cur);
  }
  return [...map.values()].sort((a, b) => b.blocks - a.blocks || b.lastHeight - a.lastHeight);
}

function num(v: any): number {
  const n = typeof v === "string" ? Number(v) : v;
  return typeof n === "number" && isFinite(n) ? n : 0;
}
function norm(a: any): string | null {
  return typeof a === "string" && a ? a.toLowerCase() : null;
}

// Hashrate unit table for the calculator's unit selector.
export const HS_UNITS: [string, number][] = [
  ["H/s", 1],
  ["KH/s", 1e3],
  ["MH/s", 1e6],
  ["GH/s", 1e9],
  ["TH/s", 1e12],
  ["PH/s", 1e15],
];
