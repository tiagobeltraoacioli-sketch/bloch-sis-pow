// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Genesis-4 RPC client.
//
// Separate from `lib/rpc.ts`, which fronts Genesis-3, and deliberately not
// merged with it: they are different chains with different method surfaces,
// and one client answering for both is how a reader ends up believing a
// Genesis-3 answer came from Genesis-4.
//
// Everything here goes through the public proxy. Nodes bind their RPC to
// loopback, so the proxy is the only path a browser has.

// The endpoints this client will read from, in order.
//
// `/rpc` is this site's own Pages Function (`functions/rpc.js`), which forwards
// to the two ARCHIVAL nodes and to nothing else. That is a hard constraint, not
// a preference: a Genesis-4 node serves RPC from the consensus thread itself
// (`EngineBackend` posts each call to the engine's event loop), so a public
// page pointed at a validator competes with block production on an endpoint
// that has no auth and no rate limit. The archivals propose nothing.
//
// `posternlabs.com/g4rpc` stays as the last resort — it corroborates across
// many upstreams and survives this site being served from somewhere else — but
// those upstreams include validators, so it is the fallback and never the
// default. In `vite dev` there is no Pages Function, so `/rpc` 404s and the
// fallback is what answers; that is intended.
export const G4_ENDPOINTS = ["/rpc", "https://posternlabs.com/g4rpc"] as const;

/** The endpoint currently answering. Shown in the footer status line. */
export let G4_RPC: string = G4_ENDPOINTS[0];

/**
 * Which node actually answered, when the proxy says so (`x-bloch-upstream`).
 *
 * Named rather than aggregated into "the chain": this project has had two
 * nodes at the same height report different block ids and different balances,
 * and a page that cannot say which box it read from cannot help anyone
 * diagnose that.
 */
export let G4_UPSTREAM: string | null = null;

/** Genesis-4's own facts, fixed at launch. Sourced from `tokenomics_v4.rs`. */
export const G4 = {
  /** Height Genesis-3 was stopped at and the carryover measured from. */
  haltHeight: 39_918,
  /** Outputs carried into the opening ledger. */
  carryoverUtxos: 452_726,
  /** BLOCH carried from Genesis-3 (whole coins). */
  carryoverBloch: 18_146_400_000n,
  /** Everything the genesis block issues: carryover plus allocations. */
  genesisIssuedBloch: 57_146_400_000n,
  /** Fixed hard cap. */
  totalSupplyBloch: 100_000_000_000n,
  /** Merkle root of the carryover set, as committed by consensus. */
  carryoverSetRoot: "7c756ee8ffff9529b40c124b36bd3e1a9934a15f063affe5596913fb858efbdf",
  /** SHA3-256 of the snapshot file — what the node checks on boot. */
  carryoverFileSha3: "3d67246e94881a17d302b464f79fee55886d8068794e76fed43081117fbe308d",
  /** SHA-256 of the same file — what `sha256sum` reproduces. */
  carryoverFileSha256: "84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6",
  /** Network digest of the genesis manifest the fleet booted from. */
  genesisDigest: "f47d3e498ff978e34471dafff5f94fe139fc3ff489b1a00f469c030258311966",
  /** First slot, UTC. */
  genesisTimeUtc: "2026-08-13 21:31:19 UTC",
  validators: 64,
  slotSecs: 30,
  slotsPerEpoch: 32,
} as const;

export interface G4Head {
  slot: number;
  height: number;
  epoch: number;
  slot_in_epoch: number;
  slots_per_epoch: number;
  finalized_height: number;
  justified: { epoch: number; root: string };
  finalized: { epoch: number; root: string };
  block_id: string;
  state_root: string;
}

export interface G4Balance {
  script_hash: string;
  /** Satoshis, as a decimal string — the value exceeds Number.MAX_SAFE_INTEGER. */
  balance_sat: string;
  utxo_count: number;
}

export interface G4ValidatorCount {
  total: number;
  active: number;
  total_active_stake_sat: string;
}

export class G4Error extends Error {}

/**
 * One JSON-RPC call, with sticky failover across `G4_ENDPOINTS`.
 *
 * A transport failure (or a 5xx, which is what the proxy answers when every
 * upstream is unreachable) moves to the next endpoint and sticks there. A
 * JSON-RPC `error` object does NOT: the node answered, and "gettransaction is
 * refused by design" is a real answer that must not be retried against a
 * second node until one of them happens to be broken enough to say something
 * else.
 */
export async function g4rpc<T>(method: string, params: unknown[] = []): Promise<T> {
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
  const order = [G4_RPC, ...G4_ENDPOINTS.filter((e) => e !== G4_RPC)];
  let last: unknown = null;

  for (const endpoint of order) {
    let parsed: { error?: { message?: string }; result?: unknown };
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
      if (res.status >= 500 || res.status === 404) {
        last = new G4Error(`${endpoint} answered ${res.status}`);
        continue;
      }
      G4_UPSTREAM = res.headers.get("x-bloch-upstream");
      parsed = await res.json();
    } catch (e) {
      last = e;
      continue;
    }
    G4_RPC = endpoint;
    if (parsed.error) throw new G4Error(parsed.error.message ?? "rpc error");
    return parsed.result as T;
  }
  throw new G4Error(
    `no Genesis-4 endpoint answered (${String((last as Error)?.message ?? last)})`,
  );
}

// The address→script_hash conversion that used to live here has been DELETED.
//
// It read: an address's 20-byte hash, zero-padded to 32. That is the CARRIED
// shape, and it is right for a Genesis-3 balance and wrong for a Genesis-4
// key, whose coins live at SHA3-256(pubkey) — all 32 bytes, no truncation.
// The faucet and the withdrawal client disagreed the same way and read
// 74,999,997,782 sat and 0 for one funded key; consensus opens both forms, so
// nothing errored. This file was the eighth site of the same mistake, and the
// one a partner would have hit first.
//
// `lib/scriptHash.ts` now states the rule once, restating
// `crates/bloch-pos-committee/src/script_hash.rs`, and `classify()` there
// keeps the PROVENANCE of what was pasted so a page can say which of the two
// entries it is showing instead of quietly picking one.

/** One unspent output, as `getutxos` reports it. Note: no slot. */
export interface G4Utxo {
  txid: string;
  vout: number;
  /** Satoshis, decimal string. */
  value_sat: string;
  script_hash: string;
}

/**
 * A page of unspent outputs — and, crucially, how much of the set it is NOT.
 *
 * `total` is the whole set; `returned` is what fitted. `truncated` means the
 * rest is unreachable through this RPC, because `getutxos` has no cursor: the
 * same first page comes back on every call. Measured against the live chain
 * 2026-09-01 — asking for 5,000 of the founder hash's 45,149 outputs returns
 * 1,000 (`UTXO_PAGE_MAX`) and `truncated: true`.
 */
export interface G4UtxoPage {
  script_hash: string;
  total: number;
  returned: number;
  truncated: boolean;
  utxos: G4Utxo[];
}

/**
 * The answer to "is this one output still unspent?".
 *
 * There is no `finalized` field. Two partner documents said there was and told
 * integrators to settle on it; the node returns
 * `{txid, vout, unspent, utxo, at_slot}` and nothing else.
 *
 * `at_slot` is NOT the slot the output landed in. It is the head slot this
 * node answered from — `Json::u(state.slot())` in `txout_json`, on both the
 * found and the not-found branch. It is there so the answer can be pinned to a
 * point on the chain, and reading it as a creation height is a real mistake
 * with a real consequence: an integrator would date a deposit to whenever they
 * happened to ask.
 */
export interface G4TxOut {
  txid: string;
  vout: number;
  unspent: boolean;
  utxo: G4Utxo | null;
  at_slot: number;
}

/** A Genesis-4 block header as the node reports it. */
export interface G4Block {
  block_id: string;
  parent: string;
  slot: number;
  epoch: number;
  height: number;
  proposer_index: number;
  timestamp: number;
  state_root: string;
  body_root: string;
  randao_mix: string;
  justified_root: string;
  finalized_root: string;
  attestation_root: string;
  /** "canonical" | "orphan" | … — the node's own word, shown verbatim. */
  finality: string;
  finalized: boolean;
  tx_count: number;
  attestation_count: number;
}

/** A validator record. Stakes are decimal strings: they exceed a JS number. */
export interface G4Validator {
  index: number;
  pubkey_hash: string;
  pubkey_bytes: number;
  state: string;
  own_stake_sat: string;
  effective_stake_sat: string;
  commission_bps: string;
  randao_commitment: string;
  slashed: boolean;
  activation_epoch: number;
  exit_epoch: number | null;
  withdrawable_epoch: number | null;
}

/**
 * Run `work` over `items` with at most `limit` in flight.
 *
 * The node's RPC is served by the consensus loop itself, so a burst of
 * parallel calls competes with block production — the thing we are asking it
 * about. Sixty-four at once is how you turn a healthy node into one that
 * times out and then read the timeout as a chain problem.
 */
async function mapLimit<T, R>(
  items: T[],
  limit: number,
  work: (item: T) => Promise<R>,
): Promise<PromiseSettledResult<R>[]> {
  const out: PromiseSettledResult<R>[] = new Array(items.length);
  let next = 0;
  const runner = async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      try {
        out[i] = { status: "fulfilled", value: await work(items[i]) };
      } catch (reason) {
        out[i] = { status: "rejected", reason };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, runner));
  return out;
}

/**
 * Blocks already known to be final.
 *
 * Only finalized blocks go in here, and that restriction is the whole point.
 * A block that is merely canonical can still be reorganised out — caching one
 * would leave the page showing a block the chain has since dropped, which is
 * exactly the class of stale-cache bug this project has been bitten by
 * before. Finality is the moment the answer stops being able to change.
 */
const finalBlocks = new Map<number, G4Block>();

/** How many RPC calls this page will have in flight at once. */
export const RPC_CONCURRENCY = 6;

/**
 * The last `n` blocks, newest first, walked back from `fromSlot`.
 *
 * There is no range call on this RPC, so this asks per slot and tolerates
 * gaps: a slot with no block is a missed proposal, which is normal and must
 * read as absence rather than as an error. Finalized slots are answered from
 * cache, so a page left open settles to asking only about the new ones.
 */
export async function recentBlocks(fromSlot: number, n: number): Promise<(G4Block | null)[]> {
  const slots = Array.from({ length: n }, (_, i) => fromSlot - i).filter((s) => s >= 0);
  const settled = await mapLimit(slots, RPC_CONCURRENCY, async (s) => {
    const hit = finalBlocks.get(s);
    if (hit) return hit;
    const b = await g4rpc<G4Block>("getblockbyslot", [s]);
    if (b.finalized) finalBlocks.set(s, b);
    return b;
  });
  return settled.map((r) => (r.status === "fulfilled" ? r.value : null));
}

/** Fetch every validator, bounded — see `mapLimit`. */
export async function allValidators(total: number): Promise<(G4Validator | null)[]> {
  const settled = await mapLimit(
    Array.from({ length: total }, (_, i) => i),
    RPC_CONCURRENCY,
    (i) => g4rpc<G4Validator>("getvalidator", [i]),
  );
  return settled.map((r) => (r.status === "fulfilled" ? r.value : null));
}

/**
 * Poll `fn` every `ms`, but only while the tab is actually being looked at.
 *
 * A backgrounded tab polling a consensus loop forever is load with no reader
 * on the other end. Returns its own teardown.
 */
export function pollWhileVisible(fn: () => void, ms: number): () => void {
  let timer: ReturnType<typeof setInterval> | null = null;
  const start = () => {
    if (timer !== null) return;
    fn();
    timer = setInterval(fn, ms);
  };
  const stop = () => {
    if (timer !== null) clearInterval(timer);
    timer = null;
  };
  const onVis = () => (document.visibilityState === "visible" ? start() : stop());
  onVis();
  document.addEventListener("visibilitychange", onVis);
  return () => {
    stop();
    document.removeEventListener("visibilitychange", onVis);
  };
}
