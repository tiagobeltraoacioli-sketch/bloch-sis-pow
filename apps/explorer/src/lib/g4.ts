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

/**
 * The explorer's own edge, same origin.
 *
 * It used to be `https://posternlabs.com/g4rpc`, which is the WALLET's proxy:
 * it fans writes out to every node and treats reads with a soft quorum, both
 * correct for a wallet and neither what an explorer should be doing to the
 * fleet. Pointing a page that polls every fifteen seconds and asks for twelve
 * blocks and sixty-four validators at a proxy that reaches a validator per
 * uncached call made public browsing into validator load.
 *
 * `/rpc` on this origin reads only from the two keyless archival observers,
 * caches on immutability, coalesces, and caps the calls it will make no matter
 * how many arrive. See `edge/core.js`.
 */
export const G4_RPC = "/rpc";

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
  previous_justified?: { epoch: number; root: string };
  block_id: string;
  state_root: string;
  /** Present on the live build; the validator set as this node sees it. */
  validators?: { total: number; active: number };
  total_active_stake_sat?: string;
  base_fee_millisat_per_gas?: string;
  next_base_fee_millisat_per_gas?: string;
  mempool?: number;
  /** Blocks this node holds. With ~38% of slots empty, well below `slot`. */
  blocks_known?: number;
  /** The slot the wall clock says it is, whether or not a block arrived. */
  wall_slot?: number;
  /** `wall_slot - slot`. Non-zero means this node is behind, not the chain. */
  behind_by_slots?: number;
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

export class G4Error extends Error {
  /** Stable machine-readable reason, when the edge gave one. Branch on this. */
  reason: string | null;
  /** Milliseconds to wait, when the edge said to wait. */
  retryAfterMs: number | null;
  constructor(message: string, reason: string | null = null, retryAfterMs: number | null = null) {
    super(message);
    this.reason = reason;
    this.retryAfterMs = retryAfterMs;
  }
}

/**
 * How well corroborated an answer is. The edge attaches this to every result.
 *
 * `level` is the field to branch on, and the UI must show it: the reason
 * `getchaininfo` is allowed to come back from a single node rather than
 * erroring is that a blank page is worse than a dated number — but a dated
 * number with no label is a number presented as a fact.
 */
export interface G4Corroboration {
  level: "final" | "corroborated" | "uncorroborated" | "node_local";
  archival_witnesses?: number;
  of?: number;
  fleet_witness?: boolean;
  missing?: string[];
  note?: string;
  degraded?: string;
  /** Bumped by the edge when it detects a reorg. A client cache must honour it. */
  cache_salt?: number;
  served_from_cache_age_ms?: number;
  witness?: { available: boolean; age_ms: number | null; height: number | null; reason?: string | null };
  plane?: { certified: boolean; behind_by_slots: number | null; reason?: string | null };
  reorg_events?: { signal: string; kind: string; at: number }[];
}

/** The corroboration of the most recent call, for a page that wants to show it. */
export let lastCorroboration: G4Corroboration | null = null;

/** Bumped by the edge whenever it detects a reorg; see `edge/lineage.js`. */
let lastSalt: number | null = null;

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
  const res = await fetch(G4_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) {
    throw new G4Error(
      body.error.message ?? "rpc error",
      body.error.data?.reason ?? null,
      body.error.data?.retry_after_ms ?? null,
    );
  }
  const corro: G4Corroboration | undefined = body.result?.corroboration;
  if (corro) {
    lastCorroboration = corro;
    honourSalt(corro.cache_salt);
  }
  return body.result as T;
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
/** One unspent output, as `getutxos`/`listunspent` reports it. */
export interface G4Utxo {
  txid: string;
  vout: number;
  /** Satoshis, decimal string. */
  value_sat: string;
  script_hash: string;
}

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

/**
 * A Genesis-4 block header as the node reports it.
 *
 * Field list verified against a live archival, not against the spec — the
 * deployed binary and the source tree are not always the same build (the
 * archivals answer `method not found` to `getcapabilities`, which `route()`
 * has had for a while).
 */
export interface G4Block {
  block_id: string;
  /** Consensus version word carried in the header. */
  version: number;
  parent: string;
  slot: number;
  epoch: number;
  /**
   * Height, or `null` for a block that is not on the canonical chain.
   *
   * Not a defensive type. `getblockbyid` serves non-canonical blocks — that
   * is deliberate and documented on the method — and the node computes height
   * by searching the canonical chain, so an orphan has no height to report.
   * Anything rendering this must handle the null rather than print "0", which
   * would put an orphan at genesis.
   */
  height: number | null;
  proposer_index: number;
  timestamp: number;
  state_root: string;
  body_root: string;
  /** The proposer's RANDAO contribution for this slot. */
  randao_reveal: string;
  randao_mix: string;
  justified_root: string;
  finalized_root: string;
  attestation_root: string;
  /** Root of the coherence commitment carried by this header. */
  coherence_root: string;
  /**
   * The node's own word, shown verbatim. Observed values, live:
   * `"finalized"`, `"justified"`, `"canonical"`, and `"not_canonical"` for a
   * block reachable by id that fork choice did not select.
   *
   * This is a reading, not a property — see `lib/source.ts`, note 2.
   */
  finality: string;
  finalized: boolean;
  /**
   * How many transactions the block carries. There is **no `transactions`
   * array** — the count is all the node gives, and a Genesis-4 transaction has
   * no id to list it under anyway. See the `/tx` page.
   */
  tx_count: number;
  attestation_count: number;
}

/** The finality word the node uses for a block it holds but did not select. */
export const NOT_CANONICAL = "not_canonical";

/** A validator record. Stakes are decimal strings: they exceed a JS number. */
export interface G4Validator {
  index: number;
  pubkey_hash: string;
  pubkey_bytes: number;
  state: string;
  own_stake_sat: string;
  /**
   * Null when the active roster does not carry this validator this epoch.
   *
   * That is a DIFFERENT statement from zero and the node keeps them apart on
   * purpose — "not sampled" and "sampled with no weight" are distinguishable
   * states and a reader cares which one it is looking at. Every consumer here
   * has to branch on it rather than defaulting it to 0.
   */
  effective_stake_sat: string | null;
  commission_bps: string;
  randao_commitment: string;
  slashed: boolean;
  /** Null when the validator has never been scheduled to activate. */
  activation_epoch: number | null;
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

// `recentBlocks` and its cache used to live here and have been REMOVED, not
// moved. The cache kept any block whose `finalized` flag was true, forever, on
// the reasoning that finality is the moment an answer stops being able to
// change. That reasoning does not hold on this chain: the finalized checkpoint
// is not a latch across a reorg, so the cache would go on serving a block the
// chain had since reorganised away, with total confidence and no expiry.
//
// The replacement is `slotRange` in `lib/source.ts`, which reads through the
// archivals rather than this client, expires entries, and distinguishes "the
// chain says this slot is empty" from "we could not find out".

/**
 * Track the edge's cache salt, which it bumps when it detects a reorg.
 *
 * There is no longer a block cache in THIS module to drop — `recentBlocks` and
 * `finalBlocks` are gone (see the note above). The salt is still recorded
 * because it is the edge's reorg signal and a future cache here must honour
 * it; `lib/source.ts` keeps its own slot cache with its own expiry.
 */
function honourSalt(salt: number | null | undefined) {
  if (salt === null || salt === undefined) return;
  lastSalt = salt;
}

/** How many RPC calls this page will have in flight at once. */
export const RPC_CONCURRENCY = 6;

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
