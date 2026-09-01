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

import { parseBlochAddress } from "./address";

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
 * Normalise what a person can paste into the 32-byte script hash the node
 * wants.
 *
 * Genesis-4 keys the ledger by script hash, not by address — `getbalance`
 * rejects anything that is not 64 hex characters. Three inputs reach the same
 * entry:
 *
 *   `bloch1q…`  a full address. Its checksum is verified, not stripped: a
 *               mistyped address must be refused, because the zero-padded
 *               hash of a wrong address is a perfectly valid script hash that
 *               simply holds nothing — the reader would be shown an empty
 *               balance and believe it.
 *   40 hex      the bare hash-160 inside such an address.
 *   64 hex      a script hash already.
 *
 * The 20-byte forms are left-aligned and zero-padded to 32. That padding is
 * the same rule consensus applies when deciding whether a key owns an output,
 * so it is not a convenience here — it is the identity.
 *
 * Returns null when the input is none of the three, rather than guessing.
 */
export function toScriptHash(input: string): string | null {
  const raw = input.trim().toLowerCase();
  if (raw.startsWith("bloch1")) {
    const parsed = parseBlochAddress(raw);
    return parsed ? parsed.hashHex + "0".repeat(24) : null;
  }
  const s = raw.replace(/^0x/, "");
  if (!/^[0-9a-f]+$/.test(s)) return null;
  if (s.length === 64) return s;
  if (s.length === 40) return s + "0".repeat(24);
  return null;
}

/** True when the script hash is a zero-padded hash-160 rather than a raw hash. */
export function isPaddedH160(scriptHash: string): boolean {
  return scriptHash.length === 64 && scriptHash.slice(40) === "0".repeat(24);
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

/**
 * Blocks the EDGE has certified as final, keyed by slot.
 *
 * This used to admit any block whose `finalized` field was true, which is the
 * unsafe version of the same idea: `finalized` is not a latch on this chain —
 * nodes have been measured below their own previously finalised checkpoint —
 * so one node saying `finalized: true` is an observation, not a promise, and
 * "which block sits at slot S" is a fork-choice answer that a reorg changes.
 *
 * Two things fixed it. Entry requires the edge's corroboration `level` to be
 * `final`, which means two archivals agreed AND a fleet witness certified the
 * lineage. And the whole map is dropped when the edge's cache salt moves,
 * which is how the edge reports that it detected a reorg. Without the second
 * half the first is only a better-informed way to be stale.
 */
const finalBlocks = new Map<number, G4Block>();

/** Drop everything the moment the edge says the lineage changed under us. */
function honourSalt(salt: number | null | undefined) {
  if (salt === null || salt === undefined) return;
  if (lastSalt !== null && salt !== lastSalt) finalBlocks.clear();
  lastSalt = salt;
}

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
    // `finalized` alone is not enough — see `finalBlocks`. The edge's own
    // judgement is, because it is the thing that watches for the contradiction.
    if ((b as any)?.corroboration?.level === "final") finalBlocks.set(s, b);
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
