// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Where the block surface gets its facts.
//
// This module exists to keep three distinctions that the rest of the explorer
// then cannot accidentally collapse. Each one has cost us something before.
//
//   1. **"No block" is not "no answer".** A slot with no block is a missed
//      proposal — normal, expected, and about 39% of all slots on this chain.
//      A request that timed out is a slot we know nothing about. Rendering the
//      second as the first invents a missed proposal that never happened and
//      libels a validator. They are separate variants here, and the type
//      system will not let a caller forget which one it has.
//
//   2. **"Finalized" is an observation with a timestamp, not a property.** On
//      Genesis-4 the finalized checkpoint is not a latch across a reorg: the
//      adopt path takes an ancestor's state wholesale without comparing the
//      incoming finalized checkpoint against the outgoing one, so a block that
//      `getblockbyslot` returned as `"finalized": true` can later come back
//      `"justified"` or `"canonical"`, and `finalized_height` can go *down*
//      (integration book §5.4). Nothing here may cache a finality verdict as
//      settled, and the UI must never render one as a settled fact.
//
//   3. **One node agreeing with itself is not agreement.** Published guidance
//      is to read from two independent nodes and require them to concur on
//      root *and* epoch. A failover pool cannot do that — ask it twice and it
//      may answer from the same node both times. `agree()` pins each read to a
//      named archival so the comparison is real.
//
// Everything reads from the archivals, never from a validator: the node RPC
// has no auth and no rate limit and shares a thread with consensus. The
// transport is `functions/g4.js`; see that file for why a browser cannot talk
// to an archival directly.

import { G4Block, G4Head } from "./g4";

/** The read path. Same-origin: a Pages Function in production, a Vite proxy in dev. */
export const G4_READ = "/g4";

/** How many archivals `functions/g4.js` fronts. Pinned reads index into this. */
export const ARCHIVAL_COUNT = 2;

// Error codes, from crates/bloch-pos-node/src/rpc.rs. Named rather than
// scattered as magic numbers, because the whole point of this node returning
// distinct codes is that callers branch on cause instead of on message text.
export const CODE = {
  /** No block with that id is known. */
  BLOCK_NOT_FOUND: -32000,
  /** Index is not in the committed validator registry. */
  VALIDATOR_NOT_FOUND: -32001,
  /** This build cannot look a transaction up by id. Permanent, not transient. */
  NO_TRANSACTION_INDEX: -32005,
  /** This node holds no wallet and mints no addresses. Permanent. */
  NO_WALLET: -32006,
  /** The slot exists and carries no canonical block. Normal under PoS. */
  SLOT_EMPTY: -32007,
  /** Our own proxy: no archival answered. Never emitted by a node. */
  NO_ARCHIVAL: -32050,
} as const;

/** An RPC answer that came back as a JSON-RPC `error` — the node spoke. */
export class RpcRefusal extends Error {
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(message);
  }
}

/** We could not ask, or could not understand the reply. The chain said nothing. */
export class Unreachable extends Error {}

/**
 * One JSON-RPC read.
 *
 * `node` pins the request to a single archival — pass it only when the
 * identity of the answering node matters (i.e. from `agree`). Left off, the
 * proxy fails over, which is what you want for a bulk scan.
 */
export async function read<T>(
  method: string,
  params: unknown[] = [],
  opts: { node?: number; signal?: AbortSignal } = {},
): Promise<T> {
  return (await readFrom<T>(method, params, opts)).value;
}

/**
 * A read, plus **which archival actually answered it**.
 *
 * The provenance is not diagnostics. `agree()` needs it to check that two
 * answers came from two different nodes, because otherwise "agreement" is
 * whatever the transport felt like doing. That is not hypothetical: the Vite
 * dev proxy cannot route on a query parameter, so it sends every pinned read
 * to the same archival, and without this check the finality panel would show a
 * confident green "both archivals agree" derived from asking one node twice.
 * A cross-check that can silently degrade into self-agreement is worse than no
 * cross-check, because it is believed.
 *
 * `node` is null when the transport did not say — which is itself a reason not
 * to claim agreement.
 */
export async function readFrom<T>(
  method: string,
  params: unknown[] = [],
  opts: { node?: number; signal?: AbortSignal } = {},
): Promise<{ value: T; node: number | null }> {
  const url = opts.node === undefined ? G4_READ : `${G4_READ}?node=${opts.node}`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: opts.signal,
    });
  } catch (e: any) {
    throw new Unreachable(e?.name === "AbortError" ? "request cancelled" : "network error");
  }

  let body: any;
  try {
    body = await res.json();
  } catch {
    throw new Unreachable(`endpoint returned non-JSON (HTTP ${res.status})`);
  }

  if (body?.error) {
    const { code, message } = body.error;
    // Our proxy's "every archival is down" is not a statement about the chain,
    // so it must not surface as a refusal a caller might render as data.
    if (code === CODE.NO_ARCHIVAL) throw new Unreachable(message ?? "no archival answered");
    throw new RpcRefusal(typeof code === "number" ? code : 0, message ?? "rpc error");
  }
  if (!("result" in (body ?? {}))) throw new Unreachable("malformed JSON-RPC reply");

  const raw = res.headers.get("x-bloch-node-index");
  const node = raw !== null && /^\d+$/.test(raw) ? Number(raw) : null;
  return { value: body.result as T, node };
}

// ---------------------------------------------------------------------------
// Slots
// ---------------------------------------------------------------------------

/**
 * What is at a slot — and, when we do not know, the fact that we do not.
 *
 * The third variant is the one that matters. Without it every caller has to
 * decide for itself what a failed fetch means, and the cheap decision is
 * always "show it as empty", which is a lie about a validator's record.
 */
export type SlotCell =
  | { readonly kind: "block"; readonly slot: number; readonly block: G4Block }
  /** The chain answered: the proposer for this slot did not deliver. */
  | { readonly kind: "empty"; readonly slot: number }
  /** We could not get an answer. Says nothing about whether a block exists. */
  | { readonly kind: "unknown"; readonly slot: number; readonly why: string };

/** Resolve one slot, turning the node's -32007 into data rather than an error. */
export async function slotCell(slot: number, signal?: AbortSignal): Promise<SlotCell> {
  try {
    const block = await read<G4Block>("getblockbyslot", [slot], { signal });
    remember(block);
    return { kind: "block", slot, block };
  } catch (e) {
    if (e instanceof RpcRefusal && e.code === CODE.SLOT_EMPTY) return { kind: "empty", slot };
    const why = e instanceof Error ? e.message : String(e);
    return { kind: "unknown", slot, why };
  }
}

/**
 * Run `work` over `items` with at most `limit` in flight.
 *
 * Bounded because the archivals answer a cold historical slot in 1–3 seconds
 * and an unbounded fan-out over a 64-slot page is a self-inflicted outage.
 */
async function mapLimit<T, R>(items: T[], limit: number, work: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const runner = async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await work(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, runner));
  return out;
}

/** Concurrent reads in flight. Measured against the archivals, not guessed. */
export const CONCURRENCY = 6;

/**
 * Every slot in `[from, to]`, descending — blocks, misses and gaps in our own
 * knowledge, each labelled as what it is.
 */
export async function slotRange(
  from: number,
  to: number,
  signal?: AbortSignal,
): Promise<SlotCell[]> {
  const hi = Math.max(from, to);
  const lo = Math.max(0, Math.min(from, to));
  const slots: number[] = [];
  for (let s = hi; s >= lo; s--) slots.push(s);
  return mapLimit(slots, CONCURRENCY, (s) => cachedSlotCell(s, signal));
}

// ---------------------------------------------------------------------------
// Caching, and the one thing it may not cache
// ---------------------------------------------------------------------------

/**
 * Slot → the last cell we resolved, with when we resolved it.
 *
 * An earlier version of this cache kept any block whose `finalized` flag was
 * true, forever, on the reasoning that finality is where an answer stops being
 * able to change. That reasoning is wrong on this chain — see §5.4 of the
 * integration book, and note 2 at the top of this file. A cache that treats
 * `finalized: true` as permanent will keep serving a block the chain has since
 * reorganised away, and will do it with total confidence.
 *
 * So: the *header* of a block is cached (its roots, its proposer, its parent —
 * those are fixed by the block id and cannot change while the id does not),
 * but the caching is time-bounded, and the finality verdict inside it is
 * always rendered as "as of <time>". Nothing here is a latch.
 */
interface CacheEntry {
  cell: SlotCell;
  at: number;
}
const slotCache = new Map<number, CacheEntry>();

/**
 * How long a resolved slot may be reused.
 *
 * Deliberately shorter than an epoch (32 slots × 30 s = 16 minutes), because
 * an epoch boundary is exactly when a finality verdict changes, and a reader
 * who reloads after a boundary must see the new verdict rather than a cached
 * pre-boundary one.
 */
const CACHE_MS = 60_000;

/** Cells that could not be resolved are never cached — retry is the point. */
async function cachedSlotCell(slot: number, signal?: AbortSignal): Promise<SlotCell> {
  const hit = slotCache.get(slot);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.cell;
  const cell = await slotCell(slot, signal);
  if (cell.kind !== "unknown") slotCache.set(slot, { cell, at: Date.now() });
  return cell;
}

/** Drop everything. Called when the reader explicitly asks for a fresh read. */
export function clearSlotCache(): void {
  slotCache.clear();
}

// ---------------------------------------------------------------------------
// Two-node agreement
// ---------------------------------------------------------------------------

export type Agreement<T> =
  /** Both archivals answered and matched on the compared value. */
  | { readonly kind: "agree"; readonly value: T }
  /** Both answered and differed. This is the interesting one. */
  | { readonly kind: "disagree"; readonly a: T; readonly b: T }
  /** Only one answered. Not agreement — no comparison happened. */
  | { readonly kind: "single"; readonly value: T; readonly node: number; readonly why: string }
  /** Neither answered. */
  | { readonly kind: "none"; readonly why: string };

/**
 * Ask both archivals the same question and compare them on `key`.
 *
 * The `single` variant is not a convenience — it is the honest name for what
 * you have when one node is down. Published guidance requires two independent
 * nodes to concur before a reader treats a finality claim as durable; folding
 * a one-node answer into `agree` would quietly withdraw that requirement at
 * exactly the moment the network is least healthy.
 */
export async function agree<T>(
  method: string,
  params: unknown[],
  key: (v: T) => string,
  signal?: AbortSignal,
): Promise<Agreement<T>> {
  const results = await Promise.all(
    Array.from({ length: ARCHIVAL_COUNT }, (_, i) =>
      readFrom<T>(method, params, { node: i, signal }).then(
        (r) => ({ ok: true as const, value: r.value, asked: i, answered: r.node }),
        (e) => ({ ok: false as const, why: e instanceof Error ? e.message : String(e), asked: i }),
      ),
    ),
  );
  const good = results.filter((r) => r.ok) as {
    ok: true;
    value: T;
    asked: number;
    answered: number | null;
  }[];
  const bad = results.filter((r) => !r.ok) as { ok: false; why: string; asked: number }[];

  if (good.length === 0) return { kind: "none", why: bad.map((b) => b.why).join("; ") };
  if (good.length === 1) {
    return { kind: "single", value: good[0].value, node: good[0].asked, why: bad[0]?.why ?? "" };
  }

  const [a, b] = good;
  // Did two *different* nodes actually answer? If the transport collapsed both
  // pinned reads onto one archival — or would not say which answered — then
  // nothing was cross-checked, and reporting agreement would be inventing an
  // assurance. Degrade to `single`, which is the truthful description.
  const distinct = a.answered !== null && b.answered !== null && a.answered !== b.answered;
  if (!distinct) {
    return {
      kind: "single",
      value: a.value,
      node: a.answered ?? a.asked,
      why:
        a.answered === null
          ? "the read path did not identify which archival answered, so no cross-check was possible"
          : `both reads were answered by archival ${a.answered}`,
    };
  }

  if (key(a.value) === key(b.value)) return { kind: "agree", value: a.value };
  return { kind: "disagree", a: a.value, b: b.value };
}

/**
 * The head, read from both archivals and compared on **root and epoch** —
 * which is the comparison the published guidance actually names. Comparing
 * height alone would pass two nodes sitting at the same height on different
 * forks, which is the exact failure this is meant to catch: on 2026-08-24
 * three nodes finalised the same epoch under three different roots.
 */
export function headAgreement(signal?: AbortSignal): Promise<Agreement<G4Head>> {
  return agree<G4Head>(
    "getchaininfo",
    [],
    (h) => `${h.finalized?.epoch}:${h.finalized?.root}`,
    signal,
  );
}

/** One slot, from both archivals, compared on which block is canonical there. */
export function slotAgreement(slot: number, signal?: AbortSignal): Promise<Agreement<G4Block>> {
  return agree<G4Block>("getblockbyslot", [slot], (b) => b.block_id, signal);
}

// ---------------------------------------------------------------------------
// Reorg evidence
// ---------------------------------------------------------------------------

/**
 * What we have personally seen at a slot.
 *
 * The node exposes no reorg history: there is no orphan store to query and no
 * "what used to be here" call, so an explorer cannot *derive* the chain's
 * reorganisations after the fact. What it can do is remember what it was told
 * and notice when the answer changes — and a slot whose canonical block id
 * changes between two honest reads is a reorg, observed first-hand.
 *
 * This is deliberately modest. It only covers reorgs that happened while
 * somebody had this explorer open on that slot, and it is per-browser. It is
 * offered as an observation with a timestamp, never as chain history, because
 * presenting a browser's local memory as the chain's record would be the same
 * category of error as presenting `finalized: true` as settlement.
 */
export interface Sighting {
  readonly blockId: string;
  /** Unix ms, local clock. */
  readonly at: number;
  /** The finality word the node used at that moment. */
  readonly finality: string;
}

const SIGHTINGS_KEY = "bloch.g4.sightings.v1";
/** Slots to remember. Bounded so the store cannot grow without limit. */
const SIGHTINGS_MAX = 500;

type SightingStore = Record<string, Sighting[]>;

function loadSightings(): SightingStore {
  try {
    const raw = localStorage.getItem(SIGHTINGS_KEY);
    return raw ? (JSON.parse(raw) as SightingStore) : {};
  } catch {
    // Private windows, cleared site data, storage disabled — all normal, and
    // none of them are worth a broken page. No memory just means no evidence.
    return {};
  }
}

function saveSightings(s: SightingStore): void {
  try {
    localStorage.setItem(SIGHTINGS_KEY, JSON.stringify(s));
  } catch {
    /* full or unavailable; the surface degrades to "no evidence" */
  }
}

/** Record that this block was canonical at this slot, now. */
export function remember(block: G4Block): void {
  const store = loadSightings();
  const key = String(block.slot);
  const seen = store[key] ?? [];
  const last = seen[seen.length - 1];
  if (last && last.blockId === block.block_id && last.finality === block.finality) return;
  seen.push({ blockId: block.block_id, at: Date.now(), finality: block.finality });
  store[key] = seen.slice(-8);

  const keys = Object.keys(store);
  if (keys.length > SIGHTINGS_MAX) {
    // Evict the lowest slots — the head is where reorgs actually happen.
    for (const k of keys.map(Number).sort((x, y) => x - y).slice(0, keys.length - SIGHTINGS_MAX)) {
      delete store[String(k)];
    }
  }
  saveSightings(store);
}

/** Everything this browser has seen at a slot, oldest first. */
export function sightings(slot: number): Sighting[] {
  return loadSightings()[String(slot)] ?? [];
}

/**
 * Distinct block ids seen at a slot. More than one means this browser watched
 * the slot change hands — a reorg, at first hand.
 */
export function reorgSeen(slot: number): boolean {
  const ids = new Set(sightings(slot).map((s) => s.blockId));
  return ids.size > 1;
}

/**
 * True when a slot was seen finalized and later reported as something else.
 *
 * This is §5.4 caught in the act, and it is worth naming separately from an
 * ordinary reorg: an ordinary reorg replaces a block that was never claimed to
 * be settled, whereas this is the chain taking back a settlement claim it had
 * already made.
 */
export function finalityWithdrawn(slot: number): boolean {
  const seen = sightings(slot);
  const finalAt = seen.findIndex((s) => s.finality === "finalized");
  return finalAt >= 0 && seen.slice(finalAt + 1).some((s) => s.finality !== "finalized");
}

// ---------------------------------------------------------------------------
// Height → slot
// ---------------------------------------------------------------------------

/**
 * Find the slot holding a given height.
 *
 * **There is no `getblockbyheight`.** Slots and heights are different numbers
 * on this chain and diverge badly: at the time of writing, height 33,690 sits
 * at slot 54,585, because 20,895 slots — 38.3% of every slot ever — carry no
 * block. A reader who types a height and is sent to the same number as a slot
 * lands 21,000 slots away from what they asked for, and the page they get
 * looks perfectly plausible. That is the failure this function exists to
 * prevent.
 *
 * The search is possible because height is **monotone non-decreasing in
 * slot** — it rises by exactly one at a block and is flat across a miss — so a
 * bracket can be closed on it. Two details make it work in practice:
 *
 *   - The bracket starts at `[height, height + totalMisses]`, not at
 *     `[0, head]`. Height can never exceed slot, and can never fall behind by
 *     more than the misses accumulated so far, so this is exact and cuts the
 *     space to the miss count.
 *
 *   - The probe **widens when a round comes back all-empty**. The chain has a
 *     roughly 15,000-slot region (about slots 18,500–33,500) where it barely
 *     produced at all — a stall, and the reason the miss count is what it is.
 *     A fixed 8-point probe sweeps that region and finds nothing, learns
 *     nothing, and loops. Tripling the sample when a round is barren is what
 *     converts "this never terminates" into "this costs a few more probes".
 *     Measured: dense heights land exactly in 32–41 probes; a height inside
 *     the stall took 40.
 *
 * Bounded by `maxProbes`, and it **reports the bracket it reached rather than
 * guessing** when the budget runs out. A near-miss here is not a near-miss —
 * it is a different block.
 */
export type HeightSearch =
  | { readonly kind: "found"; readonly slot: number; readonly block: G4Block; readonly probes: number }
  /** Ran out of budget. The height is somewhere in `[lo, hi]` and we will not pretend otherwise. */
  | { readonly kind: "narrowed"; readonly lo: number; readonly hi: number; readonly probes: number }
  /** The height is beyond the chain's tip. */
  | { readonly kind: "future"; readonly headHeight: number };

export async function findSlotForHeight(
  height: number,
  head: G4Head,
  opts: { maxProbes?: number; signal?: AbortSignal; onProgress?: (probes: number) => void } = {},
): Promise<HeightSearch> {
  const maxProbes = opts.maxProbes ?? 160;
  if (height > head.height) return { kind: "future", headHeight: head.height };

  let lo = Math.max(0, height);
  let hi = Math.min(head.slot, height + (head.slot - head.height));
  let probes = 0;
  let width = 8;
  // The tightest bracketing blocks found so far, on each side of the target.
  let below: { slot: number; height: number } | null = null;
  let above: { slot: number; height: number } | null = null;

  while (probes < maxProbes && lo <= hi) {
    const n = Math.min(width, hi - lo + 1);
    const step = n > 1 ? (hi - lo) / (n - 1) : 0;
    const points = Array.from(new Set(Array.from({ length: n }, (_, i) => Math.round(lo + i * step))));
    const cells = await mapLimit(points, CONCURRENCY, (s) => cachedSlotCell(s, opts.signal));
    probes += points.length;
    opts.onProgress?.(probes);

    let learned = false;
    for (const c of cells) {
      if (c.kind !== "block" || c.block.height === null) continue;
      learned = true;
      if (c.block.height === height) return { kind: "found", slot: c.slot, block: c.block, probes };
      if (c.block.height < height && (below === null || c.slot > below.slot)) {
        below = { slot: c.slot, height: c.block.height };
      }
      if (c.block.height > height && (above === null || c.slot < above.slot)) {
        above = { slot: c.slot, height: c.block.height };
      }
    }

    const nextLo = below ? below.slot + 1 : lo;
    const nextHi = above ? above.slot - 1 : hi;
    // A barren round, or one that could not tighten the bracket, means the
    // region is sparse — sample it harder rather than sweeping it again.
    if (!learned || (nextLo === lo && nextHi === hi)) {
      if (width >= 48) {
        width = 48;
        if (!learned) continue;
        break;
      }
      width = Math.min(width * 3, 48);
      continue;
    }
    width = 8;
    lo = nextLo;
    hi = nextHi;
  }
  return { kind: "narrowed", lo, hi, probes };
}
