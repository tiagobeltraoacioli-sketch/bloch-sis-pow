// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Observed participation, and an honest account of its limits.
//
// Genesis-4 publishes exactly one attributable participation fact: the
// `proposer_index` on a block header. Everything else people expect on a
// validator page — attestation rate, inclusion distance, missed-duty counts —
// requires knowing the duty roster or the attestation aggregation bits, and
// the node serves neither.
//
// This module therefore computes a PROPOSAL record over a bounded recent
// window, and nothing else. It deliberately offers no function that returns an
// attestation rate, because the moment such a function exists someone will
// call it with the only numbers available — included-attestation counts — and
// publish a figure that is not a rate of anything.

import { G4Validator } from "./g4";

/** Matches `MAX_LIMIT` in functions/g4/slots.js. */
const PAGE = 32;
const ENDPOINT = "/g4/slots";

export interface SlotRow {
  slot: number;
  present: boolean;
  block_id?: string;
  height?: number;
  epoch?: number;
  proposer_index?: number;
  timestamp?: number;
  tx_count?: number;
  attestation_count?: number;
  finality?: string;
  finalized?: boolean;
  /** Set only when the read itself failed — distinct from an empty slot. */
  unreadable?: string;
}

export interface SlotWindow {
  head: { slot: number; epoch: number; height: number; slots_per_epoch: number };
  from: number;
  to: number;
  slots: SlotRow[];
}

interface WindowBody extends SlotWindow {
  generated_at: number;
  error?: string;
}

async function fetchWindowPage(to: number | null, limit: number): Promise<WindowBody> {
  const q = new URLSearchParams({ limit: String(limit) });
  if (to !== null) q.set("to", String(to));
  const res = await fetch(`${ENDPOINT}?${q}`, { headers: { accept: "application/json" } });
  let body: WindowBody;
  try {
    body = await res.json();
  } catch {
    throw new Error(`slot window endpoint returned a non-JSON body (HTTP ${res.status})`);
  }
  if (!res.ok || body.error) {
    throw new Error(body.error ?? `slot window endpoint failed (HTTP ${res.status})`);
  }
  return body;
}

/**
 * The last `slots` slots, newest first.
 *
 * Fetched in sequence for the same reason the validator set is: a cold cache
 * costs an archival a fan-out, and parallelising that to save a reader a
 * second is spending someone else's node on impatience.
 */
export async function recentWindow(slots: number): Promise<SlotWindow> {
  const first = await fetchWindowPage(null, Math.min(PAGE, slots));
  const rows = first.slots.slice();
  let remaining = slots - rows.length;
  let to = first.from - 1;

  while (remaining > 0 && to >= 0) {
    const page = await fetchWindowPage(to, Math.min(PAGE, remaining));
    rows.push(...page.slots);
    remaining -= page.slots.length;
    to = page.from - 1;
    if (page.slots.length === 0) break;
  }

  return {
    head: first.head,
    from: rows.length ? rows[rows.length - 1].slot : first.from,
    to: first.to,
    slots: rows,
  };
}

export interface ProposalRecord {
  /** Slots in the window. */
  slots: number;
  /** Slots that produced a block. */
  filled: number;
  /** Slots with no block — a missed proposal, unattributable (see below). */
  empty: number;
  /** Slots the archival could not answer for. Not the same as empty. */
  unreadable: number;
  /** Blocks proposed, by validator index. */
  byProposer: Map<number, number>;
  /** Distinct validators seen proposing in the window. */
  distinctProposers: number;
  /** Mean attestations included per block in the window. */
  meanAttestations: number;
}

export function proposalRecord(win: SlotWindow): ProposalRecord {
  const byProposer = new Map<number, number>();
  let filled = 0;
  let empty = 0;
  let unreadable = 0;
  let attTotal = 0;

  for (const s of win.slots) {
    if (s.unreadable) {
      unreadable++;
      continue;
    }
    if (!s.present) {
      empty++;
      continue;
    }
    filled++;
    attTotal += s.attestation_count ?? 0;
    const p = s.proposer_index;
    if (p !== undefined) byProposer.set(p, (byProposer.get(p) ?? 0) + 1);
  }

  return {
    slots: win.slots.length,
    filled,
    empty,
    unreadable,
    byProposer,
    distinctProposers: byProposer.size,
    meanAttestations: filled === 0 ? 0 : attTotal / filled,
  };
}

/**
 * Validators that appear in the registry but never proposed in the window.
 *
 * This is NOT a liveness verdict and must never be labelled as one. Over a
 * window of `n` slots a healthy validator in a set of 64 is expected to
 * propose about n/64 times, so over two epochs — 64 slots — roughly a third of
 * a perfectly healthy set will show zero by chance alone. The list is useful
 * for the opposite reason: a validator that is genuinely gone appears here in
 * every window, and one that is merely unlucky does not.
 */
export function silentInWindow(rows: G4Validator[], rec: ProposalRecord): number[] {
  return rows.filter((v) => !rec.byProposer.has(v.index)).map((v) => v.index);
}

/**
 * The share of the window a validator proposed, against an equal-share
 * expectation.
 *
 * Returns a ratio where 1.0 means "proposed exactly its equal share". Given
 * how small these windows are, this is a texture, not a score — the pages
 * present it as counts first and this ratio second.
 */
export function proposalIndex(count: number, rec: ProposalRecord, setSize: number): number {
  if (rec.filled === 0 || setSize === 0) return 0;
  const expected = rec.filled / setSize;
  return expected === 0 ? 0 : count / expected;
}

/**
 * Seats in one slot's committee — and the reason `attestation_count: 2` is not
 * the alarming number it looks like.
 *
 * Genesis-4 does not sample a committee. `epoch_committees` sorts the roster,
 * shuffles it and cuts it into `SLOTS_PER_EPOCH` contiguous chunks, so every
 * validator has a duty every epoch and each slot's committee is the set size
 * divided by the number of slots. With 64 validators over 32 slots that is
 * TWO seats per slot, and a block carrying two attestations is carrying all of
 * them.
 *
 * This is worth a function rather than a comment because the raw figure invites
 * exactly the wrong reading: a reader who sees "2 attestations" against "64
 * validators" concludes that 97% of the chain is absent, when what they are
 * looking at is full participation. Anywhere `attestation_count` is displayed,
 * display this next to it.
 *
 * (`COMMITTEE_SIZE = 128` and `SLOT_SUBCOMMITTEE_SIZE = 8` exist in the source
 * and are dead constants from a superseded sampled-committee design. The node
 * reads neither. Sizing anything from them produces a number that describes no
 * part of this chain.)
 */
export function seatsPerSlot(activeValidators: number, slotsPerEpoch: number): number {
  if (slotsPerEpoch === 0) return 0;
  return Math.floor(activeValidators / slotsPerEpoch);
}
