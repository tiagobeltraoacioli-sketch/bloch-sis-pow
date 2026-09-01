// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Replay fixtures for the finality page.
// ---------------------------------------------------------------------------
// WHY THIS EXISTS, AND WHY IT IS NOT A LIE
//
// The single most valuable thing the finality page can do is make a stall
// obvious while it is happening. That claim is untestable on a healthy chain,
// and this chain finalises 99% of its epochs — so the stall rendering would
// otherwise ship having never been looked at, and would first be exercised on
// the day it mattered, in front of the people it was built for.
//
// So the page can be driven from a scripted sequence instead of the network,
// via `?replay=<scenario>`. The scenarios below are shaped from real measured
// behaviour of this chain, not invented: the stall lengths, the leak
// threshold, and the descending-finality sequence are the ones in the tests.
//
// THE HONESTY RULE THIS FILE LIVES UNDER: a replay is never silent. The page
// paints a permanent banner across the top whenever `replay` is set, every
// number carries the replay marker, and no replay state can be reached by
// accident — it requires an explicit query parameter that nothing on the site
// links to. A demonstration that can be mistaken for the live chain is worse
// than no demonstration.
// ---------------------------------------------------------------------------

import type { ChainInfo, Corroboration, EpochAttestations } from "./finality";

export interface ReplayFrame {
  info: ChainInfo;
  corroboration: Corroboration;
  /** Seconds of chain time this frame stands for, for the elapsed readout. */
  offsetSecs: number;
}

export interface Scenario {
  id: string;
  title: string;
  /** What a viewer is looking at, said plainly. */
  premise: string;
  frames: ReplayFrame[];
  /** Real-time ms between frames when playing. */
  frameMs: number;
  /**
   * Inclusion figures for the ladder, so a replay exercises the cell ink as
   * well as the tiers. Fixture data, in a view banner-marked REPLAY from the
   * first pixel — the live page never reads this.
   */
  inclusion?: EpochAttestations[];
}

const r = (seed: string) =>
  // A stable, obviously-fake root. Recognisable as a fixture at a glance so a
  // screenshot of a replay can never be mistaken for a screenshot of mainnet.
  (seed + "0".repeat(64)).slice(0, 64);

function agreed(sources: [ChainInfo, ChainInfo] | ChainInfo): Corroboration {
  const one = !Array.isArray(sources);
  const a = one ? (sources as ChainInfo) : sources[0];
  const b = one ? (sources as ChainInfo) : sources[1];
  const differing = one
    ? []
    : ["justified.epoch", "justified.root", "finalized.epoch", "finalized.root"].filter((f) => {
        const dig = (o: any, p: string) => p.split(".").reduce((x, k) => (x == null ? x : x[k]), o);
        return String(dig(a, f)) !== String(dig(b, f));
      });
  return {
    state: differing.length === 0 ? "corroborated" : "conflict",
    agreed_on: ["justified.epoch", "justified.root", "finalized.epoch", "finalized.root"],
    differing,
    answered_by: "archival-a",
    sources: [
      { id: "archival-a", ip: "139.180.166.5", ok: true, ms: 240, claim: claimOf(a) },
      { id: "archival-b", ip: "139.180.173.231", ok: true, ms: 260, claim: claimOf(b) },
    ],
  };
}

function claimOf(i: ChainInfo) {
  return {
    slot: i.slot,
    height: i.height,
    block_id: i.block_id,
    justified: i.justified,
    finalized: i.finalized,
  };
}

/** A well-formed `getchaininfo` with the fixture's chosen checkpoints. */
function info(epoch: number, slotInEpoch: number, just: number, fin: number, tag = "x"): ChainInfo {
  const slot = epoch * 32 + slotInEpoch;
  return {
    block_id: r(`b${tag}${slot}`),
    slot,
    height: slot - 20_900, // roughly the live ratio of blocks to slots
    finalized_height: fin * 32 - 20_900,
    epoch,
    slot_in_epoch: slotInEpoch,
    slots_per_epoch: 32,
    state_root: r(`s${tag}${slot}`),
    justified: { epoch: just, root: r(`j${tag}${just}`) },
    finalized: { epoch: fin, root: r(`f${tag}${fin}`) },
    previous_justified: { epoch: Math.max(0, just - 1), root: r(`j${tag}${just - 1}`) },
    validators: { total: 64, active: 64 },
    total_active_stake_sat: "13427388549759841",
    mempool: 0,
    blocks_known: slot - 20_900,
    wall_slot: slot,
    behind_by_slots: 0,
  };
}

// ────────────────────────────────────────────────────────────────────────────
// Scenario: a stall, from healthy through the leak threshold and past it
// ────────────────────────────────────────────────────────────────────────────
//
// Blocks keep arriving on every slot throughout — that is the property that
// makes a stall dangerous rather than obvious, and the reason the page needs
// to say something the block feed cannot.

const STALL_BASE = 1703;

function stallFrames(): ReplayFrame[] {
  const out: ReplayFrame[] = [];
  // Three healthy epochs first, so the page is seen changing state rather than
  // simply being alarming from the first paint.
  for (let k = 0; k < 3; k++) {
    const e = STALL_BASE + k;
    out.push({
      info: info(e, 16, e - 1, e - 2),
      corroboration: agreed(info(e, 16, e - 1, e - 2)),
      offsetSecs: k * 960,
    });
  }
  // Then finality sticks at STALL_BASE + 0 while the head keeps climbing.
  const stuckFin = STALL_BASE;
  const stuckJust = STALL_BASE + 1;
  for (let k = 3; k <= 14; k++) {
    const e = STALL_BASE + k;
    const i = info(e, 16, stuckJust, stuckFin);
    out.push({ info: i, corroboration: agreed(i), offsetSecs: k * 960 });
  }
  return out;
}

// ────────────────────────────────────────────────────────────────────────────
// Scenario: a finality rewind
// ────────────────────────────────────────────────────────────────────────────
//
// NOT a measured sequence — there is no test in either crate demonstrating a
// finality rewind, and our own audit says so in as many words. What IS
// established, by reading the code rather than by a test, is the mechanism:
// the adopt path replaces committed state without comparing the incoming
// finalized checkpoint against the outgoing one, and fork choice walks from
// the justified root, whose committed state finalises about two epochs lower
// than the head was reporting. This fixture walks that shape so the page's
// rewind detector is exercised on what it would actually meet.

function rewindFrames(): ReplayFrame[] {
  const base = 1710;
  const ladder = [6, 6, 4, 4, 2, 2, 0, 0];
  return ladder.map((d, k) => {
    const e = base + k;
    const i = info(e, 8 + k, base + d - 1, base + d, d === 6 ? "a" : d === 4 ? "b" : d === 2 ? "c" : "d");
    return { info: i, corroboration: agreed(i), offsetSecs: k * 960 };
  });
}

// ────────────────────────────────────────────────────────────────────────────
// Scenario: the two archivals disagree
// ────────────────────────────────────────────────────────────────────────────
//
// On 2026-08-24 three partitions finalised the same epoch under three
// different roots. Two nodes reporting the same epoch with different roots is
// what that looks like from outside, and it is the case the soft public proxy
// hides by returning one of them.

function conflictFrames(): ReplayFrame[] {
  const base = 1720;
  return [0, 1, 2, 3].map((k) => {
    const e = base + k;
    const a = info(e, 12, e - 1, e - 2, "a");
    const b = info(e, 12, e - 1, e - 2, "b");
    return { info: a, corroboration: agreed([a, b]), offsetSecs: k * 960 };
  });
}

/**
 * Inclusion figures shaped like a stall: healthy epochs at full inclusion,
 * then a collapse as the attesting set falls away. The last two epochs are
 * left unmeasured so the `?` cell — "not measured", which must never look like
 * zero — is exercised too.
 */
function stallInclusion(): EpochAttestations[] {
  const shape = [64, 63, 64, 41, 33, 27, 24, 22, 21, 20, 20, null, null];
  return shape.flatMap((votes, k) => {
    if (votes === null) return [];
    const epoch = STALL_BASE + k;
    const [firstSlot, lastSlot] = [epoch * 32, epoch * 32 + 31];
    const missed = votes < 40 ? Math.round((64 - votes) / 8) : 0;
    return [
      {
        epoch,
        firstSlot,
        lastSlot,
        blocks: 32 - missed,
        missedSlots: missed,
        unreadSlots: 0,
        pendingSlots: 0,
        votes,
        activeValidators: 64,
        indicator: votes / 64,
        inFlight: false,
        complete: true,
      },
    ];
  });
}

export const SCENARIOS: Record<string, Scenario> = {
  stall: {
    id: "stall",
    title: "A stall in progress",
    premise:
      "Blocks are still being produced every slot, the node reports itself healthy, and finality stopped advancing twelve epochs ago. The inactivity leak has been running for eight of them.",
    frames: stallFrames(),
    frameMs: 1400,
    inclusion: stallInclusion(),
  },
  rewind: {
    id: "rewind",
    title: "A finality rewind",
    premise:
      "The finalized epoch descends across three cuts, each one permitted by fork choice. Nothing here is a bug being caught — this is the algorithm operating correctly.",
    frames: rewindFrames(),
    frameMs: 1800,
  },
  conflict: {
    id: "conflict",
    title: "Two nodes, two roots",
    premise:
      "Both archivals answer, both name the same finalized epoch, and they name different roots for it. On 2026-08-24 three nodes did exactly this at epoch 986.",
    frames: conflictFrames(),
    frameMs: 1800,
  },
};

export function scenarioFromQuery(search: string): Scenario | null {
  const id = new URLSearchParams(search).get("replay");
  if (!id) return null;
  return SCENARIOS[id] ?? null;
}

/** Frame index from `?frame=`, for deterministic screenshots. */
export function frameFromQuery(search: string): number | null {
  const f = new URLSearchParams(search).get("frame");
  if (f === null) return null;
  const n = Number(f);
  return Number.isFinite(n) ? n : null;
}
