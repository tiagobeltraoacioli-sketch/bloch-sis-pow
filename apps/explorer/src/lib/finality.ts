// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The finality model.
// ---------------------------------------------------------------------------
// Everything this file computes is arithmetic over what the RPC actually
// returns. Nothing here infers, smooths, or reassures. Where a number cannot
// be derived from the available data, the type says `null` and the page is
// required to render the absence rather than a plausible substitute.
//
// This is a deliberate split: the page decides how a fact looks, this file
// decides what is true. A reviewer who wants to know whether the explorer is
// lying reads this file and nothing else.
// ---------------------------------------------------------------------------

// ────────────────────────────────────────────────────────────────────────────
// Consensus constants, quoted from the crate that enforces them
// ────────────────────────────────────────────────────────────────────────────
//
// Every value below is copied from `crates/bloch-pos-committee/src/params.rs`
// with its line cited. They are duplicated here because a browser cannot read
// Rust — which means they can drift, and a drifted constant on a page about
// honesty is worse than no page. `CONSENSUS_SOURCE` names the exact file so a
// reviewer can diff by hand; nothing in the UI may state one of these numbers
// without it being sourced from this object.

export const CONSENSUS_SOURCE = "crates/bloch-pos-committee/src/params.rs";

export const CONSENSUS = {
  /** `SLOTS_PER_EPOCH` (params.rs:30). */
  slotsPerEpoch: 32,
  /** `SLOT_DURATION_SECS` (params.rs:34). */
  slotSecs: 30,

  /**
   * `INACTIVITY_LEAK_THRESHOLD_EPOCHS` (params.rs:59).
   *
   * Epochs of non-finality after which the inactivity leak begins destroying
   * the stake of validators that are not attesting. This is the line where a
   * slow chain becomes an expensive one.
   */
  leakThresholdEpochs: 4,

  /** `INACTIVITY_LEAK_QUOTIENT` (params.rs:67) — the per-epoch bite divisor. */
  leakQuotient: 64,

  /**
   * `MIN_QUORUM_DENOMINATOR_NUM/DEN` (params.rs:147,149) — one half.
   *
   * The floor the quorum denominator may never fall below… once it binds. It
   * does not bind today; see `leakRecoveryActive`.
   */
  quorumFloor: [1, 2] as const,

  /**
   * `LEAK_RECOVERY_ACTIVATION_EPOCH = u64::MAX` (params.rs:597).
   *
   * `u64::MAX` is the idiom this codebase uses for "written, tested, and
   * deliberately never reached". Both the quorum-denominator floor above and
   * the rule that lets a returning validator's leak debt fall are gated behind
   * it. So on the live chain the denominator is leak-adjusted with **no floor
   * at all**, and leaked stake never comes back.
   */
  leakRecoveryActive: false,

  /** `LEAKED_ROSTER_ACTIVATION_EPOCH` (params.rs:244) — this one IS live. */
  leakedRosterActivationEpoch: 1400,

  /**
   * The structural minimum gap between head epoch and finalized epoch.
   *
   * Finalising epoch n requires epoch n+1 to justify on top of it, and the
   * head is inside epoch n+2 while that happens. Two is therefore healthy and
   * is not a stall — a page that alarms at two would alarm always.
   */
  floorGap: 2,
} as const;

/** Seconds in one epoch. 32 × 30 = 960 — sixteen minutes. */
export const EPOCH_SECS = CONSENSUS.slotsPerEpoch * CONSENSUS.slotSecs;

// ────────────────────────────────────────────────────────────────────────────
// Facts, each carrying the grade of its evidence
// ────────────────────────────────────────────────────────────────────────────
//
// READ THIS BEFORE ADDING A NUMBER HERE.
//
// The first draft of this file carried three figures — "27 stalls", "longest
// 45 epochs", "one node fakes a quorum after 28 epochs" — under a comment
// claiming they were test output. An audit of the consensus crate found that
// none of them exists anywhere in the repository, and that two of the tests
// this file named do not exist either. They had been written from a plausible
// memory of the shape of the problem.
//
// That is precisely the failure this page was commissioned to stop. A page
// about the difference between a claim and its support cannot itself publish
// unsupported claims, and the fact that the invented numbers pointed the same
// direction as the true ones is not a defence — it is what made them easy to
// write and hard to notice.
//
// So every figure below now carries a `grade`, and the UI renders it:
//
//   "asserted"    a test fails if this number changes. The strongest thing we
//                 have.
//   "modelled"    computed by a test from a simplified model (equal stake, a
//                 clean partition) and printed rather than asserted. True of
//                 the model; the chain is not the model.
//   "reported"    stated in the source as observed in production, with no
//                 dataset in the repository to re-derive it from.
//   "constant"    a consensus constant, read straight from params.rs.
//
// If a number cannot be given one of those four, it does not go on the page.

export type Grade = "asserted" | "modelled" | "reported" | "constant";

export interface Fact {
  /** The number, when there is one. */
  value: number | null;
  grade: Grade;
  /** What it means, in one line, in the terms the page will use it. */
  claim: string;
  /** file:line, so a reader can check it. */
  source: string;
}

export const FACTS = {
  leakThreshold: {
    value: 4,
    grade: "constant",
    claim:
      "Epochs of non-finality tolerated intact. Strictly after this, validators that are not attesting begin losing stake.",
    source: "crates/bloch-pos-committee/src/params.rs:59 (INACTIVITY_LEAK_THRESHOLD_EPOCHS)",
  },
  minorityJustifies: {
    value: 25,
    grade: "modelled",
    claim:
      "A partition holding 4 of 64 validators (6.25%) reaches two thirds of what is left and justifies its own branch — after roughly 92% of network stake has leaked away.",
    source:
      "crates/bloch-pos-committee/src/params.rs:118-121; the figure is printed by finality.rs test a_partitioned_minority_finalizes_because_the_leak_shrinks_the_denominator, which asserts only that it happens after the leak threshold. Equal-stake 64-validator model, not a chain measurement.",
  },
  sixtyOfSixtyFourZeroed: {
    value: 56,
    grade: "asserted",
    claim:
      "After 56 epochs of unbroken non-finality, 60 of 64 validators are at exactly zero stake. A test fails if this changes.",
    source: "crates/bloch-pos-committee/src/finality.rs:1126-1134",
  },
  drainedToZero: {
    value: 70,
    grade: "asserted",
    claim: "An absent validator's stake has drained to exactly zero within 70 epochs of stall.",
    source: "crates/bloch-pos-committee/src/prova.rs:167-218 (STALL_EPOCHS)",
  },
  productionStalls: {
    value: 110,
    grade: "reported",
    claim:
      "Production has reported non-finality delays in the 53-56 and 90-110 epoch bands — nodes that never reached quorum at all.",
    source: "crates/bloch-pos-committee/src/finality.rs:1073-1074 and :517-518 (prose; no dataset in-tree)",
  },
  divergentFinality: {
    value: 986,
    grade: "reported",
    claim:
      "On 2026-08-24 three nodes finalised epoch 986 under three different roots, and no amount of arriving blocks reunified them.",
    source:
      "crates/bloch-pos-committee/src/params.rs:80-83. An internal audit records a competing explanation of the same incident, so the mechanism below is the documented one rather than the only candidate.",
  },
} satisfies Record<string, Fact>;

/**
 * The two defects, restated with the audit's corrections applied.
 *
 * Note what changed between drafts and why it matters: defect 2 is NOT
 * demonstrated by a test. It is demonstrated by reading the adopt path, which
 * performs no comparison at all. That is weaker evidence than a failing test
 * and stronger evidence than a recollection, and saying which it is is the
 * whole job.
 */
export interface MeasuredDefect {
  id: string;
  title: string;
  grade: Grade | "by-inspection";
  /** One sentence, plain, no hedging. */
  short: string;
  /** The mechanism, for a reader who wants to know why. */
  mechanism: string;
  /** Where it is demonstrated. */
  evidence: string;
}

export const DEFECTS: MeasuredDefect[] = [
  {
    id: "quorum",
    title: "The quorum denominator shrinks, and nothing stops it",
    grade: "modelled",
    short:
      "Modelled on an equal-stake set, a partition holding 6.25% of the validators finalises its own branch — with no bug in the finality code and no rule broken by anyone.",
    mechanism:
      "Justification needs two thirds of the active stake, and that total is leak-adjusted: stake that is not attesting is destroyed epoch by epoch and subtracted from the very total the two-thirds test measures against. A node that can hear only part of the network counts the rest as absent, the absent stake leaks, and the denominator shrinks until it fits inside the minority that node can still hear. A floor of one half exists in the code — and does not bind: it and leak recovery are both gated behind LEAK_RECOVERY_ACTIVATION_EPOCH = u64::MAX. So today the denominator is leak-adjusted with no floor, and leaked stake never comes back.",
    evidence:
      "crates/bloch-pos-committee/src/finality.rs:975-995, with the mutation control at :1001-1014 showing the minority never justifies once the leak is taken back out of the denominator. Inertness pinned in CI at tests/integration_book_claims.rs:466-471.",
  },
  {
    id: "latch",
    title: "`finalized` is not a latch across a reorg",
    grade: "by-inspection",
    short:
      "The finalized epoch can go down. There is no test for this — there is something plainer: the code that adopts a branch never compares the incoming finalized checkpoint against the outgoing one.",
    mechanism:
      "Inside the finality gadget the checkpoint is monotone. But the node does not own that gadget across a reorg: adopting a branch replaces the whole committed state with an ancestor's. Fork choice walks from the JUSTIFIED root, and the justified root for epoch E is a block in epoch E-1 whose committed state predates the boundary walk that finalised E-1 — so reorging to it installs a state finalising around E-3 while the node had been reporting E-1. Nothing prunes branches by finalized checkpoint, and a header carrying its parent's older finalized root is valid on a competing branch. Two independent nodes do not fix this: both can rewind, and they can rewind independently.",
    evidence:
      "By inspection of crates/bloch-pos-node/src/engine.rs:1678-1760 (the adopt at :1730 is unconditional) and crates/bloch-pos-committee/src/forkchoice.rs:184. The one mention of finality on that path is a log line guarded `if after > before`, so a downward move prints nothing. No ratchet-shaped test exists in either crate.",
  },
  {
    id: "slashing",
    title: "The penalty behind the guarantee cannot currently be applied",
    grade: "by-inspection",
    short:
      "Reversing a finalized checkpoint is supposed to cost the attacker a third of the bonded stake. That penalty is unreachable from the network: slashing evidence cannot travel over the wire at all.",
    mechanism:
      "Evidence is encoded one-way. The evidence arm folds its nested messages in through the roots they were signed over plus their signatures, and never re-serialises the header or the attestation — a signing root is a hash, and nothing recovers the envelope from it. So decoding refuses outright rather than pretending, and a verifier receiving evidence through a block body would hold only hashes to re-verify against. Evidence needs its own wire shape carrying both envelopes whole, and that does not exist. Until it does, the slashing path is unreachable from the network however complete the slashing module is. The finality guarantee on this chain is therefore economic in name; the cost it threatens cannot presently be imposed.",
    evidence:
      "crates/bloch-pos-committee/src/transition.rs:715-729 and :782 — tag 0x05 returns TxDecodeError::EvidenceNotDecodable. The consequence is stated in the source itself.",
  },
];

/**
 * How to treat a finalized epoch, in the explorer's own voice.
 *
 * DELIBERATELY NOT A QUOTATION. An earlier draft presented a specific rule —
 * "finalized + 3 epochs" — as published guidance. It is not published, no
 * document names a depth, and the document that comes closest is marked
 * "Delivery: file, to named contacts. Not published." Putting its contents on
 * a public explorer would be a disclosure decision wearing a citation's
 * clothes.
 *
 * What survives is what this page can defend from the consensus code, which is
 * enough: a margin is required, the protocol does not supply its size, and the
 * operator has to choose it knowing why it is needed.
 */
export const SETTLEMENT_POSTURE = {
  /**
   * There is no default. A number here would be read as a recommendation, and
   * the protocol gives us nothing to base one on.
   */
  defaultMarginEpochs: null as number | null,
  requirements: [
    "Require two independent nodes to report the same finalized ROOT at the same EPOCH. Disagreement is a hold condition, not a retry.",
    "Add a margin of epochs past the finalized checkpoint. The margin is what absorbs a rewind, and it is the only thing here that does. Nothing in the protocol tells you how large it should be.",
    "Re-read immediately before releasing value. A finalized reading is not durable; a block that has stopped being finalized is a hold.",
    "Alert on the finalized epoch not advancing, separately from height. Production continues while finality stops, and the node looks healthy throughout.",
    "Alert on the finalized epoch moving backwards, and on the root at a given epoch changing. Neither should happen. Both do.",
    "Do not read a rising finalized epoch as recovery. Because the denominator shrinks and has no floor, a partitioned minority reaching two thirds of what remains will finalise its own branch.",
  ],
} as const;

// ────────────────────────────────────────────────────────────────────────────
// Wire types
// ────────────────────────────────────────────────────────────────────────────

export interface Checkpoint {
  epoch: number;
  root: string;
}

/** `getchaininfo`, in full. Superset of the older `G4Head`. */
export interface ChainInfo {
  block_id: string;
  slot: number;
  height: number;
  finalized_height: number;
  epoch: number;
  slot_in_epoch: number;
  slots_per_epoch: number;
  state_root: string;
  justified: Checkpoint;
  finalized: Checkpoint;
  previous_justified?: Checkpoint;
  validators?: { total: number; active: number };
  total_active_stake_sat?: string;
  mempool?: number;
  blocks_known?: number;
  /** The slot wall-clock time says it should be. */
  wall_slot?: number;
  /** `wall_slot - slot`. The node's own admission of how far behind it is. */
  behind_by_slots?: number;
}

/** What `/g4` adds on top of a plain JSON-RPC result. */
export interface Corroboration {
  /** `corroborated` two nodes agreed · `single` only one answered · `conflict` they disagree · `none` nobody answered. */
  state: "corroborated" | "single" | "conflict" | "none";
  agreed_on: string[];
  differing: string[];
  answered_by: string;
  sources: {
    id: string;
    ip: string;
    ok: boolean;
    ms: number;
    error?: string;
    claim?: {
      slot: number;
      height: number;
      block_id: string;
      justified: Checkpoint;
      finalized: Checkpoint;
    };
  }[];
}

export interface CorroboratedHead {
  info: ChainInfo;
  corroboration: Corroboration;
  /** Client clock at the moment of the read. */
  readAt: number;
}

// ────────────────────────────────────────────────────────────────────────────
// Transport
// ────────────────────────────────────────────────────────────────────────────

/**
 * The corroborating endpoint (`functions/g4.js`), which fans out to both
 * keyless archivals and reports whether they agreed.
 *
 * The soft public proxy at `posternlabs.com/g4rpc` is deliberately NOT the
 * default here. It answers `getchaininfo` with a single uncorroborated node's
 * opinion and does not say so, which is the exact thing this page exists to
 * stop doing.
 */
export const G4_CORROBORATED = "/g4";

export class RpcError extends Error {}

export async function corroboratedCall<T>(
  method: string,
  params: unknown[] = [],
  signal?: AbortSignal,
): Promise<{ result: T; corroboration: Corroboration }> {
  const res = await fetch(G4_CORROBORATED, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal,
  });
  const body = await res.json();
  if (body.error) throw new RpcError(body.error.message ?? "rpc error");
  return { result: body.result as T, corroboration: body.corroboration as Corroboration };
}

export async function readHead(signal?: AbortSignal): Promise<CorroboratedHead> {
  const { result, corroboration } = await corroboratedCall<ChainInfo>("getchaininfo", [], signal);
  return { info: result, corroboration, readAt: Date.now() };
}

// ────────────────────────────────────────────────────────────────────────────
// Attestation inclusion — NOT a participation rate
// ────────────────────────────────────────────────────────────────────────────
//
// This section is named the way it is because of a mistake worth keeping in
// the file. The obvious move is to sum `attestation_count` across an epoch's
// blocks, divide by 64, and call the result participation. It reads well, it
// tracks the right direction, and it is wrong in four independent ways. An
// audit of the consensus crate found all four:
//
//  1. DUPLICATES ARE LEGAL AND UNCOUNTED. The transition inserts each vote
//     into a map keyed by (validator, signing_root) — there is no rejection of
//     an attestation another block already carried. One node's local pool
//     housekeeping usually prevents it, but that is housekeeping, not a rule;
//     gossip reordering and reorgs both re-expose it. The sum can exceed 64.
//
//  2. MISSED SLOTS TRUNCATE IT SILENTLY. A proposer may include earlier
//     slots' attestations, but only within its own epoch — the window is
//     `s <= b` and `epoch_of(s) == epoch_of(b)`, so at most 31 slots late and
//     never across a boundary. If the last proposer of an epoch misses, every
//     vote not yet carried is lost. The votes existed; nothing records them.
//
//  3. A REORG RESCORES THE PAST. Epoch-N blocks can be replaced after you
//     have summed them, and `finalized` is not a latch, so an epoch already
//     scored can be scored differently later.
//
//  4. CONSENSUS DOES NOT COMPUTE IT THIS WAY. The committed participation set
//     is `current_participation`, a deduplicated set of distinct validators
//     committed into the state root, and finality reads `pending_votes` at the
//     epoch boundary rather than block inclusion at all. The number that
//     decides justification and the number derivable from blocks are different
//     quantities over different sets.
//
// AND THE ONE THAT MATTERS MOST: the quantity that actually decides finality
// on this chain — the leak-adjusted denominator — is exposed by NO RPC. Not
// the leak ledger, not the adjusted total. An explorer cannot show it. The
// page states that rather than substituting the number it can compute for the
// number that counts, and draws the absence where the measurement would go.
//
// What is left is still worth having: attestations included per epoch is a
// real throughput signal, and it collapsing is real news. It is presented as
// a count against the active-set size for scale, explicitly not as a rate.
//
// Sourcing for the above: `attestation_count` is `body.attestations.len()`
// (crates/bloch-pos-node/src/rpc.rs:1741); an `Attestation` names one
// `validator: u32` with no aggregation anywhere in the crate
// (crates/bloch-pos-committee/src/attestation.rs:78-85); committees partition
// the active set into 32 contiguous chunks, giving exactly 2 seats per slot at
// n=64 (crates/bloch-pos-committee/src/committees.rs:275-350); the inclusion
// window is crates/bloch-pos-committee/src/transition.rs:3369-3390. There is
// no MAX_ATTESTATIONS constant — it is proposed in a capacity spec and not
// built. `COMMITTEE_SIZE = 128` and `SLOT_SUBCOMMITTEE_SIZE = 8` are dead
// names from a superseded design that the node never reads; sizing anything
// from them is meaningless.

/** A per-slot answer. The three states are deliberately distinguishable. */
export type SlotAnswer =
  | { kind: "block"; attestation_count: number }
  /** The node answered SLOT_EMPTY: a real missed proposal. */
  | { kind: "empty" }
  /** We asked and did not get an answer. NOT a missed proposal. */
  | { kind: "unknown" };

export interface EpochAttestations {
  epoch: number;
  firstSlot: number;
  lastSlot: number;
  /** Slots that returned a block. */
  blocks: number;
  /** Slots the node explicitly reported empty — genuinely missed proposals. */
  missedSlots: number;
  /** Slots we failed to read. Must never be shown as missed. */
  unreadSlots: number;
  /** Slots not yet reached (the in-flight epoch only). */
  pendingSlots: number;
  /** Sum of `attestation_count` over the blocks found. A COUNT, not a rate. */
  votes: number;
  /** Active validator set size, for scale only. Not a denominator. */
  activeValidators: number;
  /**
   * `votes / activeValidators`, for drawing a bar. MAY EXCEED 1 (duplicates
   * are legal). The UI is required to label this as inclusion, never as
   * participation, and to render the overflow rather than clamping it away.
   */
  indicator: number | null;
  inFlight: boolean;
  /** Every slot answered, epoch closed. Anything less is not comparable. */
  complete: boolean;
}

export function epochOf(slot: number): number {
  return Math.floor(slot / CONSENSUS.slotsPerEpoch);
}

export function epochSlots(epoch: number): [number, number] {
  const first = epoch * CONSENSUS.slotsPerEpoch;
  return [first, first + CONSENSUS.slotsPerEpoch - 1];
}

/**
 * Fold per-slot answers into one epoch's inclusion figures.
 *
 * A slot we never asked about and a slot the node called empty are kept apart
 * throughout: counting our own request budget as a liveness failure would
 * invent missed proposals out of nothing, which is the same class of error as
 * inventing the numbers this file used to carry.
 */
export function foldEpoch(
  epoch: number,
  slots: Map<number, SlotAnswer>,
  activeValidators: number,
  headSlot: number,
): EpochAttestations {
  const [firstSlot, lastSlot] = epochSlots(epoch);
  let blocks = 0;
  let missedSlots = 0;
  let unreadSlots = 0;
  let pendingSlots = 0;
  let votes = 0;

  for (let s = firstSlot; s <= lastSlot; s++) {
    if (s > headSlot) {
      pendingSlots++;
      continue;
    }
    const v = slots.get(s);
    if (v === undefined || v.kind === "unknown") unreadSlots++;
    else if (v.kind === "empty") missedSlots++;
    else {
      blocks++;
      votes += v.attestation_count;
    }
  }

  const inFlight = pendingSlots > 0;
  const complete = unreadSlots === 0 && !inFlight;
  return {
    epoch,
    firstSlot,
    lastSlot,
    blocks,
    missedSlots,
    unreadSlots,
    pendingSlots,
    votes,
    activeValidators,
    // Withheld unless the epoch is closed and fully read. A partial epoch
    // produces a smaller number that looks like worse inclusion, for a reason
    // that has nothing to do with the network.
    indicator: complete && activeValidators > 0 ? votes / activeValidators : null,
    inFlight,
    complete,
  };
}

// ────────────────────────────────────────────────────────────────────────────
// Stall grading
// ────────────────────────────────────────────────────────────────────────────

export type StallGrade =
  | "floor" //     gap 0-2: the structural minimum. Healthy.
  | "lagging" //   gap 3: one epoch late. Common, uninteresting, but not silent.
  | "threshold" // gap 4: the leak begins from here.
  | "leaking" //   gap > 4: stake is being destroyed, every epoch, permanently.
  | "capture"; //  gap >= 25: a small partition can model-plausibly self-justify.

export interface StallState {
  /** Epochs between the head epoch and the finalized epoch. */
  gap: number;
  /** Epochs of non-finality beyond the structural floor. Zero when healthy. */
  overFloor: number;
  grade: StallGrade;
  /** Wall-clock estimate of how long finality has been behind. */
  approxSecs: number;
  /** Plain sentence, for the banner. No adjective outruns its evidence. */
  headline: string;
  detail: string;
  /** The grade of the evidence behind this band's threshold. Rendered. */
  grounding: Grade | null;
}

/**
 * Grade a stall against the four thresholds we can actually source.
 *
 * The bands changed after an audit. An earlier version placed the top band at
 * 28 epochs on the claim that one node alone could manufacture a quorum there.
 * The qualitative claim is sourced — params.rs:80-81 says "a handful of nodes —
 * one, even — held two thirds of what remained and finalized entirely alone" —
 * but the number 28 was not, and it was also implausible against the modelled
 * figures: a FOUR-node partition needs ~25 epochs and ~92% of stake destroyed,
 * so a single node must need strictly longer, not shorter. The band now sits at
 * the modelled 25 and is labelled as modelled.
 */
export function gradeStall(head: ChainInfo): StallState {
  const gap = head.epoch - head.finalized.epoch;
  const overFloor = Math.max(0, gap - CONSENSUS.floorGap);
  const approxSecs = overFloor * EPOCH_SECS;

  let grade: StallGrade;
  if (gap >= (FACTS.minorityJustifies.value ?? 25)) grade = "capture";
  else if (gap > CONSENSUS.leakThresholdEpochs) grade = "leaking";
  else if (gap === CONSENSUS.leakThresholdEpochs) grade = "threshold";
  else if (gap === CONSENSUS.floorGap + 1) grade = "lagging";
  else grade = "floor";

  const headline = {
    floor: "Finality is current.",
    lagging: "Finality is one epoch behind the floor.",
    threshold: "Finality has stalled to the inactivity-leak threshold.",
    leaking: "Finality has stalled. Stake is being destroyed.",
    capture:
      "Finality has stalled past the point where a small partition can justify a branch of its own.",
  }[grade];

  const detail = {
    floor:
      "The head is two epochs ahead of the finalized checkpoint, which is the structural minimum: finalising epoch n requires epoch n+1 to justify on top of it.",
    lagging:
      "One epoch beyond the floor. This usually resolves on its own; it is shown because the difference between three and five is invisible unless three is.",
    threshold: `${CONSENSUS.leakThresholdEpochs} epochs of non-finality is INACTIVITY_LEAK_THRESHOLD_EPOCHS. From the next epoch, validators that are not attesting begin losing stake.`,
    leaking:
      "The inactivity leak is running. Non-attesting validators lose stake every epoch, at a rate that grows the longer this lasts, and the loss is subtracted from the quorum denominator. It is permanent: leak recovery is gated behind an activation epoch of u64::MAX and does not bind. The set that can finalise is shrinking while you read this.",
    capture: `At ${FACTS.minorityJustifies.value} epochs a modelled 4-of-64 partition — 6.25% of the validators — has seen enough of the network's stake destroyed to hold two thirds of what is left, and finalises its own branch. Anything finalised from here may be a claim by whoever is still talking rather than by the network. The model is equal-stake and clean-partition; this chain is neither, so treat the threshold as an order of magnitude, not a line.`,
  }[grade];

  const grounding: Grade | null = {
    floor: null,
    lagging: null,
    threshold: "constant" as Grade,
    leaking: "constant" as Grade,
    capture: "modelled" as Grade,
  }[grade];

  return { gap, overFloor, grade, approxSecs, headline, detail, grounding };
}

/** Is this a state that should shout? Drives the page-level alert band. */
export function isAlarming(s: StallState): boolean {
  return s.grade === "threshold" || s.grade === "leaking" || s.grade === "capture";
}

// ────────────────────────────────────────────────────────────────────────────
// Observed history — what THIS browser has watched happen
// ────────────────────────────────────────────────────────────────────────────
//
// There is no epoch-history RPC on this chain (`getepochsummary`,
// `getparticipation`, `getcheckpoints` all answer "method not found"), and
// walking 32 slots per epoch at roughly a second a call is not something a web
// page may do to a node for the sake of a chart.
//
// So history here is honestly scoped: it is what this browser has seen while
// the tab was open, persisted locally, and labelled as such. It is not the
// chain's history and the page never claims it is. When an indexer is attached
// (`probeIndexer`), real history replaces it and the label changes.

const STORE_KEY = "bloch.finality.observed.v1";
const MAX_SAMPLES = 720; // ≈ 6 h at one sample per 30 s.

export interface Sample {
  t: number;
  epoch: number;
  slot: number;
  slotInEpoch: number;
  height: number;
  justifiedEpoch: number;
  justifiedRoot: string;
  finalizedEpoch: number;
  finalizedRoot: string;
  corroboration: Corroboration["state"];
}

export function sampleOf(h: CorroboratedHead): Sample {
  return {
    t: h.readAt,
    epoch: h.info.epoch,
    slot: h.info.slot,
    slotInEpoch: h.info.slot_in_epoch,
    height: h.info.height,
    justifiedEpoch: h.info.justified.epoch,
    justifiedRoot: h.info.justified.root,
    finalizedEpoch: h.info.finalized.epoch,
    finalizedRoot: h.info.finalized.root,
    corroboration: h.corroboration.state,
  };
}

export function loadObserved(): Sample[] {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return [];
    const v = JSON.parse(raw);
    return Array.isArray(v) ? (v as Sample[]) : [];
  } catch {
    // Private windows, cleared site data, and browsers set to block storage
    // all land here. An empty history is a correct answer, not an error.
    return [];
  }
}

export function saveObserved(samples: Sample[]): void {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(samples.slice(-MAX_SAMPLES)));
  } catch {
    /* storage unavailable — the page works without it */
  }
}

/**
 * Append a sample, collapsing runs where nothing changed.
 *
 * Only transitions are kept plus the newest reading, because the interesting
 * object is the ladder of checkpoint changes, not a log of the poll.
 */
export function appendSample(samples: Sample[], s: Sample): Sample[] {
  const last = samples[samples.length - 1];
  if (
    last &&
    last.justifiedEpoch === s.justifiedEpoch &&
    last.justifiedRoot === s.justifiedRoot &&
    last.finalizedEpoch === s.finalizedEpoch &&
    last.finalizedRoot === s.finalizedRoot &&
    last.epoch === s.epoch
  ) {
    // Same checkpoints, same epoch: replace the tail so the freshest slot and
    // timestamp win without growing the log.
    return [...samples.slice(0, -1), s];
  }
  return [...samples, s].slice(-MAX_SAMPLES);
}

// ────────────────────────────────────────────────────────────────────────────
// Rewind detection — the latch defect, caught live
// ────────────────────────────────────────────────────────────────────────────

export type RewindKind =
  /** The finalized epoch number went DOWN. */
  | "epoch-descended"
  /** Same epoch, different root: the chain re-finalised that epoch elsewhere. */
  | "root-changed";

export interface RewindEvent {
  kind: RewindKind;
  at: number;
  from: { epoch: number; root: string };
  to: { epoch: number; root: string };
}

/**
 * Every finality rewind in the observed samples.
 *
 * This is not error handling. A rewind here is the algorithm working as
 * specified — fork choice walking from the justified root, whose committed
 * state already finalises two epochs below the head. It is recorded and shown
 * because a reader who believes `finalized` only ever rises will size their
 * risk wrongly, and because the chain has been measured doing it.
 */
export function findRewinds(samples: Sample[]): RewindEvent[] {
  const out: RewindEvent[] = [];
  for (let i = 1; i < samples.length; i++) {
    const a = samples[i - 1];
    const b = samples[i];
    if (b.finalizedEpoch < a.finalizedEpoch) {
      out.push({
        kind: "epoch-descended",
        at: b.t,
        from: { epoch: a.finalizedEpoch, root: a.finalizedRoot },
        to: { epoch: b.finalizedEpoch, root: b.finalizedRoot },
      });
    } else if (b.finalizedEpoch === a.finalizedEpoch && b.finalizedRoot !== a.finalizedRoot) {
      out.push({
        kind: "root-changed",
        at: b.t,
        from: { epoch: a.finalizedEpoch, root: a.finalizedRoot },
        to: { epoch: b.finalizedEpoch, root: b.finalizedRoot },
      });
    }
  }
  return out;
}

/** Highest finalized epoch this browser has ever seen, for the rewind watermark. */
export function highWaterFinalized(samples: Sample[]): number | null {
  if (samples.length === 0) return null;
  return samples.reduce((m, s) => Math.max(m, s.finalizedEpoch), 0);
}

// ────────────────────────────────────────────────────────────────────────────
// The settlement answer
// ────────────────────────────────────────────────────────────────────────────

export type SettlementVerdict =
  | "not-finalized"
  | "finalized-no-margin"
  | "margin-met"
  | "uncorroborated";

export interface Settlement {
  verdict: SettlementVerdict;
  /** Epochs between the subject epoch and the finalized checkpoint. */
  depth: number | null;
  /** What an operator is told. Never the word "safe". */
  advice: string;
}

/**
 * Where one epoch stands, against a margin the OPERATOR chose.
 *
 * `marginEpochs` is a parameter and has no default, deliberately. An earlier
 * version hard-coded three and presented it as published guidance; no document
 * names a depth, and inventing one here would have every reader treat it as
 * the protocol's recommendation. The protocol has no opinion, and saying so is
 * more useful than a number that would be believed.
 *
 * There is no branch below that returns "confirmed". The strongest verdict is
 * that the operator's own conditions are met.
 */
export function settlementFor(
  epoch: number,
  marginEpochs: number | null,
  head: ChainInfo,
  corroboration: Corroboration,
): Settlement {
  const fin = head.finalized.epoch;
  if (epoch > fin) {
    return {
      verdict: "not-finalized",
      depth: null,
      advice:
        "Not finalized. This epoch is still subject to ordinary fork choice and can be replaced.",
    };
  }
  const depth = fin - epoch;
  if (corroboration.state !== "corroborated") {
    return {
      verdict: "uncorroborated",
      depth,
      advice:
        "The two archivals did not corroborate this read, so the first condition — two independent nodes reporting the same root at the same epoch — cannot be checked. That is a hold, not a retry. Note that corroboration does not make a rewind impossible: both nodes can rewind, and they can rewind independently.",
    };
  }
  if (marginEpochs === null) {
    return {
      verdict: "finalized-no-margin",
      depth,
      advice: `Finalized, ${depth} ${depth === 1 ? "epoch" : "epochs"} below the finalized checkpoint, and corroborated by both archivals. No margin has been set. A margin is the only thing that absorbs a rewind, and the protocol does not tell you how large it should be — choose one deliberately rather than crediting at the boundary.`,
    };
  }
  if (depth < marginEpochs) {
    return {
      verdict: "finalized-no-margin",
      depth,
      advice: `Finalized and corroborated, but ${depth} of your ${marginEpochs}-epoch margin. Finalized is a claim the chain can withdraw: the adopt path replaces committed state without comparing the incoming finalized checkpoint against the outgoing one.`,
    };
  }
  return {
    verdict: "margin-met",
    depth,
    advice: `Finalized, corroborated by both archivals, and ${depth} epochs deep against the ${marginEpochs} you chose. Your own conditions are met. Re-read immediately before releasing value — a finalized reading is not durable — and treat a block that has stopped being finalized as a hold.`,
  };
}

// ────────────────────────────────────────────────────────────────────────────
// Indexer
// ────────────────────────────────────────────────────────────────────────────

export interface IndexerEpoch {
  epoch: number;
  votes: number;
  ceiling: number;
  blocks: number;
  missedSlots: number;
  justified: boolean;
  finalized: boolean;
  root?: string;
}

/**
 * Ask whether a historical epoch index is attached.
 *
 * The contract is deliberately tiny and is documented rather than assumed:
 *
 *   GET /idx/finality/epochs?from=<epoch>&to=<epoch>
 *   → { epochs: IndexerEpoch[] }
 *
 * If it is not there, the page says so in words and falls back to what this
 * browser has watched. It does NOT quietly widen its own polling to cover the
 * gap: that would put the load of every open tab onto the nodes, which is the
 * one thing this whole surface is forbidden to do.
 */
export async function probeIndexer(signal?: AbortSignal): Promise<boolean> {
  try {
    const res = await fetch("/idx/finality/epochs?from=0&to=0", { signal });
    return res.ok;
  } catch {
    return false;
  }
}

export async function fetchIndexedEpochs(
  from: number,
  to: number,
  signal?: AbortSignal,
): Promise<IndexerEpoch[]> {
  const res = await fetch(`/idx/finality/epochs?from=${from}&to=${to}`, { signal });
  if (!res.ok) throw new RpcError(`indexer ${res.status}`);
  const body = await res.json();
  return (body.epochs ?? []) as IndexerEpoch[];
}
