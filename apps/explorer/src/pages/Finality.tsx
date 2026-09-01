// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The finality page.
// ---------------------------------------------------------------------------
// THE DESIGN PROBLEM, STATED BEFORE THE CODE
//
// Bitcoin explorers show confirmations: a probabilistic count that everyone
// already knows is probabilistic. Bloch has explicit finality, and explicit
// finality invites exactly one bad rendering — a green tick — because that is
// what "final" sounds like. On this chain a green tick would be a lie, and we
// have already had to retract a settlement guarantee built on believing it.
//
// The two things it would be lying about are both measured, not feared:
//
//   1. The quorum denominator is leak-adjusted and the floor that would bound
//      it is gated behind an activation epoch of u64::MAX, so it does not
//      bind. Modelled, a partition holding 6.25% of the validators finalises
//      its own branch once the absent majority has leaked away.
//   2. `finalized` is not a latch. The code that adopts a branch after a reorg
//      never compares the incoming finalized checkpoint against the outgoing
//      one, and fork choice walks from the justified root — whose committed
//      state finalises about two epochs lower than the head was reporting.
//
// A footnote does not fix this. Nobody reads the asterisk, and a page that
// needs one has already failed. So the visual language here is built on three
// moves, and every component below is one of them:
//
//   A. FINALITY IS A POSITION, NOT A STATE. Epochs sit on three tiers —
//      building, justified, finalized — and the reader sees the staircase. The
//      thing that matters is not any single cell's colour but the SPAN between
//      the finalized tier and the head, drawn at real width. A healthy chain
//      shows a two-cell notch. A stalled chain shows a bar that grows across
//      the page. No number has to be read for the second one to be alarming.
//
//   B. THE SUPPORT IS DRAWN INSIDE THE CLAIM — AND SO IS ITS ABSENCE. Each
//      epoch cell is inked by the attestations that reached the chain, so an
//      epoch that finalised on thin inclusion is a pale cell sitting on the
//      finalized tier: visibly final, visibly unsupported. But the quantity
//      that actually decides finality is the LEAK-ADJUSTED denominator, and no
//      RPC exposes it — not the leak ledger, not the adjusted total. So the
//      finalized rail is drawn as a dashed line and labelled with what is
//      missing. The page draws the measurement it does not have as a hole
//      rather than quietly substituting the one it does. That hole is defect 1
//      rendered as a picture instead of a disclaimer.
//
//   C. THE PAST IS DRAWN AS REVISABLE. The highest finalized epoch this
//      browser has seen is kept as a watermark. If finality descends below it,
//      the page draws the retreat as a hatched scar and keeps it. Defect 2
//      only becomes real to a reader who has seen the number go down.
//
// And one rule over all of it: a stalled chain is the dangerous state, not a
// slow one, so the stall is the loudest object on the page and it is loud
// while it is happening rather than in a report afterwards.
// ---------------------------------------------------------------------------

import { useEffect, useMemo, useRef, useState } from "react";
import {
  CONSENSUS,
  CONSENSUS_SOURCE,
  DEFECTS,
  EPOCH_SECS,
  FACTS,
  SETTLEMENT_POSTURE,
  type ChainInfo,
  type Corroboration,
  type CorroboratedHead,
  type EpochAttestations,
  type Grade,
  type SlotAnswer,
  type RewindEvent,
  type Sample,
  type StallState,
  appendSample,
  corroboratedCall,
  epochSlots,
  findRewinds,
  foldEpoch,
  gradeStall,
  highWaterFinalized,
  isAlarming,
  loadObserved,
  probeIndexer,
  readHead,
  sampleOf,
  saveObserved,
  settlementFor,
} from "../lib/finality";
import { SCENARIOS, frameFromQuery, scenarioFromQuery, type Scenario } from "../lib/replay";
import { Loading } from "../components/ui";
import "../finality.css";

const POLL_MS = 20_000;

// ════════════════════════════════════════════════════════════════════════════
// Data plumbing
// ════════════════════════════════════════════════════════════════════════════

/**
 * The head, from the network or from a replay.
 *
 * Both paths produce the same `CorroboratedHead`, deliberately: the stall
 * rendering that a replay exercises is byte-for-byte the rendering the live
 * chain will get, or the demonstration proves nothing.
 */
function useHead(scenario: Scenario | null, pinnedFrame: number | null) {
  const [head, setHead] = useState<CorroboratedHead | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [frame, setFrame] = useState(pinnedFrame ?? 0);

  useEffect(() => {
    if (!scenario) return;
    const at = Math.min(Math.max(0, frame), scenario.frames.length - 1);
    const f = scenario.frames[at];
    setHead({ info: f.info, corroboration: f.corroboration, readAt: Date.now() });
    if (pinnedFrame !== null) return; // a pinned frame is for screenshots: do not advance
    if (at >= scenario.frames.length - 1) return;
    const t = setTimeout(() => setFrame(at + 1), scenario.frameMs);
    return () => clearTimeout(t);
  }, [scenario, frame, pinnedFrame]);

  useEffect(() => {
    if (scenario) return;
    let stop = false;
    const ac = new AbortController();
    const tick = async () => {
      try {
        const h = await readHead(ac.signal);
        if (!stop) {
          setHead(h);
          setErr(null);
        }
      } catch (e: any) {
        if (!stop) setErr(String(e?.message ?? e));
      }
    };
    void tick();
    // Visibility-gated: a backgrounded tab polling a chain forever is load
    // with no reader on the other end.
    const iv = setInterval(() => {
      if (document.visibilityState === "visible") void tick();
    }, POLL_MS);
    return () => {
      stop = true;
      ac.abort();
      clearInterval(iv);
    };
  }, [scenario]);

  return { head, err, frame, setFrame };
}

/**
 * Attestation inclusion for the two most recent complete epochs.
 *
 * Bounded on purpose. There is no epoch-summary RPC on this chain —
 * `getepochinfo`, `getepochattestations` and `getcheckpoints` are all
 * specified and none is built — so each epoch costs 32 `getblockbyslot` calls
 * at roughly a second apiece. Two epochs is what a page may spend; the rest is
 * the indexer's job, and where the indexer is absent the page says so rather
 * than widening its own polling.
 */
function useRecentInclusion(head: ChainInfo | null, enabled: boolean) {
  const [epochs, setEpochs] = useState<EpochAttestations[]>([]);
  const cache = useRef(new Map<number, SlotAnswer>());
  const done = useRef(new Set<number>());

  useEffect(() => {
    if (!head || !enabled) return;
    const want = [head.epoch - 1, head.epoch - 2].filter((e) => e >= 0 && !done.current.has(e));
    if (want.length === 0) return;
    let stop = false;
    const ac = new AbortController();

    (async () => {
      for (const e of want) {
        const [first, last] = epochSlots(e);
        const slots: number[] = [];
        for (let s = first; s <= last; s++) if (!cache.current.has(s)) slots.push(s);

        // Three at a time. The archivals are keyless and hold no validator
        // key, but they are still nodes, and thirty-two parallel requests is
        // how a page turns a healthy node into one that times out — which the
        // page would then draw as a chain problem.
        const queue = [...slots];
        const worker = async () => {
          while (queue.length && !stop) {
            const s = queue.shift()!;
            try {
              const { result } = await corroboratedCall<{ attestation_count: number }>(
                "getblockbyslot",
                [s],
                ac.signal,
              );
              cache.current.set(
                s,
                result
                  ? { kind: "block", attestation_count: result.attestation_count }
                  : { kind: "empty" },
              );
            } catch (e: any) {
              // SLOT_EMPTY is an ANSWER — the node is telling us that slot has
              // no block. Anything else is our failure to read, and the two
              // must not be conflated: counting a timeout as a missed proposal
              // manufactures a liveness failure out of our own request budget.
              const empty = /slot|empty|-32007/i.test(String(e?.message ?? ""));
              cache.current.set(s, empty ? { kind: "empty" } : { kind: "unknown" });
            }
          }
        };
        await Promise.all([worker(), worker(), worker()]);
        if (stop) return;
        done.current.add(e);
        const active = head.validators?.active ?? 64;
        setEpochs((prev) => {
          const next = prev.filter((p) => p.epoch !== e);
          next.push(foldEpoch(e, cache.current, active, head.slot));
          return next.sort((a, b) => a.epoch - b.epoch);
        });
      }
    })();

    return () => {
      stop = true;
      ac.abort();
    };
  }, [head?.epoch, enabled]);

  return epochs;
}

// ════════════════════════════════════════════════════════════════════════════
// The stall band — the loudest thing on the page
// ════════════════════════════════════════════════════════════════════════════

function hms(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (h === 0) return `${m}m`;
  return `${h}h ${String(m).padStart(2, "0")}m`;
}

/**
 * The grade of the evidence behind a number, rendered next to the number.
 *
 * This is the page's answer to "an asterisk nobody reads". An asterisk defers
 * the qualification to a footnote and hopes; a grade puts it in the same
 * glance as the figure, in four words a reader learns once. `asserted` and
 * `modelled` look different because they ARE different, and the difference is
 * the thing this page exists to communicate.
 */
function GradeBadge({ grade, title }: { grade: Grade | "by-inspection"; title?: string }) {
  const t =
    title ??
    {
      asserted: "A test in the consensus crate fails if this number changes.",
      modelled:
        "Computed by a test from a simplified model — equal stake, a clean partition — and printed rather than asserted. True of the model; the chain is not the model.",
      reported:
        "Stated in the source as observed in production. No dataset in the repository to re-derive it from.",
      constant: "A consensus constant, read straight from params.rs.",
      "by-inspection":
        "Not demonstrated by a test. Established by reading the code path, which performs no such check at all.",
    }[grade];
  return (
    <span className={"fin-grade fin-grade-" + grade} title={t}>
      {grade === "by-inspection" ? "by inspection" : grade}
    </span>
  );
}

/**
 * A stall is a state, not an event, so this is a persistent band rather than a
 * toast. It appears at the leak threshold — not before, or it would cry wolf
 * on the ordinary one-epoch lag and stop meaning anything.
 */
function StallBand({ stall }: { stall: StallState }) {
  if (!isAlarming(stall)) return null;
  const toCapture = (FACTS.minorityJustifies.value ?? 25) - stall.gap;
  return (
    <div className={"fin-band fin-band-" + stall.grade} role="status" aria-live="polite">
      <div className="container fin-band-inner">
        <span className="fin-band-mark" aria-hidden="true" />
        <div className="fin-band-text">
          <strong>
            {stall.headline}
            {stall.grounding && <GradeBadge grade={stall.grounding} />}
          </strong>
          <span className="fin-band-detail">{stall.detail}</span>
        </div>
        <div className="fin-band-nums">
          <div>
            <span className="fin-band-n">{stall.overFloor}</span>
            <span className="fin-band-l">epochs of non-finality</span>
          </div>
          <div>
            <span className="fin-band-n">{hms(stall.approxSecs)}</span>
            <span className="fin-band-l">elapsed</span>
          </div>
          {toCapture > 0 && (
            <div>
              <span className="fin-band-n">{toCapture}</span>
              <span className="fin-band-l">
                epochs to the modelled
                <br />
                minority-capture point
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// The stall meter — named thresholds, live marker
// ════════════════════════════════════════════════════════════════════════════
//
// A bare "gap: 12" tells a reader nothing about whether twelve is bad. The
// scale carries the four numbers that give it meaning, all of them measured on
// this chain, so the marker's position is the interpretation.

const METER_MAX = 120; // the top of production's reported non-finality band

/**
 * The named thresholds, each with the grade of its evidence.
 *
 * These replaced an earlier set — "28: one node can fake a quorum", "45:
 * longest stall measured" — that an audit could not source anywhere in the
 * repository. Everything below is either a consensus constant, a figure a test
 * asserts, or a figure the source attributes to production and says so.
 *
 * The scale is what gives the live number its meaning: "gap 12" tells a reader
 * nothing about whether twelve is bad, and the marker's position between these
 * four is the whole interpretation.
 */
const MARKS: { at: number; label: string; note: string; grade: Grade | null; row: 0 | 1 }[] = [
  { at: CONSENSUS.floorGap, label: "floor", note: "structural minimum", grade: null, row: 1 },
  {
    at: CONSENSUS.leakThresholdEpochs,
    label: "leak",
    note: "stake starts being destroyed",
    grade: "constant",
    row: 0,
  },
  {
    at: FACTS.minorityJustifies.value ?? 25,
    label: "minority capture",
    note: "modelled: 4 of 64 can justify alone",
    grade: "modelled",
    row: 1,
  },
  {
    at: FACTS.sixtyOfSixtyFourZeroed.value ?? 56,
    label: "60 of 64 at zero",
    note: "asserted by test",
    grade: "asserted",
    row: 0,
  },
  {
    at: FACTS.productionStalls.value ?? 110,
    label: "production",
    note: "reported 90–110 band",
    grade: "reported",
    row: 1,
  },
];

function StallMeter({ stall }: { stall: StallState }) {
  const pct = (n: number) => Math.min(100, (n / METER_MAX) * 100);
  const capture = FACTS.minorityJustifies.value ?? 25;
  return (
    <div className="fin-meter">
      <div className="fin-meter-head">
        <h3>Epochs of non-finality</h3>
        <span className="fin-meter-now">
          now: <strong>{stall.gap}</strong>
          <span className="fin-meter-clock">{hms(stall.approxSecs)} past the floor</span>
        </span>
      </div>
      <div className="fin-meter-track">
        <div className="fin-meter-zone fin-zone-ok" style={{ width: `${pct(CONSENSUS.floorGap)}%` }} />
        <div
          className="fin-meter-zone fin-zone-warn"
          style={{
            left: `${pct(CONSENSUS.floorGap)}%`,
            width: `${pct(CONSENSUS.leakThresholdEpochs) - pct(CONSENSUS.floorGap)}%`,
          }}
        />
        <div
          className="fin-meter-zone fin-zone-leak"
          style={{
            left: `${pct(CONSENSUS.leakThresholdEpochs)}%`,
            width: `${pct(capture) - pct(CONSENSUS.leakThresholdEpochs)}%`,
          }}
        />
        <div
          className="fin-meter-zone fin-zone-capture"
          style={{ left: `${pct(capture)}%`, width: `${100 - pct(capture)}%` }}
        />
        <div className="fin-meter-fill" style={{ width: `${pct(stall.gap)}%` }} />
        <div className="fin-meter-marker" style={{ left: `${pct(stall.gap)}%` }} />
        {MARKS.map((m) => (
          <div
            key={m.label}
            className={"fin-meter-tick fin-tick-row" + m.row}
            style={{ left: `${pct(m.at)}%` }}
          >
            <span className="fin-meter-tick-line" />
            <span className="fin-meter-tick-label">
              <b>{m.at}</b> {m.label}
              <em>{m.note}</em>
              {m.grade && <GradeBadge grade={m.grade} />}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// The epoch ladder — position, support, and the span
// ════════════════════════════════════════════════════════════════════════════

interface Cell {
  epoch: number;
  tier: "final" | "justified" | "building";
  /**
   * Attestation inclusion, votes over active-set size. MAY EXCEED 1 —
   * duplicate inclusion is consensus-legal. `null` means unmeasured, which the
   * cell must render as unmeasured and never as zero.
   */
  inclusion: number | null;
  /** Slots in this epoch the node reported empty. */
  missed: number | null;
}

function buildCells(head: ChainInfo, parts: EpochAttestations[], span: number): Cell[] {
  const byEpoch = new Map(parts.map((p) => [p.epoch, p]));
  const last = head.epoch;
  const first = Math.max(0, Math.min(head.finalized.epoch - 2, last - span + 1));
  const cells: Cell[] = [];
  for (let e = first; e <= last; e++) {
    const tier: Cell["tier"] =
      e <= head.finalized.epoch ? "final" : e <= head.justified.epoch ? "justified" : "building";
    const p = byEpoch.get(e);
    cells.push({
      epoch: e,
      tier,
      inclusion: p && p.indicator !== null ? p.indicator : null,
      missed: p ? p.missedSlots : null,
    });
  }
  return cells;
}

const TIER_Y = { building: 12, justified: 56, final: 100 } as const;
const CELL_H = 30;

/**
 * The ladder.
 *
 * Reading it: three tiers, oldest epoch on the left. An epoch climbs from
 * building to justified to finalized. The bracket underneath spans every epoch
 * that is not yet finalized — that span IS the stall, and it grows sideways
 * across the page while one is happening. No number has to be read for a wide
 * bar to be alarming, which is the point: the reader who most needs this is
 * the one who glanced.
 *
 * The finalized rail is DASHED, and that is not decoration. A solid rail would
 * say the floor is firm. The two facts this page exists to carry are that the
 * quantity deciding whether an epoch belongs on that rail is not observable
 * through any RPC, and that the rail itself can move down. A dashed line is
 * the smallest honest way to say "this is where the chain claims the floor is"
 * without saying "and it will stay there".
 */
function EpochLadder({
  head,
  parts,
  rewinds,
  watermark,
}: {
  head: ChainInfo;
  parts: EpochAttestations[];
  rewinds: RewindEvent[];
  watermark: number | null;
}) {
  const span = 22;
  const cells = useMemo(() => buildCells(head, parts, span), [head, parts]);
  const W = 1000;
  const pad = 8;
  const cw = (W - pad * 2) / Math.max(1, cells.length);
  const cellW = Math.max(6, cw - 4);

  const unfinalised = cells.filter((c) => c.tier !== "final");
  const spanStart = unfinalised.length ? pad + cells.indexOf(unfinalised[0]) * cw : 0;
  const spanEnd = pad + cells.length * cw;

  // A rewind is drawn where the finalized tier retreated from: between the
  // high-water epoch this browser saw and where finality now sits.
  const rewound =
    watermark !== null && watermark > head.finalized.epoch
      ? cells.filter((c) => c.epoch > head.finalized.epoch && c.epoch <= watermark)
      : [];

  return (
    <div className="fin-ladder">
      <div className="fin-ladder-tiers" aria-hidden="true">
        <span style={{ top: TIER_Y.building }}>building</span>
        <span style={{ top: TIER_Y.justified }}>justified</span>
        <span style={{ top: TIER_Y.final }}>finalized</span>
      </div>
      <svg
        viewBox={`0 0 ${W} 178`}
        className="fin-ladder-svg"
        role="img"
        aria-label={`Epoch ladder. Head epoch ${head.epoch}, justified ${head.justified.epoch}, finalized ${head.finalized.epoch}. ${unfinalised.length} epochs are not finalized.`}
      >
        <defs>
          <pattern
            id="fin-scar"
            width="6"
            height="6"
            patternUnits="userSpaceOnUse"
            patternTransform="rotate(45)"
          >
            <line x1="0" y1="0" x2="0" y2="6" stroke="var(--fin-danger)" strokeWidth="2" opacity="0.55" />
          </pattern>
        </defs>

        {(["building", "justified"] as const).map((t) => (
          <line
            key={t}
            x1={pad}
            x2={W - pad}
            y1={TIER_Y[t] + CELL_H / 2}
            y2={TIER_Y[t] + CELL_H / 2}
            className="fin-rail"
          />
        ))}
        {/* the finalized rail: dashed, because it is a claim and it can move */}
        <line
          x1={pad}
          x2={W - pad}
          y1={TIER_Y.final + CELL_H / 2}
          y2={TIER_Y.final + CELL_H / 2}
          className="fin-rail fin-rail-final"
        />

        {rewound.length > 0 && (
          <rect
            x={pad + cells.indexOf(rewound[0]) * cw - 2}
            y={TIER_Y.final - 4}
            width={rewound.length * cw}
            height={CELL_H + 8}
            fill="url(#fin-scar)"
            stroke="var(--fin-danger)"
            strokeDasharray="3 3"
            rx="4"
          />
        )}

        {cells.map((c, i) => {
          const x = pad + i * cw;
          const y = TIER_Y[c.tier];
          // Duplicate inclusion is legal, so the indicator can exceed 1. Draw
          // the overflow as its own mark rather than clamping it out of sight —
          // a cell that quietly saturates hides the very thing that makes this
          // not a rate.
          const over = c.inclusion !== null && c.inclusion > 1;
          const filled = c.inclusion === null ? null : Math.max(0.06, Math.min(1, c.inclusion));
          return (
            <g key={c.epoch} className={"fin-cell fin-cell-" + c.tier}>
              <rect x={x} y={y} width={cellW} height={CELL_H} rx="3" className="fin-cell-frame" />
              {filled !== null && (
                <rect
                  x={x}
                  y={y + CELL_H * (1 - filled)}
                  width={cellW}
                  height={CELL_H * filled}
                  rx="3"
                  className="fin-cell-ink"
                />
              )}
              {over && <rect x={x} y={y - 5} width={cellW} height={3} className="fin-cell-over" />}
              {filled === null && (
                <text x={x + cellW / 2} y={y + CELL_H / 2 + 4} className="fin-cell-unknown">
                  ?
                </text>
              )}
              {c.missed ? (
                <text x={x + cellW / 2} y={y + CELL_H + 11} className="fin-cell-missed">
                  {c.missed}
                </text>
              ) : null}
            </g>
          );
        })}

        {unfinalised.length > 0 && (
          <g className="fin-span">
            <line x1={spanStart} x2={spanEnd - 4} y1={161} y2={161} className="fin-span-line" />
            <line x1={spanStart} x2={spanStart} y1={153} y2={169} className="fin-span-line" />
            <line x1={spanEnd - 4} x2={spanEnd - 4} y1={153} y2={169} className="fin-span-line" />
            <text
              x={(spanStart + spanEnd) / 2}
              y={155}
              className="fin-span-label"
              textAnchor="middle"
            >
              {unfinalised.length} {unfinalised.length === 1 ? "epoch" : "epochs"} not finalized
            </text>
          </g>
        )}
      </svg>
      <div className="fin-ladder-axis">
        <span>epoch {cells[0]?.epoch}</span>
        <span>epoch {cells[cells.length - 1]?.epoch}</span>
      </div>

      <div className="fin-missing">
        <span className="fin-missing-mark" aria-hidden="true" />
        <p>
          <strong>The finalized rail is dashed because the number that puts an epoch on it is not
          observable.</strong>{" "}
          Justification is decided by two thirds of the <em>leak-adjusted</em> active stake. No RPC
          exposes the leak ledger or the adjusted total, so an explorer — this one or any other —
          cannot show the quantity that actually decides finality on this chain. The ink in each
          cell is attestations included, which is a different measurement over a different set.
        </p>
      </div>

      <p className="fin-note">
        Ink is <strong>attestations included</strong> that epoch, against the size of the active
        set for scale. It is not a participation rate: duplicate inclusion is consensus-legal so it
        can overrun (drawn as a bar above the cell), a missed final proposal loses votes that were
        cast, and consensus counts a deduplicated set this page cannot see. Small figures under a
        cell are slots the node reported empty. Cells marked <code>?</code> are unmeasured — not
        zero.
        {rewound.length > 0 && (
          <>
            {" "}
            The hatched region is a <strong>finality rewind</strong>: {rewound.length}{" "}
            {rewound.length === 1 ? "epoch" : "epochs"} this browser saw finalized, and which the
            chain no longer finalises.
          </>
        )}
      </p>
      {rewinds.length > 0 && (
        <ul className="fin-rewind-log">
          {rewinds.slice(-4).map((r, i) => (
            <li key={i}>
              <span className="fin-rewind-when">{new Date(r.at).toLocaleTimeString()}</span>
              {r.kind === "epoch-descended" ? (
                <>
                  finalized epoch fell <b>{r.from.epoch}</b> → <b>{r.to.epoch}</b>
                </>
              ) : (
                <>
                  epoch <b>{r.to.epoch}</b> re-finalised under a different root (
                  <code>{r.from.root.slice(0, 10)}</code> → <code>{r.to.root.slice(0, 10)}</code>)
                </>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// Corroboration
// ════════════════════════════════════════════════════════════════════════════
//
// The public proxy is soft: asked for `getchaininfo` it returns one node's
// answer rather than erroring when it cannot corroborate. So every number on
// this page carries where it came from, and a conflict is rendered as both
// claims side by side rather than as a warning about one of them.

function CorroborationChip({ c }: { c: Corroboration }) {
  const label = {
    corroborated: "two nodes agree",
    single: "one node only",
    conflict: "nodes disagree",
    none: "no node answered",
  }[c.state];
  return (
    <span className={"fin-chip fin-chip-" + c.state}>
      <span className="fin-chip-dot" />
      {label}
    </span>
  );
}

function CorroborationPanel({ c }: { c: Corroboration }) {
  return (
    <section className="card fin-corrob">
      <div className="fin-sec-head">
        <h2>Where these numbers came from</h2>
        <CorroborationChip c={c} />
      </div>
      <p className="fin-note">
        Both readings are taken from the two keyless archival nodes — they hold no validator key and
        produce nothing, so reading them cannot affect what they report. Validator RPC is served by
        the consensus loop itself and is never polled from here. The fields compared are the
        finality claim only ({c.agreed_on.map((f) => <code key={f}>{f}</code>).reduce((a, b) => <>{a}, {b}</> )});
        slot and height are allowed to differ, because two honest nodes routinely answer a moment
        apart and calling that a disagreement would cry wolf until the warning meant nothing.
      </p>
      <div className="fin-nodes">
        {c.sources.map((s) => (
          <div key={s.id} className={"fin-node" + (s.ok ? "" : " fin-node-down")}>
            <div className="fin-node-head">
              <code>{s.ip}</code>
              <span className="faint">{s.ok ? `${s.ms} ms` : (s.error ?? "no answer")}</span>
            </div>
            {s.claim ? (
              <dl className="fin-node-claim">
                <div>
                  <dt>justified</dt>
                  <dd>
                    epoch {s.claim.justified.epoch} · <code>{s.claim.justified.root.slice(0, 12)}</code>
                  </dd>
                </div>
                <div>
                  <dt>finalized</dt>
                  <dd>
                    epoch {s.claim.finalized.epoch} · <code>{s.claim.finalized.root.slice(0, 12)}</code>
                  </dd>
                </div>
                <div>
                  <dt>head</dt>
                  <dd>
                    slot {s.claim.slot} · <code>{s.claim.block_id.slice(0, 12)}</code>
                  </dd>
                </div>
              </dl>
            ) : (
              <p className="faint">This node did not answer this read.</p>
            )}
          </div>
        ))}
      </div>
      {c.state === "conflict" && (
        <div className="fin-conflict">
          <strong>These two nodes are not on the same chain.</strong> They differ on{" "}
          {c.differing.map((d) => (
            <code key={d}>{d}</code>
          ))}
          . Nothing on this page should be treated as settled while that is true, and no amount of
          waiting resolves it on its own — on 2026-08-24 three partitions finalised the same epoch
          under three different roots, and each was internally consistent.
        </div>
      )}
      {c.state === "single" && (
        <div className="fin-conflict fin-conflict-soft">
          Only one archival answered, so nothing here is corroborated. This is the state the public
          proxy reports as success; it is shown as its own thing here because an uncorroborated
          finality claim is one node's opinion.
        </div>
      )}
    </section>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// Settlement
// ════════════════════════════════════════════════════════════════════════════

function SettlementPanel({ head, c }: { head: ChainInfo; c: Corroboration }) {
  const [rawEpoch, setRawEpoch] = useState("");
  const [rawMargin, setRawMargin] = useState("");
  const epoch = rawEpoch.trim() === "" ? head.finalized.epoch : Number(rawEpoch.trim());
  const margin = rawMargin.trim() === "" ? null : Number(rawMargin.trim());
  const valid = Number.isFinite(epoch) && epoch >= 0 && (margin === null || Number.isFinite(margin));
  const s = valid ? settlementFor(epoch, margin, head, c) : null;

  return (
    <section className="card fin-settle">
      <div className="fin-sec-head">
        <h2>Should this be credited?</h2>
      </div>
      <p className="fin-note">
        <strong>There is no recommended depth below, and that is the answer, not an omission.</strong>{" "}
        The protocol supplies no number: finality is not a latch, so any margin is a judgement about
        how large a rewind you are willing to survive, and a figure printed here would be read as
        the chain's own advice. Choose one deliberately. What the explorer can check for you is
        everything else.
      </p>
      <ul className="fin-posture">
        {SETTLEMENT_POSTURE.requirements.map((r, i) => (
          <li key={i}>{r}</li>
        ))}
      </ul>
      <div className="fin-settle-form">
        <label htmlFor="fin-epoch">epoch</label>
        <input
          id="fin-epoch"
          className="mine-input mono"
          inputMode="numeric"
          placeholder={String(head.finalized.epoch)}
          value={rawEpoch}
          onChange={(e) => setRawEpoch(e.target.value)}
        />
        <label htmlFor="fin-margin">your margin</label>
        <input
          id="fin-margin"
          className="mine-input mono"
          inputMode="numeric"
          placeholder="none set"
          value={rawMargin}
          onChange={(e) => setRawMargin(e.target.value)}
        />
      </div>
      {s && (
        <div className={"fin-verdict fin-verdict-" + s.verdict}>
          <div className="fin-verdict-tag">
            {
              {
                "not-finalized": "not finalized",
                "finalized-no-margin": "finalized · margin not met",
                "margin-met": "your conditions are met",
                uncorroborated: "cannot be checked — hold",
              }[s.verdict]
            }
          </div>
          <p>{s.advice}</p>
          {s.depth !== null && margin !== null && margin > 0 && (
            <div className="fin-depth">
              <span>epoch {epoch}</span>
              <span className="fin-depth-bar" aria-hidden="true">
                {Array.from({ length: Math.min(12, margin) }, (_, i) => (
                  <i key={i} className={i < (s.depth ?? 0) ? "on" : ""} />
                ))}
              </span>
              <span>
                {s.depth} of {margin} epochs below the finalized checkpoint
              </span>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// Attestation inclusion
// ════════════════════════════════════════════════════════════════════════════

function InclusionPanel({
  parts,
  head,
  indexed,
  replay,
}: {
  parts: EpochAttestations[];
  head: ChainInfo;
  indexed: boolean;
  replay: boolean;
}) {
  const active = head.validators?.active ?? 64;
  return (
    <section className="card">
      <div className="fin-sec-head">
        <h2>Attestations included per epoch</h2>
        <GradeBadge grade="asserted" title="Derived from getblockbyslot, which reports the block body's own attestation count." />
      </div>
      <p className="fin-note">
        A count of the votes that reached the chain, shown against the {active}-validator active set
        for scale. <strong>This is not a participation rate</strong> — the reasons are below, and
        they are not pedantic: three of them can move this number without any validator changing
        behaviour.
      </p>
      {parts.length === 0 ? (
        replay ? (
          <p className="fin-note fin-scope">
            Not measured under replay. The fixture drives the checkpoints only; asking the real
            nodes about slots that belong to a scripted chain would mix a live measurement into an
            invented picture.
          </p>
        ) : (
          <Loading label="Reading the last complete epochs…" />
        )
      ) : (
        <table className="tbl fin-part-tbl">
          <thead>
            <tr>
              <th className="num">Epoch</th>
              <th className="num">Votes</th>
              <th>Against {active} validators</th>
              <th className="num">Blocks</th>
              <th className="num">Empty slots</th>
              <th className="num">Unread</th>
            </tr>
          </thead>
          <tbody>
            {[...parts].reverse().map((p) => (
              <tr key={p.epoch}>
                <td className="num">{p.epoch}</td>
                <td className="num">{p.votes}</td>
                <td>
                  {p.indicator === null ? (
                    <span className="faint">{p.inFlight ? "in flight" : "incomplete read"}</span>
                  ) : (
                    <span className="fin-share">
                      <span className="fin-share-bar">
                        <i style={{ width: `${Math.min(100, p.indicator * 100)}%` }} />
                        {p.indicator > 1 && <b className="fin-share-over" />}
                      </span>
                      {p.votes}/{active}
                    </span>
                  )}
                </td>
                <td className="num">{p.blocks}</td>
                <td className="num">{p.missedSlots}</td>
                <td className="num faint">{p.unreadSlots}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="fin-derivation">
        <h4>Why this is not participation</h4>
        <p>
          Committees partition the active set into {CONSENSUS.slotsPerEpoch} contiguous chunks, so
          at {active} validators each slot has two seats and each validator gets one chance per
          epoch. That makes {active} the natural scale. It does not make this a rate:
        </p>
        <ol>
          <li>
            <strong>Duplicates are legal.</strong> The transition keys votes by (validator, signing
            root) and never rejects one an earlier block already carried. Local pool housekeeping
            usually prevents it — housekeeping, not a rule. The sum can exceed {active}.
          </li>
          <li>
            <strong>Missed proposals delete cast votes.</strong> A proposer may carry earlier slots'
            attestations, but only inside its own epoch. If the last proposer of an epoch misses,
            every vote not yet carried is gone. The votes existed; nothing records them.
          </li>
          <li>
            <strong>A reorg rescores the past.</strong> Epoch blocks can be replaced after they are
            summed, and finalized is not a latch, so an epoch already scored can score differently
            later.
          </li>
          <li>
            <strong>Consensus does not count it this way.</strong> Justification reads a
            deduplicated set of distinct validators committed into the state root, measured in
            stake, at the epoch boundary — not block inclusion. The RPC returns a length and never
            says which validators attested, so their stake cannot be looked up from here.
          </li>
        </ol>
        <p className="fin-scope">
          {indexed
            ? "Historical epochs come from the attached indexer."
            : "No epoch indexer is attached, so this reads only the last two complete epochs, and history is limited to what this tab has watched. It does not widen its own polling to fill the gap: 32 calls per epoch from every open tab is load the nodes should not carry for a chart."}
        </p>
      </div>
    </section>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// The defects
// ════════════════════════════════════════════════════════════════════════════

function DefectsPanel() {
  return (
    <section className="card fin-defects">
      <div className="fin-sec-head">
        <h2>What finality on this chain does not mean</h2>
      </div>
      <p className="fin-note">
        The chain finalises the overwhelming majority of its epochs, and none of the following says
        otherwise. They say what the guarantee rests on. It is economic — it assumes healthy
        participation and a cost to attacking — rather than cryptographic, and each item below is
        one place that assumption is load-bearing. Every claim carries the grade of its evidence,
        because the difference between "a test fails if this changes" and "a model prints this"
        is the difference this whole page exists to keep visible.
      </p>
      {DEFECTS.map((d, i) => (
        <article key={d.id} className="fin-defect">
          <div className="fin-defect-n">{i + 1}</div>
          <div>
            <h3>
              {d.title}
              <GradeBadge grade={d.grade} />
            </h3>
            <p className="fin-defect-short">{d.short}</p>
            <p className="fin-defect-mech">{d.mechanism}</p>
            <p className="fin-defect-src">
              <code>{d.evidence}</code>
            </p>
          </div>
        </article>
      ))}
      <div className="fin-inert">
        <h4>Written, tested, and not switched on</h4>
        <p>
          A floor of one half on the quorum denominator exists in the code, as does the rule that
          lets a returning validator's leak debt fall. Both are gated behind{" "}
          <code>LEAK_RECOVERY_ACTIVATION_EPOCH = u64::MAX</code> and neither binds on this chain
          today. They are drawn nowhere on this page as if they were operating, and their existence
          is not a mitigation — an inert guard is a plan, not a protection.
        </p>
      </div>
      <p className="fin-note fin-const">
        Constants quoted from <code>{CONSENSUS_SOURCE}</code>:{" "}
        <code>INACTIVITY_LEAK_THRESHOLD_EPOCHS = {CONSENSUS.leakThresholdEpochs}</code>,{" "}
        <code>INACTIVITY_LEAK_QUOTIENT = {CONSENSUS.leakQuotient}</code>,{" "}
        <code>
          MIN_QUORUM_DENOMINATOR = {CONSENSUS.quorumFloor[0]}/{CONSENSUS.quorumFloor[1]}
        </code>{" "}
        (inert), <code>LEAK_RECOVERY_ACTIVATION_EPOCH = u64::MAX</code> (inert),{" "}
        <code>LEAKED_ROSTER_ACTIVATION_EPOCH = {CONSENSUS.leakedRosterActivationEpoch}</code>{" "}
        (live). Figures on this page each carry one of four grades:{" "}
        <GradeBadge grade="constant" /> <GradeBadge grade="asserted" />{" "}
        <GradeBadge grade="modelled" /> <GradeBadge grade="reported" />.
      </p>
    </section>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// Page
// ════════════════════════════════════════════════════════════════════════════

export function FinalityPage() {
  const search = typeof location === "undefined" ? "" : location.search;
  const scenario = useMemo(() => scenarioFromQuery(search), [search]);
  const pinned = useMemo(() => frameFromQuery(search), [search]);
  const { head, err } = useHead(scenario, pinned);

  const [observed, setObserved] = useState<Sample[]>(() => (scenario ? [] : loadObserved()));
  const [indexed, setIndexed] = useState(false);

  useEffect(() => {
    if (scenario) return;
    const ac = new AbortController();
    void probeIndexer(ac.signal).then(setIndexed);
    return () => ac.abort();
  }, [scenario]);

  useEffect(() => {
    if (!head) return;
    setObserved((prev) => {
      const next = appendSample(prev, sampleOf(head));
      if (!scenario) saveObserved(next);
      return next;
    });
  }, [head, scenario]);

  // Live measurement is suppressed under replay: a fixture chain has no slots
  // to ask about, and asking the real nodes about them would mix a real
  // measurement into a scripted picture.
  const measured = useRecentInclusion(scenario ? null : head?.info ?? null, !scenario);
  // Under replay the inclusion figures come from the fixture, so the ladder
  // demonstrates its own visual language. They are fixture data in a view that
  // is banner-marked REPLAY throughout; nothing here reaches the live page.
  const parts = scenario ? (scenario.inclusion ?? []) : measured;

  if (err && !head) {
    return (
      <div className="container">
        <div className="errbox">
          The corroborating endpoint did not answer ({err}). This reports the reader's path to the
          chain, not the chain — finality may well be advancing.
        </div>
      </div>
    );
  }
  if (!head) return <Loading label="Reading both archivals…" />;

  const stall = gradeStall(head.info);
  const rewinds = findRewinds(observed);
  const watermark = highWaterFinalized(observed);

  return (
    <>
      {scenario && <ReplayBanner scenario={scenario} />}
      <StallBand stall={stall} />
      <div className="container fin-page">
        <header className="fin-hero">
          <div>
            <span className="g4-badge">Genesis-4 · finality</span>
            <h1 className="fin-title">
              {stall.grade === "floor"
                ? "Finality is current"
                : stall.grade === "lagging"
                  ? "Finality is one epoch behind"
                  : "Finality has stalled"}
            </h1>
            <p className="fin-lede">
              This chain does not count confirmations. Epochs of {CONSENSUS.slotsPerEpoch} slots are
              justified and then finalized by two thirds of the <em>leak-adjusted</em> active stake
              — a denominator that shrinks while a stall runs, and that no RPC exposes. What the
              guarantee is worth depends on facts this page shows rather than summarises.
            </p>
          </div>
          <CorroborationChip c={head.corroboration} />
        </header>

        <section className="card fin-primary">
          <div className="fin-checkpoints">
            <Checkpoint label="head" epoch={head.info.epoch} sub={`slot ${head.info.slot_in_epoch}/${head.info.slots_per_epoch}`} tone="head" />
            <Arrow n={head.info.epoch - head.info.justified.epoch} />
            <Checkpoint
              label="justified"
              epoch={head.info.justified.epoch}
              sub={head.info.justified.root.slice(0, 12)}
              tone="justified"
            />
            <Arrow n={head.info.justified.epoch - head.info.finalized.epoch} />
            <Checkpoint
              label="finalized"
              epoch={head.info.finalized.epoch}
              sub={head.info.finalized.root.slice(0, 12)}
              tone="final"
              watermark={watermark !== null && watermark > head.info.finalized.epoch ? watermark : null}
            />
          </div>
          <StallMeter stall={stall} />
          <EpochLadder head={head.info} parts={parts} rewinds={rewinds} watermark={watermark} />
        </section>

        <SettlementPanel head={head.info} c={head.corroboration} />

        <div className="grid two-col">
          <InclusionPanel parts={parts} head={head.info} indexed={indexed} replay={!!scenario} />
          <CorroborationPanel c={head.corroboration} />
        </div>

        <DefectsPanel />

        <section className="card fin-demo">
          <h2>See a stall without waiting for one</h2>
          <p className="fin-note">
            The stall rendering above is the most valuable thing this page does and the least likely
            to be exercised, because the chain finalises about 99% of its epochs. These replay the
            measured shapes through exactly the same components, and are labelled as replays
            throughout so a screenshot of one can never pass for the live chain.
          </p>
          <div className="fin-demo-links">
            {Object.values(SCENARIOS).map((s) => (
              <a key={s.id} href={`?replay=${s.id}`} className="fin-demo-link">
                <strong>{s.title}</strong>
                <span>{s.premise}</span>
              </a>
            ))}
          </div>
        </section>
      </div>
    </>
  );
}

function Checkpoint({
  label,
  epoch,
  sub,
  tone,
  watermark,
}: {
  label: string;
  epoch: number;
  sub: string;
  tone: string;
  watermark?: number | null;
}) {
  return (
    <div className={"fin-cp fin-cp-" + tone}>
      <span className="fin-cp-label">{label}</span>
      <span className="fin-cp-epoch">{epoch}</span>
      <span className="fin-cp-sub">
        <code>{sub}</code>
      </span>
      {watermark != null && (
        <span className="fin-cp-watermark" title="The highest finalized epoch this browser has seen">
          ↓ was {watermark}
        </span>
      )}
    </div>
  );
}

function Arrow({ n }: { n: number }) {
  return (
    <div className="fin-arrow" aria-hidden="true">
      <span className="fin-arrow-line" />
      <span className="fin-arrow-n">{n}</span>
    </div>
  );
}

function ReplayBanner({ scenario }: { scenario: Scenario }) {
  return (
    <div className="fin-replay" role="alert">
      <div className="container fin-replay-inner">
        <strong>REPLAY — not the live chain.</strong>
        <span>
          {scenario.title}: {scenario.premise}
        </span>
        <a href={location.pathname}>show the live chain</a>
      </div>
    </div>
  );
}
