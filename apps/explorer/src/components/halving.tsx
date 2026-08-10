import { useEffect, useMemo, useState } from "react";
import {
  halvingAt,
  fmtCountdown,
  fmtHorizon,
  fmtEtaDate,
  CARRYOVER_SOURCE_HEIGHT,
  EMISSION_V3_FORK_LOCAL_HEIGHT,
  EMISSION_V3_FORK_EMISSION_HEIGHT,
  EMISSION_V3_HALVING_INTERVAL,
  TARGET_BLOCK_SECS,
  TAIL_FLOOR_BLOCH,
} from "../lib/halving";
import { fmtInt } from "../lib/format";

/**
 * Emission countdown — to the Emission V3 fork while we are below local 40,000,
 * and to the next V3 halving after it.
 *
 * The exact figure is BLOCKS REMAINING — that one is arithmetic. The clock is an
 * estimate and is labelled as one: block arrival is Poisson, so a countdown to
 * the second is theatre unless you say what rate it assumes. Two rates are
 * shown: the 30 s protocol target, and whatever the chain has actually been
 * doing lately.
 */
export function HalvingCard({
  tipHeight,
  observedBlockSecs,
}: {
  tipHeight: number;
  observedBlockSecs?: number;
}) {
  const h = useMemo(() => halvingAt(tipHeight), [tipHeight]);

  // Re-anchor the target instant whenever the height or rate moves; tick the
  // display every second in between.
  const targetAt = useMemo(
    () => Date.now() + h.blocksRemaining * TARGET_BLOCK_SECS * 1000,
    [h.blocksRemaining],
  );
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const secsAtTarget = (targetAt - now) / 1000;
  const observed = observedBlockSecs && observedBlockSecs > 0 ? observedBlockSecs : null;
  const secsAtObserved = observed ? h.blocksRemaining * observed : null;

  if (h.tailReached) {
    return (
      <div className="card pad-lg halving">
        <div className="halving-head">
          <div className="label">Emission</div>
          <div className="halving-epoch">tail · epoch {h.epoch}</div>
        </div>
        <div className="halving-clock">{fmtInt(TAIL_FLOOR_BLOCH)} BLOCH / block</div>
        <div className="halving-note">
          The tail floor holds from here on. Further halvings do not change the subsidy — emission
          is perpetual at {fmtInt(TAIL_FLOOR_BLOCH)} BLOCH per block, so there is nothing left to
          count down to.
        </div>
      </div>
    );
  }

  const isFork = h.kind === "fork";

  return (
    <div className="card pad-lg halving">
      <div className="halving-head">
        <div className="label">{isFork ? "Emission V3 fork" : "Next halving"}</div>
        <div className="halving-epoch">
          {isFork ? "hard fork · local 40,000" : `epoch ${h.epoch} → ${h.epoch + 1}`}
        </div>
      </div>

      <div className="halving-clock">{fmtCountdown(secsAtTarget)}</div>
      <div className="halving-sub">
        estimate at the 30 s target · {fmtHorizon(secsAtTarget)} · ~{fmtEtaDate(targetAt)}
      </div>

      <div className="halving-bar" role="presentation">
        <div className="halving-bar-fill" style={{ width: `${(h.progress * 100).toFixed(2)}%` }} />
      </div>
      <div className="halving-bar-legend">
        <span>
          {(h.progress * 100).toFixed(1)}% {isFork ? "of the way to the fork" : "through this epoch"}
        </span>
        <span>
          {isFork
            ? `${fmtInt(h.eraBlocks)} blocks, Genesis-3 → fork`
            : `${fmtInt(EMISSION_V3_HALVING_INTERVAL)} blocks per epoch`}
        </span>
      </div>

      <div className="halving-grid">
        <div>
          <div className="hk">Blocks remaining</div>
          <div className="hv accent">{fmtInt(h.blocksRemaining)}</div>
          <div className="hs">exact — this is the real countdown</div>
        </div>
        <div>
          <div className="hk">At this height</div>
          <div className="hv">{fmtInt(h.nextLocalHeight)}</div>
          <div className="hs">local · absolute emission {fmtInt(h.nextAbsHeight)}</div>
        </div>
        <div>
          <div className="hk">{isFork ? "Reward cut" : "Subsidy"}</div>
          <div className="hv">
            {fmtInt(h.rewardNow)} <span className="hv-arrow">→</span> {fmtInt(h.rewardNext)}
          </div>
          <div className="hs">{isFork ? "BLOCH per block · −69%" : "BLOCH per block"}</div>
        </div>
        <div>
          <div className="hk">At the observed rate</div>
          <div className="hv">{secsAtObserved ? fmtHorizon(secsAtObserved) : "—"}</div>
          <div className="hs">
            {observed
              ? `${observed.toFixed(1)}s/block, last 50 blocks`
              : "no recent sample"}
          </div>
        </div>
      </div>

      {isFork ? (
        <div className="halving-note">
          <strong>This is a consensus hard fork, not a scheduled halving.</strong> At local height{" "}
          {fmtInt(EMISSION_V3_FORK_LOCAL_HEIGHT)} (emission height{" "}
          {fmtInt(EMISSION_V3_FORK_EMISSION_HEIGHT)}) the block reward drops from 8,400 to 2,600
          BLOCH — a 69% cut — and halvings move from every 1,036,800 blocks (~1 year) to every{" "}
          {fmtInt(EMISSION_V3_HALVING_INTERVAL)} (~1.5 years), with the epoch counter restarted at
          the fork. The 100 BLOCH perpetual tail floor is unchanged. The reason: the old schedule
          would have emitted ≈26.92B BLOCH over 100 years against a documented nominal of 17.43B;
          the new curve emits 17,423,942,400 over the 100 years after the fork. The fork logic is
          already in the deployed node binary and is inert until this height. Nodes built without
          it will reject post-fork blocks — update before the fork.
        </div>
      ) : (
        <div className="halving-note">
          <strong>Counted from the Emission V3 fork, on the emission height.</strong> Genesis-3
          restarted the local chain at height 0 but continues emission from where the carried
          ledger stopped, so the subsidy is computed at{" "}
          <span className="mono">local + {fmtInt(CARRYOVER_SOURCE_HEIGHT)}</span> — currently{" "}
          {fmtInt(h.absHeight)}. Since the V3 fork (local{" "}
          {fmtInt(EMISSION_V3_FORK_LOCAL_HEIGHT)}), halvings land every{" "}
          {fmtInt(EMISSION_V3_HALVING_INTERVAL)} blocks with the epoch counter restarted at the
          fork — not at absolute-height multiples.
        </div>
      )}
    </div>
  );
}
