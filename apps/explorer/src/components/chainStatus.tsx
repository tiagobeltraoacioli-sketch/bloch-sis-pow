// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Chain-state presentation: Genesis-3 halts at height 50,000 by consensus
// rule, so the explorer has THREE states — producing, counting down to the
// halt, and complete. "Complete" is the designed outcome and is rendered in
// the calm accent tone, never as an error. After completion the explorer is a
// historical record, so pages drop their poll from seconds to minutes.

import { useCallback, useEffect, useState } from "react";
import {
  HALT_HEIGHT,
  COMPLETE_POLL_MS,
  ChainPhase,
  chainPhase,
  isChainComplete,
  noteTipHeight,
} from "../lib/chain";
import { fmtInt, fmtTime, fmtDuration } from "../lib/format";
import { fmtHorizon } from "../lib/halving";

/**
 * Adaptive poll cadence: `fastMs` while the chain lives, COMPLETE_POLL_MS once
 * it is complete. Feed observed tip heights to `markTip`; the flag is sticky
 * (localStorage) so reloads start slow immediately.
 *
 * Usage:
 *   const { intervalMs, markTip } = useAdaptivePoll(15000);
 *   const { data } = useAsync(load, [intervalMs], intervalMs);
 *   useEffect(() => markTip(data?.dag?.tip_height), [data, markTip]);
 */
export function useAdaptivePoll(fastMs: number): {
  intervalMs: number;
  markTip: (h: number | null | undefined) => void;
} {
  const [complete, setComplete] = useState(isChainComplete);
  const markTip = useCallback((h: number | null | undefined) => {
    if (typeof h === "number" && isFinite(h) && h >= HALT_HEIGHT) {
      noteTipHeight(h);
      setComplete(true);
    }
  }, []);
  return { intervalMs: complete ? COMPLETE_POLL_MS : fastMs, markTip };
}

/** Compact phase line for banners on secondary pages. */
export function ChainPhaseBanner({
  tipHeight,
  freshestTs,
  children,
}: {
  tipHeight: number;
  freshestTs: number;
  /** Optional extra copy appended after the standard phase sentence. */
  children?: React.ReactNode;
}) {
  const phase = chainPhase(tipHeight, freshestTs);
  if (phase === "producing") return null;

  if (phase === "complete") {
    return (
      <div className="chain-banner done">
        <span className="dot done" />
        <div>
          <strong>Genesis-3 is complete.</strong> The chain reached height{" "}
          {fmtInt(HALT_HEIGHT)} and stopped, exactly as its consensus rules
          require. What you see here is the final, permanent history.
          {freshestTs > 0 && (
            <>
              {" "}
              Final block: <span className="mono">{fmtTime(freshestTs)}</span>.
            </>
          )}{" "}
          {children}
        </div>
      </div>
    );
  }

  const age = freshestTs ? Date.now() / 1000 - freshestTs : Infinity;
  return (
    <div className="chain-banner quiet">
      <span className="dot warn" />
      <div>
        <strong>No recent blocks.</strong> The newest block is{" "}
        {isFinite(age) ? fmtDuration(age) : "of unknown age"} old at height{" "}
        {fmtInt(tipHeight)}. Genesis-3 only ends at height {fmtInt(HALT_HEIGHT)};
        below that, production can pause and resume. Data shown is live and
        honest. {children}
      </div>
    </div>
  );
}

/**
 * The dashboard card. Three renders:
 *   complete  — Genesis-3 finished as planned; final block date, no clock
 *   countdown — blocks remaining to 50,000 (with a paused note when quiet)
 */
export function ChainStatusCard({
  tipHeight,
  freshestTs,
  observedBlockSecs,
}: {
  tipHeight: number;
  freshestTs: number;
  observedBlockSecs?: number;
}) {
  const phase = chainPhase(tipHeight, freshestTs);

  // tick once a minute so ages / estimates don't fossilise on screen
  const [, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick((x) => x + 1), 60_000);
    return () => clearInterval(t);
  }, []);

  if (phase === "complete") {
    return (
      <div className="card pad-lg" style={{ marginBottom: 18 }}>
        <div className="halt-head">
          <div className="label">Genesis-3 · complete</div>
          <div className="halt-sub">consensus halt at height {fmtInt(HALT_HEIGHT)}</div>
        </div>
        <div className="halt-clock">
          {freshestTs > 0 ? `Final block: ${fmtTime(freshestTs)}` : `Height ${fmtInt(tipHeight)}`}
        </div>
        <div className="halt-note">
          <strong>The chain ended as planned.</strong> Blocks above height{" "}
          {fmtInt(HALT_HEIGHT)} are invalid by a consensus rule compiled into
          every node — nobody switched anything off. A signed snapshot of every
          balance was taken at the halt and carries into Genesis-4 unchanged:
          there is no claim to file and no contract to interact with. Anyone
          asking you to migrate tokens is stealing them. This explorer keeps
          serving the complete Genesis-3 history.
        </div>
      </div>
    );
  }

  const remaining = Math.max(0, HALT_HEIGHT - tipHeight);
  const progress = Math.min(1, tipHeight / HALT_HEIGHT);
  const rate =
    observedBlockSecs && observedBlockSecs > 0.5 && observedBlockSecs < 3600
      ? observedBlockSecs
      : 30;
  const etaSecs = remaining * rate;

  return (
    <div className="card pad-lg" style={{ marginBottom: 18 }}>
      <div className="halt-head">
        <div className="label">Genesis-3 ends at height {fmtInt(HALT_HEIGHT)}</div>
        <div className="halt-sub">consensus rule · not a shutdown switch</div>
      </div>
      <div className="halt-clock">{fmtInt(remaining)} blocks to go</div>
      <div className="halt-sub" style={{ marginTop: 6, fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--muted)" }}>
        {fmtHorizon(etaSecs)} at {rate === 30 ? "the 30 s target" : `${rate.toFixed(1)} s/block observed`} — an
        estimate, not a promise
      </div>
      <div className="halt-bar" role="presentation">
        <div className="halt-bar-fill" style={{ width: `${(progress * 100).toFixed(2)}%` }} />
      </div>
      <div className="halt-bar-legend">
        <span>{(progress * 100).toFixed(1)}% of Genesis-3 produced</span>
        <span>height {fmtInt(tipHeight)} / {fmtInt(HALT_HEIGHT)}</span>
      </div>
      <div className="halt-note">
        At height {fmtInt(HALT_HEIGHT)} the chain halts, mining revenue ends, and
        a signed snapshot of every balance is taken. Genesis-4 restarts from that
        snapshot under proof of stake — balances carry across untouched.
        {phase === "quiet" && freshestTs > 0 && (
          <>
            {" "}
            <strong style={{ color: "var(--signal)" }}>
              Production is currently paused
            </strong>{" "}
            — the newest block is {fmtDuration(Date.now() / 1000 - freshestTs)} old. Below the
            halt height that can happen and resume; the countdown resumes with it.
          </>
        )}
      </div>
    </div>
  );
}
