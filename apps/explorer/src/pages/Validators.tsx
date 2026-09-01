// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Genesis-4 validator set.
//
// Under proof of work this page would have been a miner leaderboard. It is not
// the same thing and must not read like one: a miner is whoever showed up with
// hashrate this hour, a validator is a bonded identity the chain committed to
// at genesis and can slash.
//
// The page has one editorial rule. Where the chain's own numbers are
// unflattering — a set that is one operator wearing 64 hats, half of every
// bond permanently burned out of consensus weight, a validator counted active
// that has not proposed since it was switched off — it renders them plainly
// and explains the mechanism. Softening any of those would leave a reader with
// a more comfortable picture and a worse understanding, and the numbers are
// public anyway; the only thing an explorer can add is the reason.
import { useEffect, useState } from "react";
import {
  fetchValidatorSet,
  stakeShares,
  nakamotoCoefficient,
  stakeToReach,
  tallyByState,
  quantiles,
  giniBps,
  leakedFraction,
  leakedSat,
  isGap,
  ValidatorSet,
  ValidatorRow,
} from "../lib/validators";
import { G4Validator } from "../lib/g4";
import { PARAMS, cohortCapBps, independentFloorBps } from "../lib/g4params";
import { fmtBloch, fmtInt, fmtNum } from "../lib/format";
import { Link } from "../lib/router";
import { Loading } from "../components/ui";
import {
  StateBadge,
  StakeBar,
  ValidatorLink,
  CorroborationLine,
  OneOperatorNote,
} from "../components/validatorBits";

export function ValidatorsPage() {
  const [set, setSet] = useState<ValidatorSet | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    fetchValidatorSet()
      .then((s) => !stop && setSet(s))
      .catch((e) => !stop && setErr(String(e?.message ?? e)));
    return () => {
      stop = true;
    };
  }, []);

  if (err) {
    return (
      <div className="container">
        <h1 className="page-title">Validators</h1>
        <div className="errbox">
          The validator set could not be read ({err}). This reports the explorer's own aggregator,
          not the network — the chain may well be finalising normally.
        </div>
      </div>
    );
  }
  if (!set) return <Loading label="Reading the validator set…" />;

  const live = set.validators.filter((r): r is G4Validator => !isGap(r));
  const gaps = set.validators.filter(isGap);
  const { shares, total } = stakeShares(set.validators);
  const nakamoto = nakamotoCoefficient(shares, total);
  const toHalf = stakeToReach(shares, total, 0.5);
  const toTwoThirds = stakeToReach(shares, total, 2 / 3);
  const q = quantiles(shares);
  const gini = giniBps(shares);
  const states = tallyByState(set.validators);

  const ownTotal = live.reduce((a, v) => a + BigInt(v.own_stake_sat), 0n);
  const leakTotal = live.reduce((a, v) => a + (leakedSat(v) ?? 0n), 0n);
  const leakPct = ownTotal === 0n ? 0 : Number((leakTotal * 10_000n) / ownTotal) / 100;
  const maxOwn = live.reduce((m, v) => (BigInt(v.own_stake_sat) > m ? BigInt(v.own_stake_sat) : m), 0n);

  // The genesis bond every validator started with, and what the set would hold
  // if none of it had ever been leaked.
  const bondEach = PARAMS.minDepositSat.value;
  const bondTotal = bondEach * BigInt(live.length);

  // A validator that has been absent for longer than the rest carries a
  // visibly larger share of leaked weight. This is DERIVED, not asserted: the
  // median leak fraction is the fleet's shared history, and an outlier above
  // it has missed epochs the others did not.
  const fracs = live
    .map((v) => ({ v, f: leakedFraction(v) }))
    .filter((x): x is { v: G4Validator; f: number } => x.f !== null);
  const sortedF = [...fracs].map((x) => x.f).sort((a, b) => a - b);
  const medianF = sortedF.length ? sortedF[Math.floor(sortedF.length / 2)] : 0;
  const outliers = fracs
    .filter((x) => x.f > medianF + 0.03)
    .sort((a, b) => b.f - a.f);

  const capBpsNow = cohortCapBps(set.head.epoch);
  const independentNow = independentFloorBps(set.head.epoch);

  return (
    <div className="container">
      <h1 className="page-title">Validators</h1>
      <p className="page-lede">
        Genesis-4 is secured by {fmtInt(set.counts.total)} validators committed at genesis, each
        bonded and each slashable. Blocks arrive on a {PARAMS.slotSecs.value}-second slot;{" "}
        {PARAMS.slotsPerEpoch.value} slots make an epoch, and an epoch is what justifies and
        finalises.
      </p>

      <CorroborationLine c={set.corroboration} at={set.generatedAt} />

      <div className="g4-grid card vsummary">
        <div className="g4-stat">
          <span className="g4-k">Registered</span>
          <span className="g4-v">{fmtInt(set.counts.total)}</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Counted active</span>
          <span className="g4-v">{fmtInt(set.counts.active)}</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Bonded</span>
          <span className="g4-v">{fmtBloch(ownTotal, 0)}</span>
          <span className="g4-dim">own stake in the registry</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Consensus weight</span>
          <span className="g4-v">{fmtBloch(total, 0)}</span>
          <span className="g4-dim">what the roster actually carries</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Leaked away</span>
          <span className="g4-v bad-fg">{fmtNum(leakPct, 1)}%</span>
          <span className="g4-dim">{fmtBloch(leakTotal, 0)} BLCH, permanently</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Head</span>
          <span className="g4-v">epoch {fmtInt(set.head.epoch)}</span>
          <span className="g4-dim">finalised {fmtInt(set.head.finalized.epoch)}</span>
        </div>
      </div>

      {/* ── The bond, and what is left of it ───────────────────────────── */}
      <section className="card">
        <h2 className="snap-h2">Half of every bond is no longer consensus weight</h2>
        <p>
          Each validator was bonded at exactly{" "}
          <strong>{fmtBloch(bondEach, 0)} BLCH</strong> at genesis — {fmtInt(live.length)} of them,{" "}
          {fmtBloch(bondTotal, 0)} BLCH in total. That bond sits <em>outside</em> the chain's issued
          supply: consensus counts it in the validator registry and never in the eUTXO set, so it
          was never part of what the genesis block issued.
        </p>
        <p>
          Bonds have since grown on proposal rewards, to{" "}
          <strong>{fmtBloch(ownTotal, 0)} BLCH</strong>. But the roster carries only{" "}
          <strong>{fmtBloch(total, 0)} BLCH</strong> of it. The difference —{" "}
          <strong>{fmtBloch(leakTotal, 0)} BLCH, {fmtNum(leakPct, 1)}% of the whole</strong> — is
          weight the inactivity leak took during past epochs of non-finality.
        </p>
        <p className="notebox-inline">
          <strong>Two totals that look interchangeable and are not.</strong> The figure{" "}
          <code>getchaininfo</code> reports as <code>total_active_stake_sat</code> is summed over
          the roster <em>before</em> the leak is subtracted — it is the bonded number above, not
          the weight one. The <code>effective_stake_sat</code> on each validator is the leaked one.
          Dividing one by the other, which is the obvious thing to do, understates every
          validator's share of consensus weight by about half. Every share on this page is taken
          against the sum of the same post-leak records it came from.
        </p>
        <p className="notebox-inline">
          <strong>It does not come back.</strong> The leak accumulator has one write path and only
          ever adds; the code that would zero it on recovery sits behind a flag day set to{" "}
          <code>u64::MAX</code>, which means inert. It is switched off for a concrete reason:
          re-scoring historical epochs under new leak rules would make a replaying node compute a
          state root that the blocks already written do not carry, and the chain would stop. So
          this is a permanent reduction, not a temporary penalty.
        </p>
      </section>

      <OneOperatorNote withdrawalHash={PARAMS.withdrawalScriptHash.value} />

      {/* ── Concentration ─────────────────────────────────────────────── */}
      <section className="card">
        <h2 className="snap-h2">Concentration</h2>
        <div className="g4-grid">
          <div className="g4-stat">
            <span className="g4-k">Nakamoto coefficient</span>
            <span className="g4-v">{fmtInt(nakamoto)}</span>
            <span className="g4-dim">indices holding one third</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">To half</span>
            <span className="g4-v">{fmtInt(toHalf)}</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">To two thirds</span>
            <span className="g4-v">{fmtInt(toTwoThirds)}</span>
            <span className="g4-dim">enough to finalise alone</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Gini</span>
            <span className="g4-v">{fmtNum(gini / 100, 2)}%</span>
            <span className="g4-dim">by index, not by operator</span>
          </div>
        </div>
        {q && (
          <p className="lookup-hint">
            Effective stake spans {fmtBloch(q.min, 0)} to {fmtBloch(q.max, 0)} BLCH; the median
            validator carries {fmtBloch(q.p50, 0)} and the 90th percentile {fmtBloch(q.p90, 0)}.
          </p>
        )}
        <p className="notebox-inline">
          Every figure in this panel measures <strong>stake per validator index</strong>. None of
          them measures stake per operator, and on today's set the two are not related: all{" "}
          {fmtInt(set.counts.total)} indices share one withdrawal address, so the true Nakamoto
          coefficient of this chain is <strong>1</strong> and no arithmetic over the registry can
          show otherwise. The numbers above become meaningful only once validators exist that are
          not the genesis cohort.
        </p>
        <StakeChart shares={shares} total={total} />
      </section>

      {/* ── The set as it stands ──────────────────────────────────────── */}
      <section className="card">
        <h2 className="snap-h2">States</h2>
        <div className="statetally">
          {states.map((s) => (
            <div key={s.state} className="statetally-row">
              <span className={"pill " + (s.state === "active" ? "ok" : "quiet")}>{s.state}</span>
              <span className="statetally-n">{fmtInt(s.count)}</span>
              <span className="faint">{fmtBloch(s.stake, 0)} BLCH of weight</span>
            </div>
          ))}
        </div>
        <p className="lookup-hint">
          These are the node's own words. <code>getvalidator</code> reports a{" "}
          <code>state</code> — one of active, queued, exiting, exited, slashed — and a separate{" "}
          <code>slashed</code> boolean. There is no <code>status</code> field on this RPC; a script
          that reads one gets <code>undefined</code> for every healthy validator in the set.
        </p>
      </section>

      {/* ── 64 counted, 63 running ─────────────────────────────────────── */}
      <section className="card">
        <h2 className="snap-h2">The chain counts {fmtInt(set.counts.active)}. {fmtInt(set.counts.active - 1)} are running.</h2>
        <p>
          One validator — index 63 — was stopped and disabled after spending thirteen hours
          building on a fork of its own. It has not been restarted. The registry still reports it{" "}
          <span className="pill ok">active</span>, because nothing in consensus notices that a
          validator has been switched off: <code>state</code> is a function of the activation and
          exit epochs recorded on chain, and no exit was ever submitted for it.
        </p>
        <p>
          So it stays in the quorum denominator. Reaching two thirds means reaching two thirds of a
          set that includes a validator which cannot vote, and there is no process that ends this.
          The mechanism that would erode its weight — the inactivity leak — engages only after{" "}
          {PARAMS.inactivityLeakThresholdEpochs.value} consecutive epochs without finality, and a
          healthy chain finalises at a lag of {PARAMS.finalityLagEpochs.value}. While finality
          works, the leak never fires, and an absent validator is never charged for being absent.
          The only thing that removes it is its operator submitting an exit.
        </p>
        <p className="notebox-inline">
          The size of the headwind is worth stating precisely, because the obvious figure is the
          wrong one. By headcount it is one of {fmtInt(set.counts.total)} — 1.56%. By consensus
          weight, which is what a quorum actually counts, it is{" "}
          <strong>
            {(() => {
              const v63 = live.find((x) => x.index === 63);
              if (!v63 || v63.effective_stake_sat === null || total === 0n) return "not readable";
              const sh = Number((BigInt(v63.effective_stake_sat) * 1_000_000n) / total) / 1_000_000;
              return `${fmtNum(sh * 100, 3)}%`;
            })()}
          </strong>{" "}
          — smaller, because past non-finality already leaked away more of validator 63's weight
          than the fleet median. Both numbers are true; only the second one is the one a quorum
          feels.
        </p>
        <p className="lookup-hint">
          This paragraph is an operational fact, not a chain reading. Nothing the RPC serves
          distinguishes a validator that is switched off from one that is merely unlucky this
          epoch — that is precisely the gap it describes. What the chain <em>does</em> show is
          below.
        </p>
      </section>

      {outliers.length > 0 && (
        <section className="card">
          <h2 className="snap-h2">Counted active, and not keeping up</h2>
          <p>
            The fleet's shared history shows as a common leak fraction — the median validator has
            lost {fmtNum(medianF * 100, 1)}% of its bond to past non-finality. These carry
            noticeably more, which means they were absent for epochs the others attested through:
          </p>
          <ul className="outliers">
            {outliers.map(({ v, f }) => (
              <li key={v.index}>
                <ValidatorLink index={v.index} /> — {fmtNum(f * 100, 1)}% leaked against a fleet
                median of {fmtNum(medianF * 100, 1)}%, still reported{" "}
                <StateBadge state={v.state} slashed={v.slashed} />, carrying{" "}
                {fmtNum(
                  total === 0n
                    ? 0
                    : (Number((BigInt(v.effective_stake_sat ?? "0") * 1_000_000n) / total) /
                        1_000_000) *
                        100,
                  3,
                )}
                % of consensus weight
              </li>
            ))}
          </ul>
          <p className="notebox-inline">
            A validator that is switched off stays in the quorum denominator, and nothing removes
            it. The inactivity leak — the mechanism that would shrink its weight — only engages
            after {PARAMS.inactivityLeakThresholdEpochs.value} consecutive epochs without finality,
            and a healthy chain finalises at a lag of {PARAMS.finalityLagEpochs.value}. So while
            finality is working, an absent validator is never leaked against; it simply sits in the
            denominator and makes every quorum slightly harder to reach, with no expiry and no
            process that ends it. Exiting is a decision its operator has to take.
          </p>
        </section>
      )}

      {/* ── The table ─────────────────────────────────────────────────── */}
      <section className="card table-wrap">
        <h2 className="snap-h2">Every validator</h2>
        <table className="tbl vtable">
          <thead>
            <tr>
              <th className="num">#</th>
              <th>State</th>
              <th className="num">Bonded</th>
              <th className="num">Weight</th>
              <th>Weight vs bond</th>
              <th className="num">Leaked</th>
              <th className="num">Share</th>
              <th className="num">Activated</th>
            </tr>
          </thead>
          <tbody>
            {set.validators.map((r) => (
              <ValidatorRowView key={r.index} row={r} total={total} maxOwn={maxOwn} />
            ))}
          </tbody>
        </table>
      </section>

      {gaps.length > 0 && (
        <p className="lookup-hint">
          {fmtInt(gaps.length)} index{gaps.length === 1 ? "" : "es"} could not be read this round.
          That is the aggregator or the archival, not a missing validator — the registry is
          committed and its size does not change between reads.
        </p>
      )}

      <p className="lookup-hint">
        The set is fixed at {fmtInt(set.counts.total)} today, and the reason is policy rather than
        protocol: deposits are refused at mempool admission, so no queue can form.{" "}
        <Link to="/validators/queues">What happens when that opens</Link> — the activation and exit
        rules, and the cohort cap that is supposed to make the chain independent of its founder —
        is a page of its own. The cap currently allows the cohort {fmtNum(capBpsNow / 100, 2)}% of
        weight and leaves {fmtNum(independentNow / 100, 2)}% to everyone else.
      </p>
    </div>
  );
}

function ValidatorRowView({
  row,
  total,
  maxOwn,
}: {
  row: ValidatorRow;
  total: bigint;
  maxOwn: bigint;
}) {
  if (isGap(row)) {
    return (
      <tr className="row-missed">
        <td className="num">
          <ValidatorLink index={row.index} />
        </td>
        <td colSpan={7} className="faint">
          not read this round — {row.unavailable}
        </td>
      </tr>
    );
  }
  const own = BigInt(row.own_stake_sat);
  const eff = row.effective_stake_sat === null ? null : BigInt(row.effective_stake_sat);
  const lost = leakedFraction(row);
  const share = eff === null || total === 0n ? null : Number((eff * 1_000_000n) / total) / 1_000_000;
  return (
    <tr>
      <td className="num">
        <ValidatorLink index={row.index} />
      </td>
      <td>
        <StateBadge state={row.state} slashed={row.slashed} />
      </td>
      <td className="num">{fmtBloch(own, 0)}</td>
      <td className="num">
        {eff === null ? <span className="faint">not sampled</span> : fmtBloch(eff, 0)}
      </td>
      <td>
        <StakeBar own={own} effective={eff} max={maxOwn} />
      </td>
      <td className="num">{lost === null ? "—" : `${fmtNum(lost * 100, 1)}%`}</td>
      <td className="num">{share === null ? "—" : `${fmtNum(share * 100, 2)}%`}</td>
      <td className="num">
        {row.activation_epoch === null ? <span className="faint">queued</span> : fmtInt(row.activation_epoch)}
      </td>
    </tr>
  );
}

/**
 * Effective stake per validator, largest first.
 *
 * A bar chart rather than a pie: the question a reader has is "how uneven is
 * this", and length is the only encoding people compare accurately. The
 * two-thirds line is drawn because it is the threshold that decides finality —
 * where the cumulative curve crosses it is the entire story of the chart.
 */
function StakeChart({ shares, total }: { shares: { index: number; effective: bigint }[]; total: bigint }) {
  if (shares.length === 0 || total === 0n) return null;
  const W = 720;
  const H = 180;
  const max = shares[0].effective;
  const bw = W / shares.length;

  let acc = 0n;
  const cumulative = shares.map((s) => {
    acc += s.effective;
    return Number((acc * 1_000_000n) / total) / 1_000_000;
  });
  const crossTwoThirds = cumulative.findIndex((c) => c >= 2 / 3) + 1;

  return (
    <div className="vchart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" width="100%" height={H}
        aria-label="Effective stake by validator, largest first, with the cumulative share">
        {shares.map((s, i) => {
          const h = Number((s.effective * BigInt(Math.round(H - 30))) / max);
          return (
            <rect
              key={s.index}
              x={i * bw + 0.5}
              y={H - 20 - h}
              width={Math.max(1, bw - 1)}
              height={h}
              fill="var(--chart-1)"
              opacity={0.85}
            />
          );
        })}
        {/* Cumulative share, right-hand reading 0..100%. */}
        <polyline
          fill="none"
          stroke="var(--chart-3)"
          strokeWidth="1.6"
          points={cumulative.map((c, i) => `${i * bw + bw / 2},${H - 20 - c * (H - 30)}`).join(" ")}
        />
        <line
          x1="0"
          x2={W}
          y1={H - 20 - (2 / 3) * (H - 30)}
          y2={H - 20 - (2 / 3) * (H - 30)}
          stroke="var(--danger)"
          strokeWidth="1"
          strokeDasharray="4 3"
        />
        <text x={4} y={H - 24 - (2 / 3) * (H - 30)} className="vchart-lbl" fill="var(--danger)">
          two thirds — the finality threshold
        </text>
      </svg>
      <p className="lookup-hint">
        Bars are effective stake per validator, largest first; the line is the running total. It
        crosses two thirds at validator {fmtInt(crossTwoThirds)} of {fmtInt(shares.length)} — but
        see the note above on why counting indices is not counting operators.
      </p>
    </div>
  );
}
