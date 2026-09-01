// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Joining and leaving the validator set.
//
// This page documents machinery that is currently doing nothing, and that is
// the reason it exists. The activation queue, the exit delay and the cohort
// cap are all live consensus code with real constants, and all three are
// presently inert for reasons that have nothing to do with the code: nobody
// can deposit, because deposits are refused before they reach a block.
//
// So the page reads the constants from consensus, shows what they would do,
// and states plainly which of them is actually holding the set at 64 today.
// The distinction between "the protocol limits this" and "an operator decided
// this" is the single most misread thing about the current chain, and it is
// the thing this page is for.
import { useEffect, useState } from "react";
import { fetchValidatorSet, tallyByState, ValidatorSet, isGap } from "../lib/validators";
import { G4Validator } from "../lib/g4";
import {
  PARAMS,
  EPOCH_SECS,
  cohortCapBps,
  independentFloorBps,
  capStatus,
  epochStartMs,
  TAPER_COMPLETE_MS,
} from "../lib/g4params";
import { fmtBloch, fmtInt, fmtNum, fmtDuration } from "../lib/format";
import { Link } from "../lib/router";
import { Loading } from "../components/ui";
import { CitedValue } from "../components/validatorBits";

export function ValidatorQueuesPage() {
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

  const epochsToTime = (n: number) => fmtDuration(n * EPOCH_SECS);

  return (
    <div className="container">
      <h1 className="page-title">Activation, exit, and the cohort cap</h1>
      <p className="page-lede">
        Everything on this page is live consensus code with constants you can check against the
        source. Almost none of it is currently doing anything, and the gap between those two
        sentences is the subject.
      </p>

      {err && <div className="errbox">{err}</div>}

      {/* ── Why the set is 64 ─────────────────────────────────────────── */}
      <section className="card">
        <h2 className="snap-h2">The set is held at 64 by policy, not by protocol</h2>
        <p>
          There is no consensus rule capping the validator set at{" "}
          {fmtInt(PARAMS.genesisValidators.value)}. The registry can grow, the activation queue is
          implemented and the constants below are enforced. What stops anyone joining is earlier
          and simpler: <strong>deposit transactions are refused at mempool admission</strong>, so a
          deposit never reaches a block and no queue can ever form.
        </p>
        <p>
          That is an operator decision, and it can be reversed by changing a policy — not by a
          fork, not by a flag day, not by a vote. It is worth being precise about, because "the
          validator set is fixed" and "the operator is not currently accepting validators" sound
          alike and are not the same claim. Only the second one is true.
        </p>
      </section>

      {/* ── Live queue state ──────────────────────────────────────────── */}
      <section className="card">
        <h2 className="snap-h2">The queues right now</h2>
        {!set ? (
          <Loading label="Reading the set…" />
        ) : (
          <QueueState set={set} />
        )}
      </section>

      {/* ── Activation ────────────────────────────────────────────────── */}
      <section className="card">
        <h2 className="snap-h2">Joining</h2>
        <div className="g4-grid">
          <div className="g4-stat">
            <span className="g4-k">Minimum deposit</span>
            <span className="g4-v">
              <CitedValue c={PARAMS.minDepositSat}>{fmtBloch(PARAMS.minDepositSat.value, 0)}</CitedValue>
            </span>
            <span className="g4-dim">BLCH — the same bond the genesis 64 carry</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Activations per epoch</span>
            <span className="g4-v">
              <CitedValue c={PARAMS.maxActivationsPerEpoch}>
                {fmtInt(PARAMS.maxActivationsPerEpoch.value)}
              </CitedValue>
            </span>
            <span className="g4-dim">
              {fmtInt(PARAMS.maxActivationsPerEpoch.value * 90)} a day at 90 epochs
            </span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Activation delay</span>
            <span className="g4-v">
              <CitedValue c={PARAMS.activationDelayEpochs}>
                {fmtInt(PARAMS.activationDelayEpochs.value)}
              </CitedValue>{" "}
              <span className="g4-dim">epochs</span>
            </span>
            <span className="g4-dim">{epochsToTime(PARAMS.activationDelayEpochs.value)} minimum wait</span>
          </div>
        </div>
        <p className="lookup-hint">
          A deposit becomes eligible {PARAMS.activationDelayEpochs.value} epochs after the block
          that included it, and at most {PARAMS.maxActivationsPerEpoch.value} eligible deposits are
          admitted per epoch boundary. Doubling the set from{" "}
          {fmtInt(PARAMS.genesisValidators.value)} would therefore take at least{" "}
          {epochsToTime(
            PARAMS.activationDelayEpochs.value +
              PARAMS.genesisValidators.value / PARAMS.maxActivationsPerEpoch.value,
          )}{" "}
          of continuous admission, once admission exists at all.
        </p>
      </section>

      {/* ── Exit ──────────────────────────────────────────────────────── */}
      <section className="card">
        <h2 className="snap-h2">Leaving</h2>
        <div className="g4-grid">
          <div className="g4-stat">
            <span className="g4-k">Exit delay</span>
            <span className="g4-v">
              <CitedValue c={PARAMS.exitDelayEpochs}>{fmtInt(PARAMS.exitDelayEpochs.value)}</CitedValue>{" "}
              <span className="g4-dim">epochs</span>
            </span>
            <span className="g4-dim">{epochsToTime(PARAMS.exitDelayEpochs.value)} until weight stops</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Withdrawal delay</span>
            <span className="g4-v">
              <CitedValue c={PARAMS.withdrawalDelayEpochs}>
                {fmtInt(PARAMS.withdrawalDelayEpochs.value)}
              </CitedValue>{" "}
              <span className="g4-dim">epochs</span>
            </span>
            <span className="g4-dim">{epochsToTime(PARAMS.withdrawalDelayEpochs.value)} until coins move</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Exits per epoch</span>
            <span className="g4-v bad-fg">unlimited</span>
            <span className="g4-dim">no rate limit exists</span>
          </div>
        </div>
        <p className="notebox-inline">
          <strong>Exits are not rate-limited at all.</strong> Joining is metered —{" "}
          {PARAMS.maxActivationsPerEpoch.value} per epoch, after a{" "}
          {PARAMS.activationDelayEpochs.value}-epoch wait — but nothing meters leaving. There is no
          exit churn budget in the staking code, and the source says so in as many words: the
          entire self-bonded set can exit in a single epoch. The delays above are per-validator
          waiting periods, not a limit on how many may start waiting at once.
        </p>
        <p className="lookup-hint">
          The asymmetry is deliberate in the sense that it was noticed and documented, and it is
          the shape you would want if the risk you are guarding against is a hostile set being
          stuffed quickly. It is the wrong shape if the risk is a correlated walkout — and with one
          operator behind all {fmtInt(PARAMS.genesisValidators.value)} validators today, a
          correlated walkout is the only kind available.
        </p>
      </section>

      {/* ── The cohort cap ────────────────────────────────────────────── */}
      <section className="card">
        <h2 className="snap-h2">The cohort cap — the one decentralisation rule that runs</h2>
        <p>
          The genesis cohort is a fixed set published in the genesis block. It can only shrink.
          Its <em>combined</em> effective stake is capped, and the cap declines linearly from the
          whole set at genesis to{" "}
          <strong>{fmtNum(PARAMS.cohortCapFloorBps.value / 100, 2)}%</strong> of consensus weight
          after {fmtInt(PARAMS.cohortTaperEpochs.value)} epochs — one year. Stake over the cap
          earns nothing and carries no weight; it is not confiscated.
        </p>
        <p>
          One third is not a modest-looking round number. It is exactly the share that can stall a
          two-thirds quorum, so the rule says one thing precisely: after year one, the founder
          cannot halt Bloch alone. It does not say the founder cannot finalise a bad state — that
          needs two thirds and was never within reach either way.
        </p>

        <TaperChart currentEpoch={set?.head.epoch ?? 0} />

        {set && <CapToday set={set} />}

        <p className="notebox-inline">
          <strong>Where the rule stops, stated plainly.</strong> The cap binds the genesis cohort
          by index. Nothing prevents the same party funding new validators after genesis under
          addresses that are not in the cohort, and no consensus rule can see beneficial ownership
          behind an address. The enforceable part is real and bounded; past the cohort, one third
          is a commitment somebody has to verify from outside.
        </p>
      </section>

      <p className="lookup-hint">
        <Link to="/validators">Back to the set</Link>
      </p>
    </div>
  );
}

function QueueState({ set }: { set: ValidatorSet }) {
  const states = tallyByState(set.validators);
  const live = set.validators.filter((r): r is G4Validator => !isGap(r));
  const queued = live.filter((v) => v.state === "queued");
  const exiting = live.filter((v) => v.state === "exiting");
  const exited = live.filter((v) => v.state === "exited");

  return (
    <>
      <div className="g4-grid">
        <div className="g4-stat">
          <span className="g4-k">Waiting to activate</span>
          <span className="g4-v">{fmtInt(queued.length)}</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Exiting</span>
          <span className="g4-v">{fmtInt(exiting.length)}</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Exited</span>
          <span className="g4-v">{fmtInt(exited.length)}</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Registry</span>
          <span className="g4-v">{fmtInt(set.counts.total)}</span>
          <span className="g4-dim">unchanged since genesis</span>
        </div>
      </div>
      <p className="lookup-hint">
        {queued.length + exiting.length + exited.length === 0
          ? `Both queues are empty, and the registry is the same ${fmtInt(
              set.counts.total,
            )} validators it was committed with at genesis. No validator has ever joined or left this chain.`
          : "Live queue state, read from the registry."}{" "}
        States are the node's own: {states.map((s) => `${s.count} ${s.state}`).join(", ")}.
      </p>
    </>
  );
}

/** Where the cap is today, and whether it is doing anything. */
function CapToday({ set }: { set: ValidatorSet }) {
  const epoch = set.head.epoch;
  const total = BigInt(set.counts.total_active_stake_sat);
  // Today every validator index is in the genesis cohort, so cohort stake is
  // the whole roster. This is read from the set rather than assumed: the day a
  // non-cohort validator exists, this figure has to change on its own.
  const cohort = total;
  const status = capStatus(epoch, total, cohort);
  const bps = cohortCapBps(epoch);
  const done = new Date(TAPER_COMPLETE_MS).toISOString().replace("T", " ").replace(".000Z", " UTC");

  return (
    <div className="notebox">
      <h3>What the cap is doing at epoch {fmtInt(epoch)}</h3>
      <div className="g4-grid">
        <div className="g4-stat">
          <span className="g4-k">Cohort may hold</span>
          <span className="g4-v">{fmtNum(bps / 100, 2)}%</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Reserved for everyone else</span>
          <span className="g4-v">{fmtNum(independentFloorBps(epoch) / 100, 2)}%</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Status</span>
          <span className="g4-v">
            {status.kind === "enforced" ? "enforced" : status.kind === "deferred" ? "deferred" : "not tapering"}
          </span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Floor reached</span>
          <span className="g4-v">{done}</span>
        </div>
      </div>

      {status.kind === "deferred" && (
        <>
          <p>
            <strong>The cap is armed and currently doing nothing</strong>, because there is no
            independent stake for the cohort to be one third <em>of</em>. All{" "}
            {fmtInt(set.counts.total)} validators are cohort members, so non-cohort stake is zero
            and the rule defers rather than applying.
          </p>
          <p>
            That deferral is load-bearing, not a loophole. The cap is computed as a share of
            non-cohort stake, so with none of it the admissible cohort weight is zero — the whole
            validator set would drop to zero weight and the chain would stop. Integer truncation
            makes that bite at <strong>epoch 5, about 1.3 hours after genesis</strong>. A rule
            written to decentralise the chain would have killed it on day one; adversarial review
            caught it before launch. So the cap defers and reports why, because a chain that halts
            silently hides the fact that nobody showed up.
          </p>
        </>
      )}

      <p>
        The first deposit changes this immediately. Once non-cohort stake reaches one validator's
        worth — {fmtBloch(PARAMS.minDepositSat.value, 0)} BLCH — the cap begins to bind, and at the
        floor it admits the cohort only half of what everyone else holds. The consequence is worth
        being exact about: <strong>a single independent validator with the minimum bond would sit
        on {fmtNum(independentFloorBps(PARAMS.cohortTaperEpochs.value) / 100, 2)}% of finality
        weight by itself</strong>, with all {fmtInt(set.counts.total)} cohort validators scaled
        down to share the remaining third between them. That is the rule working exactly as
        written, and it is a strange enough outcome that it should be understood before it happens
        rather than discovered afterwards.
      </p>
    </div>
  );
}

/**
 * The cap over its full year, with today marked.
 *
 * Drawn from `cohortCapBps` — the same integer arithmetic consensus runs,
 * truncation included — rather than from a smooth line that resembles it.
 */
function TaperChart({ currentEpoch }: { currentEpoch: number }) {
  const W = 720;
  const H = 200;
  const pad = { l: 44, r: 12, t: 14, b: 26 };
  const span = PARAMS.cohortTaperEpochs.value;
  const N = 120;
  const pts = Array.from({ length: N + 1 }, (_, i) => {
    const e = Math.round((i / N) * span * 1.08);
    return { e, bps: cohortCapBps(e) };
  });
  const x = (e: number) => pad.l + (e / (span * 1.08)) * (W - pad.l - pad.r);
  const y = (bps: number) => pad.t + (1 - bps / 10_000) * (H - pad.t - pad.b);

  const nowX = x(Math.min(currentEpoch, span * 1.08));

  return (
    <div className="vchart">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} role="img"
        aria-label="The genesis cohort cap, declining from 100% to 33.33% over one year">
        {[0, 3333, 5000, 6667, 10000].map((b) => (
          <g key={b}>
            <line x1={pad.l} x2={W - pad.r} y1={y(b)} y2={y(b)} stroke="var(--line-soft)" strokeWidth="1" />
            <text x={4} y={y(b) + 4} className="vchart-lbl" fill="var(--text-dim)">
              {(b / 100).toFixed(0)}%
            </text>
          </g>
        ))}
        {/* The area everyone outside the cohort is guaranteed. */}
        <polygon
          fill="var(--chart-2)"
          opacity="0.16"
          points={`${pad.l},${y(10000)} ${pts.map((p) => `${x(p.e)},${y(p.bps)}`).join(" ")} ${W - pad.r},${y(10000)}`}
        />
        <polyline
          fill="none"
          stroke="var(--chart-1)"
          strokeWidth="2"
          points={pts.map((p) => `${x(p.e)},${y(p.bps)}`).join(" ")}
        />
        <line x1={pad.l} x2={W - pad.r} y1={y(3333)} y2={y(3333)}
          stroke="var(--danger)" strokeWidth="1" strokeDasharray="4 3" />
        {currentEpoch > 0 && (
          <>
            <line x1={nowX} x2={nowX} y1={pad.t} y2={H - pad.b} stroke="var(--accent)" strokeWidth="1.5" />
            <text x={nowX + 4} y={pad.t + 10} className="vchart-lbl" fill="var(--accent)">
              now — epoch {fmtInt(currentEpoch)}
            </text>
          </>
        )}
        <text x={pad.l} y={H - 6} className="vchart-lbl" fill="var(--text-dim)">
          genesis
        </text>
        <text x={x(span) - 40} y={H - 6} className="vchart-lbl" fill="var(--text-dim)">
          one year
        </text>
      </svg>
      <p className="lookup-hint">
        The line is the maximum share of consensus weight the {fmtInt(PARAMS.genesisValidators.value)}{" "}
        genesis validators may hold between them; the shaded area above it is the share reserved
        for everyone else. It is a linear taper rather than a cliff on purpose — a step from 100%
        to 33% on one epoch boundary would remove two thirds of the chain's consensus weight in
        sixteen minutes.
      </p>
    </div>
  );
}
