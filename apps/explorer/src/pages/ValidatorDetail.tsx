// SPDX-License-Identifier: AGPL-3.0-or-later
//
// One validator.
//
// The hard part of this page is what it refuses to show. A reader arriving
// here expects the columns every other chain's validator page has: uptime,
// attestation rate, missed duties, inclusion distance. Genesis-4 publishes
// none of them — a block header names its proposer and counts the attestations
// it included, and there is no bitfield saying who attested and no method
// serving the duty roster. So a "97% attestation rate" on this page could only
// be a number with the shape of a measurement and none of the content.
//
// The choice made here is to leave those fields visibly empty, name the method
// that would fill them, and show the one record that is real: which slots this
// validator actually proposed in a bounded recent window.
import { useEffect, useState } from "react";
import { G4Validator } from "../lib/g4";
import { leakedSat, leakedFraction, fetchValidatorSet, stakeShares } from "../lib/validators";
import {
  recentWindow,
  proposalRecord,
  proposalIndex,
  seatsPerSlot,
  SlotWindow,
  ProposalRecord,
} from "../lib/participation";
import { PARAMS, epochStartMs } from "../lib/g4params";
import { fmtBloch, fmtInt, fmtNum, fmtTime, timeAgo } from "../lib/format";
import { Link } from "../lib/router";
import { Loading } from "../components/ui";
import { StateBadge, StakeBar, CorroborationLine } from "../components/validatorBits";

/** Two epochs. Enough for the record to mean something, small enough to cache. */
const WINDOW_SLOTS = 64;

interface Loaded {
  v: G4Validator;
  counts: { total: number; active: number; total_active_stake_sat: string };
  /** Sum of POST-leak effective stakes — the only valid share denominator. */
  rosterWeight: bigint;
  head: { epoch: number; slot: number; height: number };
  source: string;
  generatedAt: number;
  corroboration?: any;
}

export function ValidatorDetailPage({ index }: { index: number }) {
  const [d, setD] = useState<Loaded | null>(null);
  const [win, setWin] = useState<SlotWindow | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    (async () => {
      try {
        // The WHOLE set, not just this index — and the reason is arithmetic
        // rather than convenience. This validator's share of consensus weight
        // has to be taken against the sum of the other validators' POST-leak
        // effective stakes. The obvious denominator, `total_active_stake_sat`
        // from `getchaininfo`, is summed over the PRE-leak roster, and on this
        // chain the two differ by more than half; dividing one by the other
        // would understate every share on this page by that much.
        //
        // The cost is two edge requests against a 60-second cache that the
        // set page has usually already warmed, so this buys correctness for
        // approximately nothing.
        const set = await fetchValidatorSet();
        if (stop) return;
        const found = set.validators.find((r) => r.index === index);
        if (!found) {
          setErr(`no validator at index ${index} — the registry holds ${set.counts.total}`);
          return;
        }
        if ("unavailable" in found) {
          setErr(String((found as { unavailable: string }).unavailable));
          return;
        }
        const { total } = stakeShares(set.validators);
        setD({
          v: found as G4Validator,
          counts: set.counts,
          rosterWeight: total,
          head: set.head,
          source: set.source,
          generatedAt: set.generatedAt,
          corroboration: set.corroboration,
        });
        const w = await recentWindow(WINDOW_SLOTS);
        if (!stop) setWin(w);
      } catch (e: any) {
        if (!stop) setErr(String(e?.message ?? e));
      }
    })();
    return () => {
      stop = true;
    };
  }, [index]);

  if (err) {
    return (
      <div className="container">
        <h1 className="page-title">Validator {index}</h1>
        <div className="errbox">{err}</div>
        <p className="lookup-hint">
          <Link to="/validators">Back to the set</Link>
        </p>
      </div>
    );
  }
  if (!d) return <Loading label={`Reading validator ${index}…`} />;

  const { v } = d;
  const own = BigInt(v.own_stake_sat);
  const eff = v.effective_stake_sat === null ? null : BigInt(v.effective_stake_sat);
  const lost = leakedSat(v);
  const lostFrac = leakedFraction(v);
  const total = d.rosterWeight;
  const share = eff === null || total === 0n ? null : Number((eff * 1_000_000n) / total) / 1_000_000;
  const bonded = BigInt(d.counts.total_active_stake_sat);
  const bondShare = bonded === 0n ? null : Number((own * 1_000_000n) / bonded) / 1_000_000;

  const rec: ProposalRecord | null = win ? proposalRecord(win) : null;
  const mine = rec?.byProposer.get(index) ?? 0;
  const pIndex = rec ? proposalIndex(mine, rec, d.counts.active) : 0;
  const mySlots = win?.slots.filter((s) => s.present && s.proposer_index === index) ?? [];

  return (
    <div className="container">
      <h1 className="page-title">
        Validator {index} <StateBadge state={v.state} slashed={v.slashed} />
      </h1>
      <p className="page-lede mono-wrap">
        <code>{v.pubkey_hash}</code>
      </p>
      <CorroborationLine c={d.corroboration} at={d.generatedAt} />

      <div className="g4-grid card">
        <div className="g4-stat">
          <span className="g4-k">Bonded</span>
          <span className="g4-v">{fmtBloch(own, 0)}</span>
          <span className="g4-dim">own stake</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Consensus weight</span>
          <span className="g4-v">{eff === null ? "not sampled" : fmtBloch(eff, 0)}</span>
          <span className="g4-dim">
            {share === null ? "" : `${fmtNum(share * 100, 3)}% of consensus weight`}
          </span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Leaked</span>
          <span className="g4-v bad-fg">{lostFrac === null ? "—" : `${fmtNum(lostFrac * 100, 1)}%`}</span>
          <span className="g4-dim">{lost === null ? "" : `${fmtBloch(lost, 0)} BLCH, permanently`}</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Share of bonded stake</span>
          <span className="g4-v">{bondShare === null ? "—" : `${fmtNum(bondShare * 100, 3)}%`}</span>
          <span className="g4-dim">before the leak is subtracted</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Commission</span>
          <span className="g4-v">{fmtNum(Number(v.commission_bps) / 100, 2)}%</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Activated</span>
          <span className="g4-v">
            {v.activation_epoch === null ? "queued" : `epoch ${fmtInt(v.activation_epoch)}`}
          </span>
          {v.activation_epoch !== null && (
            <span className="g4-dim">{fmtTime(epochStartMs(v.activation_epoch) / 1000)}</span>
          )}
        </div>
        <div className="g4-stat">
          <span className="g4-k">Exit</span>
          <span className="g4-v">
            {v.exit_epoch === null ? "none" : `epoch ${fmtInt(v.exit_epoch)}`}
          </span>
          <span className="g4-dim">
            {v.withdrawable_epoch === null
              ? "no withdrawal scheduled"
              : `withdrawable at epoch ${fmtInt(v.withdrawable_epoch)}`}
          </span>
        </div>
      </div>

      <section className="card">
        <h2 className="snap-h2">Bond against weight</h2>
        <StakeBar own={own} effective={eff} max={own} />
        <p className="lookup-hint">
          The full bar is this validator's bond of {fmtBloch(own, 0)} BLCH. The filled part is what
          the consensus roster carries; the rest was taken by the inactivity leak during epochs the
          chain did not finalise, and does not return — the recovery path is compiled in but held
          behind an inert flag day, because re-scoring past epochs would make replaying nodes
          compute a state root the existing blocks do not carry.
        </p>
      </section>

      {/* ── Participation, and the honest hole in it ───────────────────── */}
      <section className="card">
        <h2 className="snap-h2">Proposals in the last {fmtInt(WINDOW_SLOTS)} slots</h2>
        {!win || !rec ? (
          <Loading label="Reading the recent window…" />
        ) : (
          <>
            <div className="g4-grid">
              <div className="g4-stat">
                <span className="g4-k">Proposed</span>
                <span className="g4-v">{fmtInt(mine)}</span>
                <span className="g4-dim">of {fmtInt(rec.filled)} blocks in the window</span>
              </div>
              <div className="g4-stat">
                <span className="g4-k">Against an equal share</span>
                <span className="g4-v">{fmtNum(pIndex, 2)}×</span>
                <span className="g4-dim">1.00× is exactly its turn</span>
              </div>
              <div className="g4-stat">
                <span className="g4-k">Window</span>
                <span className="g4-v">
                  {fmtInt(win.from)}–{fmtInt(win.to)}
                </span>
                <span className="g4-dim">
                  {fmtInt(rec.empty)} slot{rec.empty === 1 ? "" : "s"} with no block
                </span>
              </div>
            </div>

            {mySlots.length > 0 && (
              <div className="table-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th className="num">Slot</th>
                      <th>Block</th>
                      <th className="num">Txs</th>
                      <th className="num">Attestations</th>
                      <th>Age</th>
                      <th>State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mySlots.map((s) => (
                      <tr key={s.slot}>
                        <td className="num">
                          <Link to={`/slot/${s.slot}`}>{fmtInt(s.slot)}</Link>
                        </td>
                        <td>
                          <code>{s.block_id?.slice(0, 16)}</code>
                        </td>
                        <td className="num">{fmtInt(s.tx_count ?? 0)}</td>
                        <td className="num">{fmtInt(s.attestation_count ?? 0)}</td>
                        <td className="faint">{s.timestamp ? timeAgo(s.timestamp) : "—"}</td>
                        <td>
                          {s.finalized ? (
                            <span className="pill ok">final</span>
                          ) : (
                            <span className="pill quiet">{s.finality}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <p className="notebox-inline">
              <strong>Two attestations per block is full participation, not a shortfall.</strong>{" "}
              Genesis-4 does not sample a committee — it sorts the roster, shuffles it and cuts it
              into {fmtInt(win.head.slots_per_epoch)} contiguous chunks, one per slot of the epoch.
              With {fmtInt(d.counts.active)} validators that is{" "}
              {fmtInt(seatsPerSlot(d.counts.active, win.head.slots_per_epoch))} seats per slot, so a
              block including {fmtInt(seatsPerSlot(d.counts.active, win.head.slots_per_epoch))}{" "}
              attestations has included all of them. The mean across this window is{" "}
              {fmtNum(rec.meanAttestations, 2)}.
            </p>
            <p className="notebox-inline">
              <strong>A window this small is a texture, not a score.</strong> With{" "}
              {fmtInt(d.counts.active)} validators sharing {fmtInt(rec.filled)} blocks, a perfectly
              healthy validator is expected to propose about{" "}
              {fmtNum(rec.filled / Math.max(1, d.counts.active), 1)} times, so zero here is
              unremarkable and two is not a distinction. Only a validator that shows zero across
              many windows is telling you anything.
            </p>
          </>
        )}
      </section>

      <section className="card">
        <h2 className="snap-h2">What this page cannot tell you</h2>
        <p>
          There is no attestation rate for this validator, and there is no honest way to compute
          one from what Genesis-4 serves today. A block header carries{" "}
          <code>attestation_count</code> — how many attestations the proposer included — and an{" "}
          <code>attestation_root</code>. It does not carry which validators attested, and the node
          serves no <code>getattestation</code>, no <code>getcommittee</code> and no duty roster.
        </p>
        <p>
          Two things follow, and both are why the columns above stop where they do. A missed slot
          cannot be charged to anyone, because nothing says whose slot it was. And a validator's
          share of attestations cannot be measured at all, because the aggregate does not name its
          signers. Filling either column would take inventing the data.
        </p>
        <p className="lookup-hint">
          Both become answerable with an archival indexer that folds the chain and keeps per-epoch
          participation. That work is scoped and not yet built; until it exists these fields stay
          empty rather than estimated.
        </p>
      </section>

      <p className="lookup-hint">
        <Link to="/validators">Back to the set</Link> ·{" "}
        <Link to="/validators/queues">Activation and exit rules</Link>
      </p>
    </div>
  );
}
