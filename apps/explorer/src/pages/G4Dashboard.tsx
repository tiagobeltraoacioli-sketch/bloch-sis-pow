// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Genesis-4 dashboard — the whole front page.
//
// One rule shapes this file: show what the chain says, and where it says
// nothing, say nothing. A proof-of-stake chain has two separate healths, and
// conflating them hides the interesting failure. Blocks can arrive on every
// slot while finality stalls; that is a real and survivable state, and it must
// be readable at a glance rather than inferred.
import { useEffect, useState } from "react";
import {
  g4rpc,
  pollWhileVisible,
  lastCorroboration,
  G4,
  G4Head,
  G4Corroboration,
  G4ValidatorCount,
} from "../lib/g4";
import { CorroborationBadge, CorroborationNote } from "../components/corroboration";
import { slotRange, SlotCell } from "../lib/source";
import { SlotTable, SlotTally } from "../components/blockstream";
import { fmtBloch, fmtInt, timeAgo } from "../lib/format";
import { Link } from "../lib/router";
import { Loading } from "../components/ui";

/**
 * The two stake totals, from `getstakedistribution`.
 *
 * They are NOT interchangeable and the gap between them is currently a factor
 * of about 2.25. `duty_total_active_stake_sat` is the pre-leak DUTY roster —
 * the number `getvalidatorcount` and `getchaininfo` report. `total_active_stake_sat`
 * is the post-leak CONSENSUS roster, and it is the one every quorum threshold
 * is actually taken against. Telling a reader to take two thirds of the duty
 * total, which is what this page used to do, overstates the quorum by that
 * whole factor. The node names them apart for exactly this reason; see
 * `stake_distribution` in crates/bloch-pos-node/src/rpc.rs.
 */
interface StakeTotals {
  epoch: number;
  total_active_stake_sat: string;
  duty_total_active_stake_sat: string;
}

const POLL_MS = 15_000;
const RECENT = 12;

interface Mempool {
  size: number;
  max: number;
  bytes: number;
}

export function G4Dashboard() {
  const [head, setHead] = useState<G4Head | null>(null);
  const [vals, setVals] = useState<G4ValidatorCount | null>(null);
  const [mp, setMp] = useState<Mempool | null>(null);
  const [cells, setCells] = useState<SlotCell[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // How well corroborated the head is. Held in state beside the head itself so
  // the two are always rendered from the same reading: showing a fresh badge
  // next to a stale number would be worse than showing no badge at all.
  const [corro, setCorro] = useState<G4Corroboration | null>(null);
  const [stake, setStake] = useState<StakeTotals | null>(null);

  useEffect(() => {
    let stop = false;
    const tick = async () => {
      try {
        // Through the EDGE (/rpc), never a validator: the node RPC has no auth
        // or rate limiting and is served by the consensus thread itself. The
        // edge additionally caps the calls it will MAKE and returns the
        // corroboration this page renders — `read()` (/g4) does neither, and is
        // used below only for the slot strip, which needs source.ts's
        // empty-vs-unknown distinction.
        const h = await g4rpc<G4Head>("getchaininfo");
        if (stop) return;
        setHead(h);
        setCorro(lastCorroboration);
        setErr(null);
        // Each of these is allowed to fail on its own. The RPC is served by
        // the consensus loop, so a slow answer during block production is
        // ordinary — one timeout must not blank the page.
        const [v, m, b, sd] = await Promise.allSettled([
          g4rpc<G4ValidatorCount>("getvalidatorcount"),
          g4rpc<Mempool>("getmempoolinfo"),
          slotRange(h.slot - RECENT + 1, h.slot),
          g4rpc<StakeTotals>("getstakedistribution"),
        ]);
        if (stop) return;
        if (v.status === "fulfilled") setVals(v.value);
        if (m.status === "fulfilled") setMp(m.value);
        if (b.status === "fulfilled") setCells(b.value);
        if (sd.status === "fulfilled") setStake(sd.value);
      } catch (e: any) {
        if (!stop) setErr(String(e?.message ?? e));
      }
    };
    const teardown = pollWhileVisible(() => void tick(), POLL_MS);
    return () => {
      stop = true;
      teardown();
    };
  }, []);

  if (err && !head) {
    return (
      <div className="container">
        <div className="errbox">
          The Genesis-4 endpoint did not answer ({err}). This reports the proxy, not the network —
          the chain may well still be producing.
        </div>
      </div>
    );
  }
  if (!head) return <Loading />;

  const finalised = head.finalized.epoch > 0 || head.finalized_height > 0;
  const lag = head.epoch - head.finalized.epoch;

  return (
    <div className="container">
      <section className="card g4-card">
        <div className="g4-head">
          <div>
            <span className="g4-badge">Genesis-4 · live</span>
            <h1 className="g4-title">Bloch, under proof of stake</h1>
          </div>
          <div className="g4-sub">
            {G4.validators} genesis validators · {G4.slotSecs}s slots ·{" "}
            {head.slots_per_epoch}-slot epochs
            <CorroborationBadge c={corro} />
          </div>
        </div>

        <CorroborationNote c={corro} />

        <div className="g4-grid">
          <div className="g4-stat">
            <span className="g4-k">Slot</span>
            <span className="g4-v">{fmtInt(head.slot)}</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Height</span>
            <span className="g4-v">{fmtInt(head.height)}</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Epoch</span>
            <span className="g4-v">
              {fmtInt(head.epoch)}
              <span className="g4-dim">
                {" "}
                · slot {head.slot_in_epoch}/{head.slots_per_epoch}
              </span>
            </span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Justified</span>
            <span className="g4-v">epoch {fmtInt(head.justified.epoch)}</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Finalized</span>
            <span className="g4-v">
              {finalised ? `epoch ${fmtInt(head.finalized.epoch)}` : "none yet"}
            </span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Finality lag</span>
            <span className="g4-v">
              {fmtInt(lag)}
              <span className="g4-dim"> {lag === 1 ? "epoch" : "epochs"}</span>
            </span>
          </div>
        </div>

        <p className="g4-note">
          Production and finality are separate questions. A block every slot says proposers are
          healthy; a finalized epoch says two thirds of the <em>consensus</em> stake agreed —
          the post-leak roster, which is <strong>not</strong> the duty total shown under the
          validators. The two differ by more than a factor of two while the leak is biting, so
          two thirds of the duty number is not a near-miss.{" "}
          {stake
            ? "Both totals are shown so the threshold can be taken against the right one."
            : "This node build does not serve the post-leak total, so no quorum figure is offered here rather than one computed from the wrong denominator."}{" "}
          It does not say they cannot take it back — see <Link to="/finality">finality</Link>. Two epochs of lag is the floor — finalizing epoch <em>n</em> requires epoch{" "}
          <em>n+1</em> to justify on top of it.
        </p>

        <div className="g4-roots">
          <span>
            head <code>{head.block_id.slice(0, 16)}</code>
          </span>
          <span>
            state <code>{head.state_root.slice(0, 16)}</code>
          </span>
        </div>
      </section>

      <div className="grid two-col">
        <section className="card">
          <h2 className="snap-h2">Validator set</h2>
          {vals ? (
            <div className="g4-grid">
              <div className="g4-stat">
                <span className="g4-k">Active</span>
                <span className="g4-v">
                  {fmtInt(vals.active)}
                  <span className="g4-dim"> of {fmtInt(vals.total)}</span>
                </span>
              </div>
              {/* Both totals or neither. Rendering one and calling it "bonded
                  stake" beside a two-thirds claim is the 2.25x error this
                  page shipped: the tile was the duty roster, the threshold is
                  taken on the consensus roster. */}
              <div className="g4-stat">
                <span className="g4-k">Duty stake</span>
                <span className="g4-v">{fmtBloch(BigInt(vals.total_active_stake_sat), 0)}</span>
                <span className="g4-dim">roster before the leak</span>
              </div>
              {stake ? (
                <div className="g4-stat">
                  <span className="g4-k">Consensus stake</span>
                  <span className="g4-v">
                    {fmtBloch(BigInt(stake.total_active_stake_sat), 0)}
                  </span>
                  <span className="g4-dim">after the leak — quorum is taken on this</span>
                </div>
              ) : (
                <div className="g4-stat">
                  <span className="g4-k">Consensus stake</span>
                  <span className="g4-v g4-absent">not served</span>
                  <span className="g4-dim">
                    <code>getstakedistribution</code> is in the node source, not in the deployed
                    build
                  </span>
                </div>
              )}
            </div>
          ) : (
            <p className="lookup-hint">The validator count did not answer this round.</p>
          )}
          <p className="lookup-hint">
            <Link to="/validators">Every validator</Link>, with its bond and commission.
          </p>
        </section>

        <section className="card">
          <h2 className="snap-h2">Mempool</h2>
          {mp ? (
            <div className="g4-grid">
              <div className="g4-stat">
                <span className="g4-k">Waiting</span>
                <span className="g4-v">
                  {fmtInt(mp.size)}
                  <span className="g4-dim"> of {fmtInt(mp.max)}</span>
                </span>
              </div>
              <div className="g4-stat">
                <span className="g4-k">Bytes</span>
                <span className="g4-v">{fmtInt(mp.bytes)}</span>
              </div>
            </div>
          ) : (
            <p className="lookup-hint">The mempool did not answer this round.</p>
          )}
          <p className="lookup-hint">
            An empty mempool this early is expected: the opening ledger was issued at genesis, not
            transferred into place.
          </p>
        </section>
      </div>

      <section className="card" style={{ marginTop: 14 }}>
        <h2 className="snap-h2">Recent blocks</h2>
        {!cells ? (
          <Loading />
        ) : (
          <>
            <SlotTable cells={cells} />
            <SlotTally cells={cells} />
          </>
        )}
        <p className="lookup-hint">
          A missed slot is a proposal that did not arrive in time. It costs that validator its
          reward for the slot and nothing else — the chain moves on to the next, and height does
          not advance. <Link to="/blocks">Browse every slot</Link>.
        </p>
      </section>
    </div>
  );
}
