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
  recentBlocks,
  pollWhileVisible,
  lastCorroboration,
  G4,
  G4Head,
  G4Block,
  G4Corroboration,
  G4ValidatorCount,
} from "../lib/g4";
import { CorroborationBadge, CorroborationNote } from "../components/corroboration";
import { fmtBloch, fmtInt, timeAgo } from "../lib/format";
import { Link } from "../lib/router";
import { Loading } from "../components/ui";

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
  const [blocks, setBlocks] = useState<(G4Block | null)[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // How well corroborated the head is. Held in state beside the head itself so
  // the two are always rendered from the same reading: showing a fresh badge
  // next to a stale number would be worse than showing no badge at all.
  const [corro, setCorro] = useState<G4Corroboration | null>(null);

  useEffect(() => {
    let stop = false;
    const tick = async () => {
      try {
        const h = await g4rpc<G4Head>("getchaininfo");
        if (stop) return;
        setHead(h);
        setCorro(lastCorroboration);
        setErr(null);
        // Each of these is allowed to fail on its own. The RPC is served by
        // the consensus loop, so a slow answer during block production is
        // ordinary — one timeout must not blank the page.
        const [v, m, b] = await Promise.allSettled([
          g4rpc<G4ValidatorCount>("getvalidatorcount"),
          g4rpc<Mempool>("getmempoolinfo"),
          recentBlocks(h.slot, RECENT),
        ]);
        if (stop) return;
        if (v.status === "fulfilled") setVals(v.value);
        if (m.status === "fulfilled") setMp(m.value);
        if (b.status === "fulfilled") setBlocks(b.value);
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
          healthy; a finalized epoch says two thirds of the bonded stake agreed and cannot take it
          back. Two epochs of lag is the floor — finalizing epoch <em>n</em> requires epoch{" "}
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
              <div className="g4-stat">
                <span className="g4-k">Bonded stake</span>
                <span className="g4-v">{fmtBloch(BigInt(vals.total_active_stake_sat), 0)}</span>
              </div>
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
        {!blocks ? (
          <Loading />
        ) : (
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th className="num">Slot</th>
                  <th className="num">Proposer</th>
                  <th>Block</th>
                  <th className="num">Txs</th>
                  <th className="num">Attestations</th>
                  <th>Age</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {blocks.map((b, i) => {
                  const slot = head.slot - i;
                  if (!b) {
                    return (
                      <tr key={slot} className="row-missed">
                        <td className="num">{fmtInt(slot)}</td>
                        <td className="num">—</td>
                        <td colSpan={4} className="faint">
                          no block for this slot
                        </td>
                        <td>
                          <span className="pill quiet">missed</span>
                        </td>
                      </tr>
                    );
                  }
                  return (
                    <tr key={b.block_id}>
                      <td className="num">{fmtInt(b.slot)}</td>
                      <td className="num">v{b.proposer_index}</td>
                      <td>
                        <Link to={`/slot/${b.slot}`}>
                          <code>{b.block_id.slice(0, 16)}</code>
                        </Link>
                      </td>
                      <td className="num">{fmtInt(b.tx_count)}</td>
                      <td className="num">{fmtInt(b.attestation_count)}</td>
                      <td className="faint">{timeAgo(b.timestamp)}</td>
                      <td>
                        {b.finalized ? (
                          <span className="pill ok">final</span>
                        ) : (
                          <span className="pill quiet">{b.finality}</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <p className="lookup-hint">
          A missed slot is a proposal that did not arrive in time. It costs that validator its
          reward for the slot and nothing else — the chain moves on to the next.
        </p>
      </section>
    </div>
  );
}
