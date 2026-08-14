// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Live Genesis-4 head.
//
// Genesis-3 is finished and the rest of this explorer serves its history. This
// card is the one place that reads the *new* chain, so a reader who arrives
// after the halt is not left thinking Bloch stopped.
//
// It talks to the public proxy rather than a node: nodes bind their RPC to
// loopback, and the proxy is the only path that exists from a browser.
import { useEffect, useState } from "react";
import { fmtInt } from "../lib/format";

const G4_RPC = "https://posternlabs.com/g4rpc";
const POLL_MS = 15_000;

/** The fields this card reads. The node returns more; none of it is needed here. */
interface G4Head {
  slot: number;
  height: number;
  epoch: number;
  slot_in_epoch: number;
  slots_per_epoch: number;
  finalized_height: number;
  justified: { epoch: number };
  finalized: { epoch: number };
  block_id: string;
  state_root: string;
}

async function fetchHead(signal: AbortSignal): Promise<G4Head> {
  const res = await fetch(G4_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getchaininfo", params: [] }),
    signal,
  });
  const body = await res.json();
  if (body.error) throw new Error(body.error.message ?? "rpc error");
  return body.result as G4Head;
}

export function Genesis4Card() {
  const [head, setHead] = useState<G4Head | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    const ac = new AbortController();
    const tick = async () => {
      try {
        const h = await fetchHead(ac.signal);
        if (!stop) {
          setHead(h);
          setErr(null);
        }
      } catch (e: any) {
        if (!stop && e?.name !== "AbortError") setErr(String(e?.message ?? e));
      }
    };
    tick();
    const id = setInterval(tick, POLL_MS);
    return () => {
      stop = true;
      ac.abort();
      clearInterval(id);
    };
  }, []);

  // Justification is a separate question from production, and the honest
  // answer is whichever the chain gives — a card that implied finality the
  // chain has not reached would be worse than one that says "none yet".
  const finalised = head ? head.finalized.epoch > 0 || head.finalized_height > 0 : false;

  return (
    <section className="card g4-card">
      <div className="g4-head">
        <div>
          <span className="g4-badge">Genesis-4 · live</span>
          <h2 className="g4-title">Proof of stake</h2>
        </div>
        <div className="g4-sub">
          64 genesis validators · 30 s slots · {head ? head.slots_per_epoch : 32}-slot epochs
        </div>
      </div>

      {err && !head ? (
        <p className="g4-note">
          The Genesis-4 endpoint did not answer ({err}). The chain may still be producing — this
          card reports the proxy, not the network.
        </p>
      ) : !head ? (
        <p className="g4-note">Reading the head…</p>
      ) : (
        <>
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
              <span className="g4-k">Finalized</span>
              <span className="g4-v">
                {finalised ? `epoch ${fmtInt(head.finalized.epoch)}` : "none yet"}
              </span>
            </div>
          </div>
          <div className="g4-roots">
            <span>
              head <code>{head.block_id.slice(0, 16)}</code>
            </span>
            <span>
              state <code>{head.state_root.slice(0, 16)}</code>
            </span>
          </div>
        </>
      )}

      <p className="g4-note">
        Genesis-4 opens with the Genesis-3 balances carried over — 452,726 outputs,
        18,146,400,000 BLOCH — plus the genesis allocations, for 57,146,400,000 BLOCH issued at
        height 0. Blocks are produced by the 64 genesis validators; the declining genesis-cohort cap
        lowers their share to a third over the first year.
      </p>
    </section>
  );
}
