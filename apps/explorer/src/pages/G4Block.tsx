// SPDX-License-Identifier: AGPL-3.0-or-later
//
// One Genesis-4 block, by slot.
//
// Every root the header commits is shown, unabbreviated. That is the point of
// a block page: the header is what the network signed, and a reader checking a
// claim needs the whole value, not a prefix that looks reassuring.
import { useEffect, useState } from "react";
import { g4rpc, G4Block } from "../lib/g4";
import { fmtInt, timeAgo } from "../lib/format";
import { Link } from "../lib/router";
import { Loading } from "../components/ui";

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="snap-digest">
      <span className="g4-k">{label}</span>
      {mono ? <code className="snap-hash">{value}</code> : <div className="bal-count">{value}</div>}
    </div>
  );
}

export function G4BlockPage({ slot }: { slot: number }) {
  const [b, setB] = useState<G4Block | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    setB(null);
    setErr(null);
    g4rpc<G4Block>("getblockbyslot", [slot])
      .then((r) => !stop && setB(r))
      .catch((e) => !stop && setErr(String(e?.message ?? e)));
    return () => {
      stop = true;
    };
  }, [slot]);

  if (err) {
    return (
      <div className="container">
        <h1 className="page-title">Slot {fmtInt(slot)}</h1>
        <div className="errbox">
          {err}
          <div style={{ marginTop: 8, fontSize: 12.5 }}>
            A slot with no block is a missed proposal, not an error in the chain.
          </div>
        </div>
        <p className="lookup-hint">
          <Link to="/">Back to the dashboard</Link>
        </p>
      </div>
    );
  }
  if (!b) return <Loading />;

  return (
    <div className="container">
      <h1 className="page-title">Slot {fmtInt(b.slot)}</h1>
      <p className="page-lede">
        Proposed by validator {b.proposer_index} in epoch {fmtInt(b.epoch)},{" "}
        {timeAgo(b.timestamp)}. Carrying {fmtInt(b.tx_count)}{" "}
        {b.tx_count === 1 ? "transaction" : "transactions"} and {fmtInt(b.attestation_count)}{" "}
        {b.attestation_count === 1 ? "attestation" : "attestations"}.{" "}
        {b.finalized
          ? "It is finalized: reversing it would require burning a third of the bonded stake."
          : `The chain calls it ${b.finality}; it is not finalized yet.`}
      </p>

      <div className="g4-grid card" style={{ marginBottom: 14 }}>
        <div className="g4-stat">
          <span className="g4-k">Height</span>
          <span className="g4-v">{fmtInt(b.height)}</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Epoch</span>
          <span className="g4-v">{fmtInt(b.epoch)}</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Proposer</span>
          <span className="g4-v">
            <Link to="/validators">v{b.proposer_index}</Link>
          </span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">State</span>
          <span className="g4-v">{b.finalized ? "final" : b.finality}</span>
        </div>
      </div>

      <section className="card">
        <h2 className="snap-h2">What the header commits</h2>
        <Row label="Block id" value={b.block_id} mono />
        <Row label="Parent" value={b.parent} mono />
        <Row label="State root" value={b.state_root} mono />
        <Row label="Body root" value={b.body_root} mono />
        <Row label="Attestation root" value={b.attestation_root} mono />
        <Row label="RANDAO mix" value={b.randao_mix} mono />
        <Row label="Justified root" value={b.justified_root} mono />
        <Row label="Finalized root" value={b.finalized_root} mono />
      </section>

      <p className="lookup-hint" style={{ marginTop: 14 }}>
        <Link to={`/slot/${b.slot - 1}`}>← slot {fmtInt(b.slot - 1)}</Link>
        {"  ·  "}
        <Link to={`/slot/${b.slot + 1}`}>slot {fmtInt(b.slot + 1)} →</Link>
        {"  ·  "}
        <Link to="/">dashboard</Link>
      </p>
    </div>
  );
}
