// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Genesis-3 terminal snapshot.
//
// This is the join between the two chains: the exact state proof of work
// ended at, and the exact numbers proof of stake opened with. It is published
// so the carry-over can be checked by anyone rather than believed — every
// digest here is what a node verifies on boot, and a node that finds a
// different one refuses to start.
import { G4 } from "../lib/g4";
import { fmtBloch, fmtInt } from "../lib/format";

function Digest({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="snap-digest">
      <span className="g4-k">{label}</span>
      <code className="snap-hash">{value}</code>
      {note && <span className="snap-note">{note}</span>}
    </div>
  );
}

export function SnapshotPage() {
  const carryoverSat = G4.carryoverBloch * 100_000_000n;
  const issuedSat = G4.genesisIssuedBloch * 100_000_000n;
  const allocatedSat = issuedSat - carryoverSat;

  return (
    <div className="container">
      <h1 className="page-title">The Genesis-3 snapshot</h1>
      <p className="page-lede">
        Proof of work ended at height {fmtInt(G4.haltHeight)}. Every unspent output at that height
        was measured, committed, and carried into Genesis-4's opening ledger. Nothing was minted to
        replace it and nothing was dropped — the numbers below are what consensus checks, not a
        summary of it.
      </p>

      <section className="card">
        <h2 className="snap-h2">What was measured</h2>
        <div className="g4-grid">
          <div className="g4-stat">
            <span className="g4-k">Terminal height</span>
            <span className="g4-v">{fmtInt(G4.haltHeight)}</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Unspent outputs</span>
            <span className="g4-v">{fmtInt(G4.carryoverUtxos)}</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Carried BLOCH</span>
            <span className="g4-v">{fmtBloch(carryoverSat, 0)}</span>
          </div>
        </div>
        <p className="lookup-hint">
          The rule was written for height 50,000. The chain was stopped at {fmtInt(G4.haltHeight)}{" "}
          instead: hashrate was falling, and waiting out the remaining blocks would have added
          nothing the snapshot did not already hold. The terminal state was taken here and verified
          on two independent nodes, byte for byte.
        </p>
      </section>

      <section className="card">
        <h2 className="snap-h2">What a node verifies</h2>
        <Digest
          label="Carryover set root"
          value={G4.carryoverSetRoot}
          note="Merkle root of the output set itself — independent of how the file is packaged."
        />
        <Digest
          label="Snapshot file · SHA3-256"
          value={G4.carryoverFileSha3}
          note="What the node hashes on boot. A mismatch here stops the node; it does not warn."
        />
        <Digest
          label="Snapshot file · SHA-256"
          value={G4.carryoverFileSha256}
          note="The same bytes under the hash an operator reproduces with sha256sum."
        />
        <Digest
          label="Genesis-4 manifest digest"
          value={G4.genesisDigest}
          note="The network the 64 validators booted. A node with a different digest is on a different chain."
        />
        <p className="lookup-hint">
          Two hash functions, one file, because they answer to two audiences. The names differ by a
          single character and the functions are unrelated — a value produced with{" "}
          <code>sha256sum</code> is not the one consensus checks.
        </p>
      </section>

      <section className="card">
        <h2 className="snap-h2">What Genesis-4 opened with</h2>
        <div className="g4-grid">
          <div className="g4-stat">
            <span className="g4-k">Carried from Genesis-3</span>
            <span className="g4-v">{fmtBloch(carryoverSat, 0)}</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Genesis allocations</span>
            <span className="g4-v">{fmtBloch(allocatedSat, 0)}</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Issued at height 0</span>
            <span className="g4-v">{fmtBloch(issuedSat, 0)}</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Hard cap</span>
            <span className="g4-v">{fmtBloch(G4.totalSupplyBloch * 100_000_000n, 0)}</span>
          </div>
        </div>
        <p className="lookup-hint">
          First slot at {G4.genesisTimeUtc}, {G4.validators} genesis validators,{" "}
          {G4.slotSecs}-second slots, {G4.slotsPerEpoch}-slot epochs. The remainder of the cap is
          issued to validators over time; the genesis-cohort share declines from the whole to a
          third across the first year.
        </p>
      </section>

      <section className="card">
        <h2 className="snap-h2">Checking a balance</h2>
        <p className="snap-body">
          A Genesis-3 holder's balance is unchanged and live. The ledger is keyed by script hash
          rather than address: take the 20-byte hash-160, pad it with twelve zero bytes, and ask
          Genesis-4 directly. The <a href="/balance">balance lookup</a> does the padding for you.
        </p>
      </section>
    </div>
  );
}
