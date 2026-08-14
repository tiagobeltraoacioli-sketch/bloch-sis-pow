// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Genesis-4 validator set.
//
// Under proof of work this page would have been a miner leaderboard. It is
// not the same thing and should not read like one: a miner is whoever showed
// up with hashrate this hour, a validator is a bonded identity the chain
// committed to at genesis and can slash.
import { useEffect, useState } from "react";
import { g4rpc, allValidators, G4, G4ValidatorCount, G4Validator } from "../lib/g4";
import { fmtBloch, fmtInt } from "../lib/format";
import { Loading } from "../components/ui";

export function ValidatorsPage() {
  const [count, setCount] = useState<G4ValidatorCount | null>(null);
  const [rows, setRows] = useState<(G4Validator | null)[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    (async () => {
      try {
        const c = await g4rpc<G4ValidatorCount>("getvalidatorcount");
        if (stop) return;
        setCount(c);
        // One call per validator: the RPC has no bulk form, and the set is 64
        // entries — small enough that asking honestly beats inventing a
        // pagination the node does not have. Bounded in flight, because this
        // RPC is served by the consensus loop and 64 at once competes with the
        // block production we are asking about. Failures are per-row, so one
        // slow answer does not blank the table.
        const rows = await allValidators(c.total);
        if (stop) return;
        setRows(rows);
      } catch (e: any) {
        if (!stop) setErr(String(e?.message ?? e));
      }
    })();
    return () => {
      stop = true;
    };
  }, []);

  return (
    <div className="container">
      <h1 className="page-title">Validators</h1>
      <p className="page-lede">
        Genesis-4 is secured by {G4.validators} validators committed at genesis, each bonded and
        each slashable. Blocks arrive on a {G4.slotSecs}-second slot; {G4.slotsPerEpoch} slots make
        an epoch, and an epoch is what justifies and finalizes.
      </p>

      {err && <div className="errbox">{err}</div>}

      {count && (
        <div className="g4-grid card" style={{ marginBottom: 22 }}>
          <div className="g4-stat">
            <span className="g4-k">Registered</span>
            <span className="g4-v">{fmtInt(count.total)}</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Active</span>
            <span className="g4-v">{fmtInt(count.active)}</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Bonded stake</span>
            <span className="g4-v">{fmtBloch(BigInt(count.total_active_stake_sat), 0)}</span>
          </div>
        </div>
      )}

      {!rows ? (
        <Loading />
      ) : (
        <div className="card table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>#</th>
                <th>Public key hash</th>
                <th className="num">Effective stake</th>
                <th className="num">Commission</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((v, i) => (
                <tr key={i}>
                  <td className="num">{v ? v.index : i}</td>
                  <td>
                    <code>{v ? v.pubkey_hash.slice(0, 20) : "—"}</code>
                  </td>
                  <td className="num">{v ? fmtBloch(BigInt(v.effective_stake_sat), 2) : "—"}</td>
                  <td className="num">
                    {v ? `${(Number(v.commission_bps) / 100).toFixed(2)}%` : "—"}
                  </td>
                  <td>
                    {!v ? (
                      <span className="pill quiet">no answer</span>
                    ) : v.slashed ? (
                      <span className="pill bad">slashed</span>
                    ) : (
                      <span className="pill ok">{v.state}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="lookup-hint" style={{ marginTop: 16 }}>
        A row reading “no answer” means that call timed out, not that the validator is missing —
        the RPC is served by the consensus loop itself and can be slow while a block is being
        built.
      </p>
    </div>
  );
}
