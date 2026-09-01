// SPDX-License-Identifier: AGPL-3.0-or-later
//
// One outpoint, and a large caveat.
//
// `gettxout` is the only per-output lookup this chain has, and it is a sharp
// tool held by the blade: it accepts any 32 bytes and any index, and answers
// `{"unspent": false, "utxo": null}` — HTTP 200, no error — for values that
// have never existed. Verified live: `ab` repeated 32 times returns exactly
// that. So a negative answer here carries almost no information, and this page
// is built to stop a reader reading one as though it did.
//
// The positive answer, by contrast, is exact: an output that IS in the eUTXO
// set is really there, with a real amount, as of a named slot.

import { useEffect, useState } from "react";
import { read } from "../lib/source";
import { fmtInt, fmtBloch } from "../lib/format";
import { Link } from "../lib/router";
import { Loading, Copyable } from "../components/ui";

interface Utxo {
  value_sat?: string | number;
  script_hash?: string;
  [k: string]: unknown;
}
interface TxOut {
  txid: string;
  vout: number;
  unspent: boolean;
  utxo: Utxo | null;
  at_slot: number;
}

export function OutpointPage({ txid, vout }: { txid: string; vout: number }) {
  const [out, setOut] = useState<TxOut | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    setOut(null);
    setErr(null);
    read<TxOut>("gettxout", [txid, vout])
      .then((r) => !stop && setOut(r))
      .catch((e) => !stop && setErr(String(e?.message ?? e)));
    return () => {
      stop = true;
    };
  }, [txid, vout]);

  if (err) {
    return (
      <div className="container">
        <h1 className="page-title">Outpoint</h1>
        <div className="errbox">{err}</div>
      </div>
    );
  }
  if (!out) return <Loading label="Reading the eUTXO set…" />;

  return (
    <div className="container">
      <h1 className="page-title">Outpoint</h1>
      <p className="page-lede">
        <Copyable text={`${txid}:${vout}`}>
          <code className="snap-hash">
            {txid}:{vout}
          </code>
        </Copyable>
      </p>

      {out.unspent && out.utxo ? (
        <section className="card">
          <h2 className="snap-h2">
            <span className="pill ok">unspent</span> This output exists and is unspent
          </h2>
          <div className="g4-grid">
            <div className="g4-stat">
              <span className="g4-k">Value</span>
              <span className="g4-v">
                {fmtBloch(String(out.utxo.value_sat ?? "0"))} <span className="g4-dim">BLOCH</span>
              </span>
            </div>
            <div className="g4-stat">
              <span className="g4-k">As of slot</span>
              <span className="g4-v">
                <Link to={`/slot/${out.at_slot}`}>{fmtInt(out.at_slot)}</Link>
              </span>
            </div>
          </div>
          {out.utxo.script_hash && (
            <p className="lookup-hint">
              Held by script hash{" "}
              <Link to={`/balance/${out.utxo.script_hash}`}>
                <code>{String(out.utxo.script_hash).slice(0, 24)}…</code>
              </Link>
            </p>
          )}
          <p className="lookup-hint">
            A positive answer here is exact — the output is in the set as of slot{" "}
            {fmtInt(out.at_slot)}. It is <em>not</em> a settlement claim: whether the block that
            created it is beyond reorg is a separate question, and on this chain finality is not a
            latch. Check the slot's page.
          </p>
          <details className="raw">
            <summary>Raw response</summary>
            <pre className="code-block">{JSON.stringify(out, null, 2)}</pre>
          </details>
        </section>
      ) : (
        <section className="card">
          <h2 className="snap-h2">
            <span className="pill quiet">nothing here</span> No unspent output under this key
          </h2>
          <p className="page-lede">
            <strong>Read this as almost nothing.</strong> <code>gettxout</code> returns this same
            well-formed, error-free answer for a spent output, for an output that never existed,
            and for a withdrawal that was silently dropped — they are indistinguishable. Pasting
            32 random bytes produces it too.
          </p>
          <pre className="code-block">{JSON.stringify(out, null, 2)}</pre>
          <p className="lookup-hint">
            If this value came from <code>sendrawtransaction</code>, it is a node-local{" "}
            <code>tx_hash</code> that other nodes do not agree on and is not an outpoint at all —{" "}
            <Link to={`/tx/${txid}`}>here is what that means and what to do instead</Link>. To
            find out whether funds actually arrived somewhere, read the recipient's{" "}
            <Link to="/balance">balance</Link>, which is exact in both directions.
          </p>
        </section>
      )}
    </div>
  );
}
