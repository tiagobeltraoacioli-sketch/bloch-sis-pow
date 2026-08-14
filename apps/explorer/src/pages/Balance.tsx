// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Genesis-4 balance lookup.
//
// The Wallet page next door scans Genesis-3's history, which is now a fixed
// archive. This one asks the live chain what a script hash holds *today* —
// including every balance carried over from Genesis-3, which is where almost
// all of the opening ledger came from.
import { useEffect, useState } from "react";
import { g4rpc, toScriptHash, isPaddedH160, G4Balance, G4 } from "../lib/g4";
import { fmtBloch, fmtInt } from "../lib/format";

export function BalancePage({ initial }: { initial?: string }) {
  const [input, setInput] = useState(initial ?? "");
  const [result, setResult] = useState<G4Balance | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // A hash that arrived in the URL is looked up without waiting for a click:
  // the person already asked, by navigating here.
  useEffect(() => {
    if (initial) void run(initial);
  }, [initial]);

  async function run(raw: string) {
    const sh = toScriptHash(raw);
    if (!sh) {
      setResult(null);
      setErr(
        raw.trim().toLowerCase().startsWith("bloch1")
          ? "That address does not check out — its checksum does not match, so it has a typo " +
            "somewhere. Refusing it on purpose: the wrong address would simply show a balance of zero."
          : "Not recognised. Paste a bloch1… address, its 40-character hash-160, or a 64-character script hash.",
      );
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      setResult(await g4rpc<G4Balance>("getbalance", [sh]));
    } catch (e: any) {
      setResult(null);
      setErr(String(e?.message ?? e));
    } finally {
      setBusy(false);
    }
  }

  function lookup(e: React.FormEvent) {
    e.preventDefault();
    void run(input);
  }

  return (
    <div className="container">
      <h1 className="page-title">Balance</h1>
      <p className="page-lede">
        What a script hash holds on Genesis-4 right now. Every Genesis-3 balance was carried into
        the opening ledger at height {fmtInt(G4.haltHeight)} — {fmtInt(G4.carryoverUtxos)} outputs,{" "}
        {fmtBloch(G4.carryoverBloch * 100_000_000n, 0)} BLOCH — so a Genesis-3 holder can look
        theirs up here unchanged.
      </p>

      <form className="card lookup" onSubmit={lookup}>
        <label className="lookup-label" htmlFor="sh">
          Address, hash-160, or script hash
        </label>
        <div className="lookup-row">
          <input
            id="sh"
            className="lookup-input"
            placeholder="bloch1q…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            spellCheck={false}
            autoComplete="off"
          />
          <button className="lookup-go" type="submit" disabled={busy}>
            {busy ? "Asking…" : "Look up"}
          </button>
        </div>
        <p className="lookup-hint">
          Paste an address and the checksum is verified before anything is asked of the chain — a
          mistyped address is refused rather than answered with an empty balance. Underneath,
          Genesis-4 keys the ledger by script hash: the 20-byte hash inside your address, padded
          with twelve zero bytes. That padding is the same rule consensus uses to decide whether a
          key owns an output, so all three forms name one entry.
        </p>
      </form>

      {err && <div className="errbox">{err}</div>}

      {result && (
        <section className="card">
          <div className="bal-head">
            <div>
              <span className="g4-k">Balance</span>
              <div className="bal-value">{fmtBloch(BigInt(result.balance_sat), 8)} BLOCH</div>
            </div>
            <div className="bal-side">
              <span className="g4-k">Unspent outputs</span>
              <div className="bal-count">{fmtInt(result.utxo_count)}</div>
            </div>
          </div>
          <div className="bal-meta">
            <div>
              <span className="g4-k">Script hash</span>
              <code className="bal-hash">{result.script_hash}</code>
            </div>
            {isPaddedH160(result.script_hash) && (
              <p className="lookup-hint">
                This is a zero-padded hash-160 — an entry that came across from Genesis-3.
              </p>
            )}
          </div>
          <p className="lookup-hint">
            Satoshis are the source of truth (1 BLOCH = 1e8 sat). The value is carried as a decimal
            string because it exceeds what a JavaScript number holds exactly.
          </p>
        </section>
      )}
    </div>
  );
}
