// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The lookup form. It does not look anything up.
//
// It classifies what was typed, refuses what it cannot name, and navigates to
// `/hash/<64 hex>` — the canonical page for one eUTXO-set entry. Keeping the
// resolution here as well as there would be a second implementation of the one
// rule this whole area exists to have only once.
import { useState } from "react";
import { classify, permalink } from "../lib/scriptHash";
import { fmtBloch, fmtInt } from "../lib/format";
import { G4 } from "../lib/g4";
import { useRouter, Link } from "../lib/router";

export function BalancePage() {
  const { navigate } = useRouter();
  const [input, setInput] = useState("");
  const [err, setErr] = useState<string | null>(null);

  function lookup(e: React.FormEvent) {
    e.preventDefault();
    const q = classify(input);
    const to = permalink(q);
    if (to) {
      setErr(null);
      navigate(to);
      return;
    }
    setErr(
      q.kind === "bad_address"
        ? "That address does not check out — its checksum does not match, so it has a typo " +
            "somewhere. Refusing it on purpose: the zero-extended hash of a wrong address is a " +
            "perfectly valid script hash that simply holds nothing, and you would have been " +
            "shown an empty balance and believed it."
        : "Not recognised. Paste a 64-character script hash, a bloch1q… Genesis-3 address, or " +
            "its 40-character hash-160.",
    );
  }

  return (
    <div className="container">
      <h1 className="page-title">Look up an entry</h1>
      <p className="page-lede">
        Genesis-4 has no addresses. It locks every output with 32 bytes — a{" "}
        <strong>script hash</strong> — and that is the only identifier the chain has. A
        Genesis-3 balance still resolves: all {fmtInt(G4.carryoverUtxos)} outputs it ended
        with, {fmtBloch(G4.carryoverBloch * 100_000_000n, 0)} BLOCH, were transcribed into
        the opening ledger at height {fmtInt(G4.haltHeight)}, and a Genesis-3 address names
        the entry they landed in.
      </p>

      <form className="card lookup" onSubmit={lookup}>
        <label className="lookup-label" htmlFor="sh">
          Script hash, address, or hash-160
        </label>
        <div className="lookup-row">
          <input
            id="sh"
            className="lookup-input"
            placeholder="64-hex script hash, or bloch1q…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            spellCheck={false}
            autoComplete="off"
          />
          <button className="lookup-go" type="submit">
            Look up
          </button>
        </div>
        {err && <div className="err-box">{err}</div>}
      </form>

      <section className="card">
        <h2 className="snap-h2">What each of those three names</h2>
        <p className="lookup-hint">
          <strong>A 64-hex script hash</strong> is used exactly as given. If all 32 bytes
          carry information it is a native key's hash, <code>SHA3-256(public key)</code>,
          which is what <code>bloch-pos spendkey</code> prints. If the last twelve bytes
          are zero it is a carried entry from the Genesis-3 snapshot.
        </p>
        <p className="lookup-hint">
          <strong>A <code>bloch1q…</code> address or a bare hash-160</strong> names the
          carried entry, and only that. Its checksum is verified before anything is asked
          of the chain. What it does <em>not</em> name is a Genesis-4 key's holdings: an
          address carries 20 bytes and a key's hash is 32, so there is no conversion, in
          this explorer or anywhere. If you are expecting coins paid to a Genesis-4 key,
          ask its holder for the script hash.
        </p>
        <p className="lookup-hint">
          That distinction is not pedantry. Two tools in this project each computed their
          own version of it and the same funded key read 74,999,997,782 sat under one and 0
          under the other — with no error anywhere, because consensus accepts both shapes.
          The entry page shows both and says which is which.{" "}
          <Link to="/snapshot">The snapshot page</Link> has the handover in full.
        </p>
      </section>
    </div>
  );
}
