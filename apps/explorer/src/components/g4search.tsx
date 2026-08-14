// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Search, for a proof-of-stake chain.
//
// The Genesis-3 box probed the node to work out what it had been handed. This
// one does not need to: on Genesis-4 the shape of the input already says what
// it is, and resolving locally means the box answers instantly and cannot be
// left hanging by a slow consensus loop.
//
//   digits    -> a slot
//   40 hex    -> a Genesis-3 hash-160, i.e. a balance
//   64 hex    -> a script hash (balance) or a block id; ask the chain
//   anything else -> say so, rather than guessing
import { useState } from "react";
import { useRouter } from "../lib/router";
import { g4rpc, G4Block } from "../lib/g4";

export function G4Search({ hero }: { hero?: boolean }) {
  const { navigate } = useRouter();
  const [q, setQ] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function go(e: React.FormEvent) {
    e.preventDefault();
    const s = q.trim().toLowerCase().replace(/^0x/, "");
    setErr(null);
    if (!s) return;

    if (s.startsWith("bloch1")) {
      navigate(`/balance/${s}`);
      return;
    }
    if (/^\d+$/.test(s)) {
      navigate(`/slot/${s}`);
      return;
    }
    if (/^[0-9a-f]{40}$/.test(s)) {
      navigate(`/balance/${s}`);
      return;
    }
    if (/^[0-9a-f]{64}$/.test(s)) {
      // Ambiguous by construction: a block id and a script hash are both 32
      // bytes. Ask whether a block exists; if none does, it is an address.
      setBusy(true);
      try {
        // Navigate by the block's SLOT, not by the id we searched with — the
        // block route is keyed by slot, and sending an id there would 404 on
        // a block that exists.
        const b = await g4rpc<G4Block>("getblockbyid", [s]);
        navigate(`/slot/${b.slot}`);
      } catch {
        navigate(`/balance/${s}`);
      } finally {
        setBusy(false);
      }
      return;
    }
    setErr("Not an address, a slot, a script hash, or a block id.");
  }

  return (
    <form className={"search" + (hero ? " hero" : "")} onSubmit={go}>
      <input
        className="search-input"
        placeholder="Address, slot, or block id"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        spellCheck={false}
        autoComplete="off"
        aria-label="Search Genesis-4"
      />
      <button className="search-go" type="submit" disabled={busy}>
        {busy ? "…" : "Go"}
      </button>
      {err && <div className="search-err">{err}</div>}
    </form>
  );
}
