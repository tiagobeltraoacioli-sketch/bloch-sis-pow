// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Search, for a proof-of-stake chain.
//
// The Genesis-3 box probed the node to work out what it had been handed. This
// one does not need to: on Genesis-4 the shape of the input already says what
// it is, and resolving locally means the box answers instantly and cannot be
// left hanging by a slow consensus loop.
//
//   digits            -> a slot
//   bloch1q… / 40 hex -> a Genesis-3 identifier: the carried entry it names
//   64 hex            -> a script hash or a block id; ask the chain
//   64 hex + ":" + n  -> an outpoint, which is as close to a transaction as
//                        this chain gets (there are no transaction ids)
//   anything else     -> say so, rather than guessing
//
// Resolution of the address forms is `lib/scriptHash.ts` and nowhere else.
// This box used to hold its own copy of that rule; the copy is what drifts.
import { useState } from "react";
import { useRouter } from "../lib/router";
import { g4rpc, G4Block } from "../lib/g4";
import { classify, permalink, outpointLink } from "../lib/scriptHash";

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

    // A slot is the only purely numeric thing here.
    if (/^\d+$/.test(s)) {
      navigate(`/slot/${s}`);
      return;
    }

    // `<64 hex>:<n>` — an outpoint. Accepted before the bare-hash cases so the
    // colon is never mistaken for a typo in a script hash.
    const op = /^([0-9a-f]{64}):(\d+)$/.exec(s);
    if (op) {
      navigate(outpointLink(op[1], Number(op[2])));
      return;
    }

    const parsed = classify(s);
    if (parsed.kind === "bad_address") {
      setErr("That bloch1… address fails its own checksum — it has a typo.");
      return;
    }

    if (parsed.kind === "script_hash") {
      // Ambiguous by construction: a block id and a script hash are both 32
      // bytes. Ask whether a block exists; if none does, it is an entry.
      setBusy(true);
      try {
        // Navigate by the block's SLOT, not by the id we searched with — the
        // block route is keyed by slot, and sending an id there would 404 on
        // a block that exists.
        const b = await g4rpc<G4Block>("getblockbyid", [s]);
        navigate(`/slot/${b.slot}`);
      } catch {
        navigate(`/hash/${parsed.scriptHash}`);
      } finally {
        setBusy(false);
      }
      return;
    }

    const to = permalink(parsed);
    if (to) {
      navigate(to);
      return;
    }
    setErr("Not a script hash, an address, a slot, a block id, or an outpoint.");
  }

  return (
    <form className={"search" + (hero ? " hero" : "")} onSubmit={go}>
      <input
        className="search-input"
        placeholder="Script hash, address, slot, block id, or txid:vout"
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
