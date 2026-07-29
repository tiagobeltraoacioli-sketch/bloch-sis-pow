import { useState } from "react";
import { useRouter } from "../lib/router";
import { rpc } from "../lib/rpc";

// Resolve an arbitrary query to a route:
//  - all digits            -> block by height
//  - 64 hex                -> could be block hash OR txid; probe getblock first
//  - bloch1... address     -> address view
export async function resolveQuery(q: string): Promise<string | null> {
  const s = q.trim();
  if (!s) return null;
  if (/^\d+$/.test(s)) return `/block/height/${s}`;
  if (/^(bloch1|blocht1|bloch1t)/i.test(s)) return `/address/${s}`;
  if (/^[0-9a-fA-F]{64}$/.test(s)) {
    // probe: is it a block hash?
    try {
      const b = await rpc("getblock", [s.toLowerCase(), false]);
      if (b && b.hash) return `/block/${s.toLowerCase()}`;
    } catch {
      /* fall through to tx */
    }
    return `/tx/${s.toLowerCase()}`;
  }
  return null;
}

export function SearchBox({ hero }: { hero?: boolean }) {
  const { navigate } = useRouter();
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function go(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    const route = await resolveQuery(q);
    setBusy(false);
    if (route) {
      setQ("");
      navigate(route);
    } else {
      setErr("Not a height, hash, txid or address");
    }
  }

  return (
    <form className={"search" + (hero ? " search-hero" : "")} onSubmit={go}>
      <svg className="icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="11" cy="11" r="7" />
        <path d="m21 21-4.3-4.3" />
      </svg>
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder={hero ? "Search height, block hash, txid, or bloch1 address…" : "Search…"}
        spellCheck={false}
        autoComplete="off"
      />
      {busy && <span className="spinner" style={{ position: "absolute", right: 12, top: hero ? 17 : 11 }} />}
      {err && <div className="faint" style={{ position: "absolute", fontSize: 12, marginTop: 4 }}>{err}</div>}
    </form>
  );
}
