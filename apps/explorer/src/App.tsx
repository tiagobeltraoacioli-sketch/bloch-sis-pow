// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from "react";
import { useRouter, Link, matchRoute } from "./lib/router";
import { rpcIsDegraded, activeRpcEndpoint } from "./lib/rpc";
import { G4Search } from "./components/g4search";
import { read, readFrom, G4_READ } from "./lib/source";
import { G4Dashboard } from "./pages/G4Dashboard";
import { G4BlockPage } from "./pages/G4Block";
import { G4BlocksPage } from "./pages/G4Blocks";
import { TxAnswerPage } from "./pages/TxAnswer";
import { OutpointPage } from "./pages/Outpoint";
import { BalancePage } from "./pages/Balance";
import { ValidatorsPage } from "./pages/Validators";
import { SnapshotPage } from "./pages/Snapshot";
import "./features.css";
import "./blocks.css";

// The Bloch sphere — one qubit, every state. Canonical protocol mark,
// self-theming via the brand tokens.
const Logo = () => (
  <svg className="logo" viewBox="0 0 26 26" fill="none" aria-label="Bloch Protocol">
    <circle cx="13" cy="13" r="11.2" stroke="var(--accent)" strokeWidth="1.5" />
    <ellipse cx="13" cy="13" rx="11.2" ry="4.2" stroke="var(--accent)" strokeWidth="1.1" opacity="0.55" />
    <line x1="13" y1="13" x2="19.6" y2="7.2" stroke="var(--ink)" strokeWidth="1.6" strokeLinecap="round" />
    <circle cx="19.6" cy="7.2" r="2.1" fill="var(--accent)" />
  </svg>
);

// Two chains, one explorer. Genesis-4 first because it is the live one; the
// Genesis-3 entries stay because its history is the ledger Genesis-4 opened
// with, and a reader who came looking for it must still find it.
const NAV = [
  { to: "/", label: "Chain" },
  { to: "/blocks", label: "Blocks" },
  { to: "/balance", label: "Balance" },
  { to: "/validators", label: "Validators" },
  { to: "/snapshot", label: "Snapshot" },
];

function renderRoute(path: string) {
  if (path === "/" || path === "") return <G4Dashboard />;
  if (path === "/balance") return <BalancePage />;
  {
    const mb = matchRoute(path, "/balance/:h");
    if (mb) return <BalancePage initial={mb.h} key={"bal" + mb.h} />;
  }
  if (path === "/validators") return <ValidatorsPage />;
  if (path === "/snapshot") return <SnapshotPage />;

  const m = matchRoute(path, "/slot/:s");
  if (m) return <G4BlockPage slot={Number(m.s)} key={"s" + m.s} />;

  // By block id rather than by slot. This is the only way to reach a block
  // fork choice did not select: `getblockbyslot` resolves through the
  // canonical chain and cannot return an orphan, while `getblockbyid` can.
  {
    const mid = matchRoute(path, "/block/:id");
    if (mid) return <G4BlockPage blockId={mid.id} key={"b" + mid.id} />;
  }

  if (path === "/blocks") return <G4BlocksPage />;
  {
    const mr = matchRoute(path, "/blocks/:from");
    if (mr) return <G4BlocksPage from={Number(mr.from)} key={"r" + mr.from} />;
  }

  // Where a transaction hash lands. Not a 404 — see pages/TxAnswer for why a
  // 404 and a fake "found" are both worse answers than the explanation.
  if (path === "/tx") return <TxAnswerPage />;
  {
    const mt = matchRoute(path, "/tx/:h");
    if (mt) return <TxAnswerPage hash={mt.h} key={"t" + mt.h} />;
  }

  {
    const mo = matchRoute(path, "/outpoint/:op");
    if (mo) {
      const [txid, vout] = mo.op.split(":");
      if (/^[0-9a-f]{64}$/i.test(txid || "")) {
        return <OutpointPage txid={txid.toLowerCase()} vout={Number(vout) || 0} key={"o" + mo.op} />;
      }
    }
  }

  // Genesis-3 routes are gone, not broken-on-purpose: this explorer is the
  // proof-of-stake chain now. The state proof of work ended in is published
  // whole on /snapshot, which is what anyone following an old link is
  // actually after.
  return (
    <div className="container">
      <div className="card" style={{ marginTop: 24 }}>
        <h1 className="page-title">Nothing at that address</h1>
        <p className="page-lede">
          No route for <code>{path}</code>. This explorer serves Genesis-4, the proof-of-stake
          chain. If you came looking for Genesis-3 — the proof-of-work era that ended at height
          39,918 — its terminal state is published in full on the{" "}
          <Link to="/snapshot">snapshot page</Link>.
        </p>
      </div>
    </div>
  );
}

// Which archival is answering, and whether it is answering at all.
//
// Names the node index rather than just "up/down", because the two archivals
// are what the whole two-node cross-check rests on: a page that has quietly
// been served by one box for an hour is in a different epistemic position from
// one being answered by both, and that should be visible rather than inferred.
function RpcStatus() {
  const [state, setState] = useState<"live" | "warn">("warn");
  const [node, setNode] = useState<number | null>(null);
  useEffect(() => {
    let stop = false;
    const ping = async () => {
      try {
        const r = await readFrom("getchaininfo");
        if (!stop) {
          setState("live");
          setNode(r.node);
        }
      } catch {
        if (!stop) setState("warn");
      }
    };
    ping();
    const t = setInterval(ping, 20_000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, []);
  return (
    <div
      className="rpc-status"
      title="Reads go to the archival peers, never to a validator: the node RPC has no auth or rate limiting and shares a thread with consensus."
    >
      <span className={"dot " + state} />
      <span>
        {state === "live" ? (
          <>
            Reading Genesis-4 from the archivals via <code>{G4_READ}</code>
            {node !== null && <> — answered by archival {node}</>}
          </>
        ) : (
          <>
            No archival answering on <code>{G4_READ}</code>
          </>
        )}
      </span>
    </div>
  );
}

export function App() {
  const { path } = useRouter();
  const isActive = (to: string) => (to === "/" ? path === "/" : path.startsWith(to));

  return (
    <div className="app">
      <header className="topbar">
        <div className="container">
          <div className="topbar-inner">
            <Link to="/" className="brand">
              <Logo />
              <span className="brand-word">Bloch</span>
              <span className="tag">Explorer</span>
            </Link>
            <nav className="mainnav">
              {NAV.map((n) => (
                <Link key={n.to} to={n.to} className={isActive(n.to) ? "active" : ""}>
                  {n.label}
                </Link>
              ))}
              <a href="https://posternlabs.com" className="ext" rel="noopener">
                posternlabs.com ↗
              </a>
            </nav>
            <div className="topbar-spacer" />
            <G4Search />
          </div>
        </div>
      </header>

      <main>{renderRoute(path)}</main>

      <footer className="foot">
        <div className="container">
          <div className="foot-lockup">
            <span className="foot-brand">
              <Logo />
              <span className="wordmark">Bloch Protocol</span>
            </span>
            <span className="foot-tagline">
              <a href="https://posternlabs.com" rel="noopener">Postern Labs</a> · nothing here is
              investment advice
            </span>
          </div>
          Independent reference explorer for <strong>Bloch Genesis-4</strong> — a post-quantum
          proof-of-stake chain, 64 genesis validators, 30-second slots, finality by epoch. It
          opened carrying every balance from Genesis-3, the proof-of-work era that ended at height
          39,918; that handover is published in full on the <Link to="/snapshot">snapshot</Link>.
          Not an official service; Bloch is ownerless/neutral. Integer satoshis are the source of
          truth (1 BLOCH = 1e8 sat). Not an official service; Bloch is
          ownerless/neutral. Integer satoshis are the source of truth (1 BLOCH = 1e8 sat); “bloch”
          values are display-only. BLCH is neutral native gas, never a value or investment claim.
          <RpcStatus />
        </div>
      </footer>
    </div>
  );
}
