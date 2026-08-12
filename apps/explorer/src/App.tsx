// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from "react";
import { useRouter, Link, matchRoute } from "./lib/router";
import { rpcIsDegraded, activeRpcEndpoint } from "./lib/rpc";
import { SearchBox } from "./components/search";
import { Dashboard } from "./pages/Dashboard";
import { Blocks } from "./pages/Blocks";
import { BlockDetail } from "./pages/BlockDetail";
import { TxDetail } from "./pages/TxDetail";
import { AddressView } from "./pages/AddressView";
import { ChartsPage } from "./pages/Charts";
import { DagPage } from "./pages/Dag";
import { DagLivePage } from "./pages/DagLive";
import { MiningPage } from "./pages/Mining";
import { WalletPage } from "./pages/Wallet";
import { LeaderboardPage } from "./pages/Leaderboard";
import "./features.css";

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

const NAV = [
  { to: "/", label: "Dashboard" },
  { to: "/blocks", label: "Blocks" },
  { to: "/livedag", label: "Live DAG" },
  { to: "/mining", label: "Mining" },
  { to: "/wallet", label: "Wallet" },
  { to: "/leaderboard", label: "Leaderboard" },
  { to: "/charts", label: "Charts" },
];

function renderRoute(path: string) {
  if (path === "/" || path === "") return <Dashboard />;
  if (path === "/blocks") return <Blocks />;
  if (path === "/dag") return <DagPage />;
  if (path === "/livedag") return <DagLivePage />;
  if (path === "/mining") return <MiningPage />;
  if (path === "/wallet") return <WalletPage />;
  if (path === "/leaderboard") return <LeaderboardPage />;
  if (path === "/charts") return <ChartsPage />;

  let m = matchRoute(path, "/block/height/:h");
  if (m) return <BlockDetail height={Number(m.h)} key={"bh" + m.h} />;
  m = matchRoute(path, "/block/:hash");
  if (m) return <BlockDetail hash={m.hash} key={"b" + m.hash} />;
  m = matchRoute(path, "/tx/:txid");
  if (m) return <TxDetail txid={m.txid} key={"t" + m.txid} />;
  m = matchRoute(path, "/address/:addr");
  if (m) return <AddressView addr={m.addr} key={"a" + m.addr} />;

  return (
    <div className="container">
      <div className="page-title">Not found</div>
      <p className="muted">
        No route for <code>{path}</code>. <Link to="/">Back to dashboard</Link>.
      </p>
    </div>
  );
}

// Surfaces the RPC client's own failover state (src/lib/rpc.ts). Reads the
// exported getters on a slow tick — no extra network traffic.
function RpcStatus() {
  const [, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick((x) => x + 1), 10_000);
    return () => clearInterval(t);
  }, []);
  const degraded = rpcIsDegraded();
  const ep = activeRpcEndpoint();
  const label = ep === "/rpc" ? "same-origin /rpc" : ep;
  return (
    <div className="rpc-status" title="Which JSON-RPC endpoint this session is pinned to">
      <span className={"dot " + (degraded ? "warn" : "live")} />
      <span>
        RPC {degraded ? "degraded — failed over to" : "via"} <code>{label}</code>
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
            <SearchBox />
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
          Independent reference explorer for the <strong>Bloch</strong> chain — a GhostDAG-Q,
          post-quantum proof-of-work network. Genesis-3 ends by consensus rule at height 50,000;
          this explorer serves its history in full. Not an official service; Bloch is
          ownerless/neutral. Integer satoshis are the source of truth (1 BLOCH = 1e8 sat); “bloch”
          values are display-only. BLCH is neutral native gas, never a value or investment claim.
          <RpcStatus />
        </div>
      </footer>
    </div>
  );
}
