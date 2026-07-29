import { useRouter, Link, matchRoute } from "./lib/router";
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

// Postern Labs triangle emblem (canonical mark) — full colour, self-theming.
const Logo = () => (
  <svg className="logo" viewBox="0 0 120 120" fill="none" aria-label="Postern Labs">
    <polygon points="60,14 104,92 16,92" fill="none" stroke="#D2955C" strokeWidth="3" strokeLinejoin="round" />
    <line x1="60" y1="14" x2="60" y2="92" stroke="#3A4657" strokeWidth="2" />
    <line x1="38" y1="53" x2="82" y2="53" stroke="#3A4657" strokeWidth="2" />
    <circle cx="38" cy="92" r="4.5" fill="#D2955C" />
    <circle cx="60" cy="92" r="4.5" fill="#D2955C" />
    <circle cx="82" cy="92" r="4.5" fill="#D2955C" />
    <circle cx="60" cy="14" r="6" fill="#E0A870" />
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
              <span className="wordmark">
                <span className="wm-postern">postern</span>
                <span className="wm-mid">·</span>
                <span className="wm-labs">labs</span>
              </span>
            </span>
            <span className="foot-tagline">Math, applied. For life.</span>
          </div>
          Independent reference explorer for the <strong>Bloch</strong> chain — a GhostDAG-Q,
          post-quantum proof-of-work network. Not an official service; Bloch is ownerless/neutral.
          Integer satoshis are the source of truth (1 BLOCH = 1e8 sat); “bloch” values are display-only.
          BLCH is neutral native gas, never a value or investment claim.
        </div>
      </footer>
    </div>
  );
}
