// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from "react";
import { useRouter, Link, matchRoute } from "./lib/router";
import { rpcIsDegraded, activeRpcEndpoint } from "./lib/rpc";
import { G4Search } from "./components/g4search";
import { g4rpc, G4_RPC } from "./lib/g4";
import { G4Dashboard } from "./pages/G4Dashboard";
import { G4BlockPage } from "./pages/G4Block";
import { BalancePage } from "./pages/Balance";
import { ValidatorsPage } from "./pages/Validators";
import { ValidatorDetailPage } from "./pages/ValidatorDetail";
import { ValidatorQueuesPage } from "./pages/ValidatorQueues";
import { SnapshotPage } from "./pages/Snapshot";
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

// Two chains, one explorer. Genesis-4 first because it is the live one; the
// Genesis-3 entries stay because its history is the ledger Genesis-4 opened
// with, and a reader who came looking for it must still find it.
const NAV = [
  { to: "/", label: "Chain" },
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
  // Order matters: the literal route must be tested before the :index pattern,
  // or "/validators/queues" is read as validator number NaN.
  if (path === "/validators/queues") return <ValidatorQueuesPage />;
  {
    const mv = matchRoute(path, "/validators/:index");
    if (mv && /^\d+$/.test(mv.index)) {
      return <ValidatorDetailPage index={Number(mv.index)} key={"v" + mv.index} />;
    }
  }
  if (path === "/snapshot") return <SnapshotPage />;

  const m = matchRoute(path, "/slot/:s");
  if (m) return <G4BlockPage slot={Number(m.s)} key={"s" + m.s} />;

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

// Surfaces the RPC client's own failover state (src/lib/rpc.ts). Reads the
// exported getters on a slow tick — no extra network traffic.
function RpcStatus() {
  const [state, setState] = useState<"live" | "warn">("warn");
  useEffect(() => {
    let stop = false;
    const ping = async () => {
      try {
        await g4rpc("getchaininfo");
        if (!stop) setState("live");
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
    <div className="rpc-status" title="The Genesis-4 endpoint this page reads">
      <span className={"dot " + state} />
      <span>
        Genesis-4 RPC {state === "live" ? "via" : "not answering —"} <code>{G4_RPC}</code>
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
