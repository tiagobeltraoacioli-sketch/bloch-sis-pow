// SPDX-License-Identifier: AGPL-3.0-or-later
import { Fragment, useEffect, useState } from "react";
import { useRouter, Link } from "./lib/router";
import { Route, match } from "./routes";
import { G4Search } from "./components/g4search";
import { g4rpc, G4_RPC } from "./lib/g4";
import { G4Dashboard } from "./pages/G4Dashboard";
import { FinalityPage } from "./pages/Finality";
import { G4BlockPage } from "./pages/G4Block";
import { BalancePage } from "./pages/Balance";
import { ValidatorsPage } from "./pages/Validators";
import { SnapshotPage } from "./pages/Snapshot";
import { SupplyPage } from "./pages/Supply";
import { FeesPage } from "./pages/Fees";
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

// The route table and the nav are one declaration.
//
// `nav: true` on a route puts it in the header. That is deliberate: a nav
// entry pointing at a path with no route, or a route nobody can reach from
// the header, are both bugs that used to be possible because NAV and the
// if-chain were two independent lists that had to be kept in step by hand.
//
// See `src/routes.tsx` for why this is a table and how literals are protected
// from being shadowed by patterns.
const ROUTES: (Route & { nav?: string })[] = [
  { pattern: "/", nav: "Chain", render: () => <G4Dashboard /> },
  { pattern: "/finality", nav: "Finality", render: () => <FinalityPage /> },
  { pattern: "/balance", nav: "Balance", render: () => <BalancePage /> },
  {
    pattern: "/balance/:h",
    render: (p) => <BalancePage initial={p.h} />,
    key: (p) => "bal" + p.h,
  },
  { pattern: "/supply", nav: "Supply", render: () => <SupplyPage /> },
  { pattern: "/fees", nav: "Fees", render: () => <FeesPage /> },
  { pattern: "/validators", nav: "Validators", render: () => <ValidatorsPage /> },
  { pattern: "/snapshot", nav: "Snapshot", render: () => <SnapshotPage /> },
  {
    pattern: "/slot/:s",
    render: (p) => <G4BlockPage slot={Number(p.s)} />,
    guard: (p) => /^\d+$/.test(p.s),
    key: (p) => "s" + p.s,
  },
];

const NAV = ROUTES.filter((r) => r.nav).map((r) => ({ to: r.pattern, label: r.nav! }));

function renderRoute(path: string) {
  const hit = match(ROUTES, path);
  if (hit) {
    const el = hit.route.render(hit.params);
    const k = hit.route.key ? hit.route.key(hit.params) : hit.route.pattern;
    return <Fragment key={k}>{el}</Fragment>;
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
          truth (1 BLOCH = 1e8 sat); “bloch” values are display-only. BLCH is neutral native gas, never a value or investment claim.
          <RpcStatus />
        </div>
      </footer>
    </div>
  );
}
