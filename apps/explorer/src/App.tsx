// SPDX-License-Identifier: AGPL-3.0-or-later
import { Fragment, useEffect, useState } from "react";
import { useRouter, Link } from "./lib/router";
import { Route, match } from "./routes";
import { G4Search } from "./components/g4search";
import { read, readFrom, G4_READ } from "./lib/source";
import { G4Dashboard } from "./pages/G4Dashboard";
import { FinalityPage } from "./pages/Finality";
import { G4BlockPage } from "./pages/G4Block";
import { G4BlocksPage } from "./pages/G4Blocks";
import { TxAnswerPage } from "./pages/TxAnswer";
import { BalancePage } from "./pages/Balance";
import { HashPage } from "./pages/Hash";
import { OutpointPage } from "./pages/Outpoint";
import { ValidatorsPage } from "./pages/Validators";
import { ValidatorDetailPage } from "./pages/ValidatorDetail";
import { ValidatorQueuesPage } from "./pages/ValidatorQueues";
import { SnapshotPage } from "./pages/Snapshot";
import { SupplyPage } from "./pages/Supply";
import { FeesPage } from "./pages/Fees";
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
  // `/hash/<64 hex>` is the canonical name of an eUTXO-set entry, and every
  // other identifier a person can paste redirects into it. `/balance…` are the
  // old URLs, kept resolving rather than 404'd: a permalink that stops working
  // is how a reader concludes the balance is gone.
  { pattern: "/hash", nav: "Balance", render: () => <BalancePage /> },
  { pattern: "/balance", render: () => <BalancePage /> },
  {
    pattern: "/hash/:q",
    render: (p) => <HashPage q={p.q} />,
    key: (p) => "h" + p.q,
  },
  {
    pattern: "/balance/:h",
    render: (p) => <HashPage q={p.h} />,
    key: (p) => "h" + p.h,
  },
  // An OUTPOINT, not a transaction: this chain has no transaction ids, so
  // there is no /tx/:id to offer and pretending otherwise would promise a
  // lookup `gettransaction` refuses by design.
  {
    pattern: "/outpoint/:txid/:vout",
    render: (p) => <OutpointPage txid={p.txid.toLowerCase()} vout={Number(p.vout)} />,
    guard: (p) => /^[0-9a-f]{64}$/i.test(p.txid) && /^\d+$/.test(p.vout),
    key: (p) => "o" + p.txid + p.vout,
  },
  { pattern: "/supply", nav: "Supply", render: () => <SupplyPage /> },
  { pattern: "/fees", nav: "Fees", render: () => <FeesPage /> },
  { pattern: "/validators", nav: "Validators", render: () => <ValidatorsPage /> },
  // No "must come before /validators/:index" comment here: match() tries every
  // literal before any pattern, so this is safe wherever it sits. See routes.tsx.
  { pattern: "/validators/queues", render: () => <ValidatorQueuesPage /> },
  {
    pattern: "/validators/:index",
    render: (p) => <ValidatorDetailPage index={Number(p.index)} />,
    guard: (p) => /^\d+$/.test(p.index),
    key: (p) => "v" + p.index,
  },
  { pattern: "/snapshot", nav: "Snapshot", render: () => <SnapshotPage /> },
  { pattern: "/blocks", nav: "Blocks", render: () => <G4BlocksPage /> },
  {
    pattern: "/blocks/:from",
    render: (p) => <G4BlocksPage from={Number(p.from)} />,
    guard: (p) => /^\d+$/.test(p.from),
    key: (p) => "r" + p.from,
  },
  // By block id rather than by slot. The only way to reach a block fork choice
  // did not select: getblockbyslot resolves through the canonical chain and
  // cannot return an orphan; getblockbyid can.
  {
    pattern: "/block/:id",
    render: (p) => <G4BlockPage blockId={p.id} />,
    key: (p) => "b" + p.id,
  },
  // Where a transaction hash lands. Not a 404 — see pages/TxAnswer for why a
  // 404 and a fake "found" are both worse answers than the explanation.
  { pattern: "/tx", render: () => <TxAnswerPage /> },
  {
    pattern: "/tx/:h",
    render: (p) => <TxAnswerPage hash={p.h} />,
    key: (p) => "t" + p.h,
  },
  // The colon form, `/outpoint/<txid>:<vout>`, which is what the search box
  // emits. Same page as the two-segment form above — one outpoint should not
  // have two different-looking pages just because it has two URL spellings.
  {
    pattern: "/outpoint/:op",
    render: (p) => {
      const [txid, vout] = p.op.split(":");
      return <OutpointPage txid={txid.toLowerCase()} vout={Number(vout) || 0} />;
    },
    guard: (p) => /^[0-9a-f]{64}(:\d+)?$/i.test(p.op),
    key: (p) => "o" + p.op,
  },
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
          truth (1 BLOCH = 1e8 sat); “bloch” values are display-only. BLCH is neutral native gas, never a value or investment claim.
          <RpcStatus />
        </div>
      </footer>
    </div>
  );
}
