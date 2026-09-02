// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The supply surface.
//
// A reader arriving from Bitcoin will default to reading "issued" as
// circulating supply and the remainder as "left to mine". Both are wrong here,
// and both are wrong in ways that flatter the chain — so every caveat on this
// page is rendered beside the number it qualifies, not linked from it. A
// footnote nobody opens is the same as no footnote.
import { useEffect, useState } from "react";
import { g4rpc, G4, G4ValidatorCount, G4Balance, G4Head } from "../lib/g4";
import { fmtBloch, fmtInt } from "../lib/format";
import { Link } from "../lib/router";
import {
  FOUNDER_POSITION,
  PUBLISHED_UNDERSTATEMENT,
  NO_ONCHAIN_LOCKUP,
  SAT,
  TOTAL_SUPPLY_BLOCH,
  TOTAL_SUPPLY_SAT,
  FOUNDER_BLOCH,
  VC_BLOCH,
  TEAM_BLOCH,
  MARKETING_BLOCH,
  LIQUIDITY_BLOCH,
  ALLOCATIONS_TOTAL_BLOCH,
  CARRYOVER_TOTAL_BLOCH,
  VALIDATOR_EMISSION_BLOCH,
  GENESIS_ISSUED_BLOCH,
  GENESIS_ISSUED_SAT,
  VALIDATOR_EMISSION_SAT,
  EMISSION_YEARS,
  SLOTS_PER_YEAR,
  EMISSION_SLOTS,
  FOUNDER_SCRIPT_HASH,
  FOUNDER_H160,
  LARGEST_CARRYOVER_BLOCH,
  LARGEST_CARRYOVER_UTXOS,
  CARRYOVER_UTXOS,
  CARRYOVER_ADDRESSES,
  CONCENTRATED_BLOCH,
  COHORT_VALIDATORS,
  MIN_DEPOSIT_BLOCH,
  COHORT_BOND_BLOCH,
  CARRYOVER_DISPUTE,
  EMISSION_DUST_SAT,
  INITIAL_REWARD_SAT,
  INITIAL_ANNUAL_SAT,
  rewardFlatSat,
  emittedFlatBy,
  emittedHalvingBy,
  emittedDecayBy,
  annualInflationBps,
  supplyMirrorSelfCheck,
  CIRCULATING_NOT_SERVED,
  G4Supply,
} from "../lib/supply";

// ── small pieces ────────────────────────────────────────────────────────────

/** Percentage of a bigint total, to two places, without leaving bigint. */
function pct(part: bigint, whole: bigint): string {
  if (whole === 0n) return "—";
  return (Number((part * 10_000n) / whole) / 100).toFixed(2) + "%";
}

/**
 * A quantity with its own caveat attached. `isNot` is the line that stops the
 * default misreading; it is not optional styling.
 */
function Quantity({
  label,
  value,
  unit = "BLCH",
  is,
  isNot,
  tone,
}: {
  label: string;
  value: string;
  unit?: string;
  is: React.ReactNode;
  isNot?: React.ReactNode;
  tone?: "cap" | "live" | "unissued";
}) {
  return (
    <div className={"sup-q" + (tone ? " tone-" + tone : "")}>
      <div className="sup-q-label">{label}</div>
      <div className="sup-q-value">
        {value}
        <span className="sup-q-unit">{unit}</span>
      </div>
      <div className="sup-q-is">{is}</div>
      {isNot && (
        <div className="sup-q-not">
          <span className="sup-q-not-tag">not</span>
          <span>{isNot}</span>
        </div>
      )}
    </div>
  );
}

function Caveat({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="warn-box sup-caveat">
      <span className="warn-ico" aria-hidden="true">
        ⚠
      </span>
      <div>
        <strong className="sup-caveat-title">{title}</strong>
        {children}
      </div>
    </div>
  );
}

// ── the emission chart ──────────────────────────────────────────────────────

const CURVES = [
  {
    key: "decay",
    name: "Smooth decay",
    detail: "−10%/year",
    color: "var(--accent)",
    live: true,
    fn: emittedDecayBy,
    note: "What the chain emits today — the only curve the transition function calls.",
  },
  {
    key: "halving",
    name: "Halving",
    detail: "every 4 years, 10 eras",
    color: "var(--violet)",
    live: false,
    fn: emittedHalvingBy,
    note: "Ten scheduled dates on which every validator's revenue halves at once.",
  },
  {
    key: "flat",
    name: "Flat",
    detail: "constant for 40 years",
    color: "var(--signal)",
    live: false,
    fn: emittedFlatBy,
    note: "Modelled as failing the 25%-of-active-stake gate: validators never out-earn the unlock schedule.",
  },
] as const;

function EmissionChart() {
  const W = 760;
  const H = 300;
  const PAD = { t: 16, r: 18, b: 30, l: 64 };
  const iw = W - PAD.l - PAD.r;
  const ih = H - PAD.t - PAD.b;

  const genesis = Number(GENESIS_ISSUED_BLOCH);
  const cap = Number(TOTAL_SUPPLY_BLOCH);
  const years = Number(EMISSION_YEARS);

  const x = (yr: number) => PAD.l + (yr / years) * iw;
  const y = (bloch: number) => PAD.t + ih - (bloch / cap) * ih;

  const path = (fn: (s: bigint) => bigint) => {
    const pts: string[] = [];
    for (let yr = 0; yr <= years; yr++) {
      const emitted = Number(fn(BigInt(yr) * SLOTS_PER_YEAR) / SAT);
      pts.push(`${x(yr).toFixed(1)},${y(genesis + emitted).toFixed(1)}`);
    }
    return "M" + pts.join(" L");
  };

  const gridY = [0, 0.25, 0.5, 0.75, 1];

  return (
    <div className="sup-chart-wrap">
      <svg viewBox={`0 0 ${W} ${H}`} className="sup-chart" role="img"
        aria-label="Cumulative supply against the hard cap over the forty-year emission window, under three candidate curves">
        {gridY.map((g) => (
          <g key={g}>
            <line
              x1={PAD.l}
              x2={W - PAD.r}
              y1={y(g * cap)}
              y2={y(g * cap)}
              stroke="var(--line)"
              strokeDasharray={g === 1 ? "0" : "3 4"}
            />
            <text x={PAD.l - 8} y={y(g * cap) + 4} textAnchor="end" className="sup-axis">
              {(g * 100).toFixed(0)}%
            </text>
          </g>
        ))}

        {/* Everything below this line existed at slot 0. It is the point of the chart. */}
        <rect
          x={PAD.l}
          y={y(genesis)}
          width={iw}
          height={PAD.t + ih - y(genesis)}
          fill="var(--accent)"
          opacity="0.07"
        />
        <line
          x1={PAD.l}
          x2={W - PAD.r}
          y1={y(genesis)}
          y2={y(genesis)}
          stroke="var(--accent)"
          strokeWidth="1.2"
          opacity="0.55"
        />
        <text x={PAD.l + 8} y={y(genesis) - 7} className="sup-band-label">
          issued at slot 0 — {pct(GENESIS_ISSUED_BLOCH, TOTAL_SUPPLY_BLOCH)} of the cap, before any block
        </text>

        {CURVES.map((c) => (
          <path
            key={c.key}
            d={path(c.fn)}
            fill="none"
            stroke={c.color}
            strokeWidth={c.live ? 2.4 : 1.5}
            strokeDasharray={c.live ? undefined : "5 4"}
            opacity={c.live ? 1 : 0.75}
          />
        ))}

        {[0, 10, 20, 30, 40].map((yr) => (
          <text key={yr} x={x(yr)} y={H - 10} textAnchor="middle" className="sup-axis">
            {yr === 0 ? "genesis" : `yr ${yr}`}
          </text>
        ))}
      </svg>

      <div className="sup-legend">
        {CURVES.map((c) => (
          <div key={c.key} className="sup-legend-row">
            <span className="sup-swatch" style={{ background: c.color }} />
            <div>
              <span className="sup-legend-name">{c.name}</span>{" "}
              <span className="sup-legend-detail">{c.detail}</span>{" "}
              {c.live ? (
                <span className="pill ok sup-pill-sm">live</span>
              ) : (
                <span className="pill quiet sup-pill-sm">not wired</span>
              )}
              <div className="sup-legend-note">{c.note}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── page ────────────────────────────────────────────────────────────────────

export function SupplyPage() {
  const check = supplyMirrorSelfCheck();

  const [head, setHead] = useState<G4Head | null>(null);
  const [vc, setVc] = useState<G4ValidatorCount | null>(null);
  const [conc, setConc] = useState<G4Balance | null>(null);
  const [supply, setSupply] = useState<G4Supply | null>(null);
  const [supplyErr, setSupplyErr] = useState<string | null>(null);
  const [liveErr, setLiveErr] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    (async () => {
      // Three cheap committed reads. No scan, no per-validator fan-out: this
      // page must not be the reason a node misses a slot.
      //
      // Settled individually rather than Promise.all: `getbalance` is the one
      // uncached read of the three and the most likely to time out, and losing
      // the bonded-stake figure because the concentration read was slow would
      // be the wrong trade on this page in particular.
      const [h, c, b] = await Promise.allSettled([
        g4rpc<G4Head>("getchaininfo"),
        g4rpc<G4ValidatorCount>("getvalidatorcount"),
        g4rpc<G4Balance>("getbalance", [FOUNDER_SCRIPT_HASH]),
      ]);
      if (stop) return;
      if (h.status === "fulfilled") setHead(h.value);
      if (c.status === "fulfilled") setVc(c.value);
      if (b.status === "fulfilled") setConc(b.value);
      const failed = [h, c, b].filter((r) => r.status === "rejected");
      if (failed.length)
        setLiveErr(
          failed
            .map((r) => String((r as PromiseRejectedResult).reason?.message ?? r))
            .join("; "),
        );
      // Asked for separately and allowed to fail: it does not exist yet, and
      // the refusal is itself something the reader should see.
      try {
        const s = await g4rpc<G4Supply>("getsupply");
        if (!stop) setSupply(s);
      } catch (e: any) {
        if (!stop) setSupplyErr(String(e?.message ?? e));
      }
    })();
    return () => {
      stop = true;
    };
  }, []);

  const bondedSat = vc ? BigInt(vc.total_active_stake_sat) : null;
  const concSat = conc ? BigInt(conc.balance_sat) : null;

  return (
    <div className="container">
      <h1 className="page-title">Supply</h1>
      <p className="page-lede">
        Genesis-4 has a hard cap of {fmtInt(TOTAL_SUPPLY_BLOCH)} BLCH, and the cap is not a target
        the chain approaches — it is an identity. <code>GENESIS_ISSUED + VALIDATOR_EMISSION</code>{" "}
        equals the cap <em>exactly</em>, by definition of the second term. There is no headroom by
        construction, and there is no bucket left over to discover.
      </p>
      <p className="page-lede">
        That construction has a consequence worth stating before any number below.{" "}
        <strong>{pct(GENESIS_ISSUED_BLOCH, TOTAL_SUPPLY_BLOCH)} of the cap existed at slot 0</strong>
        , before a single block was produced. If you have arrived from Bitcoin, the two habits that
        will mislead you here are reading “issued” as circulating supply and reading the remainder
        as “left to mine”. Neither holds. Each is corrected beside the figure it applies to.
      </p>

      {!check.ok && (
        <Caveat title="This page does not agree with the chain's own constants. ">
          The figures below are mirrored from <code>tokenomics_v4.rs</code> and re-derived against
          the assertions that crate compiles with. The re-derivation failed:{" "}
          {check.failures.join("; ")}. Treat everything on this page as unreliable until it is
          fixed.
        </Caveat>
      )}

      {/* ── the four quantities ── */}
      <section className="card sup-card">
        <h2 className="snap-h2">Four quantities, each labelled for what it is</h2>
        <div className="sup-q-grid">
          <Quantity
            tone="cap"
            label="Hard cap"
            value={fmtInt(TOTAL_SUPPLY_BLOCH)}
            is={
              <>
                A consensus invariant, enforced twice: per-epoch issuance is clamped to the
                remaining headroom, so emission stops at the cap rather than crossing it; and a
                block built on a state that already claims more than the cap is refused outright.
              </>
            }
            isNot={
              <>
                unchangeable. No transaction, key, vote or governance path can raise it — but a hard
                fork every operator adopts can change any rule, this one included.
              </>
            }
          />
          <Quantity
            label="Issued at genesis"
            value={fmtInt(GENESIS_ISSUED_BLOCH)}
            is={
              <>
                The carried Genesis-3 ledger plus the five allocation buckets. Vesting locks
                spendability; it does not defer existence, so vested and unvested alike are counted
                here.
              </>
            }
            isNot={
              <>
                circulating supply. It is also not time-locked:{" "}
                {pct(CONCENTRATED_BLOCH, GENESIS_ISSUED_BLOCH)} of it sits at one address, and no
                part of it is vested by consensus — see below.
              </>
            }
          />
          <Quantity
            tone="unissued"
            label="Validator emission"
            value={fmtInt(VALIDATOR_EMISSION_BLOCH)}
            is={
              <>
                The remainder of the fixed total, to be issued to validators across{" "}
                {Number(EMISSION_YEARS)} years. It is defined as{" "}
                <code>cap − carryover − buckets</code> — a subtraction, not an allocation decision.
              </>
            }
            isNot={
              <>
                “left to mine”. It is not open to anyone who shows up: it accrues to whoever is
                validating, and the validator set is {Number(COHORT_VALIDATORS)} identities
                committed at genesis.
              </>
            }
          />
          <Quantity
            tone="live"
            label="Bonded stake"
            value={bondedSat === null ? "—" : fmtBloch(bondedSat, 0)}
            is={
              <>
                Live, from <code>getvalidatorcount</code>
                {head ? ` at slot ${fmtInt(head.slot)}` : ""}. The launch cohort bonded{" "}
                {fmtInt(COHORT_BOND_BLOCH)} BLCH at genesis ({Number(COHORT_VALIDATORS)} ×{" "}
                {fmtInt(MIN_DEPOSIT_BLOCH)}, the minimum deposit); everything above that is
                accumulated emission.
              </>
            }
            isNot={
              <>
                part of genesis issuance — see below. It also is not{" "}
                {Number(COHORT_VALIDATORS)} independent parties.
              </>
            }
          />
        </div>
        {liveErr && (
          <p className="lookup-hint">
            The live reads did not answer (<code>{liveErr}</code>). The constants above come from
            the tokenomics crate and are unaffected; only the bonded-stake figure is missing.
          </p>
        )}
      </section>

      {/* ── issued is gross and monotone ── */}
      <section className="card sup-card">
        <h2 className="snap-h2">“Issued” is gross and monotone — it is not circulating supply</h2>
        <p className="snap-body">
          The counter consensus actually commits is <code>issued_sat</code>. It only ever goes up.
          Fees move coins that already exist; whistleblower rewards come out of slashed bonds; and{" "}
          <strong>burns never decrement it</strong> — a burn widens the gap below the cap instead.
          A chain that had burned half its supply would report the same <code>issued_sat</code> as
          one that had burned none.
        </p>
        <Caveat title="Circulating supply is not published, by anyone, today. ">
          {CIRCULATING_NOT_SERVED} Nothing on this page is circulating supply, and no figure here
          should be used as one — including by an exchange building a market-cap number.
        </Caveat>

        <div className="sup-rpc">
          {supply ? (
            <>
              <div className="sup-rpc-head">
                <span className="pill ok">getsupply · live</span>
                <span className="faint">
                  at slot {fmtInt(supply.at_slot)}, epoch {fmtInt(supply.at_epoch)} —{" "}
                  {supply.finalized ? "finalized state" : "head state, not yet finalized"}
                </span>
              </div>
              <div className="g4-grid">
                <div className="g4-stat">
                  <span className="g4-k">Issued (gross)</span>
                  <span className="g4-v">{fmtBloch(BigInt(supply.issued_sat), 0)}</span>
                  <span className="g4-dim">not circulating</span>
                </div>
                <div className="g4-stat">
                  <span className="g4-k">Emitted since genesis</span>
                  <span className="g4-v">
                    {fmtBloch(BigInt(supply.emitted_since_genesis_sat), 0)}
                  </span>
                  <span className="g4-dim">the number that actually grows</span>
                </div>
                <div className="g4-stat">
                  <span className="g4-k">Remaining under the cap</span>
                  <span className="g4-v">{fmtBloch(BigInt(supply.remaining_sat), 0)}</span>
                  <span className="g4-dim">unminted emission budget, not unfound coins</span>
                </div>
              </div>
            </>
          ) : (
            <>
              <div className="sup-rpc-head">
                <span className="pill quiet">getsupply · not served</span>
              </div>
              <p className="snap-body">
                There is no endpoint that reads the issued-supply counter. The node's own method
                table carries the name with its reason —{" "}
                <em>“proposed as <code>getsupply</code>, not built”</em> — and the public proxy
                answers <code>-32601</code>
                {supplyErr ? (
                  <>
                    {" "}
                    (<code>{supplyErr}</code>)
                  </>
                ) : null}
                . The counter itself exists in committed state and reading it is O(1); it is the
                accessor that is missing. Until it lands, every issuance figure on this page is
                arithmetic from the genesis constants and <strong>not a measurement of the running
                chain</strong>.
              </p>
            </>
          )}
        </div>
      </section>

      {/* ── concentration ── */}
      <section className="card sup-card">
        <h2 className="snap-h2">Concentration</h2>
        <p className="snap-body">
          One script hash is the recipient of <strong>all five</strong> allocation buckets. It is
          also the largest carried address, holding {fmtInt(LARGEST_CARRYOVER_UTXOS)} of the{" "}
          {fmtInt(CARRYOVER_UTXOS)} outputs carried from Genesis-3 — a set with{" "}
          {CARRYOVER_ADDRESSES} distinct addresses in total. This is already public in the genesis
          artefacts; the only thing done here is adding it up.
        </p>

        <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Bucket</th>
                <th className="num">BLCH</th>
                <th className="num">of cap</th>
                <th>Recipient</th>
                <th>Spendable</th>
                <th>Schedule on paper</th>
              </tr>
            </thead>
            <tbody>
              {(
                [
                  ["Founder grant", FOUNDER_BLOCH, "2-year cliff, 8-year linear"],
                  ["VC / funds", VC_BLOCH, "12-month cliff, 24-month linear"],
                  ["Team", TEAM_BLOCH, "18-month cliff, 36-month linear"],
                  ["Marketing", MARKETING_BLOCH, "25% at genesis, rest over 24 months"],
                  ["Liquidity", LIQUIDITY_BLOCH, "unlocked at genesis by design"],
                ] as [string, bigint, string][]
              ).map(([name, amt, unlock]) => (
                <tr key={name}>
                  <td>{name}</td>
                  <td className="num">{fmtInt(amt)}</td>
                  <td className="num">{pct(amt, TOTAL_SUPPLY_BLOCH)}</td>
                  <td>
                    <code className="sup-addr">{FOUNDER_H160.slice(0, 12)}…</code>
                  </td>
                  <td>
                    <span className="pill bad sup-pill-sm">slot 0</span>
                  </td>
                  <td className="sup-unlock">{unlock}</td>
                </tr>
              ))}
              <tr className="sup-row-sub">
                <td>Allocations, all five</td>
                <td className="num">{fmtInt(ALLOCATIONS_TOTAL_BLOCH)}</td>
                <td className="num">{pct(ALLOCATIONS_TOTAL_BLOCH, TOTAL_SUPPLY_BLOCH)}</td>
                <td>
                  <code className="sup-addr">{FOUNDER_H160.slice(0, 12)}…</code>
                </td>
                <td>
                  <span className="pill bad sup-pill-sm">slot 0</span>
                </td>
                <td className="sup-unlock">one address, five purposes</td>
              </tr>
              <tr>
                <td>Carried balance at the same address</td>
                <td className="num">{fmtInt(LARGEST_CARRYOVER_BLOCH)}</td>
                <td className="num">{pct(LARGEST_CARRYOVER_BLOCH, TOTAL_SUPPLY_BLOCH)}</td>
                <td>
                  <code className="sup-addr">{FOUNDER_H160.slice(0, 12)}…</code>
                </td>
                <td>
                  <span className="pill bad sup-pill-sm">slot 0</span>
                </td>
                <td className="sup-unlock">none — carried balances were never vested</td>
              </tr>
              <tr className="sup-row-total">
                <td>Controlled by one script hash</td>
                <td className="num">{fmtInt(CONCENTRATED_BLOCH)}</td>
                <td className="num">{pct(CONCENTRATED_BLOCH, TOTAL_SUPPLY_BLOCH)}</td>
                <td colSpan={3}>
                  {pct(CONCENTRATED_BLOCH, GENESIS_ISSUED_BLOCH)} of everything issued at genesis —
                  all of it spendable from slot 0
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <Caveat title="None of these buckets is vested on-chain. Every row above reads “slot 0” for two independent reasons. ">
          The mainnet manifest sets <code>unlock_epoch: 0</code> on all five allocations — the field
          that would make vesting consensus is present, and set to “liquid now.” And it would not
          bind if it were set to anything else: <code>unlock_epoch</code> appears{" "}
          <strong>nowhere in the consensus crate</strong>, so no node checks it. An external
          integrator audit found the second half of this on 2026-08-31 and it is recorded in the
          repository. The cliffs and linear vests in the tokenomics constants are real intentions
          and real documents; they are not enforced by the chain. Treat them as a promise held by
          whoever holds the key, which is the same key for all {fmtInt(ALLOCATIONS_TOTAL_BLOCH)}{" "}
          BLCH.
        </Caveat>

        <div className="sup-bar" role="img"
          aria-label={`${pct(CONCENTRATED_BLOCH, TOTAL_SUPPLY_BLOCH)} of the hard cap is at one script hash`}>
          <div
            className="sup-bar-fill"
            style={{ width: pct(CONCENTRATED_BLOCH, TOTAL_SUPPLY_BLOCH) }}
          />
          <div
            className="sup-bar-mark"
            style={{ left: pct(GENESIS_ISSUED_BLOCH, TOTAL_SUPPLY_BLOCH) }}
            title="everything issued at genesis"
          />
        </div>
        <div className="sup-bar-key">
          <span>
            <span className="sup-swatch" style={{ background: "var(--signal)" }} /> one script hash
            — {pct(CONCENTRATED_BLOCH, TOTAL_SUPPLY_BLOCH)} of the cap
          </span>
          <span className="faint">
            the tick marks everything issued at genesis ({pct(GENESIS_ISSUED_BLOCH, TOTAL_SUPPLY_BLOCH)})
          </span>
        </div>

        <Caveat title="The same address is the withdrawal address of all 64 launch validators. ">
          This is checkable, not asserted: the manifest the fleet booted from is published in the
          repository, and decoding it yields <strong>one distinct withdrawal credential across all
          64 validators</strong> — this one — alongside all five allocations. The credential appears
          69 times in the file: 64 validators plus 5 buckets. Each validator bonded exactly{" "}
          {fmtInt(MIN_DEPOSIT_BLOCH)} BLCH at zero commission. The consequence is that the cohort's
          bonds, and every reward those bonds earn, withdraw to the address above: a stake
          distribution that reads as {Number(COHORT_VALIDATORS)} validators is one withdrawal
          credential, and a Nakamoto coefficient computed over validator indices will not say so.
        </Caveat>

        <div className="sup-live-conc">
          <div className="g4-grid">
            <div className="g4-stat">
              <span className="g4-k">Script hash</span>
              <span className="g4-v sup-hash">{FOUNDER_SCRIPT_HASH}</span>
              <span className="g4-dim">
                the 20-byte hash-160 zero-extended to 32 — the same rule consensus applies
              </span>
            </div>
            <div className="g4-stat">
              <span className="g4-k">Unspent balance now</span>
              <span className="g4-v">{concSat === null ? "—" : fmtBloch(concSat, 0)}</span>
              <span className="g4-dim">
                {conc ? `${fmtInt(conc.utxo_count)} unspent outputs, live` : "live read"}
              </span>
            </div>
            <div className="g4-stat">
              <span className="g4-k">Expected from the artefacts</span>
              <span className="g4-v">{fmtInt(CONCENTRATED_BLOCH)}</span>
              <span className="g4-dim">allocations plus carried balance</span>
            </div>
          </div>
          {concSat !== null && (
            <>
              <p className="lookup-hint">
                The two do not match, and the live figure is{" "}
                <strong>{fmtBloch(CONCENTRATED_BLOCH * SAT - concSat, 0)} BLCH lower</strong>. Read
                the live number as a <em>lower bound</em> on what one key controls, never as the
                whole of it. Genesis-4 has two lock forms: carried balances use the zero-extended
                hash queried above, while <strong>every output a Genesis-4 transaction creates uses
                the native 32-byte form</strong> — a different script hash. The founder's
                acknowledged consolidation sweep moved 426,194 carried inputs after the epoch-800
                flag day, and the coins it produced are invisible to this query by construction, not
                by loss. Value cannot have been destroyed at this scale: conservation is a strict
                equality and fees are hundreds of satoshis per transaction.
              </p>
              <Caveat title="What is not accounted for. ">
                That mechanism explains how the balance can fall; it does not explain{" "}
                <em>this</em> figure. No artefact in the repository reconciles the live balance,
                names the sweep's destination script hash, or accounts for the{" "}
                {conc ? fmtInt(conc.utxo_count) : "residual"} outputs that remain of the 426,199
                the address held at genesis. Until that is traced, the honest statement is the one
                the artefacts support — one key was given{" "}
                {pct(CONCENTRATED_BLOCH, TOTAL_SUPPLY_BLOCH)} of the cap at genesis — and{" "}
                <strong>no live reading on this page should be presented as showing that
                concentration has decreased</strong>. It shows where the coins are not.{" "}
                <Link to={"/balance/" + FOUNDER_SCRIPT_HASH}>Check the address yourself</Link>.
              </Caveat>
            </>
          )}
        </div>
      </section>

      {/* ── the founder's position, every denominator named ── */}
      <section className="card sup-card">
        <h2 className="snap-h2">Founder concentration — three figures, three denominators</h2>
        <p className="snap-body">
          One number cannot answer this. The same balance is 37.92% or 66.35% depending only on
          whether you divide by the 100 billion cap or by what has actually been issued, and both
          are legitimate questions. So all of them are published, each against the denominator it
          belongs to, and none is nominated as “the” concentration figure.
        </p>
        <div className="conc-table-wrap">
          <table className="conc-table">
            <thead>
              <tr>
                <th>Position</th>
                <th className="num">BLCH</th>
                <th className="num">of the 100B cap</th>
                <th className="num">of 57.1464B issued</th>
                <th>Provenance</th>
              </tr>
            </thead>
            <tbody>
              {FOUNDER_POSITION.map((r) => (
                <tr key={r.key} className={r.provenance === "stated" ? "row-stated" : undefined}>
                  <td>
                    <strong>{r.label}</strong>
                    <span className="conc-note">{r.note}</span>
                  </td>
                  <td className="num">{r.bloch}</td>
                  <td className="num">{r.ofCap}</td>
                  <td className="num">{r.ofIssued}</td>
                  <td>
                    <span className={"prov prov-" + r.provenance}>{r.provenance}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Caveat title="The genesis row is not optional. ">
          Read the first two rows together or not at all. Against the cap the position went from{" "}
          <strong>56.05% to 37.92%</strong> — it <em>shrank</em>. Quoting the published 27.04%
          beside today's 37.92% produces the opposite story, a rise, out of two numbers that are
          not measuring the same thing.
        </Caveat>
        <Caveat title="What “stated” means, and why it is marked. ">
          That 18,128,356,145.07 BLCH <em>left the address</em> across epochs 184–1618, to 14 addresses, is measured — anyone
          can reproduce it. That it was <strong>sold to third parties</strong> is the founder's
          statement, and it is marked as such because the chain cannot attribute control of an
          address to a person and never will. An auditor re-running this page must reproduce every
          measured row and must <em>fail</em> to reproduce that one. Keeping that line visible is
          what makes the rest of the audit worth anything; erasing it would turn a disclosure into
          a proof it is not. Supply is genuinely more distributed than the genesis row — on the
          founder's word, not the chain's.
        </Caveat>
        <Caveat title="The 27.04% published today is a fourth thing, and it is wrong. ">
          It is <code>FOUNDER_TOTAL_BLOCH</code> — the largest carryover plus the founder grant —
          and it omits the other four buckets ({PUBLISHED_UNDERSTATEMENT.omittedBuckets},{" "}
          {PUBLISHED_UNDERSTATEMENT.omittedBloch} BLCH) that{" "}
          <code>main.rs:605-622</code> writes to the <em>same script hash</em>. It has understated
          from genesis onward. A compile-time assert pins it, which proves the constant has not
          drifted — not that it measures what its name says. It appears in none of the rows above
          and should not be quoted.
        </Caveat>
        <Caveat title="There is no on-chain lockup on any of it. ">
          Not on what was sold, and not on what is retained.{" "}
          <code>unlock_epoch</code> is <strong>{NO_ONCHAIN_LOCKUP.unlockEpoch}</strong> on all five
          buckets, <strong>no node reads the field</strong>, and all five were spent between epochs{" "}
          {NO_ONCHAIN_LOCKUP.bucketsSpentFrom} and {NO_ONCHAIN_LOCKUP.bucketsSpentTo} (documented
          and tested on <code>main</code>, commit <code>{NO_ONCHAIN_LOCKUP.evidenceCommit}</code>).
          The vesting schedule in the tokenomics is a statement of intent, not a constraint the
          chain enforces. A reader comparing this page against that schedule should learn the
          difference here rather than discover it later.
        </Caveat>
      </section>

      {/* ── cohort bond sits outside issuance ── */}
      <section className="card sup-card">
        <h2 className="snap-h2">
          The cohort's {fmtInt(COHORT_BOND_BLOCH)} BLCH of bonded stake sits outside genesis
          issuance
        </h2>
        <p className="snap-body">
          <code>genesis_issued_sat()</code> sums the carryover and the allocations, and nothing
          else. A validator's <code>stake_sat</code> never enters it. The proof is not the code
          reading — it is that <strong>the arithmetic balances to zero without the stake</strong>:
          carryover plus the five buckets equals <code>GENESIS_ISSUED_SAT</code> to the satoshi, and
          adding {fmtInt(COHORT_BOND_BLOCH)} BLCH on top would make it fail.
        </p>
        <Caveat title="Why this is not a rounding question. ">
          Counting the bond as issued would not breach the cap on the day. It would silently{" "}
          <em>short the emission schedule</em> by exactly that amount — and{" "}
          <code>close_epoch</code> clamps against the cap rather than refusing, so nothing would
          fail, nothing would log, and the shortfall would land decades later on whoever is
          validating at the end of the {Number(EMISSION_YEARS)}-year window. That is the failure
          mode: not a wrong number today, a quiet debt assigned to people who are not in the room.
        </Caveat>

        <p className="snap-body" style={{ marginTop: 16 }}>
          Being outside the counter is only safe if the bond came out of a bucket that <em>is</em>{" "}
          inside it. The ceremony's own design says it did: its supply table reads{" "}
          <em>“Liquidity — 5,000,000,000 <strong>minus cohort stake</strong>”</em>, and states that
          with that subtraction the accounting “closes to <strong>exactly</strong>{" "}
          {fmtInt(TOTAL_SUPPLY_BLOCH)} BLCH — outputs plus bonded cohort stake plus emission, not
          ‘at most’.”
        </p>
        <Caveat title="The subtraction was not applied. ">
          The manifest the fleet actually booted from carries the liquidity bucket at the full{" "}
          {fmtInt(LIQUIDITY_BLOCH)} BLCH. So on the live chain the bond is not carved out of
          liquidity — it exists <em>in addition to</em> the {fmtInt(GENESIS_ISSUED_BLOCH)} BLCH the
          issuance counter was seeded with, and no artefact in the repository names another bucket
          it was taken from. On the ceremony's own arithmetic that puts{" "}
          {fmtInt(COHORT_BOND_BLOCH)} BLCH of real, bonded coins outside the accounting that is
          supposed to close exactly. It is {pct(COHORT_BOND_BLOCH, TOTAL_SUPPLY_BLOCH)} of the cap —
          economically negligible, and precisely the reason it can sit unnoticed. The cap check
          reads the committed counter, and the committed counter has never seen these coins.
        </Caveat>
      </section>

      {/* ── the tautology ── */}
      <section className="card sup-card">
        <h2 className="snap-h2">
          <code>check_supply()</code> is tautological — it corroborates nothing
        </h2>
        <p className="snap-body">
          The genesis tool verifies that carryover plus allocations equals{" "}
          <code>GENESIS_ISSUED_SAT</code>, and that check is worth having: it catches a manifest
          typed wrong. It is <strong>not</strong> independent evidence that the supply figures are
          right, and it must never be cited as such.
        </p>
        <div className="sup-proof">
          <div className="sup-proof-row">
            <span className="sup-proof-k">by definition</span>
            <code>GENESIS_ISSUED_SAT = TOTAL − VALIDATOR_EMISSION</code>
          </div>
          <div className="sup-proof-row">
            <span className="sup-proof-k">by definition</span>
            <code>VALIDATOR_EMISSION = TOTAL − CARRYOVER − buckets</code>
          </div>
          <div className="sup-proof-row sup-proof-sub">
            <span className="sup-proof-k">substituting</span>
            <code>GENESIS_ISSUED_SAT = CARRYOVER + buckets</code>
          </div>
          <div className="sup-proof-row sup-proof-out">
            <span className="sup-proof-k">so the check</span>
            <code>CARRYOVER + buckets == GENESIS_ISSUED_SAT</code> <span>is X == X.</span>
          </div>
        </div>
        <p className="lookup-hint">
          A manifest built from these constants cannot fail this check no matter what the constants
          say. If the carryover figure is wrong, the check passes anyway — and the emission
          remainder absorbs the error silently, which is precisely the situation on the next card.
        </p>
      </section>

      {/* ── the carryover disagreement ── */}
      <section className="card sup-card sup-dispute">
        <h2 className="snap-h2">Two artefacts disagree about the carryover, by {fmtInt(CARRYOVER_DISPUTE.differenceBloch)} BLCH</h2>
        <p className="snap-body">
          The carried Genesis-3 ledger is the one input to the supply arithmetic that was{" "}
          <em>measured</em> rather than decided, and the repository currently holds two different
          measurements. This is unresolved as of this page. It is shown rather than picked.
        </p>
        <div className="sup-versus">
          <div className="sup-versus-side">
            <div className="sup-versus-tag">
              <span className="pill ok">the chain is on this side</span>
            </div>
            <div className="sup-versus-value">{fmtInt(CARRYOVER_DISPUTE.pinned)}</div>
            <div className="sup-versus-src">
              <code>{CARRYOVER_DISPUTE.pinnedSource}</code>
            </div>
            <div className="sup-versus-note">
              Terminal snapshot at height {fmtInt(CARRYOVER_DISPUTE.pinnedHeight)},{" "}
              {fmtInt(CARRYOVER_DISPUTE.pinnedUtxos)} outputs. The mainnet manifest was decoded from
              three hosts and is byte-identical, so this is the figure the live chain committed to.
            </div>
          </div>
          <div className="sup-versus-gap">
            <span className="sup-versus-delta">Δ {fmtInt(CARRYOVER_DISPUTE.differenceBloch)}</span>
            <span className="faint">BLCH</span>
          </div>
          <div className="sup-versus-side">
            <div className="sup-versus-tag">
              <span className="pill quiet">disagrees</span>
            </div>
            <div className="sup-versus-value">{fmtInt(CARRYOVER_DISPUTE.measured)}</div>
            <div className="sup-versus-src">
              <code>{CARRYOVER_DISPUTE.measuredSource}</code>
            </div>
            <div className="sup-versus-note">
              The genesis ceremony tool asserts this figure, against a set of{" "}
              {fmtInt(CARRYOVER_DISPUTE.measuredUtxos)} outputs — an earlier, smaller snapshot. A
              tool that builds the artefact and a constant that describes it should not be able to
              disagree. It is not one number in isolation either: the tool's documentation carries a
              matching emission remainder of 43,029,120,000 BLCH, so the two artefacts describe two
              internally consistent chains.
            </div>
          </div>
        </div>
        <Caveat title="What is at stake in the difference, and what is not. ">
          Because the validator emission is defined as the remainder, a larger carryover is not
          extra supply — it is {fmtInt(CARRYOVER_DISPUTE.differenceBloch)} BLCH{" "}
          <em>less</em> future emission, taken from the one bucket nobody holds yet. The cap is
          unaffected either way, which is exactly why the disagreement could persist unnoticed:{" "}
          <code>check_supply()</code> passes on both figures. A resolution is in progress; until it
          lands, read every carryover-derived figure on this page — including the emission
          remainder — as carrying this uncertainty.
        </Caveat>
      </section>

      {/* ── emission curve ── */}
      <section className="card sup-card">
        <h2 className="snap-h2">The emission curve — decided, but not where it says it was</h2>
        <p className="snap-body">
          Three curves are implemented, and the tokenomics crate presents the choice between them
          as an open founder decision: it declines to alias any one of them as “the” reward, on the
          stated grounds that doing so “would make a founder decision look like an implementation
          detail.” <strong>That is no longer the situation.</strong> The transition function calls{" "}
          <code>validator_reward_decay_sat</code> and nothing else — one call site, no flag, no gate
          — so the running chain emits on the smooth-decay curve today. The other two are reachable
          only from tests.
        </p>
        <Caveat title="Two artefacts describing the same decision, and only one of them runs. ">
          The choice was made in the transition function while the constants file still describes it
          as open. Read the crate comment as history, not as status: if you are deciding the
          emission curve, you are changing a live consensus rule, not filling in a blank. Both
          curves below that are not marked live would need a flag day.
        </Caveat>
        <p className="snap-body" style={{ marginTop: 14 }}>
          All three issue the same {fmtInt(VALIDATOR_EMISSION_BLOCH)} BLCH across{" "}
          {Number(EMISSION_YEARS)} years and land at the same cap. They differ in <em>when</em> —
          and the modelling in the crate concluded that this shape, not the vesting schedule, is
          what decides whether the validator set can ever outweigh the allocation buckets.
        </p>

        <EmissionChart />

        <div className="table-wrap" style={{ marginTop: 18 }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Curve</th>
                <th className="num">Reward at slot 0</th>
                <th className="num">Emitted by year 10</th>
                <th className="num">Emitted by year 40</th>
              </tr>
            </thead>
            <tbody>
              <tr className="sup-row-live">
                <td>
                  Smooth decay (−10%/yr) <span className="pill ok sup-pill-sm">live</span>
                </td>
                <td className="num">{fmtBloch(INITIAL_ANNUAL_SAT / SLOTS_PER_YEAR, 2)}</td>
                <td className="num">{fmtBloch(emittedDecayBy(10n * SLOTS_PER_YEAR), 0)}</td>
                <td className="num">{fmtBloch(emittedDecayBy(EMISSION_SLOTS), 0)}</td>
              </tr>
              <tr>
                <td>
                  Halving (every 4 years) <span className="pill quiet sup-pill-sm">not wired</span>
                </td>
                <td className="num">{fmtBloch(INITIAL_REWARD_SAT, 2)}</td>
                <td className="num">{fmtBloch(emittedHalvingBy(10n * SLOTS_PER_YEAR), 0)}</td>
                <td className="num">{fmtBloch(emittedHalvingBy(EMISSION_SLOTS), 0)}</td>
              </tr>
              <tr>
                <td>
                  Flat <span className="pill quiet sup-pill-sm">not wired</span>
                </td>
                <td className="num">{fmtBloch(rewardFlatSat(0n), 2)}</td>
                <td className="num">{fmtBloch(emittedFlatBy(10n * SLOTS_PER_YEAR), 0)}</td>
                <td className="num">{fmtBloch(emittedFlatBy(EMISSION_SLOTS), 0)}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="g4-grid" style={{ marginTop: 18 }}>
          <div className="g4-stat">
            <span className="g4-k">Year-1 issuance, live curve</span>
            <span className="g4-v">
              {(Number(annualInflationBps(0n)) / 100).toFixed(2)}%
            </span>
            <span className="g4-dim">
              of TOTAL supply — the way Solana and Ethereum quote it. The crate justifies that
              denominator by saying the circulating figure would be distorted by vesting; on this
              chain nothing is vested on-chain, so the honest reason to quote against total supply
              is simply that circulating supply is not measured at all.
            </span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Year 10</span>
            <span className="g4-v">{(Number(annualInflationBps(9n)) / 100).toFixed(2)}%</span>
            <span className="g4-dim">of total supply</span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Permanently unissued</span>
            <span className="g4-v">{fmtBloch(EMISSION_DUST_SAT, 8)}</span>
            <span className="g4-dim">
              {fmtInt(EMISSION_DUST_SAT)} sat the decay curve can never emit — integer truncation
              against a total that is not a multiple of the slots per year. It errs under the cap,
              never over.
            </span>
          </div>
        </div>

        <Caveat title="Reading the flat line as “fair” inverts the finding. ">
          A constant reward looks like the neutral choice and is the one the crate's own modelling
          rejects: under it the validator share is still only about a quarter of circulating supply
          after ten years, so the allocation buckets — one address — stay dominant for longer.
          Front-loading emission is what dilutes the genesis holder. That is the argument, and it is
          an argument about who ends up holding the chain, not about yield.
        </Caveat>
      </section>

      {/* ── provenance ── */}
      <section className="card sup-card">
        <h2 className="snap-h2">Where these numbers come from</h2>
        <div className="kv">
          <div className="k">Constants</div>
          <div className="v">
            <code>crates/bloch-pos-committee/src/tokenomics_v4.rs</code> — mirrored into this page
            and re-derived here against the two invariants that crate asserts at compile time
            (the emission remainder, and the 40-year decay residual of {fmtInt(EMISSION_DUST_SAT)}{" "}
            sat). {check.ok ? "Both re-derive correctly." : "The re-derivation is FAILING — see the top of this page."}
          </div>
          <div className="k">Allocation recipient</div>
          <div className="v">
            <code>crates/bloch-pos-node/src/main.rs</code> — all five{" "}
            <code>GenesisAllocation</code> rows are built from one constant,{" "}
            <code>FOUNDER_WITHDRAWAL_H160</code>.
          </div>
          <div className="k">Live figures</div>
          <div className="v">
            <code>getchaininfo</code>, <code>getvalidatorcount</code> and one{" "}
            <code>getbalance</code> — three constant-cost committed reads per page load. No scan and
            no per-validator fan-out: this RPC is served by the consensus loop itself.
          </div>
          <div className="k">Not sourced</div>
          <div className="v">
            The issued-supply counter. It exists in committed state; no method reads it.
            Every issuance figure above is arithmetic from the genesis constants.
          </div>
        </div>
        <p className="lookup-hint">
          The handover this supply opened with — the Genesis-3 terminal state, its digests, and what
          a node verifies on boot — is on the <Link to="/snapshot">snapshot page</Link>. Nothing
          here is investment advice, and none of it is a claim about price.
        </p>
      </section>
    </div>
  );
}
