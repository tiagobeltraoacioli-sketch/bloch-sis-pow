// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fees & Mempool — the surface mempool.space is actually named after.
//
// Four questions, in the order someone actually has them: what does a
// transfer cost right now, has the price moved, what is waiting, and why does
// a transfer that missed its block have to be REBUILT rather than resubmitted.
//
// The last one is the reason this page exists. Genesis-4's fee is not
// declared by the transaction and not a minimum — it is derived from the
// transaction's class and byte count, priced at the block's own committed
// base fee, and conservation is checked with `!=`. A transfer is therefore
// valid at exactly one price point, and a price that moved under it is not a
// "low fee", it is an invalid transaction. Every explorer convention borrowed
// from Bitcoin — a fee-rate ladder, "your tx will confirm in ~3 blocks",
// bump-to-replace — is wrong here, and wrong in the direction that loses
// people money.
//
// Two things this page deliberately refuses to draw:
//
//   1. A transaction tracker. There are no transaction ids (§ "What cannot be
//      tracked"). Inventing an identifier so the UI feels familiar would be
//      the single most harmful thing this page could do.
//   2. A fee-history chart. The RPC exposes the CURRENT base fee and no
//      series, and per-block payload bytes are not exposed either — so a
//      historical price line could only be fabricated. What is drawn instead
//      is the real per-block transaction count, which for the zero case is
//      not a proxy but a proof: no transactions means no payload bytes, means
//      usage strictly under target, means the price stepped down into the
//      floor and stayed.
import { useEffect, useMemo, useState } from "react";
import { g4rpc, pollWhileVisible, G4Head, G4Block } from "../lib/g4";
import { fmtInt, fmtBytes } from "../lib/format";
import { Link } from "../lib/router";
import { Loading } from "../components/ui";
import {
  quote,
  nextBaseFee,
  maxBlockTxBytes,
  blockTxBytesTarget,
  intrinsicGas,
  satToBloch,
  feePartsSat,
  BLOCK_GAS_LIMIT,
  MIN_BASE_FEE_MILLISAT_PER_GAS,
  BLOCK_BYTES_V2_ACTIVATION_EPOCH,
  HYBRID_VERIFY_GAS,
  GAS_PER_BYTE,
  TX_FLAT_GAS,
  ILLUSTRATIVE_TRANSFER_BYTES,
} from "../lib/fees";

const POLL_MS = 15_000;
/** Blocks in the occupancy strip. 96 slots = ~48 minutes of chain. */
const STRIP = 96;
/**
 * Newest slots re-read on every tick even when already cached.
 *
 * Everything older is kept. A naive implementation re-fetches all 96 slots
 * every 15 seconds — 96 RPC calls a tick, forever, per open tab, against an
 * endpoint whose nodes serve their RPC from the consensus loop. This window is
 * the reorg allowance instead: observed reorgs here are depth 1, occasionally
 * 2, so re-reading the last four slots covers what can still change and the
 * settled tail is asked for exactly once.
 */
const REORG_REREAD = 4;
/**
 * Block reads in flight at once.
 *
 * A node serves its RPC from the same thread that runs consensus, so a burst
 * of parallel calls competes with the block production it is being asked
 * about. Four is enough to fill the strip in a few seconds and small enough
 * that an open tab is never the reason a node answers slowly.
 */
const FETCH_CONCURRENCY = 4;

interface MempoolInfo {
  size: number;
  max: number;
  bytes: number;
  next_base_fee_millisat_per_gas: string;
}

/** getchaininfo carries the price; the type in lib/g4 predates it. */
type HeadWithFee = G4Head & {
  base_fee_millisat_per_gas?: string;
  next_base_fee_millisat_per_gas?: string;
  mempool?: number;
};

export function FeesPage() {
  const [head, setHead] = useState<HeadWithFee | null>(null);
  const [mp, setMp] = useState<MempoolInfo | null>(null);
  const [mpErr, setMpErr] = useState<string | null>(null);
  // slot -> block, or null for a slot the proposer missed. Accumulates.
  const [strip, setStrip] = useState<Map<number, G4Block | null> | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    const known = new Map<number, G4Block | null>();
    const tick = async () => {
      try {
        const h = await g4rpc<HeadWithFee>("getchaininfo");
        if (stop) return;
        setHead(h);
        setErr(null);
        const m = await Promise.allSettled([g4rpc<MempoolInfo>("getmempoolinfo")]).then(
          (r) => r[0],
        );
        if (stop) return;
        if (m.status === "fulfilled") {
          setMp(m.value);
          setMpErr(null);
        } else {
          // Worth surfacing rather than hiding: the mempool is node-local, and
          // a read that has to agree across nodes can legitimately fail on it.
          setMpErr(String((m.reason as Error)?.message ?? m.reason));
        }

        // Only the slots this tab has never resolved, plus the reorg window.
        const want: number[] = [];
        for (let i = 0; i < STRIP; i++) {
          const s = h.slot - i;
          if (s < 0) break;
          if (i < REORG_REREAD || !known.has(s)) want.push(s);
        }
        let next = 0;
        const worker = async () => {
          for (;;) {
            const i = next++;
            if (i >= want.length || stop) return;
            const s = want[i];
            try {
              known.set(s, await g4rpc<G4Block>("getblockbyslot", [s]));
            } catch {
              // -32007 SLOT_EMPTY is the normal answer for a missed proposal,
              // not a fault. Anything else also lands here and reads as a gap,
              // which is the honest rendering of "this tab does not know".
              known.set(s, null);
            }
          }
        };
        await Promise.all(
          Array.from({ length: Math.min(FETCH_CONCURRENCY, want.length) }, worker),
        );
        if (stop) return;
        // Drop what has scrolled out of the window so the map stays bounded.
        for (const s of [...known.keys()]) if (s < h.slot - STRIP) known.delete(s);
        setStrip(new Map(known));
      } catch (e: any) {
        if (!stop) setErr(String(e?.message ?? e));
      }
    };
    const teardown = pollWhileVisible(() => void tick(), POLL_MS);
    return () => {
      stop = true;
      teardown();
    };
  }, []);

  if (err && !head) {
    return (
      <div className="container">
        <div className="err-box" style={{ marginTop: 24 }}>
          The Genesis-4 endpoint did not answer ({err}). That reports the proxy, not the network.
        </div>
      </div>
    );
  }
  if (!head) return <Loading label="Reading the fee market…" />;

  const epoch = head.epoch;
  const baseNow = BigInt(head.base_fee_millisat_per_gas ?? "10");
  const baseNext = BigInt(
    head.next_base_fee_millisat_per_gas ?? mp?.next_base_fee_millisat_per_gas ?? "10",
  );
  const atFloor = baseNext === MIN_BASE_FEE_MILLISAT_PER_GAS;
  const capBytes = maxBlockTxBytes(epoch);
  const targetBytes = blockTxBytesTarget(epoch);

  return (
    <div className="container">
      <section className="card g4-card">
        <div className="g4-head">
          <div>
            <span className="g4-badge">Genesis-4 · fee market</span>
            <h1 className="g4-title">What a transfer costs, and why it expires</h1>
          </div>
          <div className="g4-sub">
            price in millisatoshi per gas · fees settle in whole satoshis, rounded up
          </div>
        </div>

        <p className="page-lede" style={{ maxWidth: 760, marginTop: 14 }}>
          Genesis-4 has one fee market, one unit — gas — and one protocol-set price. The fee is
          never declared by the transaction: it is <strong>derived</strong> from the transaction's
          class and byte count, priced at the block's committed base fee, and the difference
          between inputs and outputs must equal it <strong>exactly</strong>. Not at least. Exactly.
          Everything else on this page follows from that.
        </p>

        <div className="g4-grid" style={{ marginTop: 18 }}>
          <div className="g4-stat">
            <span className="g4-k">Base fee, this block</span>
            <span className="g4-v">
              {baseNow.toString()}
              <span className="g4-dim"> msat/gas</span>
            </span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Price for the next block</span>
            <span className="g4-v">
              {baseNext.toString()}
              <span className="g4-dim"> msat/gas</span>
            </span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Waiting on this node</span>
            <span className="g4-v">
              {mp ? fmtInt(mp.size) : "—"}
              <span className="g4-dim"> / {mp ? fmtInt(mp.max) : "4,096"}</span>
            </span>
          </div>
          <div className="g4-stat">
            <span className="g4-k">Payload cap · epoch {fmtInt(epoch)}</span>
            <span className="g4-v">
              {fmtBytes(Number(capBytes))}
              <span className="g4-dim">
                {" "}
                · target {fmtBytes(Number(targetBytes))}
              </span>
            </span>
          </div>
        </div>

        {atFloor && (
          <p className="g4-note" style={{ marginTop: 14 }}>
            The price is at its <strong>floor</strong> — 10 millisatoshi per gas, the lowest value
            the controller can hold. It has never been anywhere else, and the section below shows
            why that is arithmetic rather than luck.
          </p>
        )}
      </section>

      <Calculator epoch={epoch} baseMsat={baseNext} />
      <PriceHistory epoch={epoch} baseNext={baseNext} strip={strip} headSlot={head.slot} />
      <WhyRebuild epoch={epoch} baseMsat={baseNext} />
      <MempoolTruth mp={mp} mpErr={mpErr} head={head} />
      <NotTrackable />
    </div>
  );
}

// ── 1. What a transfer costs right now ──────────────────────────────────────

function Calculator({ epoch, baseMsat }: { epoch: number; baseMsat: bigint }) {
  const [bytes, setBytes] = useState(String(ILLUSTRATIVE_TRANSFER_BYTES));
  const [keys, setKeys] = useState("1");
  const [tip, setTip] = useState("0");
  const [v2, setV2] = useState(true);

  const parsed = useMemo(() => {
    const b = /^\d+$/.test(bytes.trim()) ? BigInt(bytes.trim()) : null;
    const k = /^\d+$/.test(keys.trim()) ? BigInt(keys.trim()) : null;
    const t = /^\d+$/.test(tip.trim()) ? BigInt(tip.trim()) : null;
    return { b, k, t };
  }, [bytes, keys, tip]);

  const ok = parsed.b !== null && parsed.k !== null && parsed.t !== null && parsed.k > 0n;
  const q = ok ? quote(parsed.b!, parsed.k!, baseMsat, parsed.t!, epoch) : null;

  return (
    <section className="card fee-card">
      <h2 className="section-title">What it costs</h2>
      <div className="fee-formula">
        <code>
          gas = {fmtInt(TX_FLAT_GAS)} + tx_bytes × {GAS_PER_BYTE.toString()} +{" "}
          {fmtInt(HYBRID_VERIFY_GAS)} × verifications
        </code>
        <div className="fee-formula-note">
          <code>fee_sat = ceil(gas × base / 1000) + ceil(gas × tip / 1000)</code> — the two parts
          settle and round up <em>independently</em>.
        </div>
      </div>

      <div className="fee-calc">
        <div className="fee-inputs">
          <label className="fee-field">
            <span className="fee-lbl">
              Encoded bytes
              <span className="fee-hint">measure yours — see below</span>
            </span>
            <input
              className="lookup-input"
              value={bytes}
              inputMode="numeric"
              onChange={(e) => setBytes(e.target.value)}
            />
          </label>
          <label className="fee-field">
            <span className="fee-lbl">
              {v2 ? "Distinct owner keys" : "Inputs"}
              <span className="fee-hint">
                {v2 ? "witness-table entries" : "one verification each"}
              </span>
            </span>
            <input
              className="lookup-input"
              value={keys}
              inputMode="numeric"
              onChange={(e) => setKeys(e.target.value)}
            />
          </label>
          <label className="fee-field">
            <span className="fee-lbl">
              Tip <span className="fee-hint">msat/gas · leave at 0</span>
            </span>
            <input
              className="lookup-input"
              value={tip}
              inputMode="numeric"
              onChange={(e) => setTip(e.target.value)}
            />
          </label>
          <div className="fee-field">
            <span className="fee-lbl">Format</span>
            <div className="fee-toggle">
              <button className={v2 ? "" : "on"} onClick={() => setV2(false)}>
                V1 · 0x01
              </button>
              <button className={v2 ? "on" : ""} onClick={() => setV2(true)}>
                V2 · 0x06
              </button>
            </div>
          </div>
        </div>

        {q ? (
          <div className="fee-out">
            <div className="fee-total">
              <span className="fee-total-v">{fmtInt(q.totalSat)}</span>
              <span className="fee-total-u">sat</span>
              <span className="fee-total-b">{satToBloch(q.totalSat)} BLOCH</span>
            </div>
            <table className="tbl fee-breakdown">
              <tbody>
                <tr>
                  <td>Flat</td>
                  <td className="num">{fmtInt(q.flatGas)}</td>
                  <td className="faint">gas</td>
                </tr>
                <tr>
                  <td>
                    Bytes <span className="faint">× {GAS_PER_BYTE.toString()}</span>
                  </td>
                  <td className="num">{fmtInt(q.byteGas)}</td>
                  <td className="faint">gas</td>
                </tr>
                <tr>
                  <td>
                    Verification{" "}
                    <span className="faint">× {fmtInt(HYBRID_VERIFY_GAS)}</span>
                  </td>
                  <td className="num">{fmtInt(q.verifyGas)}</td>
                  <td className="faint">gas</td>
                </tr>
                <tr className="fee-sum">
                  <td>Total gas</td>
                  <td className="num">{fmtInt(q.gas)}</td>
                  <td className="faint">
                    {((Number(q.gas) / Number(BLOCK_GAS_LIMIT)) * 100).toFixed(2)}% of the block
                  </td>
                </tr>
                <tr>
                  <td>Base fee</td>
                  <td className="num">{fmtInt(q.baseFeeSat)}</td>
                  <td className="faint">sat @ {baseMsat.toString()} msat/gas</td>
                </tr>
                <tr>
                  <td>Priority (tip)</td>
                  <td className="num">{fmtInt(q.priorityFeeSat)}</td>
                  <td className="faint">sat</td>
                </tr>
              </tbody>
            </table>

            {(q.overByteCap || q.overGasCap) && (
              <div className="warn-box" style={{ marginTop: 12 }}>
                <strong>Does not fit a block.</strong>{" "}
                {q.overByteCap && (
                  <>
                    {fmtInt(parsed.b!)} bytes is over the {fmtBytes(Number(maxBlockTxBytes(epoch)))}{" "}
                    payload cap.{" "}
                  </>
                )}
                {q.overGasCap && <>{fmtInt(q.gas)} gas is over the 60,000,000 block gas cap.</>}
              </div>
            )}

            {q.foldedSat !== q.totalSat && (
              <div className="warn-box" style={{ marginTop: 12 }}>
                <strong>
                  A wallet that folds base and tip together computes {fmtInt(q.foldedSat)} sat —{" "}
                  {fmtInt(q.totalSat - q.foldedSat)} short.
                </strong>{" "}
                <code>ceil(gas × (base+tip) / 1000)</code> is not{" "}
                <code>ceil(gas × base / 1000) + ceil(gas × tip / 1000)</code>. Under strict
                equality, one satoshi short is a hard rejection.
              </div>
            )}
          </div>
        ) : (
          <div className="fee-out faint">Enter whole numbers; owner keys must be at least 1.</div>
        )}
      </div>

      <div className="fee-notes">
        <p>
          <strong>The default size is an illustration, not a constant.</strong> Falcon-1024
          signatures are variable length, so the encoded size of a transfer is not a function of
          its input count and no fixed number is a correct ceiling. Build the transaction, measure
          the bytes you produced, and check both caps against that:{" "}
          <code>bytes ≤ {fmtInt(maxBlockTxBytes(epoch))}</code> and{" "}
          <code>
            {fmtInt(TX_FLAT_GAS)} + bytes×{GAS_PER_BYTE.toString()} + {fmtInt(HYBRID_VERIFY_GAS)}
            ×keys ≤ {fmtInt(BLOCK_GAS_LIMIT)}
          </code>
          .
        </p>
        <p>
          <strong>The verification term is where integrators go wrong.</strong> Under V2 it counts{" "}
          <em>distinct owner keys</em>, not inputs — one signature over the shared signing root
          authorises every input that key owns. A published formula once took the byte term from V2
          and the verification term from V1 and derived a ceiling of 815 inputs for a transaction
          that cannot exist in either format. If your inputs share one key — the ordinary exchange
          case — the verification term is <code>{fmtInt(HYBRID_VERIFY_GAS)} × 1</code>, and the
          binding constraint is
          bytes, not gas.
        </p>
      </div>
    </section>
  );
}

// ── 2. How the base fee has moved ───────────────────────────────────────────

function PriceHistory({
  epoch,
  baseNext,
  strip,
  headSlot,
}: {
  epoch: number;
  baseNext: bigint;
  strip: Map<number, G4Block | null> | null;
  headSlot: number;
}) {
  const target = blockTxBytesTarget(epoch);
  const cap = maxBlockTxBytes(epoch);

  // The controller, run for real on the four usages that matter. Nothing here
  // is a remembered figure — each is nextBaseFee() applied to this chain's
  // current price at this chain's current epoch.
  const ladder: [string, bigint, string][] = [
    [
      "An empty block — what almost every block is",
      nextBaseFee(baseNext, { gasUsed: 0n, txBytes: 0n }, epoch),
      "usage 0, so the controller steps down; from the floor there is nowhere down to go",
    ],
    [
      `Exactly at target (${fmtBytes(Number(target))})`,
      nextBaseFee(baseNext, { gasUsed: 0n, txBytes: target }, epoch),
      "the neutral point — the price is unchanged",
    ],
    [
      "One byte over target",
      nextBaseFee(baseNext, { gasUsed: 0n, txBytes: target + 1n }, epoch),
      "the computed delta truncates to zero and is floored at 1: a congested block must always move the price",
    ],
    [
      `A payload-saturated block (${fmtBytes(Number(cap))})`,
      nextBaseFee(baseNext, { gasUsed: 0n, txBytes: cap }, epoch),
      "twice target — the largest single step there is, +1/8",
    ],
  ];

  // Oldest to newest, left to right, only over slots this tab has resolved.
  const cells: (G4Block | null)[] = [];
  if (strip) {
    for (let s = headSlot - STRIP + 1; s <= headSlot; s++) {
      if (strip.has(s)) cells.push(strip.get(s)!);
    }
  }
  const withBlocks = cells.filter((b): b is G4Block => b !== null);
  const missed = cells.length - withBlocks.length;
  const txTotal = withBlocks.reduce((a, b) => a + b.tx_count, 0);
  const maxTx = Math.max(1, ...withBlocks.map((b) => b.tx_count));

  return (
    <section className="card fee-card">
      <h2 className="section-title">How the price has moved</h2>

      <div className="fee-flat">
        <div className="fee-flat-line">
          <span className="fee-flat-price">{baseNext.toString()}</span>
          <span className="fee-flat-u">msat/gas</span>
        </div>
        <p>
          <strong>It is at the floor, where it started.</strong> The base fee is a deterministic
          function of the parent block's usage: over target it rises by at most 1/8, under target
          it falls by at most 1/8, and it is clamped at a floor of 10 — the price the chain opened
          at. Only an over-target block can lift it, and a single empty block afterwards takes 1/8
          straight back off, so on a chain this quiet any excursion decays into the floor within a
          few blocks. What the RPC can tell you is the price now; what it cannot give you is a
          series, so this page does not draw one.
        </p>
      </div>

      <div className="fee-strip-wrap">
        <div className="fee-strip-head">
          <span className="section-title" style={{ margin: 0 }}>
            Transactions per block · last {fmtInt(STRIP)} slots
          </span>
          <span className="faint">
            {fmtInt(withBlocks.length)} blocks, {fmtInt(missed)} missed slots,{" "}
            <strong>{fmtInt(txTotal)}</strong> transactions
          </span>
        </div>
        {strip === null ? (
          <Loading label="Reading blocks…" />
        ) : (
          <div
            className="fee-strip"
            role="img"
            aria-label={`${txTotal} transactions across the last ${withBlocks.length} blocks`}
          >
            {cells.map((b, i) =>
                b === null ? (
                  <span key={i} className="fee-tick missed" title="slot missed — no block" />
                ) : (
                  <span
                    key={i}
                    className={"fee-tick" + (b.tx_count > 0 ? " has-tx" : "")}
                    style={{ ["--h" as any]: b.tx_count > 0 ? `${(b.tx_count / maxTx) * 100}%` : "2px" }}
                    title={`slot ${b.slot} · height ${b.height} · ${b.tx_count} tx`}
                  />
                ),
            )}
          </div>
        )}
        <p className="faint fee-strip-note">
          A flat line is the honest rendering. Blocks here are almost always empty — and an empty
          block is not merely weak evidence about the price, it is <em>proof</em>: no transactions
          means no payload bytes, which is strictly under target, which forces the controller down
          into the floor. The RPC exposes no per-block payload-byte or gas-used figure and no
          historical price series, so this strip counts transactions rather than pretending to a
          utilisation curve. Where it reads zero, the two are the same thing.
        </p>
        <p className="faint fee-strip-note">
          <strong>Measured 2026-09-01</strong>, so that the window above is not the only evidence:
          a full sweep of slots 48,500–54,540 (heights 27,748–33,645) read 5,252 blocks and 129
          missed slots, and found <strong>two transactions</strong> in the whole range — one each
          at heights 30,907 and 30,909. A single transfer is about 3% of the byte target. That is
          an observation with a date on it, not a live figure; the strip is the live one.
        </p>
      </div>

      <h3 className="fee-h3">What it would take to move it</h3>
      <div className="table-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>Parent block</th>
              <th className="num">Next price</th>
              <th>Why</th>
            </tr>
          </thead>
          <tbody>
            {ladder.map(([what, price, why]) => (
              <tr key={what}>
                <td>{what}</td>
                <td className="num">
                  {price.toString()}{" "}
                  <span className="faint">
                    {price === baseNext ? "—" : price > baseNext ? "▲" : "▼"}
                  </span>
                </td>
                <td className="faint">{why}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="faint fee-notes">
        At roughly {fmtInt(Math.floor(Number(target) / Number(ILLUSTRATIVE_TRANSFER_BYTES)))} typical
        transfers, a block reaches target and the price stops falling; past that it starts to
        climb. Utilisation is measured as the <em>maximum</em> of the gas axis and the byte axis,
        not gas alone — a block full of eUTXO transfers saturates the byte cap while using under a
        tenth of the {fmtInt(BLOCK_GAS_LIMIT)} gas cap, and a gas-only controller would read that
        as slack and lower the price of the resource that is actually exhausted. Skipped slots
        produce no block and therefore no update: the price carries over unchanged.
      </p>

      <div className="fee-eras">
        <h3 className="fee-h3">The payload cap has two eras</h3>
        <p>
          At <strong>epoch {BLOCK_BYTES_V2_ACTIVATION_EPOCH}</strong> the payload cap doubled from
          262,144 to 524,288 bytes, and the EIP-1559 byte target moved with it — from 131,072 to
          262,144. Both halves matter: a planner that took the new cap but kept the old target
          would read a legal 300 KiB block as 2.3× over target and misprice everything after it.
          The same flag day activated the deduplicated V2 transfer format. This chain is at epoch{" "}
          {fmtInt(epoch)}, so both are long since live. Consensus asks for the cap as a function of
          the block's own epoch rather than reading a constant, which is what makes the boundary a
          flag day rather than a fork.
        </p>
      </div>
    </section>
  );
}

// ── 3. Why a missed transaction must be rebuilt ─────────────────────────────

function WhyRebuild({ epoch, baseMsat }: { epoch: number; baseMsat: bigint }) {
  const gas = intrinsicGas(ILLUSTRATIVE_TRANSFER_BYTES, 1n);
  const signed = feePartsSat(gas, baseMsat, 0n)[0];

  // What the same transfer owes if the price moves under it. Both directions
  // are failures; only the upward one is reachable from the floor today.
  const rows: [string, bigint][] = [
    ["the price you signed at", baseMsat],
    ["one block over target", nextBaseFee(baseMsat, { gasUsed: 0n, txBytes: blockTxBytesTarget(epoch) + 1n }, epoch)],
    ["one saturated block", nextBaseFee(baseMsat, { gasUsed: 0n, txBytes: maxBlockTxBytes(epoch) }, epoch)],
    ["two saturated blocks", nextBaseFee(
      nextBaseFee(baseMsat, { gasUsed: 0n, txBytes: maxBlockTxBytes(epoch) }, epoch),
      { gasUsed: 0n, txBytes: maxBlockTxBytes(epoch) }, epoch)],
  ];

  return (
    <section className="card fee-card fee-card-key">
      <h2 className="section-title">Why a transfer that missed its block must be rebuilt</h2>

      <p className="page-lede" style={{ maxWidth: 760 }}>
        This is the part with no Bitcoin analogue, and the part that costs people money. A
        Genesis-4 transfer <strong>commits to exactly one base fee</strong>. It does not offer a
        fee and wait to be chosen; it encodes an input total, an output total, and the difference
        between them <em>is</em> the fee — a fee the transaction never states, which consensus
        recomputes from the block's own price and compares with <code>!=</code>.
      </p>

      <div className="fee-eq">
        <code>sum(inputs) == sum(outputs) + fee</code>
        <span className="faint">checked with <code>!=</code>, in either direction</span>
      </div>

      <p>
        So there is no such thing as a transfer with a low fee here, only a transfer that is
        invalid. And <strong>overpaying fails identically to underpaying</strong>: an overpaying
        transfer is <code>ValueNotConserved</code> exactly like a short one, because sweeping the
        remainder to the proposer would be a fee nobody set. Being off by one millisatoshi fails in
        either direction.
      </p>

      <p>
        The consequence for a transfer that sat in the mempool while the price moved: it is not
        late, it is <strong>wrong</strong>. Resubmitting the same bytes cannot help — they encode a
        fee that is no longer the fee. The transfer has to be repriced, re-signed and rebroadcast.
      </p>

      <h3 className="fee-h3">
        What the drift costs, on a {fmtInt(ILLUSTRATIVE_TRANSFER_BYTES)}-byte one-owner transfer
      </h3>
      <div className="table-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>If the block prices at…</th>
              <th className="num">msat/gas</th>
              <th className="num">fee owed</th>
              <th className="num">you signed</th>
              <th>Verdict</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([label, price], i) => {
              const owed = feePartsSat(gas, price, 0n)[0];
              const diff = owed - signed;
              return (
                <tr key={i}>
                  <td>{label}</td>
                  <td className="num">{price.toString()}</td>
                  <td className="num">{fmtInt(owed)} sat</td>
                  <td className="num faint">{fmtInt(signed)} sat</td>
                  <td>
                    {diff === 0n ? (
                      <span className="pill ok">accepted</span>
                    ) : (
                      <span className="pill bad">
                        ValueNotConserved · {diff > 0n ? "short" : "over"} by{" "}
                        {fmtInt(diff < 0n ? -diff : diff)} sat
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <p className="faint">
        The price moves by at most ±1/8 per block and only blocks move it, so a quote is off by at
        most (9/8)<sup>k</sup> after k blocks. That bound is small and it does not help: under
        strict equality, "off by at most 12.5%" is still a rejection. Read the price immediately
        before building, bake it into the change output, and broadcast promptly. A quote more than
        one block old is a rejection risk. The floor is absorbing — the price cannot fall below 10
        — so today, sitting on the floor, only the upward direction is reachable at all.
      </p>

      <h3 className="fee-h3">Two refusals that look alike and are not</h3>
      <div className="table-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>What you see</th>
              <th>What it means</th>
              <th>What to do</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>
                <code>-32008 TX_REFUSED</code>
              </td>
              <td>The node judged those exact bytes invalid — a bad signature, a spent input.</td>
              <td>
                <strong>Terminal.</strong> Never resubmit those bytes. Rebuild.
              </td>
            </tr>
            <tr>
              <td>
                <code>-32003 MEMPOOL_FULL</code>
              </td>
              <td>
                The pool is at its {fmtInt(4096)}-entry bound. The transaction was <em>not</em>{" "}
                judged invalid.
              </td>
              <td>
                <strong>Retryable.</strong> Wait and resend.
              </td>
            </tr>
            <tr>
              <td>Refused by the transition on price</td>
              <td>
                A statement about the chain at one moment, not about the bytes. The same coins are
                perfectly spendable at the current price.
              </td>
              <td>
                <strong>Reprice, re-sign, rebroadcast.</strong>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p className="faint">
        Getting these backwards is how an operator ends up growing the mempool to fix a bad
        signature, or abandoning coins that were never unspendable.
      </p>
    </section>
  );
}

// ── 4. What is waiting ──────────────────────────────────────────────────────

function MempoolTruth({
  mp,
  mpErr,
  head,
}: {
  mp: MempoolInfo | null;
  mpErr: string | null;
  head: G4Head & { mempool?: number };
}) {
  return (
    <section className="card fee-card">
      <h2 className="section-title">What is waiting</h2>

      {mpErr && (
        <div className="warn-box" style={{ marginBottom: 14 }}>
          <strong>No mempool answer:</strong> {mpErr}
        </div>
      )}

      <div className="g4-grid">
        <div className="g4-stat">
          <span className="g4-k">Pending</span>
          <span className="g4-v">{mp ? fmtInt(mp.size) : "—"}</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Capacity</span>
          <span className="g4-v">{mp ? fmtInt(mp.max) : "4,096"}</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Bytes held</span>
          <span className="g4-v">{mp ? fmtBytes(mp.bytes) : "—"}</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Head</span>
          <span className="g4-v">
            {fmtInt(head.height)}
            <span className="g4-dim"> · slot {fmtInt(head.slot)}</span>
          </span>
        </div>
      </div>

      <div className="fee-notes">
        <p>
          <strong>This is one node's view, and it is not consensus.</strong> The mempool is
          node-local state: two honest nodes reading the same network at the same second can and do
          report different pending counts, because a transaction reaches them at different times
          and is dropped from each on its own schedule. Nothing here is a network-wide figure, and
          this explorer will not present it as one.
        </p>
        <p>
          <strong>Admission is fee-blind today.</strong> The 4,096-entry limit is a{" "}
          <em>bound, not a policy</em> — it exists so an unauthenticated transport cannot turn into
          unbounded memory, and nothing more. There is no fee ordering (the pool is
          insertion-ordered), no per-sender limit, and no eviction by price; admission checks only
          that the bytes decode. The node's own comment says real admission control "is{" "}
          <code>gossip.rs</code> work", and that work is not done. A price-eviction and per-sender
          policy exists on an unmerged branch; if it lands, this section stops being true and will
          be rewritten rather than quietly left standing.
        </p>
        <p>
          The practical consequence, while the pool is fee-blind and effectively always empty:
          there is no bidding, no fee ladder, and no "pay more to go sooner". A tip buys ordering
          in a queue that has nothing in it. Set it to zero unless you have a specific reason.
        </p>
        <p>
          <strong>An expiring re-admission bar is not in the released binary.</strong> A mempool
          rejection cache — which removes a refused transaction and bars it from re-entering for
          128 slots, about 64 minutes — exists on an unmerged branch. On the binary the network
          runs there is no such bar, which is why a refused transaction can be re-offered by peers
          that still hold it and walk straight back in. When that bar does land, note what it is
          and is not: it <em>expires</em>, deliberately. A refusal like{" "}
          <code>UnknownInput</code> is a statement about state at one moment, and a permanent bar
          would strand a legitimate chained spend — coins quietly unspendable through a node that
          will never reconsider. "Dropped" would still not mean "gone forever".
        </p>
      </div>
    </section>
  );
}

// ── 5. What cannot be tracked ───────────────────────────────────────────────

function NotTrackable() {
  return (
    <section className="card fee-card">
      <h2 className="section-title">What this page cannot show you</h2>
      <p className="page-lede" style={{ maxWidth: 760 }}>
        <strong>There are no transaction ids.</strong> Not "we haven't indexed them" — there is no
        identifier to index. Asking a node for one is refused by design:
      </p>
      <pre className="fee-quote">
        <code>
          {`> gettransaction
-32005  this node cannot look up a transaction by id: at Genesis-4's
        current layer a transaction carries no id […] and the block store
        keeps no txid index. […] This is a permanent answer for this
        build, not a transient failure — do not retry.`}
        </code>
      </pre>
      <p>
        <code>sendrawtransaction</code> does hand back a <code>tx_hash</code>, and it is a trap: it
        is computed by the node you happened to talk to, other nodes do not agree on it, and
        nothing on the chain is keyed by it. It identifies your submission to that one node for
        that one moment. Building a "track my transaction" page on it — the Bitcoin-shaped page
        every reader expects to find here — would mean inventing an identifier so the interface
        feels familiar, and then watching people trust it. This explorer will not do that.
      </p>
      <p>
        <strong>What you can do instead</strong>, and it is exact rather than approximate: watch
        the ledger. <code>getbalance</code> and <code>listunspent</code> answer against committed
        state for a script hash, and <code>gettxout</code> answers whether one specific outpoint is
        still unspent. A spend is visible as its inputs disappearing and its outputs appearing —
        which is the thing you actually wanted to know. Start from the{" "}
        <Link to="/balance">balance page</Link>.
      </p>
      <p className="faint">
        Also absent, so that silence is not read as assurance: there is no fee-rate estimator (a
        price you cannot choose cannot be estimated — read the current one and use it), no
        replace-by-fee (a replacement is a different transaction), no historical base-fee series
        from the RPC, and no per-block payload-byte or gas-used figure. Where this page shows a
        derived number, it is derived live from the same arithmetic consensus runs, and pinned
        against that crate by a test.
      </p>
    </section>
  );
}
