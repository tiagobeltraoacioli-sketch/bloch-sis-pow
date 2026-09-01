// SPDX-License-Identifier: AGPL-3.0-or-later
//
// One block.
//
// Two things this page refuses to do, both of which the obvious design does.
//
// **It does not render finality as a settled fact.** On Genesis-4 the
// finalized checkpoint is not a latch across a reorg: `do_reorg` adopts an
// ancestor's state wholesale with no comparison of the incoming finalized
// checkpoint against the outgoing one, and fork choice walks from the
// *justified* root, so a reorg down to justified installs a state whose
// finalized epoch predates what the node was reporting a moment ago. A block
// this page showed as `finalized: true` can come back `justified`. We have
// already publicly retracted a settlement guarantee built on the opposite
// assumption, and a green "FINAL" badge is that same guarantee wearing a
// different hat. The badge here reports a reading, timestamped, from named
// nodes — and says what it would take to trust it.
//
// **It does not claim a block is unique to its slot.** Slots change hands.
// The node offers no way to ask what a slot used to hold — there is no orphan
// listing, no reorg feed, and orphans are memory-only and dropped on restart —
// so this page cannot show reorg history it does not have. What it can do is
// (a) compare the two archivals right now, (b) surface what this browser has
// itself watched happen at this slot, and (c) resolve a block id that fork
// choice did not select, which the node does serve. All three are labelled as
// what they are.

import { useEffect, useState } from "react";
import {
  SlotCell,
  slotCell,
  slotAgreement,
  Agreement,
  sightings,
  Sighting,
  read,
  RpcRefusal,
  CODE,
} from "../lib/source";
import { G4Block, NOT_CANONICAL } from "../lib/g4";
import { fmtInt, timeAgo, fmtTime } from "../lib/format";
import { Link } from "../lib/router";
import { Loading, Copyable } from "../components/ui";
import { FinalityBadge } from "../components/blockstream";
import { epochOf } from "../lib/query";

function Row({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="hdr-row">
      <span className="g4-k" title={hint}>
        {label}
      </span>
      <Copyable text={value}>
        <code className="snap-hash">{value}</code>
      </Copyable>
    </div>
  );
}

/** What this browser has personally watched happen at this slot. */
function Sightings({ seen }: { seen: Sighting[] }) {
  const ids = new Set(seen.map((s) => s.blockId));
  if (ids.size < 2) return null;
  return (
    <section className="card reorg-card">
      <h2 className="snap-h2">This slot has held more than one block</h2>
      <p className="page-lede">
        This browser has seen {ids.size} different block ids at this slot. That is a reorg,
        observed first-hand — not read from the chain, because the chain does not keep a record
        anyone can query. It is local to this browser and covers only what happened while this
        explorer was open on this slot.
      </p>
      <div className="table-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>Seen at</th>
              <th>Block id</th>
              <th>Reported as</th>
            </tr>
          </thead>
          <tbody>
            {seen.map((s, i) => (
              <tr key={i} className={i === seen.length - 1 ? "" : "faint"}>
                <td>{new Date(s.at).toISOString().replace("T", " ").slice(0, 19)} UTC</td>
                <td>
                  <code>{s.blockId.slice(0, 20)}…</code>
                </td>
                <td>{s.finality}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/** How much of the finality bar this reading actually clears. */
function FinalityTruth({ block, agreement, headEpoch }: { block: G4Block; agreement: Agreement<G4Block> | null; headEpoch: number | null }) {
  const epochsPast = headEpoch === null ? null : headEpoch - block.epoch;
  const agreed = agreement?.kind === "agree";
  const disagreed = agreement?.kind === "disagree";
  const margin = epochsPast !== null && epochsPast >= 3;

  return (
    <section className="card finality-card">
      <h2 className="snap-h2">What that state word is worth</h2>

      {disagreed && (
        <div className="errbox">
          <strong>The two archivals name different blocks for this slot.</strong> One says{" "}
          <code>{(agreement as any).a.block_id.slice(0, 20)}…</code>, the other{" "}
          <code>{(agreement as any).b.block_id.slice(0, 20)}…</code>. This is a live fork as seen
          from two independent nodes. Nothing on this page is settled while that is true.
        </div>
      )}

      <ul className="truth-list">
        <li className={block.finalized ? "yes" : "no"}>
          <span className="mark">{block.finalized ? "✓" : "✗"}</span>
          The answering node reports this block <strong>{block.finality}</strong>.
          {!block.finalized && " Not finalized, so it is reorganisable by the ordinary rules."}
        </li>
        <li className={agreed ? "yes" : "no"}>
          <span className="mark">{agreed ? "✓" : "✗"}</span>
          {agreed
            ? "Both archivals name the same block for this slot."
            : agreement?.kind === "single"
              ? "Only one archival answered — no cross-check happened."
              : agreement?.kind === "disagree"
                ? "The two archivals do not agree."
                : "No archival answered the cross-check."}{" "}
          Published guidance is two independent nodes concurring on root <em>and</em> epoch.
        </li>
        <li className={margin ? "yes" : "no"}>
          <span className="mark">{margin ? "✓" : "✗"}</span>
          {epochsPast === null
            ? "Depth past finality unknown — the head did not answer."
            : `This block is ${fmtInt(Math.max(0, epochsPast))} ${Math.abs(epochsPast) === 1 ? "epoch" : "epochs"} behind the head.`}{" "}
          Current guidance asks for a margin of <strong>finalized + 3 epochs</strong>, because the
          margin is the only thing that absorbs a finality rewind.
        </li>
      </ul>

      <p className="g4-note">
        <strong>No depth is provably safe on this chain.</strong> The finalized checkpoint is not
        a latch across a reorg, and the quorum denominator that "two thirds" is measured against
        shrinks with no floor — the leak accumulator has one write path and never decays, so once
        enough stake has been written off, a shrinking handful of validators hold two thirds of
        what remains. On 2026-08-24 three nodes finalised the same epoch under three different
        roots. The two mitigations for this are compiled in and both are inert behind an
        activation constant. Treat everything above as evidence, not as settlement.
      </p>
    </section>
  );
}

type View =
  | { kind: "loading" }
  | { kind: "block"; block: G4Block }
  | { kind: "empty"; slot: number }
  | { kind: "unknown"; slot: number; why: string }
  | { kind: "nosuchid"; id: string };

export function G4BlockPage({ slot, blockId }: { slot?: number; blockId?: string }) {
  const [view, setView] = useState<View>({ kind: "loading" });
  const [agreement, setAgreement] = useState<Agreement<G4Block> | null>(null);
  const [headEpoch, setHeadEpoch] = useState<number | null>(null);
  const [seen, setSeen] = useState<Sighting[]>([]);

  useEffect(() => {
    let stop = false;
    setView({ kind: "loading" });
    setAgreement(null);

    (async () => {
      if (blockId !== undefined) {
        // By id. This path is what makes a non-canonical block reachable at
        // all: `getblockbyid` serves blocks fork choice did not select, and
        // `getblockbyslot` by construction cannot — it resolves through the
        // canonical chain and answers SLOT_EMPTY for everything else.
        try {
          const b = await read<G4Block>("getblockbyid", [blockId]);
          if (!stop) setView({ kind: "block", block: b });
        } catch (e) {
          if (stop) return;
          if (e instanceof RpcRefusal && e.code === CODE.BLOCK_NOT_FOUND) {
            setView({ kind: "nosuchid", id: blockId });
          } else {
            setView({ kind: "unknown", slot: -1, why: e instanceof Error ? e.message : String(e) });
          }
        }
        return;
      }

      const cell: SlotCell = await slotCell(slot!);
      if (stop) return;
      if (cell.kind === "block") setView({ kind: "block", block: cell.block });
      else if (cell.kind === "empty") setView({ kind: "empty", slot: cell.slot });
      else setView({ kind: "unknown", slot: cell.slot, why: cell.why });
    })();

    return () => {
      stop = true;
    };
  }, [slot, blockId]);

  // The cross-check and the head are secondary: they refine the verdict, and
  // neither should hold up the page or blank it on failure.
  useEffect(() => {
    if (view.kind !== "block") return;
    let stop = false;
    const s = view.block.slot;
    setSeen(sightings(s));
    slotAgreement(s).then((a) => !stop && setAgreement(a));
    read<{ epoch: number }>("getchaininfo")
      .then((h) => !stop && setHeadEpoch(h.epoch))
      .catch(() => {});
    return () => {
      stop = true;
    };
  }, [view]);

  if (view.kind === "loading") return <Loading label="Reading the block…" />;

  if (view.kind === "empty") return <EmptySlot slot={view.slot} />;
  if (view.kind === "unknown") return <UnreadSlot slot={view.slot} why={view.why} />;
  if (view.kind === "nosuchid") return <NoSuchId id={view.id} />;

  const b = view.block;
  const orphan = b.finality === NOT_CANONICAL;
  return <BlockBody b={b} orphan={orphan} agreement={agreement} headEpoch={headEpoch} seen={seen} />;
}

/**
 * A slot the proposer missed.
 *
 * Data, not an error — and by far the most common non-block answer this
 * explorer gives, at 38.2% of all slots. Its own component because it is a
 * substantive page in its own right, not a failure branch: it is what a reader
 * following a link to a slot number legitimately arrives at, one time in three.
 */
export function EmptySlot({ slot }: { slot: number }) {
  return (
    <div className="container">
      <h1 className="page-title">Slot {fmtInt(slot)}</h1>
      <div className="card">
        <p className="page-lede">
          <strong>No block here.</strong> The validator scheduled to propose at this slot did
          not deliver one in time. This is a normal state, not a failure of the chain and not an
          error in this lookup — 38.3% of every slot on Genesis-4 is empty, and there is a
          stretch of roughly 15,000 consecutive slots where the chain barely produced at all.
        </p>
        <p className="lookup-hint">
          A miss costs that validator its reward for the slot and nothing else. The chain
          carries on: the next block's parent is the last block that <em>did</em> arrive, so
          height does not advance across a miss — which is why slot and height are{" "}
          {fmtInt(20895)}-odd apart today and why there is no lookup by height.
        </p>
        <p className="lookup-hint">
          <Link to={`/slot/${slot - 1}`}>← slot {fmtInt(slot - 1)}</Link>
          {"  ·  "}
          <Link to={`/slot/${slot + 1}`}>slot {fmtInt(slot + 1)} →</Link>
          {"  ·  "}
          <Link to={`/blocks/${slot + 16}`}>this range</Link>
        </p>
      </div>
    </div>
  );
}

/**
 * We could not find out what is at this slot.
 *
 * Kept rigorously distinct from `EmptySlot`. The cheap thing is to render a
 * failed read as "no block here", and that invents a missed proposal and
 * attributes it to a named validator who may well have proposed.
 */
export function UnreadSlot({ slot, why }: { slot: number; why: string }) {
  return (
    <div className="container">
      <h1 className="page-title">{slot >= 0 ? `Slot ${fmtInt(slot)}` : "Block"}</h1>
      <div className="errbox">
        <strong>Could not read this slot.</strong> {why}
        <div style={{ marginTop: 8, fontSize: 12.5 }}>
          This is not the same as "no block here". The archivals did not answer, so we do not
          know what is at this slot — it may well hold a block. Reload to try again.
        </div>
      </div>
    </div>
  );
}

/** A block id nobody holds — very often a `tx_hash` in disguise. */
export function NoSuchId({ id }: { id: string }) {
  return (
    <div className="container">
      <h1 className="page-title">No block with that id</h1>
      <div className="card">
        <p className="page-lede">
          The archivals hold no block, canonical or otherwise, with id{" "}
          <code>{id.slice(0, 24)}…</code>.
        </p>
        <p className="lookup-hint">
          If this came out of <code>sendrawtransaction</code>, it is not a block id at all —
          see <Link to={`/tx/${id}`}>what a transaction hash means here</Link>. If it is a
          block id you saw earlier, note that orphaned blocks are held in memory only and are
          dropped when a node restarts, so a block fork choice rejected can stop being
          retrievable.
        </p>
      </div>
    </div>
  );
}

/** The block itself. Exported so it can be rendered against real data. */
export function BlockBody({
  b,
  orphan,
  agreement,
  headEpoch,
  seen,
}: {
  b: G4Block;
  orphan: boolean;
  agreement: Agreement<G4Block> | null;
  headEpoch: number | null;
  seen: Sighting[];
}) {
  return (
    <div className="container">
      <h1 className="page-title">
        {orphan ? "Orphaned block" : `Slot ${fmtInt(b.slot)}`} <FinalityBadge block={b} />
      </h1>

      {orphan && (
        <div className="errbox warn">
          <strong>Fork choice did not select this block.</strong> It was proposed for slot{" "}
          {fmtInt(b.slot)} and the node still holds it, but it is not on the canonical chain, so
          it has no height and nothing in it counts. Whatever <em>is</em> canonical at that slot
          is at <Link to={`/slot/${b.slot}`}>slot {fmtInt(b.slot)}</Link>.
        </div>
      )}

      <p className="page-lede">
        Proposed by validator {b.proposer_index} in epoch {fmtInt(b.epoch)},{" "}
        {timeAgo(b.timestamp)} ({fmtTime(b.timestamp)}). Carrying {fmtInt(b.tx_count)}{" "}
        {b.tx_count === 1 ? "transaction" : "transactions"} and {fmtInt(b.attestation_count)}{" "}
        {b.attestation_count === 1 ? "attestation" : "attestations"}.{" "}
        {b.finalized
          ? "It is finalized: two thirds of the CONSENSUS stake — the post-leak roster, not the larger bonded total — voted for a checkpoint above it. That is the chain's claim, not a proof; see the finality page for what it does and does not rule out."
          : `The chain calls it ${b.finality}; it is not finalized yet.`}
      </p>

      <div className="g4-grid card" style={{ marginBottom: 14 }}>
        <div className="g4-stat">
          <span className="g4-k">Height</span>
          <span className="g4-v">
            {b.height === null ? <span className="faint">none</span> : fmtInt(b.height)}
          </span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Slot</span>
          <span className="g4-v">{fmtInt(b.slot)}</span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Epoch</span>
          <span className="g4-v">
            {fmtInt(b.epoch)}
            <span className="g4-dim"> · slot {b.slot % 32}/32</span>
          </span>
        </div>
        <div className="g4-stat">
          <span className="g4-k">Proposer</span>
          <span className="g4-v">
            <Link to={`/validators#v${b.proposer_index}`}>v{b.proposer_index}</Link>
          </span>
        </div>
      </div>

      <FinalityTruth block={b} agreement={agreement} headEpoch={headEpoch} />

      <Sightings seen={seen} />

      <section className="card">
        <h2 className="snap-h2">Transactions</h2>
        <p className="page-lede">
          This block carries <strong>{fmtInt(b.tx_count)}</strong>{" "}
          {b.tx_count === 1 ? "transaction" : "transactions"}. That count is all there is — the
          node exposes no transaction list for a block, and a Genesis-4 transaction has no id to
          list it under. To follow value, read the eUTXO set directly with{" "}
          <Link to="/balance">a balance lookup</Link>, which is exact.{" "}
          <Link to="/tx">Why there are no transaction ids</Link>.
        </p>
      </section>

      <section className="card">
        <h2 className="snap-h2">What the header commits</h2>
        <Row label="Block id" value={b.block_id} hint="The hash the network signed over." />
        <Row label="Parent" value={b.parent} hint="The block this one builds on." />
        <Row label="State root" value={b.state_root} hint="Commitment to the whole ledger after this block." />
        <Row label="Body root" value={b.body_root} />
        <Row label="Attestation root" value={b.attestation_root} />
        <Row label="Coherence root" value={b.coherence_root} />
        <Row label="RANDAO reveal" value={b.randao_reveal} hint="This proposer's contribution to the beacon." />
        <Row label="RANDAO mix" value={b.randao_mix} hint="The accumulated beacon after mixing the reveal in." />
        <Row label="Justified root" value={b.justified_root} hint="The checkpoint this block's view had justified." />
        <Row
          label="Finalized root"
          value={b.finalized_root}
          hint="The checkpoint this block's view had finalized. A later block may carry an older one — that is the rewind."
        />
      </section>

      <p className="lookup-hint" style={{ marginTop: 14 }}>
        <Link to={`/slot/${b.slot - 1}`}>← slot {fmtInt(b.slot - 1)}</Link>
        {"  ·  "}
        <Link to={`/block/${b.parent}`}>parent block</Link>
        {"  ·  "}
        <Link to={`/slot/${b.slot + 1}`}>slot {fmtInt(b.slot + 1)} →</Link>
        {"  ·  "}
        <Link to={`/blocks/${b.slot + 16}`}>this range</Link>
        {"  ·  "}
        <Link to="/blocks">all blocks</Link>
      </p>
      <p className="lookup-hint faint">
        Epoch {fmtInt(epochOf(b.slot))} covers slots {fmtInt(epochOf(b.slot) * 32)}–
        {fmtInt(epochOf(b.slot) * 32 + 31)}.
      </p>
    </div>
  );
}
