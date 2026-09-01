// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The slot table — one row per slot, whatever that slot turned out to be.
//
// Shared by the dashboard's recent-blocks stream and by the /blocks range
// browser, so that a slot looks the same wherever a reader meets it.
//
// The rule this component enforces, and the reason it is a component rather
// than a loop in each page: **a slot has three states, not two.** It holds a
// block, or the chain told us it holds nothing, or we could not find out. The
// third is not a rendering edge case — measured against the live archivals,
// roughly one read in twenty times out, and every one of those would otherwise
// be drawn as a missed proposal against a named validator who in fact
// proposed. Three states, three visibly different rows.

import { SlotCell, reorgSeen, finalityWithdrawn } from "../lib/source";
import { G4Block, NOT_CANONICAL } from "../lib/g4";
import { fmtInt, timeAgo, short } from "../lib/format";
import { Link } from "../lib/router";

/**
 * How the chain currently regards a block, as a badge.
 *
 * Never rendered as a settled fact, and the wording is deliberate. On this
 * chain the finalized checkpoint is not a latch across a reorg — a block
 * returned as `finalized: true` can later come back `justified` or
 * `canonical`, and `finalized_height` can move down. So the badge reports a
 * reading, the tooltip says as of when, and no badge anywhere in this
 * explorer says "settled", "confirmed" or "irreversible".
 */
export function FinalityBadge({ block }: { block: G4Block }) {
  const f = block.finality;
  if (f === NOT_CANONICAL) {
    return (
      <span className="pill bad" title="This block exists but fork choice did not select it.">
        not canonical
      </span>
    );
  }
  if (f === "finalized") {
    return (
      <span
        className="pill ok"
        title="Reported finalized by the node that answered. Not a latch: a reorg can install an ancestor's state whose finalized checkpoint is older, and this can revert to justified or canonical."
      >
        finalized
      </span>
    );
  }
  if (f === "justified") {
    return (
      <span className="pill warn" title="Attested by a supermajority, one step short of finalized. Reorganisable.">
        justified
      </span>
    );
  }
  return (
    <span className="pill quiet" title="On the canonical chain, not yet justified. Freely reorganisable.">
      {f}
    </span>
  );
}

/** One slot. Blocks, misses and gaps in our knowledge are visibly different. */
export function SlotRow({ cell }: { cell: SlotCell }) {
  if (cell.kind === "empty") {
    return (
      <tr className="row-missed">
        <td className="num">
          <Link to={`/slot/${cell.slot}`}>{fmtInt(cell.slot)}</Link>
        </td>
        <td className="num faint">—</td>
        <td className="faint" colSpan={4}>
          no block — the proposer for this slot missed it
        </td>
        <td>
          <span className="pill quiet">missed</span>
        </td>
      </tr>
    );
  }

  if (cell.kind === "unknown") {
    // Emphatically not "missed". We do not know, and saying so is the whole
    // job of this row.
    return (
      <tr className="row-unknown">
        <td className="num">
          <Link to={`/slot/${cell.slot}`}>{fmtInt(cell.slot)}</Link>
        </td>
        <td className="num faint">?</td>
        <td className="faint" colSpan={4}>
          not read — {cell.why}. This says nothing about whether a block exists here.
        </td>
        <td>
          <span className="pill unknown">unread</span>
        </td>
      </tr>
    );
  }

  const b = cell.block;
  const changed = reorgSeen(cell.slot);
  const withdrawn = finalityWithdrawn(cell.slot);
  return (
    <tr>
      <td className="num">
        <Link to={`/slot/${b.slot}`}>{fmtInt(b.slot)}</Link>
        {changed && (
          <span
            className="reorg-flag"
            title="This browser has seen more than one block id at this slot — a reorg, observed first-hand."
          >
            ⟲
          </span>
        )}
        {withdrawn && (
          <span
            className="reorg-flag danger"
            title="This slot was seen finalized and later reported as something else."
          >
            !
          </span>
        )}
      </td>
      <td className="num">
        <Link to={`/validators#v${b.proposer_index}`}>v{b.proposer_index}</Link>
      </td>
      <td>
        <Link to={`/slot/${b.slot}`} className="mono-link">
          <code>{short(b.block_id, 10, 6)}</code>
        </Link>
      </td>
      <td className="num">{b.height === null ? "—" : fmtInt(b.height)}</td>
      <td className="num">{fmtInt(b.tx_count)}</td>
      <td className="num">{fmtInt(b.attestation_count)}</td>
      <td>
        <FinalityBadge block={b} />
        <span className="faint age"> {timeAgo(b.timestamp)}</span>
      </td>
    </tr>
  );
}

/** The table itself, header included, so both callers agree on the columns. */
export function SlotTable({ cells }: { cells: SlotCell[] }) {
  return (
    <div className="table-wrap">
      <table className="tbl">
        <thead>
          <tr>
            <th className="num">Slot</th>
            <th className="num">Proposer</th>
            <th>Block</th>
            <th className="num">Height</th>
            <th className="num">Txs</th>
            <th className="num">Att.</th>
            <th>State</th>
          </tr>
        </thead>
        <tbody>
          {cells.map((c) => (
            <SlotRow key={c.slot} cell={c} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Counts for a run of slots — the honest three-way split, not a percentage. */
export function SlotTally({ cells }: { cells: SlotCell[] }) {
  const blocks = cells.filter((c) => c.kind === "block").length;
  const empty = cells.filter((c) => c.kind === "empty").length;
  const unread = cells.filter((c) => c.kind === "unknown").length;
  return (
    <p className="lookup-hint">
      {fmtInt(blocks)} {blocks === 1 ? "block" : "blocks"}, {fmtInt(empty)} missed
      {unread > 0 && (
        <>
          , <strong>{fmtInt(unread)} unread</strong>
        </>
      )}{" "}
      across {fmtInt(cells.length)} slots.
      {unread > 0 &&
        " Unread slots are ones the archivals did not answer for; they are not counted as missed, because we do not know that they were."}
    </p>
  );
}
