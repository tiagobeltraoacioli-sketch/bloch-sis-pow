// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Blocks, by slot.
//
// A page of slots rather than a page of blocks, and that is the substantive
// choice here. Every explorer anyone has used lists *blocks*, consecutively,
// because on a proof-of-work chain a block is produced for every step of the
// chain and the two lists are the same list. Under proof of stake they are
// not: a slot is a scheduled opportunity, and on this chain 38.3% of those
// opportunities produced nothing — 20,895 empty slots out of 54,585 at the
// time of writing.
//
// Listing only the blocks would hide every one of those. The misses are not
// noise; they are the single clearest picture of the network's health this
// explorer can show, and there is a stretch of roughly 15,000 consecutive
// slots (about slots 18,500–33,500) where the chain barely produced at all. A
// block-only list renders that catastrophe as an unremarkable run of blocks.
// So the unit of this page is the slot, and an empty one gets a row.

import { useCallback, useEffect, useState } from "react";
import { SlotCell, slotRange, clearSlotCache, headAgreement, Agreement } from "../lib/source";
import { G4Head } from "../lib/g4";
import { SlotTable, SlotTally } from "../components/blockstream";
import { fmtInt } from "../lib/format";
import { Link, useRouter } from "../lib/router";
import { Loading } from "../components/ui";
import { epochOf } from "../lib/query";

/**
 * Slots per page.
 *
 * One epoch's worth, so a page boundary is a meaningful boundary rather than
 * an arbitrary one — finality moves at epoch granularity, and a reader
 * checking "did this epoch finalize" wants its slots together. It is also
 * about as many cold historical lookups (1–3 s each, six at a time) as is
 * decent to ask of the archivals for one screen.
 */
const PAGE = 32;

export function G4BlocksPage({ from }: { from?: number }) {
  const { navigate } = useRouter();
  const [head, setHead] = useState<G4Head | null>(null);
  const [headState, setHeadState] = useState<Agreement<G4Head> | null>(null);
  const [cells, setCells] = useState<SlotCell[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Where the page starts. Explicit in the URL when the reader navigated to a
  // range; otherwise the head, resolved once.
  const [top, setTop] = useState<number | null>(from ?? null);

  useEffect(() => {
    let stop = false;
    headAgreement().then((a) => {
      if (stop) return;
      setHeadState(a);
      const h = a.kind === "agree" ? a.value : a.kind === "single" ? a.value : a.kind === "disagree" ? a.a : null;
      if (h) {
        setHead(h);
        setTop((t) => (t === null ? h.slot : t));
      } else {
        setErr("No archival answered.");
      }
    });
    return () => {
      stop = true;
    };
  }, []);

  const load = useCallback(
    (topSlot: number) => {
      const ac = new AbortController();
      setBusy(true);
      setErr(null);
      slotRange(Math.max(0, topSlot - PAGE + 1), topSlot, ac.signal)
        .then((cs) => {
          setCells(cs);
          setBusy(false);
        })
        .catch((e) => {
          setErr(String(e?.message ?? e));
          setBusy(false);
        });
      return () => ac.abort();
    },
    [],
  );

  useEffect(() => {
    if (top === null) return;
    return load(top);
  }, [top, load]);

  const goto = (t: number) => {
    const clamped = Math.max(PAGE - 1, t);
    setTop(clamped);
    navigate(`/blocks/${clamped}`);
  };

  if (err && !cells) {
    return (
      <div className="container">
        <h1 className="page-title">Blocks</h1>
        <div className="errbox">{err}</div>
      </div>
    );
  }
  if (top === null || !cells) return <Loading label="Reading slots…" />;

  const bottom = Math.max(0, top - PAGE + 1);
  const atHead = head !== null && top >= head.slot;

  return (
    <div className="container">
      <h1 className="page-title">Blocks, by slot</h1>
      <p className="page-lede">
        Slots {fmtInt(bottom)}–{fmtInt(top)}, newest first — epoch{" "}
        {fmtInt(epochOf(bottom))}
        {epochOf(bottom) !== epochOf(top) ? `–${fmtInt(epochOf(top))}` : ""}. Every slot gets a
        row, including the ones that produced nothing: a slot is a scheduled
        opportunity to propose, and on this chain about{" "}
        {head ? ((1 - head.height / Math.max(1, head.slot)) * 100).toFixed(1) : "38"}% of them
        have gone unused. Height and slot are different numbers and diverge by exactly that
        much — there is no lookup by height on this chain, so if you have one,{" "}
        <Link to="/">use the search box</Link>, which searches for it.
      </p>

      {headState?.kind === "disagree" && (
        <div className="errbox warn">
          <strong>The two archivals disagree about the finalized checkpoint.</strong> One reports
          epoch {fmtInt(headState.a.finalized.epoch)} at root{" "}
          <code>{headState.a.finalized.root.slice(0, 16)}</code>, the other epoch{" "}
          {fmtInt(headState.b.finalized.epoch)} at root{" "}
          <code>{headState.b.finalized.root.slice(0, 16)}</code>. Published guidance is to treat
          disagreement as a hold condition, not a retry — nothing on this page should be read as
          settled while it stands.
        </div>
      )}
      {headState?.kind === "single" && (
        <div className="errbox warn">
          <strong>Nothing here has been cross-checked</strong> — {headState.why || "only one archival answered"}.
          Two independent nodes agreeing on root <em>and</em> epoch is the published bar for
          treating a finality reading as durable, and it has not been met for this page.
        </div>
      )}

      <div className="card">
        <div className="range-bar">
          <button className="pill-tab" onClick={() => goto(top + PAGE)} disabled={busy || atHead}>
            ← newer
          </button>
          <button
            className="pill-tab"
            onClick={() => head && goto(head.slot)}
            disabled={busy || !head || atHead}
          >
            head
          </button>
          <span className="range-label">
            slot {fmtInt(bottom)} – {fmtInt(top)}
          </span>
          <button className="pill-tab" onClick={() => goto(top - PAGE)} disabled={busy || bottom <= 0}>
            older →
          </button>
          <button
            className="pill-tab go"
            onClick={() => {
              clearSlotCache();
              load(top);
            }}
            disabled={busy}
            title="Discard cached slot readings and read them again. Finality verdicts change; cached ones go stale."
          >
            {busy ? "…" : "re-read"}
          </button>
        </div>

        <SlotTable cells={cells} />
        <SlotTally cells={cells} />
      </div>

      <p className="lookup-hint" style={{ marginTop: 14 }}>
        Jump to a slot:{" "}
        <input
          className="slot-jump"
          type="number"
          min={0}
          defaultValue={top}
          onKeyDown={(e) => {
            if (e.key !== "Enter") return;
            const v = Number((e.target as HTMLInputElement).value);
            if (Number.isSafeInteger(v) && v >= 0) goto(v);
          }}
          aria-label="Jump to slot"
        />{" "}
        then press Enter.
      </p>
    </div>
  );
}
