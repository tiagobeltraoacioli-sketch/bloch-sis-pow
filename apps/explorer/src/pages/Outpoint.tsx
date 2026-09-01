// SPDX-License-Identifier: AGPL-3.0-or-later
//
// One outpoint — the honest replacement for a transaction page.
//
// A Bitcoin explorer is organised around transaction ids. Genesis-4 has none:
// `gettransaction` is refused by the node in so many words ("at Genesis-4's
// current layer a transaction carries no id … This is a permanent answer for
// this build, not a transient failure — do not retry"), because
// `PosTransaction::Transfer` encodes only fee-market terms and the block store
// keeps no txid index.
//
// What the chain does have is outpoints: a 32-byte reference plus an output
// index, which `getutxos` returns and `gettxout` answers questions about. So
// the permalink is `/outpoint/<32-byte-ref>/<index>` and the page is titled
// for an outpoint, because calling it `/tx/<id>` would be a promise the chain
// cannot keep — and would invite exactly the mistake below.
//
// ── The trap this page exists to spell out ──────────────────────────────────
//
// `sendrawtransaction` returns a node-local `tx_hash`. Other nodes do not
// agree on it. Feeding one to `gettxout` returns a well-formed
// `{unspent: false, utxo: null}` — which is byte-identical to the answer for
// an outpoint that was created and then spent. A withdrawal that landed
// perfectly and a withdrawal that vanished look the same. This page therefore
// never renders `unspent: false` as "spent"; it renders it as "this node has
// no such unspent output", and lists the reasons, because they are not the
// same statement.
import { useEffect, useState } from "react";
import { g4rpc, G4Head, G4TxOut, G4_RPC } from "../lib/g4";
import { indexerHealth, indexedOutpoint, IndexedOutpoint, IndexerHealth } from "../lib/indexer";
import { fmtBloch, fmtInt, toSats } from "../lib/format";
import { Link } from "../lib/router";
import { Loading } from "../components/ui";

export function OutpointPage({ txid, vout }: { txid: string; vout: number }) {
  const [d, setD] = useState<{ out: G4TxOut; head: G4Head; endpoint: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [idx, setIdx] = useState<IndexerHealth | null | undefined>(undefined);
  const [indexed, setIndexed] = useState<IndexedOutpoint | null>(null);

  const wellFormed = /^[0-9a-f]{64}$/.test(txid) && Number.isInteger(vout) && vout >= 0;

  useEffect(() => {
    if (!wellFormed) return;
    let stop = false;
    setD(null);
    setErr(null);
    setIndexed(null);
    (async () => {
      const head = await g4rpc<G4Head>("getchaininfo");
      const out = await g4rpc<G4TxOut>("gettxout", [txid, vout]);
      return { head, out, endpoint: G4_RPC };
    })()
      .then((r) => !stop && setD(r))
      .catch((e) => !stop && setErr(String(e?.message ?? e)));

    indexerHealth().then((h) => {
      if (stop) return;
      setIdx(h);
      if (h) indexedOutpoint(txid, vout).then((o) => !stop && setIndexed(o)).catch(() => {});
    });
    return () => {
      stop = true;
    };
  }, [txid, vout, wellFormed]);

  if (!wellFormed) {
    return (
      <div className="container">
        <h1 className="page-title">Not an outpoint</h1>
        <div className="err-box">
          An outpoint is a 64-character hex reference and a non-negative output index. Got{" "}
          <code>
            {txid}:{String(vout)}
          </code>
          .
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <h1 className="page-title">Outpoint</h1>
      <p className="page-lede">
        <code>
          {txid}:{vout}
        </code>
        <br />
        Not a transaction page — Genesis-4 has no transaction ids, so there is nothing to
        put on one. This is the output itself: a value, an owner, and whether it is still
        unspent.
      </p>

      {err && <div className="err-box">{err}</div>}
      {!d && !err && <Loading label="Asking the archival…" />}

      {d && (
        <>
          <div className="g4-grid card" style={{ marginBottom: 14 }}>
            <div className="g4-stat">
              <span className="g4-k">Value</span>
              <span className="g4-v">
                {d.out.utxo ? `${fmtBloch(toSats(d.out.utxo.value_sat), 8)} BLOCH` : "—"}
              </span>
            </div>
            <div className="g4-stat">
              <span className="g4-k">Unspent</span>
              <span className="g4-v">{d.out.unspent ? "yes" : "no"}</span>
            </div>
            <div className="g4-stat">
              <span className="g4-k">Answered at slot</span>
              <span className="g4-v">{fmtInt(d.out.at_slot)}</span>
            </div>
            <div className="g4-stat">
              <span className="g4-k">Finalized to</span>
              <span className="g4-v">{fmtInt(d.head.finalized_height)}</span>
            </div>
          </div>

          {d.out.utxo && (
            <section className="card">
              <h2 className="snap-h2">Owner</h2>
              <div className="bal-meta">
                <span className="g4-k">Script hash</span>
                <code className="bal-hash">
                  <Link className="mono-link" to={`/hash/${d.out.utxo.script_hash}`}>
                    {d.out.utxo.script_hash}
                  </Link>
                </code>
              </div>
              <p className="lookup-hint">
                {fmtInt(d.out.utxo.value_sat)} sat. Whoever can open this hash can spend
                this output — see the entry page for the second hash the same key may also
                open.
              </p>
            </section>
          )}

          <AtSlot out={d.out} head={d.head} endpoint={d.endpoint} indexed={indexed} />
          {!d.out.unspent && <NotUnspent indexed={indexed} idx={idx} />}
          <Settlement head={d.head} out={d.out} indexed={indexed} />
        </>
      )}
    </div>
  );
}

/**
 * `at_slot` is the head, not the birthday.
 *
 * `txout_json` emits `("at_slot", Json::u(state.slot()))` on BOTH branches —
 * found and not-found. It is the point on the chain the node answered from, so
 * that the answer can be pinned; it is not the slot the output landed in, and
 * an integrator who reads it as one dates every deposit to whenever they
 * happened to ask. Measured 2026-09-01: an output created long before returned
 * `at_slot: 54570`, the head at the moment of the call.
 */
function AtSlot({
  out,
  head,
  endpoint,
  indexed,
}: {
  out: G4TxOut;
  head: G4Head;
  endpoint: string;
  indexed: IndexedOutpoint | null;
}) {
  return (
    <section className="card">
      <h2 className="snap-h2">When</h2>
      <div className="snap-digest">
        <span className="g4-k">Created in slot</span>
        <div className="bal-count">
          {indexed ? (
            <Link to={`/slot/${indexed.created_slot}`}>{fmtInt(indexed.created_slot)}</Link>
          ) : (
            "not available"
          )}
        </div>
      </div>
      <div className="snap-digest">
        <span className="g4-k">Spent in slot</span>
        <div className="bal-count">
          {indexed
            ? indexed.spent_slot != null
              ? <Link to={`/slot/${indexed.spent_slot}`}>{fmtInt(indexed.spent_slot)}</Link>
              : "still unspent"
            : "not available"}
        </div>
      </div>
      <p className="lookup-hint">
        <strong>
          <code>at_slot</code> ({fmtInt(out.at_slot)}) is not when this output was created.
        </strong>{" "}
        It is the head slot <code>{endpoint}</code> answered from — the node emits it on
        both the found and the not-found branch, so the answer can be pinned to a point on
        the chain. <code>getutxos</code> carries no slot at all.{" "}
        {indexed
          ? "The creation and spend slots above come from the indexer, which watches blocks go by; the node cannot supply them."
          : "So until the indexer is deployed, the slot an output landed in exists nowhere on this RPC, and this page says 'not available' rather than showing you a number that means something else."}{" "}
        The chain head at the time of this read was slot {fmtInt(head.slot)}, height{" "}
        {fmtInt(head.height)}.
      </p>
    </section>
  );
}

/** Why `unspent: false` is three different situations wearing one answer. */
function NotUnspent({
  indexed,
  idx,
}: {
  indexed: IndexedOutpoint | null;
  idx: IndexerHealth | null | undefined;
}) {
  if (indexed) {
    return (
      <section className="card">
        <h2 className="snap-h2">Why it is not unspent</h2>
        <p className="lookup-hint">
          The indexer has it: created in slot {fmtInt(indexed.created_slot)}
          {indexed.spent_slot != null
            ? `, spent in slot ${fmtInt(indexed.spent_slot)}.`
            : ", and it has no spend recorded — which disagrees with the node and is worth reporting."}
        </p>
      </section>
    );
  }
  return (
    <section className="card">
      <h2 className="snap-h2">Why it is not unspent</h2>
      <div className="warn-box">
        <span className="warn-ico">!</span>
        <div>
          The node said <code>unspent: false</code>, and on its own that sentence is
          ambiguous. It is the identical answer for all three of:
          <ul>
            <li>an output that existed and has since been spent;</li>
            <li>an output that never existed — a reference this chain has never seen;</li>
            <li>
              a lookup made with a node-local <code>tx_hash</code> from{" "}
              <code>sendrawtransaction</code>, which other nodes do not agree on. That is the
              dangerous one: a withdrawal that settled perfectly and one that vanished both
              land here.
            </li>
          </ul>
          {idx === null
            ? "Distinguishing them needs a spend index, and no indexer is reachable. Do not read this page as 'spent'."
            : "Distinguishing them needs the indexer's spend record; it did not answer for this outpoint."}
        </div>
      </div>
    </section>
  );
}

/**
 * The settlement judgement, stated correctly.
 *
 * Two partner documents told integrators that `gettxout` returns a `finalized`
 * field and to settle on it. It does not: the response is
 * `{txid, vout, unspent, utxo, at_slot}`, five fields, and none of them is
 * finality. Finality is a property of the chain, read from `getchaininfo`.
 */
function Settlement({
  head,
  out,
  indexed,
}: {
  head: G4Head;
  out: G4TxOut;
  indexed: IndexedOutpoint | null;
}) {
  const final =
    indexed != null && indexed.created_height <= head.finalized_height && out.unspent;
  return (
    <section className="card">
      <h2 className="snap-h2">Is it settled?</h2>
      <div className="warn-box">
        <span className="warn-ico">!</span>
        <div>
          <code>gettxout</code> has <strong>no <code>finalized</code> field</strong>. It
          returns exactly <code>txid</code>, <code>vout</code>, <code>unspent</code>,{" "}
          <code>utxo</code> and <code>at_slot</code>. Integration notes that told partners
          to read a <code>finalized</code> flag off this call were describing a field that
          has never existed, and a client keying settlement on{" "}
          <code>result.finalized</code> reads <code>undefined</code> — falsy — and settles
          nothing, or worse, coerces it and settles everything.
        </div>
      </div>
      <p className="lookup-hint">
        The judgement is made against the chain, not against the output: an output is
        settled when the block that created it is at or below the finalized height, and it
        is still unspent. Right now the chain is finalized to height{" "}
        {fmtInt(head.finalized_height)} (epoch {fmtInt(head.finalized.epoch)}), at head
        height {fmtInt(head.height)}.{" "}
        {indexed
          ? final
            ? `This output was created at height ${fmtInt(indexed.created_height)}, which is final, and it is unspent. Settled.`
            : `This output was created at height ${fmtInt(indexed.created_height)}; ${
                indexed.created_height > head.finalized_height
                  ? "that is above the finalized height, so it is not settled yet."
                  : "it is no longer unspent, so there is nothing to settle."
              }`
          : "The creating height is what the node cannot tell you, so this page cannot complete the judgement for you — that is the second thing the indexer is for."}
      </p>
    </section>
  );
}
