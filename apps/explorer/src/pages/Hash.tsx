// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The address page — for a chain whose addresses are not addresses.
//
// One entry in the eUTXO set, named by the only identifier Genesis-4 has: a
// 32-byte `script_hash`. The URL is always `/hash/<64 hex>`; every other form
// a person can paste redirects into it, so two people looking at "the same
// address" are provably looking at the same row.
//
// Three things this page refuses to do, each of which is a bug the project has
// already paid for once:
//
//  1. It does not convert an address into a Genesis-4 key's hash. It cannot —
//     `SHA3-256(pubkey)` is 32 bytes and an address carries 20 — so where an
//     address arrives it says which entry it named and which it did not.
//
//  2. It does not show one of the two entries a key can open and call it "the
//     balance". `owns()` matches a key against an output two ways, so a native
//     hash H and its truncated sibling H[0..20]‖0×12 are two rows with two
//     balances. Both are shown, and if the sibling holds anything, loudly.
//
//  3. It does not present a truncated UTXO list as a complete one. `getutxos`
//     has no cursor; when the set is larger than one page, the page says how
//     much of it you are not seeing and why.
import { useEffect, useState } from "react";
import {
  g4rpc,
  G4Balance,
  G4Head,
  G4Utxo,
  G4UtxoPage,
  G4_RPC,
  G4_UPSTREAM,
} from "../lib/g4";
import {
  Query,
  classify,
  isCarriedShape,
  shapeOf,
  siblingOf,
  outpointLink,
} from "../lib/scriptHash";
import { indexerHealth, indexedUtxos, IndexedUtxo, IndexerHealth } from "../lib/indexer";
import { fmtBloch, fmtInt, short, toSats } from "../lib/format";
import { Link, useRouter } from "../lib/router";
import { Loading } from "../components/ui";

/** How many outputs the first read asks for. The node's own default is 100. */
const FIRST_PAGE = 100;
/** `UTXO_PAGE_MAX` in `crates/bloch-pos-node/src/rpc.rs`. Server-side clamp. */
const NODE_PAGE_MAX = 1000;

interface Loaded {
  balance: G4Balance;
  /** null when there is no computable sibling (a carried hash). */
  sibling: G4Balance | null;
  head: G4Head;
  page: G4UtxoPage;
  endpoint: string;
}

type Row = { txid: string; vout: number; value_sat: string; created_slot?: number };

export function HashPage({ q }: { q: string }) {
  const { navigate } = useRouter();
  const parsed = classify(q);
  const [d, setD] = useState<Loaded | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [idx, setIdx] = useState<IndexerHealth | null | undefined>(undefined);
  const [rows, setRows] = useState<Row[] | null>(null);
  const [more, setMore] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const scriptHash =
    parsed.kind === "script_hash" ||
    parsed.kind === "g3_address" ||
    parsed.kind === "g3_hash160"
      ? parsed.scriptHash
      : null;

  // A Genesis-3 form in the URL is normalised to the canonical one, in place.
  // `replaceState`, not a push: the reader typed one thing and got one page,
  // and Back should leave the page, not un-normalise the URL.
  useEffect(() => {
    if (!scriptHash) return;
    const want = `/hash/${scriptHash}`;
    if (window.location.pathname !== want) window.history.replaceState({}, "", want);
  }, [scriptHash]);

  useEffect(() => {
    if (!scriptHash) return;
    let stop = false;
    setD(null);
    setErr(null);
    setRows(null);
    setMore(null);

    const sib = siblingOf(scriptHash);
    (async () => {
      // Head first, so "as of" is never later than the balance it labels.
      // Two calls means two reads of a moving chain; the page says so rather
      // than implying the node stamped the balance with a slot. It does not.
      const head = await g4rpc<G4Head>("getchaininfo");
      const balance = await g4rpc<G4Balance>("getbalance", [scriptHash]);
      const sibling = sib ? await g4rpc<G4Balance>("getbalance", [sib]) : null;
      const page = await g4rpc<G4UtxoPage>("getutxos", [scriptHash, FIRST_PAGE]);
      return { head, balance, sibling, page, endpoint: G4_UPSTREAM ?? G4_RPC };
    })()
      .then((r) => {
        if (stop) return;
        setD(r);
        setRows(r.page.utxos.map(toRow));
      })
      .catch((e) => !stop && setErr(String(e?.message ?? e)));

    indexerHealth().then((h) => !stop && setIdx(h));
    return () => {
      stop = true;
    };
  }, [scriptHash]);

  if (!scriptHash) return <Refused parsed={parsed} onRetry={(v) => navigate(`/hash/${v}`)} />;

  const shape = shapeOf(scriptHash);

  async function loadMore() {
    if (!scriptHash) return;
    setBusy(true);
    try {
      if (idx) {
        const p = await indexedUtxos(scriptHash, more, 500);
        setRows((prev) => [...(prev ?? []), ...p.utxos.map(toIndexedRow)]);
        setMore(p.next_cursor);
      } else {
        // No cursor exists on the node, so "more" can only mean "ask for the
        // biggest page it will serve" — once. Asking twice returns the same
        // rows, and appending them would invent duplicates.
        const p = await g4rpc<G4UtxoPage>("getutxos", [scriptHash, NODE_PAGE_MAX]);
        setRows(p.utxos.map(toRow));
        setD((prev) => (prev ? { ...prev, page: p } : prev));
      }
    } catch (e) {
      setErr(String((e as Error)?.message ?? e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="container">
      <h1 className="page-title">
        {shape === "carried" ? "Carried entry" : "Script hash"}{" "}
        <span className="badge">{shape}</span>
      </h1>
      <p className="page-lede">
        Genesis-4 has no addresses. It locks an output with 32 bytes — a{" "}
        <strong>script hash</strong> — and this page is one such entry in the
        unspent-output set.{" "}
        {shape === "carried" ? (
          <>
            Its last twelve bytes are zero, which is the shape the Genesis-3
            carryover wrote: a snapshot row's 20-byte hash160, transcribed into
            the 32-byte field once, at genesis. Nothing derived it from a key.
          </>
        ) : (
          <>
            All 32 bytes carry information, so this is a native key's hash —{" "}
            <code>SHA3-256(public key)</code>, which is what{" "}
            <code>bloch-pos spendkey</code> prints. There is no address form of
            it, and there is not meant to be.
          </>
        )}
      </p>

      <Provenance parsed={parsed} />

      <section className="card">
        <div className="bal-head">
          <div>
            <span className="g4-k">Balance</span>
            <div className="bal-value">
              {d ? fmtBloch(toSats(d.balance.balance_sat), 8) : "…"} BLOCH
            </div>
            {d && <div className="faint">{fmtInt(d.balance.balance_sat)} sat</div>}
          </div>
          <div className="bal-side">
            <span className="g4-k">Unspent outputs</span>
            <div className="bal-count">{d ? fmtInt(d.balance.utxo_count) : "…"}</div>
          </div>
        </div>
        <div className="bal-meta">
          <span className="g4-k">Script hash</span>
          <code className="bal-hash">{scriptHash}</code>
        </div>
        {d && (
          <p className="lookup-hint">
            Read from <code>{d.endpoint}</code>, an archival node, at head slot{" "}
            {fmtInt(d.head.slot)} (height {fmtInt(d.head.height)}, finalized to{" "}
            {fmtInt(d.head.finalized_height)}). The balance and that head are two separate
            calls against a chain that keeps moving — the node does not stamp a balance
            with the slot it was read at, so treat the slot as "no earlier than", not as
            an exact reading. Satoshis are the source of truth; the value is carried as a
            decimal string because it exceeds what a JavaScript number holds exactly.
          </p>
        )}
      </section>

      {err && <div className="err-box">{err}</div>}
      {!d && !err && <Loading label="Asking the archival…" />}

      {d && <Sibling scriptHash={scriptHash} d={d} />}

      {d && (
        <section className="card">
          <h2 className="snap-h2">Unspent outputs</h2>
          <Coverage d={d} rows={rows} idx={idx} />
          {rows && rows.length > 0 && (
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Outpoint</th>
                    <th style={{ textAlign: "right" }}>Value</th>
                    {idx && <th style={{ textAlign: "right" }}>Created</th>}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((u) => (
                    <tr key={`${u.txid}:${u.vout}`}>
                      <td>
                        <Link className="mono-link" to={outpointLink(u.txid, u.vout)}>
                          {short(u.txid, 10, 6)}:{u.vout}
                        </Link>
                      </td>
                      <td style={{ textAlign: "right" }}>
                        {fmtBloch(toSats(u.value_sat), 8)}
                      </td>
                      {idx && (
                        <td style={{ textAlign: "right" }}>
                          {u.created_slot != null ? (
                            <Link to={`/slot/${u.created_slot}`}>{fmtInt(u.created_slot)}</Link>
                          ) : (
                            "—"
                          )}
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {canLoadMore(d, rows, idx, more) && (
            <p className="lookup-hint">
              <button className="lookup-go" onClick={loadMore} disabled={busy}>
                {busy ? "Asking…" : idx ? "Next page" : `Ask for the node's maximum (${NODE_PAGE_MAX})`}
              </button>
            </p>
          )}
        </section>
      )}

      <History scriptHash={scriptHash} idx={idx} />
    </div>
  );
}

function toRow(u: G4Utxo): Row {
  return { txid: u.txid, vout: u.vout, value_sat: u.value_sat };
}
function toIndexedRow(u: IndexedUtxo): Row {
  return { txid: u.txid, vout: u.vout, value_sat: u.value_sat, created_slot: u.created_slot };
}

function canLoadMore(
  d: Loaded,
  rows: Row[] | null,
  idx: IndexerHealth | null | undefined,
  cursor: string | null,
): boolean {
  if (idx) return cursor !== null;
  // Without an indexer there is exactly one more thing to ask for: the node's
  // maximum page. Once we are holding it, there is nothing further to press.
  return d.page.truncated && (rows?.length ?? 0) < NODE_PAGE_MAX;
}

/**
 * How much of the set is on screen, said plainly.
 *
 * This is the paragraph the whole page is built around. `getutxos` takes a
 * limit and no cursor, so beyond `UTXO_PAGE_MAX` the remainder is not "on the
 * next page" — it is unreachable, and a pager that pretended otherwise would
 * be showing the same thousand rows under different page numbers.
 */
function Coverage({
  d,
  rows,
  idx,
}: {
  d: Loaded;
  rows: Row[] | null;
  idx: IndexerHealth | null | undefined;
}) {
  const have = rows?.length ?? 0;
  const total = d.balance.utxo_count;
  if (total === 0) return <p className="lookup-hint">This entry holds no unspent outputs.</p>;
  if (have >= total) {
    return (
      <p className="lookup-hint">
        All {fmtInt(total)} of them, as of head slot {fmtInt(d.head.slot)}.
      </p>
    );
  }
  if (idx) {
    return (
      <p className="lookup-hint">
        Showing {fmtInt(have)} of {fmtInt(total)}, paged through the indexer (indexed to slot{" "}
        {fmtInt(idx.indexed_to_slot)}, {fmtInt(idx.lag_slots)} behind the head).
      </p>
    );
  }
  return (
    <div className="warn-box">
      <span className="warn-ico">!</span>
      <div>
        Showing {fmtInt(have)} of {fmtInt(total)}. The remaining {fmtInt(total - have)}{" "}
        <strong>cannot be read from a node at all</strong>: <code>getutxos</code> takes a
        script hash and a limit, has no cursor and no offset, and the limit is clamped
        server-side to {fmtInt(NODE_PAGE_MAX)}. Asking again returns the same rows. This is
        not a loading state and pressing anything will not fix it — the missing outputs
        arrive when the indexer does. The <strong>balance and the count above are exact</strong>;
        it is only the enumeration that is capped.
      </div>
    </div>
  );
}

/**
 * The other entry the same key can open.
 *
 * `owns(key_hash, script_hash)` returns true when the two are equal OR when the
 * script hash's last twelve bytes are zero and the first twenty match. So one
 * key reaches two rows of the eUTXO set, and asking about one of them is the
 * question that returned 74,999,997,782 sat under one client and 0 under
 * another for a single funded key. Both are shown, always.
 */
function Sibling({ scriptHash, d }: { scriptHash: string; d: Loaded }) {
  if (isCarriedShape(scriptHash)) {
    return (
      <section className="card">
        <h2 className="snap-h2">Is there another entry for this owner?</h2>
        <p className="lookup-hint">
          Possibly, and this explorer cannot tell you. A carried entry is 20 bytes of a
          Genesis-3 hash160; the key behind it, if its holder has one on Genesis-4, owns a
          second entry at <code>SHA3-256(public key)</code> — all 32 bytes, a different row
          with a different balance. Twenty bytes cannot be turned back into thirty-two, so
          that hash is not derivable from anything on this page. Its holder can print it
          with <code>bloch-pos spendkey</code>; nobody else can compute it.
        </p>
      </section>
    );
  }

  const sib = siblingOf(scriptHash);
  if (!sib || !d.sibling) return null;
  const holds = toSats(d.sibling.balance_sat) > 0n;

  return (
    <section className="card">
      <h2 className="snap-h2">The other entry this key can open</h2>
      <p className="lookup-hint">
        Consensus's ownership rule (<code>transition.rs</code>, <code>owns</code>) matches a
        key against an output two ways: the hashes are equal, or the output's last twelve
        bytes are zero and the first twenty match. So whoever holds the key for the hash
        above also opens the truncated form of it below — a <em>different row</em> in the
        unspent-output set, with its own balance. Software that computes only one of the two
        reports the other one as zero and nothing anywhere errors.
      </p>
      <div className="bal-meta">
        <span className="g4-k">Truncated form</span>
        <code className="bal-hash">
          <Link className="mono-link" to={`/hash/${sib}`}>
            {sib}
          </Link>
        </code>
      </div>
      {holds ? (
        <div className="warn-box">
          <span className="warn-ico">!</span>
          <div>
            It holds {fmtBloch(toSats(d.sibling.balance_sat), 8)} BLOCH across{" "}
            {fmtInt(d.sibling.utxo_count)} outputs. Those coins are spendable by the same
            key and they are <strong>not</strong> in the balance at the top of this page.
            Anything totalling a position for this owner must add both.
          </div>
        </div>
      ) : (
        <p className="lookup-hint">It is empty — nothing was ever paid to the truncated form.</p>
      )}
    </section>
  );
}

/**
 * "Transaction history", and why this chain does not have one.
 *
 * Not a placeholder for a feature that is coming: a statement of what the
 * chain can and cannot say, which stays true after the indexer lands. The
 * indexer adds the slots; it does not invent transaction ids, because there
 * are none to invent.
 */
function History({
  scriptHash,
  idx,
}: {
  scriptHash: string;
  idx: IndexerHealth | null | undefined;
}) {
  return (
    <section className="card">
      <h2 className="snap-h2">History</h2>
      <p className="lookup-hint">
        There is no transaction history for this entry, and there is no honest way to build
        one the way a Bitcoin explorer does. <code>gettransaction</code> is refused by the
        node <em>by design</em>: at this layer a Genesis-4 transaction carries no id, and
        the block store keeps no txid index. The <code>tx_hash</code> that{" "}
        <code>sendrawtransaction</code> hands back is node-local — other nodes do not agree
        on it, and feeding it to <code>gettxout</code> returns a well-formed{" "}
        <code>unspent: false</code> that is indistinguishable from a lost withdrawal.
      </p>
      <p className="lookup-hint">
        What exists instead are <strong>outpoints</strong>: a 32-byte reference and an
        index, the slot that created it, and the slot that spent it. That is the honest
        unit of history here, and it is what the rows above link to.
      </p>
      {idx === undefined ? (
        <p className="lookup-hint faint">Checking whether an indexer is reachable…</p>
      ) : idx ? (
        <p className="lookup-hint">
          The indexer is up (slot {fmtInt(idx.indexed_to_slot)}, {fmtInt(idx.lag_slots)}{" "}
          behind). Created-and-spent slots for{" "}
          <code>{short(scriptHash, 10, 6)}</code> are available on the outpoint pages.
        </p>
      ) : (
        <div className="warn-box">
          <span className="warn-ico">!</span>
          <div>
            No indexer is reachable, so even the outpoint view is partial: the node's{" "}
            <code>getutxos</code> carries no slot for the outputs it returns, and{" "}
            <code>gettxout</code>'s <code>at_slot</code> is the head the node answered from
            — not the slot the output landed in. Until the indexer is deployed, the slot an
            output was created in exists nowhere on this RPC.
          </div>
        </div>
      )}
    </section>
  );
}

/** Where an arriving Genesis-3 identifier is explained rather than hidden. */
function Provenance({ parsed }: { parsed: Query }) {
  if (parsed.kind === "g3_address") {
    return (
      <div className="warn-box">
        <span className="warn-ico">i</span>
        <div>
          You searched <code>{parsed.address}</code>, a Genesis-3 address. Its checksum
          checks out, and it names <strong>one</strong> thing on this chain: the carried
          entry below, holding whatever that address held when Genesis-3 stopped at height
          39,918, minus anything spent since. It does <strong>not</strong> name a
          Genesis-4 key's holdings — a key's coins live at{" "}
          <code>SHA3-256(public key)</code>, 32 bytes, which cannot be recovered from the
          20 inside an address. If you are looking for coins sent to a Genesis-4 key, ask
          its holder for the 64-hex script hash; there is no conversion.
        </div>
      </div>
    );
  }
  if (parsed.kind === "g3_hash160") {
    return (
      <div className="warn-box">
        <span className="warn-ico">i</span>
        <div>
          You searched a bare 20-byte hash160 — the inside of a Genesis-3 address, with no
          checksum to verify. It resolves to the carried entry below. A mistyped hash160
          also resolves, to an entry that simply holds nothing, so a zero here is not proof
          of a zero balance; paste the full <code>bloch1q…</code> address if you have it and
          the checksum will catch the typo.
        </div>
      </div>
    );
  }
  return null;
}

function Refused({ parsed, onRetry }: { parsed: Query; onRetry: (v: string) => void }) {
  const [v, setV] = useState("");
  const bad = parsed.kind === "bad_address";
  return (
    <div className="container">
      <h1 className="page-title">Not a Genesis-4 identifier</h1>
      <div className="err-box">
        {bad ? (
          <>
            That address does not check out — its checksum does not match, so it has a typo
            somewhere. Refused on purpose: the zero-extended hash of a <em>wrong</em>{" "}
            address is a perfectly valid script hash that simply holds nothing, and you
            would have been shown an empty balance and believed it.
          </>
        ) : (
          <>
            Not recognised. Paste a 64-character script hash (what this chain actually
            uses), a <code>bloch1q…</code> Genesis-3 address, or its 40-character hash160.
          </>
        )}
      </div>
      <form
        className="card lookup"
        onSubmit={(e) => {
          e.preventDefault();
          const c = classify(v);
          if (c.kind === "script_hash" || c.kind === "g3_address" || c.kind === "g3_hash160")
            onRetry(c.scriptHash);
          else onRetry(v.trim());
        }}
      >
        <label className="lookup-label" htmlFor="retry">
          Try again
        </label>
        <div className="lookup-row">
          <input
            id="retry"
            className="lookup-input"
            value={v}
            onChange={(e) => setV(e.target.value)}
            spellCheck={false}
            autoComplete="off"
            placeholder="64-hex script hash, or bloch1q…"
          />
          <button className="lookup-go" type="submit">
            Look up
          </button>
        </div>
      </form>
    </div>
  );
}
