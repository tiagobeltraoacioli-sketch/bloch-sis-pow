// SPDX-License-Identifier: AGPL-3.0-or-later
//
// "I pasted a transaction hash and got nothing."
//
// Somebody will do this on their first visit, and they will be right to. Every
// wallet and every exchange integration hands the user a transaction hash,
// because `sendrawtransaction` returns one. On every other chain they have
// used, pasting it into an explorer is *the* thing an explorer is for.
//
// Here it resolves to nothing, and the three obvious ways to handle that are
// all worse than telling the truth:
//
//   * A 404 is a lie by omission. It reads as "not found yet" — try again
//     later — when the correct answer is "this can never be found, and here is
//     what to do instead". The person retries for an hour.
//
//   * Pretending to find it is worse. `gettxout` accepts any 32 bytes and
//     answers `{"unspent": false, "utxo": null}` with HTTP 200 and no error
//     for a value that has never existed — verified live against the archivals
//     with a hash of nothing but `ab` repeated. That answer is byte-identical
//     to the one a spent output gives and to the one a withdrawal that was
//     silently dropped gives. An explorer that renders it as "spent" or
//     "confirmed" is manufacturing a settlement claim out of noise.
//
//   * Silence about `sendrawtransaction`'s return value leaves the trap armed.
//     The hash it returns is computed by the node that received the
//     transaction and is not agreed on by any other node, so it is not even a
//     stable local handle.
//
// So this page says what the value is, demonstrates the trap on the reader's
// own input rather than describing it, and routes them to the two lookups that
// are exact.

import { useEffect, useState } from "react";
import { read } from "../lib/source";
import { Link } from "../lib/router";
import { fmtInt } from "../lib/format";
import { Copyable } from "../components/ui";

interface TxOut {
  txid: string;
  vout: number;
  unspent: boolean;
  utxo: unknown | null;
  at_slot: number;
}

/**
 * The live demonstration.
 *
 * Showing the reader the exact JSON the node returns for *their* hash is worth
 * more than any amount of prose about it, because the point is precisely that
 * the response looks fine. Prose saying "this answer is meaningless" is easy
 * to skim past; the same claim next to a well-formed `"unspent": false` that
 * the reader can see is about their own value is not.
 */
function TrapDemo({ hash }: { hash: string }) {
  const [out, setOut] = useState<TxOut | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let stop = false;
    read<TxOut>("gettxout", [hash, 0])
      .then((r) => !stop && setOut(r))
      .catch((e) => !stop && setErr(String(e?.message ?? e)));
    return () => {
      stop = true;
    };
  }, [hash]);

  if (err) return <p className="lookup-hint">The archivals did not answer: {err}</p>;
  if (!out) return <p className="lookup-hint">Asking the chain about your value…</p>;

  return (
    <>
      <p className="page-lede">
        Here is what <code>gettxout</code> actually returns for the value you pasted, right now,
        from a live archival:
      </p>
      <pre className="code-block">
        {JSON.stringify(
          { txid: out.txid, vout: out.vout, unspent: out.unspent, utxo: out.utxo, at_slot: out.at_slot },
          null,
          2,
        )}
      </pre>
      <p className="page-lede">
        <strong>That is not a finding.</strong> No error, HTTP 200, a well-formed answer — and it
        would be exactly the same if you had pasted 32 bytes of nothing. It means only "the eUTXO
        set has no unspent output under this key at slot {fmtInt(out.at_slot)}", which is true of
        essentially every 32-byte number. It does not distinguish
        {" "}<em>never existed</em> from <em>existed and was spent</em> from{" "}
        <em>a withdrawal that was dropped</em>. Anything that reads this response as a
        confirmation is inventing one.
      </p>
    </>
  );
}

export function TxAnswerPage({ hash }: { hash?: string }) {
  return (
    <div className="container">
      <h1 className="page-title">There are no transaction ids on Genesis-4</h1>

      {hash && (
        <div className="card" style={{ marginBottom: 14 }}>
          <p className="page-lede">
            You searched for{" "}
            <Copyable text={hash}>
              <code className="snap-hash">{hash}</code>
            </Copyable>
          </p>
          <p className="page-lede">
            If a wallet or an exchange gave you this, it came from{" "}
            <code>sendrawtransaction</code>, which returns a <code>tx_hash</code> computed by the
            node that accepted your transaction. <strong>Other nodes do not agree on it.</strong>{" "}
            It is not a network-wide identifier, it is not recorded in any block, and there is
            nothing to look it up in.
          </p>
          <TrapDemo hash={hash} />
        </div>
      )}

      <section className="card">
        <h2 className="snap-h2">Why the lookup does not exist</h2>
        <p className="page-lede">
          <code>gettransaction</code> is not missing from this build; it is{" "}
          <strong>refused on purpose and permanently</strong>, with its own error code
          (<code>-32005</code>) rather than "method not found", specifically so that nobody goes
          looking for a newer node that has it. The node's own words:
        </p>
        <blockquote className="node-quote">
          this node cannot look up a transaction by id: at Genesis-4's current layer a transaction
          carries no id (the transfer format is not yet specified — <code>PosTransaction::Transfer</code>{" "}
          encodes only fee-market terms), and the block store keeps no txid index. Track deposits by
          scanning blocks via <code>getblockbyslot</code> and reading the eUTXO set via{" "}
          <code>getbalance</code> / <code>listunspent</code>, both of which are exact. This is a
          permanent answer for this build, not a transient failure — do not retry.
        </blockquote>
        <p className="lookup-hint">
          Two separate facts stack up there: the transfer format is not frozen yet, so there is
          nothing stable to hash into an id; and even if there were, no index maps one to a block.
          A block page can tell you a block carries <code>tx_count: 3</code> and cannot tell you
          which three.
        </p>
      </section>

      <section className="card">
        <h2 className="snap-h2">What to do instead</h2>
        <p className="page-lede">
          Both of these are exact. Neither needs a transaction id, because the ledger is keyed by
          output, not by transaction.
        </p>
        <ol className="how-list">
          <li>
            <strong>Look up the recipient, not the transfer.</strong> Genesis-4 keys the eUTXO set
            by <em>script hash</em> — 32 bytes, no address encoding at consensus level. A{" "}
            <Link to="/balance">balance lookup</Link> gives you the exact holdings and the
            individual unspent outputs. If you hold a <code>bloch1q…</code> address, or the bare
            20-byte hash a carried Genesis-3 balance uses, the search box converts either into the
            32-byte key consensus actually compares — a 20-byte hash is left-aligned and
            zero-padded, which is the identity rule, not a convenience.
          </li>
          <li>
            <strong>Watch the slots.</strong> If you know roughly when a transfer should have
            landed, <Link to="/blocks">walk the range</Link> and look for the blocks with a
            non-zero transaction count. Combined with a balance reading before and after, that
            brackets it.
          </li>
          <li>
            <strong>If you have an outpoint</strong> — a 32-byte id and an output index — the
            search box accepts <code>&lt;hash&gt;:&lt;n&gt;</code> and asks{" "}
            <code>gettxout</code> directly. Read the answer with the caveat above firmly in mind:{" "}
            <code>unspent: false</code> is not evidence of anything.
          </li>
        </ol>
      </section>

      <section className="card">
        <h2 className="snap-h2">If you are integrating</h2>
        <p className="page-lede">
          Do not build a deposit flow that tracks transactions by id — there is no id to track,
          and the <code>tx_hash</code> your node hands back will not survive being asked of a
          different node. Credit against the eUTXO set: read{" "}
          <code>getbalance</code> / <code>listunspent</code> for the script hash you issued, from
          two independent nodes, and require them to agree on the finalized root <em>and</em>{" "}
          epoch before you release funds. Add a margin past finality; the checkpoint is not a
          latch and can move backwards.
        </p>
      </section>
    </div>
  );
}
