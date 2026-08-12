// SPDX-License-Identifier: AGPL-3.0-or-later
import { rpc, rpcAllSettled } from "../lib/rpc";
import { useAsync } from "../lib/hooks";
import { Loading, ErrorBox, KV, Copyable } from "../components/ui";
import { Link } from "../lib/router";
import { fmtInt, fmtTime, timeAgo, short, difficultyFromBits, fmtNum, fmtBytes, fmtBloch } from "../lib/format";

export function BlockDetail({ hash, height }: { hash?: string; height?: number }) {
  const { data, error, loading } = useAsync(async () => {
    const block = hash
      ? await rpc("getblock", [hash, false])
      : await rpc("getblockbyheight", [height!, false]);
    const bh = block.hash;
    const rest = await rpcAllSettled({
      txs: rpc("gettxsbyblock", [bh]),
    });
    return { block, txs: rest.txs };
  }, [hash, height]);

  if (loading && !data) return <div className="container"><Loading label="Loading block…" /></div>;
  if (error && !data) return <div className="container"><ErrorBox error={error} /></div>;
  const b = data!.block;
  const txs = data!.txs?.txs || [];
  const bits = typeof b.bits === "string" ? parseInt(b.bits, 16) : b.bits;
  const parents: string[] = b.parents || [];

  return (
    <div className="container">
      <div className="page-title">
        Block <span className="mono" style={{ color: "var(--brass)" }}>#{fmtInt(b.height)}</span>
      </div>

      <KV
        rows={[
          ["Hash", <Copyable text={b.hash}><code>{b.hash}</code></Copyable>],
          ["Height", fmtInt(b.height)],
          ["Blue score", fmtInt(b.blue_score)],
          [
            "Parents",
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {parents.length === 0 && <span className="faint">genesis / none</span>}
              {parents.map((p, i) => (
                <span key={p}>
                  {i === 0 && <span className="badge blue" style={{ marginRight: 6 }}>selected</span>}
                  <Link to={`/block/${p}`} className="mono-link">{short(p, 16, 12)}</Link>
                </span>
              ))}
            </div>,
          ],
          ["Merkle root", <code>{b.merkle_root}</code>],
          ["Timestamp", <>{fmtTime(b.timestamp)} <span className="faint">· {timeAgo(b.timestamp)}</span></>],
          ["Difficulty", <>{fmtNum(difficultyFromBits(bits), 2)} <span className="faint">· bits {typeof b.bits === "string" ? b.bits : "0x" + (bits >>> 0).toString(16)}</span></>],
          ["Nonce", <code>{fmtInt(b.nonce)}</code>],
          ["Size", fmtBytes(b.size)],
          ["Transactions", fmtInt(b.tx_count)],
        ]}
      />

      <div className="section-title">Transactions ({fmtInt(txs.length)})</div>
      {txs.length === 0 ? (
        <div className="faint">No transaction detail available.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Txid</th>
                <th>Type</th>
                <th className="num">In</th>
                <th className="num">Out</th>
                <th className="num">Fee</th>
                <th className="num">Size</th>
              </tr>
            </thead>
            <tbody>
              {txs.map((t: any) => (
                <tr key={t.txid}>
                  <td>
                    <Link to={`/tx/${t.txid}`} className="mono-link">{short(t.txid, 16, 10)}</Link>
                  </td>
                  <td>
                    {t.is_coinbase ? <span className="badge coinbase">coinbase</span> : <span className="badge gray">payment</span>}
                  </td>
                  <td className="num">{fmtInt(t.inputs_count)}</td>
                  <td className="num">{fmtInt(t.outputs_count)}</td>
                  <td className="num">{t.is_coinbase ? "—" : fmtBloch(t.fee_sats, 8)}</td>
                  <td className="num">{fmtInt(t.size_bytes)} B</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
