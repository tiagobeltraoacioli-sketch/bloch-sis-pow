import { rpc, rpcAllSettled } from "../lib/rpc";
import { useAsync } from "../lib/hooks";
import { Loading, ErrorBox, KV, Copyable } from "../components/ui";
import { Link } from "../lib/router";
import { addressFromHashHex } from "../lib/sha3";
import { fmtInt, fmtTime, timeAgo, short, fmtBloch } from "../lib/format";

function statusBadge(status: string) {
  const map: Record<string, string> = { pending: "gold", confirmed: "blue", final: "green", unknown: "gray" };
  return <span className={"badge " + (map[status] || "gray")}>{status}</span>;
}

// script_pubkey is a 20-byte P2PKH pubkey hash -> derive a clickable address.
function OutAddr({ scriptPubkey }: { scriptPubkey: string }) {
  const addr = addressFromHashHex(scriptPubkey);
  if (!addr) return <code>{scriptPubkey}</code>;
  return <Link to={`/address/${addr}`} className="mono-link">{short(addr, 14, 10)}</Link>;
}

export function TxDetail({ txid }: { txid: string }) {
  const { data, error, loading } = useAsync(async () => {
    const t = await rpc("gettransaction", [txid]);
    const rest = await rpcAllSettled({ status: rpc("gettxstatus", [txid]) });
    return { t, status: rest.status };
  }, [txid]);

  if (loading && !data) return <div className="container"><Loading label="Loading transaction…" /></div>;
  if (error && !data) return <div className="container"><ErrorBox error={error} /></div>;

  const t = data!.t;
  const tx = t.transaction || {};
  const status = data!.status;
  const outputs = tx.outputs || [];
  const inputs = tx.inputs || [];
  const outTotal = outputs.reduce((a: bigint, o: any) => a + BigInt(o.value), 0n);
  const isCoinbase = tx.coinbase;

  return (
    <div className="container">
      <div className="page-title">Transaction</div>

      <KV
        rows={[
          ["Txid", <Copyable text={t.txid}><code>{t.txid}</code></Copyable>],
          [
            "Status",
            <>
              {status ? statusBadge(status.status) : <span className="badge gray">?</span>}{" "}
              {isCoinbase && <span className="badge coinbase" style={{ marginLeft: 6 }}>coinbase</span>}
            </>,
          ],
          ["Block", <Link to={`/block/${t.block_hash}`} className="mono-link">#{fmtInt(t.block_height)} · {short(t.block_hash, 12, 8)}</Link>],
          ["Confirmations", fmtInt(t.confirmations)],
          ["Timestamp", <>{fmtTime(t.timestamp)} <span className="faint">· {timeAgo(t.timestamp)}</span></>],
          ["Output total", <>{fmtBloch(outTotal.toString(), 8)} <span className="faint">BLOCH</span></>],
        ]}
      />

      <div className="section-title">Inputs ({fmtInt(inputs.length)})</div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th className="num">#</th>
              <th>Prev txid</th>
              <th className="num">Vout</th>
            </tr>
          </thead>
          <tbody>
            {inputs.map((inp: any, i: number) => {
              const isCb = /^0+$/.test(inp.prev_txid);
              return (
                <tr key={i}>
                  <td className="num">{i}</td>
                  <td>
                    {isCb ? <span className="badge coinbase">coinbase (newly minted)</span> : (
                      <Link to={`/tx/${inp.prev_txid}`} className="mono-link">{short(inp.prev_txid, 16, 10)}</Link>
                    )}
                  </td>
                  <td className="num">{isCb ? "—" : inp.prev_index}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="section-title">Outputs ({fmtInt(outputs.length)})</div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th className="num">#</th>
              <th>Address (P2PKH)</th>
              <th className="num">Value</th>
            </tr>
          </thead>
          <tbody>
            {outputs.map((o: any) => (
              <tr key={o.index}>
                <td className="num">{o.index}</td>
                <td><OutAddr scriptPubkey={o.script_pubkey} /></td>
                <td className="num">{fmtBloch(o.value, 8)} <span className="faint">BLOCH</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="rail" style={{ marginTop: 22 }}>
        Finality is proof-of-work depth: 0 = in mempool, 1–99 = confirmed, 100+ = final (coinbase
        maturity). On this experimental network that depth carries no strong security guarantee yet.
      </div>
    </div>
  );
}
