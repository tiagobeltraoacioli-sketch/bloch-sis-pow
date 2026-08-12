// SPDX-License-Identifier: AGPL-3.0-or-later
import { rpc, rpcAllSettled } from "../lib/rpc";
import { useAsync } from "../lib/hooks";
import { Loading, ErrorBox, KV, Copyable } from "../components/ui";
import { Stat } from "../components/ui";
import { Link } from "../lib/router";
import { fmtInt, fmtBloch, fmtTime, timeAgo, short } from "../lib/format";

export function AddressView({ addr }: { addr: string }) {
  const { data, error, loading } = useAsync(async () => {
    const r = await rpcAllSettled({
      info: rpc("getaddressinfo", [addr]),
      bal: rpc("getbalance", [addr]),
      hist: rpc("listtransactions", [addr, 50, 0, 0, 0]),
    });
    return r;
  }, [addr]);

  if (loading && !data) return <div className="container"><Loading label="Loading address…" /></div>;
  if (error && !data) return <div className="container"><ErrorBox error={error} /></div>;

  const info = data!.info;
  const bal = data!.bal;
  const hist = data!.hist;
  const balanceSats = info?.balance_sats ?? bal?.satoshis ?? 0;
  const utxoCount = info?.utxo_count ?? bal?.utxo_count ?? 0;
  const txs = hist?.transactions || [];
  const poolRole = info?.pool_role;

  return (
    <div className="container">
      <div className="page-title">Address</div>
      <div style={{ marginBottom: 16 }}>
        <Copyable text={addr}><code style={{ fontSize: 13 }}>{addr}</code></Copyable>
        {poolRole && poolRole !== "none" && <span className="badge gold" style={{ marginLeft: 10 }}>{poolRole}</span>}
      </div>

      <div className="grid stat-grid">
        <Stat label="Balance" value={fmtBloch(balanceSats, 4)} unit="BLOCH" sub={`${fmtInt(balanceSats)} sat`} />
        <Stat label="UTXOs" value={fmtInt(utxoCount)} />
        <Stat label="Pending in" value={fmtBloch(info?.pending_incoming ?? 0, 4)} unit="BLOCH" small />
        <Stat label="Pending out" value={fmtBloch(info?.pending_outgoing ?? 0, 4)} unit="BLOCH" small />
      </div>

      {info == null && bal == null && (
        <div className="err-box" style={{ marginTop: 16 }}>
          Address not found or invalid. Bloch addresses are checksummed <code>bloch1q…</code> (mainnet).
        </div>
      )}

      <div className="section-title">
        Transaction history {hist?.total_available != null && <span className="faint">({fmtInt(hist.total_available)} total)</span>}
      </div>
      {txs.length === 0 ? (
        <div className="faint">No transactions found for this address.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Txid</th>
                <th>Direction</th>
                <th className="num">Amount</th>
                <th className="num">Height</th>
                <th className="num">Confs</th>
                <th>Age</th>
              </tr>
            </thead>
            <tbody>
              {txs.map((t: any, i: number) => (
                <tr key={t.txid + i}>
                  <td><Link to={`/tx/${t.txid}`} className="mono-link">{short(t.txid, 14, 8)}</Link></td>
                  <td>
                    <span className={"badge " + (t.direction === "in" || t.direction === "received" ? "green" : "gray")}>
                      {t.direction}
                    </span>
                  </td>
                  <td className="num">{fmtBloch(t.amount_sats, 8)}</td>
                  <td className="num"><Link to={`/block/height/${t.block_height}`} className="mono-link">{fmtInt(t.block_height)}</Link></td>
                  <td className="num">{fmtInt(t.confirmations)}</td>
                  <td className="faint">{t.timestamp ? timeAgo(t.timestamp) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="faint" style={{ fontSize: 12, marginTop: 10 }}>
        Note: the address-history indexer does not roll back on reorg (documented RPC limitation).
      </div>
    </div>
  );
}
