// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from "react";
import { rpc } from "../lib/rpc";
import { useAsync } from "../lib/hooks";
import { Loading, ErrorBox } from "../components/ui";
import { useAdaptivePoll } from "../components/chainStatus";
import { Link } from "../lib/router";
import { fmtInt, short, timeAgo, fmtTime, difficultyFromBits, fmtNum } from "../lib/format";
import { ArchiveBanner } from "../components/archive";

export function Blocks() {
  const [count, setCount] = useState(50);
  const { intervalMs, markTip } = useAdaptivePoll(20000);
  const { data, error, loading } = useAsync(
    () => rpc<any[]>("getrecentblocks", [count]),
    [count, intervalMs],
    intervalMs
  );
  useEffect(() => {
    if (data?.length) markTip(Math.max(...data.map((b: any) => b.height || 0)));
  }, [data, markTip]);

  return (
    <div className="container">
      <ArchiveBanner what="This block list" />
      <div className="page-title">Blocks</div>
      <div className="row-actions" style={{ marginBottom: 14 }}>
        {[15, 30, 50].map((c) => (
          <button key={c} className={"pill-tab" + (count === c ? " active" : "")} onClick={() => setCount(c)}>
            Last {c}
          </button>
        ))}
        <span className="faint" style={{ fontSize: 12.5 }}>
          getrecentblocks caps at 50 per call; for deeper history use search by height.
        </span>
      </div>

      {loading && !data && <Loading />}
      {error && !data && <ErrorBox error={error} />}
      {data && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Height</th>
                <th>Hash</th>
                <th className="num">Txs</th>
                <th className="num">Size</th>
                <th className="num">Difficulty</th>
                <th>Time (UTC)</th>
                <th>Age</th>
              </tr>
            </thead>
            <tbody>
              {data.map((b) => (
                <tr key={b.hash}>
                  <td>
                    <Link to={`/block/${b.hash}`} className="mono-link">{fmtInt(b.height)}</Link>
                  </td>
                  <td>
                    <Link to={`/block/${b.hash}`} className="mono-link">{short(b.hash, 14, 8)}</Link>
                  </td>
                  <td className="num">{fmtInt(b.tx_count)}</td>
                  <td className="num">{fmtInt(b.size)} B</td>
                  <td className="num">{fmtNum(difficultyFromBits(b.bits), 0)}</td>
                  <td className="faint mono" style={{ fontSize: 12 }}>{b.timestamp ? fmtTime(b.timestamp) : "—"}</td>
                  <td className="faint">{b.timestamp ? timeAgo(b.timestamp) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
