// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect } from "react";
import { rpcAllSettled, rpc } from "../lib/rpc";
import {
  fetchDagWindow,
  NetworkInfo,
  DagInfo,
  chainPhase,
  totalSupplySat,
  CARRYOVER_TOTAL_SAT,
} from "../lib/chain";
import { useAsync } from "../lib/hooks";
import { Stat, Loading, ErrorBox } from "../components/ui";
import { HalvingCard } from "../components/halving";
import { ChainStatusCard, useAdaptivePoll } from "../components/chainStatus";
import { Genesis4Card } from "../components/genesis4";
import { EMISSION_V3_FORK_LOCAL_HEIGHT } from "../lib/halving";
import { SearchBox } from "../components/search";
import { DagView } from "../components/dag";
import { Link } from "../lib/router";
import {
  fmtInt,
  fmtBloch,
  fmtHashrate,
  fmtDuration,
  fmtTime,
  timeAgo,
  short,
  difficultyFromBits,
  fmtNum,
} from "../lib/format";

interface DashData {
  net: NetworkInfo | null;
  dag: DagInfo | null;
  chain: any;
  bt: any;
  supply: any;
  mp: any;
  recent: any[] | null;
  window: Awaited<ReturnType<typeof fetchDagWindow>> | null;
}

async function load(): Promise<DashData> {
  const base = await rpcAllSettled({
    net: rpc<NetworkInfo>("getnetworkinfo"),
    dag: rpc<DagInfo>("getdaginfo"),
    chain: rpc("getchainstats"),
    bt: rpc("getblocktimepercentiles", [100]),
    supply: rpc("getsupplydistribution"),
    mp: rpc("getmempoolstats"),
    recent: rpc<any[]>("getrecentblocks", [12]),
  });
  let window = null;
  try {
    window = await fetchDagWindow(26);
  } catch {
    /* non-fatal */
  }
  return { ...base, window };
}

export function Dashboard() {
  const { intervalMs, markTip } = useAdaptivePoll(15000);
  const { data, error, loading } = useAsync(load, [intervalMs], intervalMs);
  useEffect(() => markTip(data?.dag?.tip_height), [data, markTip]);

  if (loading && !data) return <div className="container"><Loading label="Loading chain…" /></div>;
  if (error && !data) return <div className="container"><ErrorBox error={error} /></div>;
  const d = data!;
  const net = d.net;
  const dag = d.dag;
  const chain = d.chain;

  const recent = d.recent || [];
  const freshestTs = recent.length ? Math.max(...recent.map((b) => b.timestamp || 0)) : 0;

  const tipHeight = dag?.tip_height ?? 0;
  const blockCount = dag?.block_count ?? net?.blocks ?? 0;
  const orphanGap = blockCount - tipHeight;

  const phase = chainPhase(tipHeight, freshestTs);
  const complete = phase === "complete";

  const diff = recent.length ? difficultyFromBits(recent[0].bits) : chain?.current_difficulty ?? 0;

  return (
    <div className="container">
      <div className="search-hero" style={{ marginTop: 6, marginBottom: 22 }}>
        <SearchBox hero />
      </div>

      <Genesis4Card />

      <ChainStatusCard
        tipHeight={tipHeight}
        freshestTs={freshestTs}
        observedBlockSecs={chain?.avg_block_time_secs}
      />

      {/* The emission-fork countdown is only meaningful while the fork is still
          ahead; past it the next scheduled halving lies beyond the halt, so the
          halt card above is the only honest countdown. */}
      {!complete && tipHeight < EMISSION_V3_FORK_LOCAL_HEIGHT && (
        <HalvingCard tipHeight={tipHeight} observedBlockSecs={chain?.avg_block_time_secs} />
      )}

      <div className="grid stat-grid">
        <Stat
          label="Tip height"
          icon={<span className={"dot " + (complete ? "done" : phase === "quiet" ? "warn" : "live")} />}
          value={fmtInt(tipHeight)}
          sub={dag ? `blue score ${fmtInt(dag.tip_blue_score)}` : undefined}
        />
        <Stat
          label={complete ? "Final block" : "Last block"}
          value={freshestTs ? (complete ? fmtTime(freshestTs).slice(0, 10) : timeAgo(freshestTs)) : "—"}
          sub={
            complete
              ? freshestTs
                ? fmtTime(freshestTs).slice(11)
                : "as designed, at the halt"
              : "newest bodied block"
          }
        />
        <Stat label="DAG tips" value={fmtInt(dag?.tip_count ?? 0)} sub={`GhostDAG k = ${dag?.k ?? "?"}`} />
        <Stat
          label="Total blocks"
          value={fmtInt(blockCount)}
          sub={orphanGap > 0 ? `${fmtInt(orphanGap)} merged/side blocks` : "single chain"}
        />
        <Stat
          label="Hashrate"
          value={complete ? "0 H/s" : fmtHashrate(chain?.hashrate_hs ?? 0)}
          sub={complete ? `final difficulty ${fmtNum(diff, 0)}` : `difficulty ${fmtNum(diff, 0)}`}
        />
        <Stat
          label="Avg block time"
          value={fmtDuration(chain?.avg_block_time_secs ?? 0)}
          sub={`target 30s · median ${fmtDuration(d.bt?.p50_secs ?? 0)}`}
        />
        <Stat
          label="Total supply"
          value={fmtBloch(totalSupplySat(d.supply?.total_sats), 0)}
          unit="BLOCH"
          sub={`incl. ${fmtBloch(CARRYOVER_TOTAL_SAT, 0)} carry-over`}
        />
        <Stat label="Mempool" value={fmtInt(net?.mempool ?? d.mp?.size ?? 0)} sub="pending txs" />
        <Stat
          label="Peers"
          value={fmtInt(net?.peers ?? 0)}
          sub={complete ? "archival" : net?.syncing ? "syncing" : "in sync"}
        />
      </div>

      {d.window && d.window.blocks.length > 0 && (
        <>
          <div className="section-title">{complete ? "DAG at the final height" : "DAG near the tip"}</div>
          <DagView blocks={d.window.blocks} tips={d.window.tips} selectedTip={d.window.selectedTip} ghostTips={d.window.ghostTips} />
          <div className="faint" style={{ fontSize: 12, marginTop: 8 }}>
            Showing the selected-chain backbone plus every open tip near height {fmtInt(tipHeight)}.{" "}
            <Link to="/dag">Open full DAG view →</Link>
          </div>
        </>
      )}

      <div className="section-title">{complete ? "Final blocks" : "Latest blocks"}</div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Height</th>
              <th>Hash</th>
              <th className="num">Txs</th>
              <th className="num">Size</th>
              <th>{complete ? "Time (UTC)" : "Age"}</th>
            </tr>
          </thead>
          <tbody>
            {recent.map((b) => (
              <tr key={b.hash}>
                <td>
                  <Link to={`/block/${b.hash}`} className="mono-link">
                    {fmtInt(b.height)}
                  </Link>
                </td>
                <td>
                  <Link to={`/block/${b.hash}`} className="mono-link">
                    {short(b.hash, 12, 8)}
                  </Link>
                </td>
                <td className="num">{fmtInt(b.tx_count)}</td>
                <td className="num">{fmtInt(b.size)} B</td>
                <td className="faint">
                  {b.timestamp ? (complete ? fmtTime(b.timestamp) : timeAgo(b.timestamp)) : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div style={{ marginTop: 12 }}>
        <Link to="/blocks">View all blocks →</Link>
      </div>

    </div>
  );
}
