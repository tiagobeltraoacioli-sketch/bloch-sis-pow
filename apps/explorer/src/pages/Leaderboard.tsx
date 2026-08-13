// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect } from "react";
import { rpc, rpcAllSettled } from "../lib/rpc";
import { useAsync } from "../lib/hooks";
import { Loading, ErrorBox, Stat } from "../components/ui";
import { ProportionBars } from "../components/charts";
import { chainPhase } from "../lib/chain";
import { useAdaptivePoll } from "../components/chainStatus";
import { Link } from "../lib/router";
import {
  fetchPoolAddresses,
  scanMinerBlocks,
  rankMiners,
  MinerBlock,
  MinerRank,
  PoolAddresses,
} from "../lib/mining";
import { fmtHashrate, fmtInt, fmtBloch, fmtTime, timeAgo, short } from "../lib/format";

const SCAN_DEPTH = 40;

// Light live poll: network hashrate + newest block only (cheap). The heavy
// per-block coinbase scan refreshes on its own slower cadence / manual re-scan.
function LiveHeader() {
  const { intervalMs, markTip } = useAdaptivePoll(15000);
  const { data } = useAsync(async () => {
    const r = await rpcAllSettled({
      chain: rpc<any>("getchainstats"),
      recent: rpc<any[]>("getrecentblocks", [1]),
      dag: rpc<any>("getdaginfo"),
    });
    return r;
  }, [intervalMs], intervalMs);
  useEffect(() => markTip(data?.dag?.tip_height), [data, markTip]);

  const chain = data?.chain;
  const top = data?.recent?.[0];
  const dag = data?.dag;
  const complete =
    chainPhase(dag?.tip_height ?? top?.height ?? 0, top?.timestamp ?? 0) === "complete";

  return (
    <div className="grid stat-grid" style={{ marginTop: 14 }}>
      <Stat
        label="Network hashrate"
        value={complete ? "0 H/s" : fmtHashrate(chain?.hashrate_hs ?? 0)}
        sub={complete ? "mining ended at the halt" : "live estimate"}
      />
      <Stat label="Tip height" value={fmtInt(dag?.tip_height ?? top?.height ?? 0)} sub={`${fmtInt(dag?.tip_count ?? 0)} open tips`} />
      <Stat
        label={complete ? "Final block" : "Last block"}
        value={top ? "h" + fmtInt(top.height) : "—"}
        sub={
          top?.timestamp
            ? complete
              ? fmtTime(top.timestamp)
              : timeAgo(top.timestamp)
            : "no recent block"
        }
      />
      <Stat label="Blocks 24h" value={fmtInt(chain?.blocks_last_24h ?? 0)} sub="node-reported" />
    </div>
  );
}

interface Board {
  ranks: MinerRank[];
  blocks: MinerBlock[];
  pools: PoolAddresses;
  networkHs: number;
}

export function LeaderboardPage() {
  const { data, error, loading, refresh } = useAsync<Board>(async () => {
    const pools = await fetchPoolAddresses();
    const chain = await rpc<any>("getchainstats").catch(() => ({}));
    const blocks = await scanMinerBlocks(SCAN_DEPTH, pools);
    const ranks = rankMiners(blocks, pools);
    return { ranks, blocks, pools, networkHs: chain?.hashrate_hs ?? 0 };
  }, [], 0);

  const totalBlocks = data?.ranks.reduce((a, r) => a + r.blocks, 0) ?? 0;
  const attributed = data?.blocks.filter((b) => b.miner).length ?? 0;

  const rows =
    data?.ranks.map((r) => {
      const pct = totalBlocks ? (r.blocks / totalBlocks) * 100 : 0;
      const label =
        (r.isFounder ? "★ founder · " : "") + short(r.miner, 10, 8);
      return {
        label,
        value: r.blocks,
        pct,
        color: r.isFounder ? "var(--brass)" : "var(--blue)",
        sub: `${r.blocks} block${r.blocks === 1 ? "" : "s"} · ${fmtBloch(r.rewardSats, 2)} BLOCH`,
      };
    }) ?? [];

  return (
    <div className="container">
      <div className="page-title">Pool leaderboard</div>
      <p className="muted" style={{ marginTop: -8, maxWidth: 780 }}>
        Miners ranked by blocks found in the recent window, derived from each block's coinbase output.
        Hashrate share is estimated by allocating the live network hashrate in proportion to those blocks.
        If one miner (the founder) is currently the only one producing blocks, that's exactly what you'll
        see here — we don't fake a crowd.
      </p>

      <LiveHeader />

      {loading && !data && <div style={{ marginTop: 16 }}><Loading label="Deriving miners from recent coinbases…" /></div>}
      {error && !data && <div style={{ marginTop: 16 }}><ErrorBox error={error} /></div>}

      {data && (
        <>
          <div className="section-title" style={{ marginTop: 22 }}>
            Ranking <span className="faint">· last {SCAN_DEPTH} bodied blocks · {fmtInt(attributed)} attributed</span>
          </div>

          {rows.length === 0 ? (
            <div className="rail">
              <strong>No attributable blocks in the window.</strong> The node returned no bodied blocks whose
              coinbase we could resolve to a miner address right now. If blocks flow, miners appear here
              ranked by blocks found.
            </div>
          ) : (
            <>
              {rows.length === 1 && (
                <div className="rail" style={{ marginBottom: 14 }}>
                  <strong>Single active miner.</strong> Every attributed block in this window was mined by one
                  address{data.ranks[0].isFounder ? " (the founder)" : ""}. That's the honest current state of
                  the network — not a leaderboard of many competitors yet.
                </div>
              )}
              <div className="card pad-lg">
                <ProportionBars rows={rows} />
              </div>

              <div className="section-title" style={{ marginTop: 20 }}>Miners</div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th className="num">#</th>
                      <th>Miner</th>
                      <th className="num">Blocks</th>
                      <th className="num">Share</th>
                      <th className="num">Est. hashrate</th>
                      <th className="num">Coinbase</th>
                      <th>Last block</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.ranks.map((r, i) => {
                      const share = totalBlocks ? r.blocks / totalBlocks : 0;
                      return (
                        <tr key={r.miner}>
                          <td className="num">{i + 1}</td>
                          <td>
                            <Link to={`/address/${r.miner}`} className="mono-link">{short(r.miner, 12, 8)}</Link>
                            {r.isFounder && <span className="badge gold" style={{ marginLeft: 8 }}>founder</span>}
                          </td>
                          <td className="num">{fmtInt(r.blocks)}</td>
                          <td className="num">{(share * 100).toFixed(1)}%</td>
                          <td className="num">{data.networkHs ? fmtHashrate(share * data.networkHs) : "—"}</td>
                          <td className="num">{fmtBloch(r.rewardSats, 3)}</td>
                          <td className="faint">
                            h{fmtInt(r.lastHeight)} · {r.lastTs ? timeAgo(r.lastTs) : "—"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}

          <div className="rail" style={{ marginTop: 20 }}>
            <strong>Honest scope.</strong> Miner identity is derived from the coinbase output that isn't the
            founder premine address — the node doesn't tag blocks with a
            miner field. "Est. hashrate" splits the live network hashrate by block share over a small recent
            window, so it's noisy and luck-driven, not a measured per-miner rate.{" "}
            <button className="linklike" onClick={refresh}>Re-scan window</button>.
          </div>
        </>
      )}
    </div>
  );
}
