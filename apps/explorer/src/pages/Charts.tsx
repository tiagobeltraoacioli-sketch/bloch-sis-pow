import { rpcAllSettled, rpc } from "../lib/rpc";
import { useAsync } from "../lib/hooks";
import { Loading, ErrorBox } from "../components/ui";
import { ChartCard, LineChart, BarChart, ProportionBars } from "../components/charts";
import { difficultyFromBits, fmtNum, fmtDuration, fmtHashrate, fmtBloch, fmtInt } from "../lib/format";
import { totalSupplySat, CARRYOVER_TOTAL_SAT, CARRYOVER_UTXO_COUNT } from "../lib/chain";

// Brand ramp: Amber Copper family carries the signal; cool blue / sage / slate
// fill the secondary categories. One accent per figure stays true to the kit.
const TIER_COLORS = ["#E0A870", "#D2955C", "#B87740", "#8F6238", "#5E88C8", "#8FB99A", "#7E93B4", "#E0736A"];

export function ChartsPage() {
  const { data, error, loading } = useAsync(
    () =>
      rpcAllSettled({
        diff: rpc("getdifficultyhistory", [40]),
        bt: rpc("getblocktimepercentiles", [200]),
        supply: rpc("getsupplydistribution"),
        pools: rpc("getpools"),
        chain: rpc("getchainstats"),
      }),
    [],
    30000
  );

  if (loading && !data) return <div className="container"><Loading label="Loading analytics…" /></div>;
  if (error && !data) return <div className="container"><ErrorBox error={error} /></div>;
  const d = data!;

  const diffPoints = (d.diff?.points || [])
    .map((p: any) => ({ x: p.height, y: difficultyFromBits(p.bits), label: `h${p.height}: ${fmtNum(difficultyFromBits(p.bits), 0)}` }))
    .sort((a: any, b: any) => a.x - b.x);

  // Percentage change between the last two retarget points — the number that
  // actually moves. Absolute difficulty barely does at this magnitude.
  const diffDelta =
    diffPoints.length >= 2 && diffPoints[diffPoints.length - 2].y > 0
      ? ((diffPoints[diffPoints.length - 1].y - diffPoints[diffPoints.length - 2].y) /
          diffPoints[diffPoints.length - 2].y) * 100
      : null;

  const bt = d.bt;
  const btBars = bt
    ? [
        { label: "min", value: bt.min_secs, color: "#8FB99A" },
        { label: "p50", value: bt.p50_secs, color: "#D2955C" },
        { label: "p90", value: bt.p90_secs, color: "#E0A870" },
        { label: "p99", value: bt.p99_secs, color: "#B87740" },
        { label: "max", value: bt.max_secs, color: "#E0736A" },
        { label: "avg", value: bt.avg_secs, color: "#5E88C8" },
      ]
    : [];

  const tiers = (d.supply?.tiers || []).filter((t: any) => t.address_count > 0);
  const supplyRows = tiers.map((t: any, i: number) => ({
    label: t.label,
    value: t.total_sats,
    pct: t.pct_of_supply,
    color: TIER_COLORS[i % TIER_COLORS.length],
    sub: `${t.address_count} addr`,
  }));

  const pools = d.pools?.pools;
  const subsidy = d.pools?.subsidy_per_block_sat || 1;
  const shareRows = pools
    ? [
        { label: "Miner", value: d.pools.miner_share_sat, pct: (d.pools.miner_share_sat / subsidy) * 100, color: "#D2955C" },
      ]
    : [];

  return (
    <div className="container">
      <div className="page-title">Charts &amp; analytics</div>

      <div className="grid two-col">
        <ChartCard title="Difficulty history" hint={`${diffPoints.length} retarget points`}>
          <LineChart points={diffPoints} color="#D2955C" yFormat={(v) => fmtNum(v, 0)} xFormat={(v) => "h" + Math.round(v)} step emptyNote="No retarget points yet — the chain has produced no difficulty adjustments in range." />
        </ChartCard>

        <ChartCard title="Block-time percentiles" hint={`window ${bt?.window ?? 0} · target ${bt?.target_secs ?? 30}s`}>
          <BarChart bars={btBars} yFormat={(v) => fmtDuration(v)} />
        </ChartCard>
      </div>

      <div className="grid two-col" style={{ marginTop: 14 }}>
        <ChartCard
          title="Supply distribution"
          hint={`${fmtInt(d.supply?.total_addresses ?? 0)} addresses · ${fmtBloch(d.supply?.total_sats ?? 0, 0)} BLOCH in the UTXO set`}
        >
          <ProportionBars rows={supplyRows} />
          <div className="faint" style={{ fontSize: 12, marginTop: 8 }}>
            Bars cover the live UTXO set only. Total supply is{" "}
            {fmtBloch(totalSupplySat(d.supply?.total_sats), 0)} BLOCH — the Genesis-1 carry-over
            ({fmtBloch(CARRYOVER_TOTAL_SAT, 0)} BLOCH across {fmtInt(CARRYOVER_UTXO_COUNT)} UTXOs) is
            loaded at genesis and is not walked by <code>getsupplydistribution</code>, so it does not
            appear in these tiers. Concentration reflects the disclosed 17% founder premine plus that
            carry-over set.
          </div>
        </ChartCard>

        <ChartCard title="Block subsidy split" hint={`${fmtBloch(subsidy, 0)} BLOCH / block`}>
          <ProportionBars rows={shareRows} />
          {pools && (
            <div className="faint" style={{ fontSize: 12, marginTop: 8 }}>
              Pure PoW — 100% of the block subsidy goes to the miner (no validators or oracles). Founder vesting:{" "}
              {pools.founder?.vesting_active_at_next ? "active" : "inactive"} at next block.
            </div>
          )}
        </ChartCard>
      </div>

      <div className="card chart-card" style={{ marginTop: 14 }}>
        <div className="chart-head"><h3>Network</h3><span className="hint">from getchainstats</span></div>
        <div className="grid stat-grid" style={{ marginTop: 8 }}>
          <div className="stat"><div className="label">Hashrate</div><div className="value sm">{fmtHashrate(d.chain?.hashrate_hs ?? 0)}</div></div>
          <div className="stat">
            <div className="label">Difficulty</div>
            {/* Shown scaled, with the change since the last retarget. As a raw
                integer this reads as frozen: consecutive retargets differ by
                ~22k out of ~437M (0.005%), so every leading digit stays put and
                a live value looks stale. Full precision is in the title. */}
            <div className="value sm" title={fmtNum(d.chain?.current_difficulty ?? 0, 0)}>
              {fmtNum((d.chain?.current_difficulty ?? 0) / 1e6, 2)}<span className="unit">M</span>
            </div>
            {diffDelta != null && (
              <div className="sub">{diffDelta >= 0 ? "+" : ""}{fmtNum(diffDelta, 3)}% since last retarget</div>
            )}
          </div>
          <div className="stat"><div className="label">Avg block time</div><div className="value sm">{fmtDuration(d.chain?.avg_block_time_secs ?? 0)}</div></div>
          <div className="stat"><div className="label">Blocks / 24h</div><div className="value sm">{fmtInt(d.chain?.blocks_last_24h ?? 0)}</div></div>
          <div className="stat"><div className="label">Txs / 24h</div><div className="value sm">{fmtInt(d.chain?.txs_last_24h ?? 0)}</div></div>
          <div className="stat"><div className="label">Total txs</div><div className="value sm">{fmtInt(d.chain?.total_txs ?? 0)}</div></div>
        </div>
      </div>
    </div>
  );
}
