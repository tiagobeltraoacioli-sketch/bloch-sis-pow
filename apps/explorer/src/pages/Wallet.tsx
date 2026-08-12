// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from "react";
import { rpc, rpcAllSettled } from "../lib/rpc";
import { useAsync } from "../lib/hooks";
import { Loading, ErrorBox, Stat, Copyable } from "../components/ui";
import { ChartCard, LineChart } from "../components/charts";
import { Link } from "../lib/router";
import { parseBlochAddress, looksLikeBlochAddress } from "../lib/address";
import { fetchPoolAddresses, scanMinerBlocks, MinerBlock, PoolAddresses } from "../lib/mining";
import { fmtBloch, fmtInt, toSats, timeAgo, short } from "../lib/format";

const LS_KEY = "bloch:wallet:addr";
const SCAN_DEPTH = 40;

export function WalletPage() {
  const [addr, setAddr] = useState("");
  const [active, setActive] = useState<string | null>(null);

  useEffect(() => {
    const saved = localStorage.getItem(LS_KEY);
    if (saved) {
      setAddr(saved);
      setActive(saved);
    }
  }, []);

  const parsed = parseBlochAddress(addr);
  const submit = () => {
    if (!parsed) return;
    localStorage.setItem(LS_KEY, parsed.address);
    setActive(parsed.address);
  };

  return (
    <div className="container">
      <div className="page-title">Wallet dashboard</div>
      <p className="muted" style={{ marginTop: -8, maxWidth: 760 }}>
        Paste your <code>bloch1q…</code> address for a personal panel: balance, blocks you mined in the
        recent window, and estimated coinbase earnings. Nothing leaves your browser except the read-only
        RPC lookups; your last address is remembered locally for convenience.
      </p>

      <div className="card pad-lg" style={{ marginTop: 12 }}>
        <div className="mine-inline" style={{ maxWidth: 640 }}>
          <input
            className={"mine-input mono" + (addr.trim() && !parsed ? " bad" : parsed ? " good" : "")}
            value={addr}
            spellCheck={false}
            autoCapitalize="off"
            placeholder="bloch1q…"
            onChange={(e) => setAddr(e.target.value.trim())}
            onKeyDown={(e) => e.key === "Enter" && submit()}
          />
          <button className="pill-tab go" onClick={submit} disabled={!parsed}>
            Load
          </button>
        </div>
        {addr.trim() && !parsed && (
          <div className="faint" style={{ marginTop: 6, color: "var(--red)" }}>
            {looksLikeBlochAddress(addr)
              ? "Checksum/format not valid yet — a Bloch address is bloch1q + 48 hex chars."
              : "Not a Bloch address (must start with bloch1q / bloch1t)."}
          </div>
        )}
      </div>

      {active && <WalletPanel address={active} key={active} />}
    </div>
  );
}

interface PanelData {
  /** bigint: a balance can exceed 2^53 sat (the largest carryover does, ~39x). */
  balanceSats: bigint;
  utxoCount: number;
  poolRole: string | null;
  pools: PoolAddresses;
  mined: MinerBlock[];
}

function WalletPanel({ address }: { address: string }) {
  const { data, error, loading, refresh } = useAsync<PanelData>(async () => {
    const pools = await fetchPoolAddresses();
    const base = await rpcAllSettled({
      info: rpc<any>("getaddressinfo", [address]),
      bal: rpc<any>("getbalance", [address]),
    });
    const info = base.info || {};
    const bal = base.bal || {};
    const blocks = await scanMinerBlocks(SCAN_DEPTH, pools);
    const mined = blocks.filter((b) => b.miner && b.miner.toLowerCase() === address.toLowerCase());
    return {
      balanceSats: toSats(info.balance_sats ?? bal.satoshis),
      utxoCount: info.utxo_count ?? bal.utxo_count ?? 0,
      poolRole: info.pool_role && info.pool_role !== "none" ? info.pool_role : null,
      pools,
      mined,
    };
  }, [address]);

  if (loading && !data) return <div style={{ marginTop: 18 }}><Loading label="Scanning recent blocks for your address…" /></div>;
  if (error && !data) return <div style={{ marginTop: 18 }}><ErrorBox error={error} /></div>;
  const d = data!;

  // Sum in satoshis as bigint, and only convert to a float for the CHART axis
  // (a plotted pixel coordinate is display, an accounting total is not).
  const minedReward = d.mined.reduce((a, b) => a + b.rewardSats, 0n);
  const sorted = [...d.mined].sort((a, b) => a.height - b.height);
  let cum = 0n;
  const points = sorted.map((b) => {
    cum += b.rewardSats;
    return { x: b.height, y: Number(cum) / 1e8, label: `h${b.height}` };
  });

  return (
    <>
      <div style={{ margin: "16px 0 6px" }}>
        <Copyable text={address}>
          <code style={{ fontSize: 13 }}>{address}</code>
        </Copyable>
        {d.poolRole && <span className="badge gold" style={{ marginLeft: 10 }}>{d.poolRole}</span>}
      </div>

      <div className="grid stat-grid">
        <Stat label="Balance" value={fmtBloch(d.balanceSats, 4)} unit="BLOCH" sub={`${fmtInt(d.balanceSats)} sat`} />
        <Stat label="UTXOs" value={fmtInt(d.utxoCount)} />
        <Stat
          label={`Blocks mined (last ${SCAN_DEPTH})`}
          value={fmtInt(d.mined.length)}
          sub="in the scanned window"
        />
        <Stat
          label="Est. coinbase earned"
          value={fmtBloch(minedReward, 4)}
          unit="BLOCH"
          sub="from those blocks"
        />
      </div>

      {d.balanceSats === 0n && d.mined.length === 0 && (
        <div className="rail" style={{ marginTop: 16 }}>
          <strong>Nothing found.</strong> This address has no balance and mined no blocks in the last{" "}
          {SCAN_DEPTH} bodied blocks the node returned — we won't invent activity. Note that Genesis-3
          ends at height 50,000; after the halt this scan is a fixed historical window, not a live feed.
        </div>
      )}

      {d.mined.length > 0 && (
        <>
          <div className="section-title" style={{ marginTop: 22 }}>Your cumulative coinbase (scanned window)</div>
          <ChartCard title="Cumulative BLOCH mined" hint={`${d.mined.length} block${d.mined.length === 1 ? "" : "s"}`}>
            <LineChart
              points={points}
              area
              step
              yFormat={(v) => v.toFixed(2)}
              xFormat={(v) => "h" + Math.round(v)}
            />
          </ChartCard>

          <div className="section-title" style={{ marginTop: 20 }}>Blocks you mined</div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Height</th>
                  <th>Hash</th>
                  <th className="num">Coinbase</th>
                  <th>Age</th>
                </tr>
              </thead>
              <tbody>
                {sorted
                  .slice()
                  .reverse()
                  .map((b) => (
                    <tr key={b.hash}>
                      <td><Link to={`/block/${b.hash}`} className="mono-link">{fmtInt(b.height)}</Link></td>
                      <td><Link to={`/block/${b.hash}`} className="mono-link">{short(b.hash, 12, 8)}</Link></td>
                      <td className="num">{fmtBloch(b.rewardSats, 4)}</td>
                      <td className="faint">{b.timestamp ? timeAgo(b.timestamp) : "—"}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <div className="rail" style={{ marginTop: 20 }}>
        <strong>Honest scope.</strong> "Blocks mined" is derived by matching your address to the coinbase
        miner output of the last {SCAN_DEPTH} bodied blocks — it is a recent-window view, not full history.
        The node RPC does not expose per-miner PPLNS shares, so pooled-earnings splits can't be computed
        here; the figure above is the on-chain coinbase value credited to your address in that window.{" "}
        <button className="linklike" onClick={refresh}>Re-scan</button>.
      </div>
    </>
  );
}
