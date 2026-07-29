import { useState } from "react";
import { fetchDagWindow, STALL_THRESHOLD_SECS } from "../lib/chain";
import { useAsync } from "../lib/hooks";
import { Loading, ErrorBox } from "../components/ui";
import { InteractiveDag } from "../components/dagInteractive";
import { Link } from "../lib/router";
import { fmtInt, timeAgo } from "../lib/format";

export function DagLivePage() {
  const [depth, setDepth] = useState(40);
  const { data, error, loading } = useAsync(() => fetchDagWindow(depth), [depth], 12000);

  const freshestTs = data ? Math.max(0, ...data.blocks.map((b) => b.timestamp || 0)) : 0;
  const stalled = freshestTs ? Date.now() / 1000 - freshestTs > STALL_THRESHOLD_SECS : true;

  return (
    <div className="container">
      <div className="page-title">Live GhostDAG</div>
      <p className="muted" style={{ marginTop: -8, maxWidth: 780 }}>
        An explorable view of the DAG near the tip. Scroll or pinch to zoom, drag to pan, hover a node
        for its stats, and click any block to open it. New blocks pop in as the node reports them. The
        static <Link to="/dag">DAG view</Link> stays available too.
      </p>

      <div className="row-actions" style={{ margin: "14px 0" }}>
        <span className="faint" style={{ fontSize: 13 }}>Depth:</span>
        {[20, 40, 60].map((c) => (
          <button key={c} className={"pill-tab" + (depth === c ? " active" : "")} onClick={() => setDepth(c)}>
            {c} heights
          </button>
        ))}
      </div>

      {loading && !data && <Loading label="Building live DAG…" />}
      {error && !data && <ErrorBox error={error} />}

      {data && (
        <>
          {stalled && (
            <div className="banner-stale" style={{ marginBottom: 14 }}>
              <span className="dot stale" />
              <div>
                <strong>Chain is stalled.</strong> {fmtInt(data.dag.tip_count)} open tips at height{" "}
                {fmtInt(data.dag.tip_height)}; newest bodied block is{" "}
                {freshestTs ? timeAgo(freshestTs) : "unknown age"}. The view stays live and degrades
                gracefully — header-only tips render as a dashed fan rather than invented branches.
              </div>
            </div>
          )}

          <div className="grid stat-grid" style={{ marginBottom: 16 }}>
            <div className="card stat"><div className="label">Tip height</div><div className="value sm">{fmtInt(data.dag.tip_height)}</div></div>
            <div className="card stat"><div className="label">Open tips</div><div className="value sm">{fmtInt(data.dag.tip_count)}</div></div>
            <div className="card stat"><div className="label">Bodied blocks</div><div className="value sm">{fmtInt(data.blocks.length)}</div><div className="sub">{fmtInt(data.ghostTips.length)} header-only</div></div>
            <div className="card stat"><div className="label">GhostDAG k</div><div className="value sm">{fmtInt(data.dag.k)}</div></div>
          </div>

          <InteractiveDag
            blocks={data.blocks}
            tips={data.tips}
            selectedTip={data.selectedTip}
            ghostTips={data.ghostTips}
          />

          <div className="rail" style={{ marginTop: 16 }}>
            <strong>What you're seeing.</strong> The <span style={{ color: "var(--gold)" }}>amber</span> node is
            the selected tip; solid <span style={{ color: "var(--red)" }}>red</span> nodes are competing bodied
            tips; <span style={{ color: "var(--blue)" }}>blue</span> nodes are merged history (shaded by blue
            score). Bold edges are selected-parent links. The node RPC doesn't expose the per-block blue/red
            mergeset classification, so we colour only by roles we can prove — nothing is invented.
          </div>
        </>
      )}
    </div>
  );
}
