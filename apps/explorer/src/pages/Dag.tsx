import { useState } from "react";
import { fetchDagWindow } from "../lib/chain";
import { useAsync } from "../lib/hooks";
import { Loading, ErrorBox } from "../components/ui";
import { DagView } from "../components/dag";
import { fmtInt } from "../lib/format";

export function DagPage() {
  const [depth, setDepth] = useState(40);
  const { data, error, loading } = useAsync(() => fetchDagWindow(depth), [depth], 15000);

  return (
    <div className="container">
      <div className="page-title">DAG visualization</div>
      <p className="muted" style={{ marginTop: -8, maxWidth: 760 }}>
        Bloch is a GhostDAG-Q chain — blocks reference multiple parents, so the ledger is a directed
        acyclic graph, not a single line. Chain progresses left → right by height; each block links to
        its parents.
      </p>

      <div className="row-actions" style={{ margin: "14px 0" }}>
        <span className="faint" style={{ fontSize: 13 }}>Depth:</span>
        {[20, 40, 60].map((c) => (
          <button key={c} className={"pill-tab" + (depth === c ? " active" : "")} onClick={() => setDepth(c)}>
            {c} heights
          </button>
        ))}
      </div>

      {loading && !data && <Loading label="Building DAG…" />}
      {error && !data && <ErrorBox error={error} />}
      {data && (
        <>
          <div className="grid stat-grid" style={{ marginBottom: 16 }}>
            <div className="card stat"><div className="label">Tip height</div><div className="value sm">{fmtInt(data.dag.tip_height)}</div></div>
            <div className="card stat"><div className="label">Open tips</div><div className="value sm">{fmtInt(data.dag.tip_count)}</div></div>
            <div className="card stat"><div className="label">Bodied blocks</div><div className="value sm">{fmtInt(data.blocks.length)}</div><div className="sub">{fmtInt(data.ghostTips.length)} header-only</div></div>
            <div className="card stat"><div className="label">GhostDAG k</div><div className="value sm">{fmtInt(data.dag.k)}</div></div>
          </div>

          <DagView blocks={data.blocks} tips={data.tips} selectedTip={data.selectedTip} ghostTips={data.ghostTips} />

          <div className="rail" style={{ marginTop: 16 }}>
            <strong>What the colours mean.</strong> Blocks are coloured by the role the RPC lets us
            prove: the <span style={{ color: "var(--brass-hi)" }}>selected tip</span> (amber), any bodied{" "}
            <span style={{ color: "var(--red)" }}>competing tip</span> (solid red), and{" "}
            <span style={{ color: "var(--blue)" }}>merged history</span> (cool steel, shaded by blue score).
            Bold edges are selected-parent links; thin edges are merge-set links. The node does not
            expose the per-block blue/red mergeset classification, so we don't invent it.
            {data.ghostTips.length > 0 && (
              <>
                {" "}
                The <span style={{ color: "var(--red)" }}>dashed red</span> fan is{" "}
                {fmtInt(data.ghostTips.length)} <strong>header-only tips</strong> — the node knows
                these tip hashes but has no block body for them (bodies never arrived), so they can't
                be placed on the DAG. That large open-tip count is the current stall near height{" "}
                {fmtInt(data.dag.tip_height)}; once a consensus fix lands and the chain advances,
                bodied tips will render as real coloured branches here.
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}
