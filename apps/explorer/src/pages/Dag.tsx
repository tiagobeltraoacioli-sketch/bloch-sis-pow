// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from "react";
import { fetchDagWindow, HALT_HEIGHT } from "../lib/chain";
import { useAsync } from "../lib/hooks";
import { Loading, ErrorBox } from "../components/ui";
import { DagView } from "../components/dag";
import { useAdaptivePoll } from "../components/chainStatus";
import { fmtInt } from "../lib/format";

export function DagPage() {
  const [depth, setDepth] = useState(40);
  const { intervalMs, markTip } = useAdaptivePoll(15000);
  const { data, error, loading } = useAsync(() => fetchDagWindow(depth), [depth, intervalMs], intervalMs);
  useEffect(() => markTip(data?.dag?.tip_height), [data, markTip]);

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
            prove: the <span style={{ color: "var(--accent)" }}>selected tip</span> (emerald), any bodied{" "}
            <span style={{ color: "var(--red)" }}>competing tip</span> (solid red), and{" "}
            <span style={{ color: "var(--violet)" }}>merged history</span> (violet, shaded by blue score).
            Bold edges are selected-parent links; thin edges are merge-set links. The node does not
            expose the per-block blue/red mergeset classification, so we don't invent it.
            {data.ghostTips.length > 0 && (
              <>
                {" "}
                The <span style={{ color: "var(--red)" }}>dashed red</span> fan is{" "}
                {fmtInt(data.ghostTips.length)} <strong>header-only tips</strong> — the node knows
                these tip hashes but has no block body for them (bodies never arrived), so they can't
                be placed on the DAG.{" "}
                {data.dag.tip_height >= HALT_HEIGHT
                  ? "They are part of the final, permanent record of Genesis-3."
                  : "They render as bodied, coloured branches if their bodies arrive."}
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}
