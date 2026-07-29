import { useMemo, useState } from "react";
import { useRouter } from "../lib/router";
import { short } from "../lib/format";

export interface DagBlock {
  hash: string;
  height: number;
  blue_score: number;
  parents: string[];
  timestamp: number;
}

// GhostDAG structure renderer.
//  x  = height (chain progresses left → right)
//  y  = a per-height lane so same-height blocks stack without overlap
//  edges = block → each parent. The FIRST parent is the selected parent
//          (drawn bold); the rest are merge-set edges (thin).
//
// Honesty note surfaced in the UI: the node RPC exposes parents, blue_score,
// the tip set and the selected tip — but NOT the per-block blue/red mergeset
// classification. So we colour by role we CAN prove: selected tip (gold),
// competing tips (red), and merged history (blue), with a blue_score gradient.
export function DagView({
  blocks,
  tips,
  selectedTip,
  ghostTips = [],
}: {
  blocks: DagBlock[];
  tips: Set<string>;
  selectedTip: string | null;
  ghostTips?: string[];
}) {
  const { navigate } = useRouter();
  const [hover, setHover] = useState<string | null>(null);

  const layout = useMemo(() => {
    if (!blocks.length) return null;
    const byHeight = new Map<number, DagBlock[]>();
    for (const b of blocks) {
      const arr = byHeight.get(b.height) || [];
      arr.push(b);
      byHeight.set(b.height, arr);
    }
    const heights = [...byHeight.keys()].sort((a, b) => a - b);
    const minH = heights[0];
    const maxH = heights[heights.length - 1];
    const maxLane = Math.max(...[...byHeight.values()].map((a) => a.length));

    const laneH = 46;
    const padX = 46;
    const padY = 34;
    // reserve room on the right for a ghost-tip fan when tips are header-only
    const ghostZone = ghostTips.length ? 160 : 0;
    const span = maxH - minH || 1;
    // Fit the backbone to a target width so the whole structure (incl. the
    // ghost fan) is visible without horizontal scrolling for typical depths.
    const targetInner = 1120 - padX * 2 - ghostZone;
    const colW = Math.min(80, Math.max(16, targetInner / span));
    const width = padX * 2 + span * colW + ghostZone;
    const height = Math.max(padY * 2 + Math.max(maxLane - 1, 1) * laneH, ghostTips.length ? 300 : 120);

    const pos = new Map<string, { x: number; y: number; b: DagBlock }>();
    for (const h of heights) {
      const arr = byHeight.get(h)!.sort((a, b) => a.hash.localeCompare(b.hash));
      const x = padX + (h - minH) * colW;
      arr.forEach((b, i) => {
        // center the lane stack vertically
        const total = arr.length;
        const y = height / 2 + (i - (total - 1) / 2) * laneH;
        pos.set(b.hash, { x, y, b });
      });
    }
    return { pos, width, height, minH, maxH };
  }, [blocks, ghostTips.length]);

  if (!layout) return <div className="faint" style={{ padding: 24 }}>No blocks to render.</div>;

  const { pos, width, height } = layout;
  const bsList = blocks.map((b) => b.blue_score);
  const bsMin = Math.min(...bsList), bsMax = Math.max(...bsList);
  const blueShade = (bs: number) => {
    const t = (bs - bsMin) / (bsMax - bsMin || 1); // 0..1
    // cool steel backbone: darker (old) → brighter (recent), kept calm on navy
    const l = 34 + t * 24;
    return `hsl(214 42% ${l}%)`;
  };

  const edges: JSX.Element[] = [];
  for (const { b, x, y } of pos.values()) {
    b.parents.forEach((ph, idx) => {
      const p = pos.get(ph);
      if (!p) return;
      const selected = idx === 0;
      const active = hover === b.hash || hover === ph || hover === null;
      const mx = (x + p.x) / 2;
      edges.push(
        <path
          key={b.hash + "->" + ph}
          className="dag-edge"
          d={`M${x},${y} C${mx},${y} ${mx},${p.y} ${p.x},${p.y}`}
          stroke={selected ? "#5E88C8" : "#2C3A55"}
          strokeWidth={selected ? 1.8 : 1}
          strokeOpacity={active ? (selected ? 0.85 : 0.5) : 0.12}
        />
      );
    });
  }

  const nodes: JSX.Element[] = [];
  for (const { b, x, y } of pos.values()) {
    const isSel = b.hash === selectedTip;
    const isTip = tips.has(b.hash);
    let fill = blueShade(b.blue_score);
    let stroke = "transparent";
    let r = 7;
    if (isSel) { fill = "#E0A870"; stroke = "#F6DCB8"; r = 9; }
    else if (isTip) { fill = "#E0736A"; stroke = "#EFA79E"; r = 8; }
    const active = hover === null || hover === b.hash;
    nodes.push(
      <g
        key={b.hash}
        className="dag-node"
        transform={`translate(${x},${y})`}
        opacity={active ? 1 : 0.35}
        onMouseEnter={() => setHover(b.hash)}
        onMouseLeave={() => setHover(null)}
        onClick={() => navigate(`/block/${b.hash}`)}
      >
        {/* backbone depth: soft halo under every node, amber hero glow on the selected tip */}
        <circle r={r + (isSel ? 9 : 4)} fill={isSel ? "#E0A870" : fill} opacity={isSel ? 0.2 : 0.1} />
        <circle r={r} fill={fill} stroke={stroke} strokeWidth={2} />
        {hover === b.hash && (
          <g>
            <rect x={-72} y={-r - 40} width={144} height={31} rx={6} fill="#1E2532" stroke="#37424F" />
            <text x={0} y={-r - 26} textAnchor="middle" fill="#E3E7EA" style={{ fontSize: 9.5 }}>
              h{b.height} · bs{b.blue_score}
            </text>
            <text x={0} y={-r - 15} textAnchor="middle" fill="#9AA7B4" style={{ fontSize: 8.5 }}>
              {short(b.hash, 8, 8)}
            </text>
          </g>
        )}
      </g>
    );
  }

  // Ghost-tip fan: header-only tips (no body) we know exist from getdaginfo but
  // cannot place precisely. Anchor them off the rightmost bodied block.
  const ghostEls: JSX.Element[] = [];
  if (ghostTips.length) {
    const anchor = [...pos.values()].sort((a, b) => b.x - a.x)[0];
    const ax = anchor ? anchor.x : width - 160;
    const ay = anchor ? anchor.y : height / 2;
    const shown = ghostTips.slice(0, 24);
    const fanX = ax + 96;
    shown.forEach((h, i) => {
      const gy = height / 2 + (i - (shown.length - 1) / 2) * ((height - 40) / Math.max(shown.length, 1));
      const active = hover === null || hover === h;
      ghostEls.push(
        <g key={"gh" + h}>
          <path
            className="dag-edge"
            d={`M${ax},${ay} C${(ax + fanX) / 2},${ay} ${(ax + fanX) / 2},${gy} ${fanX},${gy}`}
            stroke="#E0736A"
            strokeWidth={1}
            strokeOpacity={active ? 0.28 : 0.08}
            strokeDasharray="3 3"
          />
          <g
            className="dag-node"
            transform={`translate(${fanX},${gy})`}
            opacity={active ? 1 : 0.4}
            onMouseEnter={() => setHover(h)}
            onMouseLeave={() => setHover(null)}
            onClick={() => navigate(`/block/${h}`)}
          >
            <circle r={5} fill="none" stroke="#E0736A" strokeWidth={1.6} strokeDasharray="2 2" />
            {hover === h && (
              <text x={10} y={3} textAnchor="start" fill="#9AA7B4" style={{ fontSize: 8.5 }}>
                {short(h, 8, 6)} (header-only)
              </text>
            )}
          </g>
        </g>
      );
    });
    if (ghostTips.length > shown.length) {
      ghostEls.push(
        <text key="ghmore" x={fanX} y={height - 8} textAnchor="middle" fill="#6B7787" style={{ fontSize: 9 }}>
          +{ghostTips.length - shown.length} more
        </text>
      );
    }
  }

  return (
    <div className="dag-wrap">
      <div className="dag-scroll">
        <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} preserveAspectRatio="xMidYMid meet" style={{ display: "block" }}>
          {edges}
          {ghostEls}
          {nodes}
        </svg>
      </div>
      <div className="legend" style={{ padding: "12px 16px", borderTop: "1px solid var(--border)" }}>
        <span className="item"><span className="swatch" style={{ background: "#E0A870" }} /> selected tip</span>
        <span className="item"><span className="swatch" style={{ background: "#E0736A" }} /> competing tip</span>
        <span className="item"><span className="swatch" style={{ background: "hsl(214 42% 50%)" }} /> merged block (shade = blue score)</span>
        <span className="item"><span className="swatch" style={{ background: "#5E88C8", height: 3, borderRadius: 2 }} /> selected-parent edge</span>
        <span className="item"><span className="swatch" style={{ background: "#2C3A55", height: 2, borderRadius: 2 }} /> merge edge</span>
        {ghostTips.length > 0 && (
          <span className="item">
            <span className="swatch" style={{ background: "transparent", border: "1.5px dashed #E0736A", borderRadius: "50%" }} /> header-only tip ({ghostTips.length})
          </span>
        )}
      </div>
    </div>
  );
}
