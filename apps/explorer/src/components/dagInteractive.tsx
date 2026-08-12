// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { useRouter } from "../lib/router";
import { short, timeAgo } from "../lib/format";
import type { DagBlock } from "./dag";

// Explorable GhostDAG canvas: scroll/pinch to zoom, drag to pan, hover for a
// tooltip, click a node to open its block. New blocks pop in on refresh. Built as
// a NEW component so the existing static DagView is untouched.

interface Node {
  hash: string;
  x: number;
  y: number;
  b: DagBlock;
  isSel: boolean;
  isTip: boolean;
  ghost?: boolean;
}

export function InteractiveDag({
  blocks,
  tips,
  selectedTip,
  ghostTips = [],
  height = 560,
}: {
  blocks: DagBlock[];
  tips: Set<string>;
  selectedTip: string | null;
  ghostTips?: string[];
  height?: number;
}) {
  const { navigate } = useRouter();
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const [wrapW, setWrapW] = useState(1120);
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });
  const [hover, setHover] = useState<string | null>(null);
  const prevHashes = useRef<Set<string>>(new Set());
  const [freshNodes, setFreshNodes] = useState<Set<string>>(new Set());

  // measure container width (responsive)
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const measure = () => setWrapW(el.clientWidth || 1120);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // ── layout in unscaled "world" coordinates ──────────────────────────────
  const layout = useMemo(() => {
    const byHeight = new Map<number, DagBlock[]>();
    for (const b of blocks) {
      const arr = byHeight.get(b.height) || [];
      arr.push(b);
      byHeight.set(b.height, arr);
    }
    const heights = [...byHeight.keys()].sort((a, b) => a - b);
    const minH = heights[0] ?? 0;
    const maxH = heights[heights.length - 1] ?? 0;
    const maxLane = Math.max(1, ...[...byHeight.values()].map((a) => a.length));
    const laneH = 48;
    const colW = 92;
    const padX = 60;
    const padY = 40;
    const span = maxH - minH || 1;
    const worldW = padX * 2 + span * colW + (ghostTips.length ? 200 : 0);
    const worldH = Math.max(padY * 2 + (maxLane - 1) * laneH, 320);

    const nodes: Node[] = [];
    const pos = new Map<string, { x: number; y: number }>();
    for (const h of heights) {
      const arr = byHeight.get(h)!.slice().sort((a, b) => a.hash.localeCompare(b.hash));
      const x = padX + (h - minH) * colW;
      arr.forEach((b, i) => {
        const y = worldH / 2 + (i - (arr.length - 1) / 2) * laneH;
        pos.set(b.hash, { x, y });
        nodes.push({ hash: b.hash, x, y, b, isSel: b.hash === selectedTip, isTip: tips.has(b.hash) });
      });
    }

    // ghost (header-only) tips fanned off the rightmost node
    const ghostNodes: Node[] = [];
    if (ghostTips.length && nodes.length) {
      const anchor = nodes.reduce((a, b) => (b.x > a.x ? b : a), nodes[0]);
      const fanX = anchor.x + 120;
      const shown = ghostTips.slice(0, 40);
      shown.forEach((h, i) => {
        const gy = worldH / 2 + (i - (shown.length - 1) / 2) * ((worldH - 40) / Math.max(shown.length, 1));
        ghostNodes.push({
          hash: h,
          x: fanX,
          y: gy,
          ghost: true,
          isSel: false,
          isTip: true,
          b: { hash: h, height: anchor.b.height + 1, blue_score: 0, parents: [anchor.hash], timestamp: 0 },
        });
      });
    }

    return { nodes, ghostNodes, pos, worldW, worldH, minH, maxH };
  }, [blocks, tips, selectedTip, ghostTips]);

  const bs = blocks.map((b) => b.blue_score);
  const bsMin = bs.length ? Math.min(...bs) : 0;
  const bsMax = bs.length ? Math.max(...bs) : 1;

  // ── fit-to-width whenever the world size changes ────────────────────────
  const fit = useCallback(() => {
    if (!layout.worldW) return;
    const k = Math.min(1.6, Math.max(0.25, (wrapW - 16) / layout.worldW));
    const x = (wrapW - layout.worldW * k) / 2;
    const y = (height - layout.worldH * k) / 2;
    setView({ k, x, y });
  }, [layout.worldW, layout.worldH, wrapW, height]);

  useEffect(() => {
    fit();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout.worldW, layout.worldH, wrapW]);

  // ── new-block animation ─────────────────────────────────────────────────
  useEffect(() => {
    const now = new Set(blocks.map((b) => b.hash));
    if (prevHashes.current.size) {
      const fresh = new Set<string>();
      now.forEach((h) => {
        if (!prevHashes.current.has(h)) fresh.add(h);
      });
      if (fresh.size) {
        setFreshNodes(fresh);
        const t = window.setTimeout(() => setFreshNodes(new Set()), 1200);
        prevHashes.current = now;
        return () => clearTimeout(t);
      }
    }
    prevHashes.current = now;
  }, [blocks]);

  // ── pointer pan + pinch zoom ─────────────────────────────────────────────
  const pointers = useRef<Map<number, { x: number; y: number }>>(new Map());
  const pinchRef = useRef<{ dist: number; k: number } | null>(null);
  const dragRef = useRef<{ x: number; y: number; vx: number; vy: number; moved: boolean } | null>(null);

  const onPointerDown = (e: React.PointerEvent) => {
    (e.target as Element).setPointerCapture?.(e.pointerId);
    suppressClick.current = false;
    pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pointers.current.size === 1) {
      dragRef.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y, moved: false };
    } else if (pointers.current.size === 2) {
      const [a, b] = [...pointers.current.values()];
      pinchRef.current = { dist: Math.hypot(a.x - b.x, a.y - b.y), k: view.k };
    }
  };

  const onPointerMove = (e: React.PointerEvent) => {
    if (!pointers.current.has(e.pointerId)) return;
    pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });

    if (pointers.current.size >= 2 && pinchRef.current) {
      const [a, b] = [...pointers.current.values()];
      const dist = Math.hypot(a.x - b.x, a.y - b.y);
      const rect = wrapRef.current!.getBoundingClientRect();
      const cx = (a.x + b.x) / 2 - rect.left;
      const cy = (a.y + b.y) / 2 - rect.top;
      const nk = clamp(pinchRef.current.k * (dist / pinchRef.current.dist), 0.15, 6);
      zoomAround(cx, cy, nk);
      return;
    }
    if (dragRef.current) {
      const dx = e.clientX - dragRef.current.x;
      const dy = e.clientY - dragRef.current.y;
      if (Math.abs(dx) + Math.abs(dy) > 4) dragRef.current.moved = true;
      setView((v) => ({ ...v, x: dragRef.current!.vx + dx, y: dragRef.current!.vy + dy }));
    }
  };

  const onPointerUp = (e: React.PointerEvent) => {
    pointers.current.delete(e.pointerId);
    if (pointers.current.size < 2) pinchRef.current = null;
    if (pointers.current.size === 0) {
      const d = dragRef.current;
      dragRef.current = null;
      // suppress click after a pan
      if (d && d.moved) suppressClick.current = true;
    }
  };

  const suppressClick = useRef(false);

  const zoomAround = (cx: number, cy: number, nk: number) => {
    setView((v) => {
      const k = clamp(nk, 0.15, 6);
      // keep the world point under (cx,cy) fixed
      const wx = (cx - v.x) / v.k;
      const wy = (cy - v.y) / v.k;
      return { k, x: cx - wx * k, y: cy - wy * k };
    });
  };

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const rect = wrapRef.current!.getBoundingClientRect();
    const factor = Math.exp(-e.deltaY * 0.0015);
    zoomAround(e.clientX - rect.left, e.clientY - rect.top, view.k * factor);
  };

  const btnZoom = (factor: number) => zoomAround(wrapW / 2, height / 2, view.k * factor);

  const nodeFill = (n: Node) => {
    if (n.isSel) return "var(--gold)";
    if (n.isTip) return "var(--red)";
    const t = (n.b.blue_score - bsMin) / (bsMax - bsMin || 1);
    return `color-mix(in srgb, var(--blue) ${Math.round(40 + t * 55)}%, var(--surface))`;
  };

  const hoverNode =
    (hover && [...layout.nodes, ...layout.ghostNodes].find((n) => n.hash === hover)) || null;

  return (
    <div className="dag-wrap">
      <div className="idag-toolbar">
        <div className="idag-btns">
          <button className="pill-tab" onClick={() => btnZoom(1.3)} aria-label="Zoom in">＋</button>
          <button className="pill-tab" onClick={() => btnZoom(1 / 1.3)} aria-label="Zoom out">－</button>
          <button className="pill-tab" onClick={fit}>Fit</button>
        </div>
        <span className="idag-hint">scroll / pinch to zoom · drag to pan · click a block to open it</span>
      </div>

      <div
        ref={wrapRef}
        className="idag-canvas"
        style={{ height, cursor: dragRef.current?.moved ? "grabbing" : "grab" }}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        onWheel={onWheel}
      >
        <svg width="100%" height={height} style={{ display: "block", touchAction: "none" }}>
          <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
            {/* edges */}
            {layout.nodes.map((n) =>
              n.b.parents.map((ph, idx) => {
                const p = layout.pos.get(ph);
                if (!p) return null;
                const sel = idx === 0;
                const active = hover === null || hover === n.hash || hover === ph;
                const mx = (n.x + p.x) / 2;
                return (
                  <path
                    key={n.hash + "->" + ph}
                    className="dag-edge"
                    d={`M${n.x},${n.y} C${mx},${n.y} ${mx},${p.y} ${p.x},${p.y}`}
                    style={{
                      stroke: sel ? "var(--blue)" : "var(--blue-dim)",
                      strokeWidth: (sel ? 2 : 1.2) / view.k,
                      strokeOpacity: active ? (sel ? 0.9 : 0.45) : 0.1,
                    }}
                  />
                );
              })
            )}
            {/* ghost fan */}
            {layout.ghostNodes.map((n) => {
              const p = layout.pos.get(n.b.parents[0]);
              const active = hover === null || hover === n.hash;
              return (
                <g key={"g" + n.hash}>
                  {p && (
                    <path
                      className="dag-edge"
                      d={`M${p.x},${p.y} C${(p.x + n.x) / 2},${p.y} ${(p.x + n.x) / 2},${n.y} ${n.x},${n.y}`}
                      style={{
                        stroke: "var(--red)",
                        strokeWidth: 1 / view.k,
                        strokeOpacity: active ? 0.3 : 0.08,
                        strokeDasharray: `${3 / view.k} ${3 / view.k}`,
                      }}
                    />
                  )}
                  <circle
                    cx={n.x}
                    cy={n.y}
                    r={5}
                    className="idag-dot"
                    style={{ fill: "none", stroke: "var(--red)", strokeWidth: 1.6 / view.k, strokeDasharray: `${2 / view.k} ${2 / view.k}`, opacity: active ? 1 : 0.4 }}
                    onMouseEnter={() => setHover(n.hash)}
                    onMouseLeave={() => setHover(null)}
                    onClick={() => !suppressClick.current && navigate(`/block/${n.hash}`)}
                  />
                </g>
              );
            })}
            {/* nodes */}
            {layout.nodes.map((n) => {
              const active = hover === null || hover === n.hash;
              const r = (n.isSel ? 9 : n.isTip ? 8 : 7) + (freshNodes.has(n.hash) ? 3 : 0);
              return (
                <circle
                  key={n.hash}
                  cx={n.x}
                  cy={n.y}
                  r={r}
                  className={"idag-dot" + (freshNodes.has(n.hash) ? " fresh" : "")}
                  style={{
                    fill: nodeFill(n),
                    stroke: n.isSel ? "var(--brass-hi)" : n.isTip ? "var(--red)" : "transparent",
                    strokeWidth: 2 / view.k,
                    opacity: active ? 1 : 0.35,
                  }}
                  onMouseEnter={() => setHover(n.hash)}
                  onMouseLeave={() => setHover(null)}
                  onClick={() => {
                    if (suppressClick.current) {
                      suppressClick.current = false;
                      return;
                    }
                    navigate(`/block/${n.hash}`);
                  }}
                />
              );
            })}
          </g>
        </svg>

        {hoverNode && (
          <div
            className="idag-tip"
            style={{
              left: Math.min(wrapW - 190, Math.max(6, hoverNode.x * view.k + view.x + 14)),
              top: Math.min(height - 96, Math.max(6, hoverNode.y * view.k + view.y - 10)),
            }}
          >
            {hoverNode.ghost ? (
              <>
                <div className="idag-tip-h">header-only tip</div>
                <div className="idag-tip-r">{short(hoverNode.hash, 10, 8)}</div>
                <div className="idag-tip-r faint">body not yet received</div>
              </>
            ) : (
              <>
                <div className="idag-tip-h">
                  h{hoverNode.b.height}
                  {hoverNode.isSel ? " · selected tip" : hoverNode.isTip ? " · competing tip" : ""}
                </div>
                <div className="idag-tip-r">blue score {hoverNode.b.blue_score}</div>
                <div className="idag-tip-r">{hoverNode.b.parents.length} parent{hoverNode.b.parents.length === 1 ? "" : "s"}</div>
                {hoverNode.b.timestamp > 0 && <div className="idag-tip-r faint">{timeAgo(hoverNode.b.timestamp)}</div>}
                <div className="idag-tip-r faint">{short(hoverNode.hash, 8, 6)}</div>
              </>
            )}
          </div>
        )}
      </div>

      <div className="legend" style={{ padding: "12px 16px", borderTop: "1px solid var(--border)" }}>
        <span className="item"><span className="swatch" style={{ background: "var(--gold)" }} /> selected tip</span>
        <span className="item"><span className="swatch" style={{ background: "var(--red)" }} /> competing tip</span>
        <span className="item"><span className="swatch" style={{ background: "var(--blue)" }} /> merged block (shade = blue score)</span>
        {ghostTips.length > 0 && (
          <span className="item">
            <span className="swatch" style={{ background: "transparent", border: "1.5px dashed var(--red)", borderRadius: "50%" }} /> header-only tip ({ghostTips.length})
          </span>
        )}
      </div>
    </div>
  );
}

function clamp(v: number, lo: number, hi: number) {
  return Math.max(lo, Math.min(hi, v));
}
