// SPDX-License-Identifier: AGPL-3.0-or-later
import { ReactNode, useId, useRef, useState } from "react";

// Hand-rolled SVG charts — zero chart-lib dependency, keeps the bundle lean.
// Responsive via viewBox + width:100%. Brand-styled: emerald primary series
// via theme tokens (so light/dark both work), gradient area fills, soft series
// glow, draw-on animation, and a mempool.space-style crosshair + floating
// tooltip on the time-series charts.
// DATA is untouched — this file only renders what it is handed.

const W = 640;
const H = 220;
const PAD = { t: 16, r: 18, b: 28, l: 52 };

const PRIMARY = "var(--accent)";
const PRIMARY_HI = "var(--accent-strong)";

function niceTicks(min: number, max: number, count = 4): number[] {
  if (min === max) return [min];
  const span = max - min;
  const step0 = span / count;
  const mag = Math.pow(10, Math.floor(Math.log10(step0)));
  const norm = step0 / mag;
  const step = (norm >= 5 ? 5 : norm >= 2 ? 2 : 1) * mag;
  const start = Math.ceil(min / step) * step;
  const ticks: number[] = [];
  for (let v = start; v <= max + step * 0.001; v += step) ticks.push(v);
  return ticks;
}

export function ChartCard({
  title,
  hint,
  children,
  legend,
}: {
  title: string;
  hint?: string;
  children: ReactNode;
  legend?: { color: string; label: string }[];
}) {
  return (
    <div className="card chart-card chart">
      <div className="chart-head">
        <h3>{title}</h3>
        {hint && <span className="hint">{hint}</span>}
      </div>
      {children}
      {legend && (
        <div className="legend">
          {legend.map((l, i) => (
            <span className="item" key={i}>
              <span className="swatch" style={{ background: l.color }} /> {l.label}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function EmptyPlot({ note }: { note: string }) {
  return <div className="chart-empty">{note}</div>;
}

export interface LinePoint {
  x: number; // domain value (e.g. height)
  y: number;
  label?: string;
}

export function LineChart({
  points,
  color = PRIMARY,
  yFormat = (v) => String(Math.round(v)),
  xFormat = (v) => String(Math.round(v)),
  area = true,
  step = false,
  emptyNote = "No data yet — nothing to plot.",
}: {
  points: LinePoint[];
  color?: string;
  yFormat?: (v: number) => string;
  xFormat?: (v: number) => string;
  area?: boolean;
  step?: boolean;
  emptyNote?: string;
}) {
  const uid = useId().replace(/:/g, "");
  const plotRef = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const [tip, setTip] = useState<{ left: number; top: number } | null>(null);

  if (!points.length) return <EmptyPlot note={emptyNote} />;

  const sorted = [...points].sort((a, b) => a.x - b.x);
  const xs = sorted.map((p) => p.x);
  const ys = sorted.map((p) => p.y);
  const xMin = Math.min(...xs), xMax = Math.max(...xs);
  let yMin = Math.min(...ys), yMax = Math.max(...ys);
  if (yMin === yMax) { yMin = yMin - 1; yMax = yMax + 1; }
  const yPad = (yMax - yMin) * 0.08;
  yMin -= yPad; yMax += yPad;

  const px = (x: number) => PAD.l + ((x - xMin) / (xMax - xMin || 1)) * (W - PAD.l - PAD.r);
  const py = (y: number) => H - PAD.b - ((y - yMin) / (yMax - yMin || 1)) * (H - PAD.t - PAD.b);

  let d = "";
  sorted.forEach((p, i) => {
    const X = px(p.x), Y = py(p.y);
    if (i === 0) d += `M${X},${Y}`;
    else if (step) d += `H${X}V${Y}`;
    else d += `L${X},${Y}`;
  });
  const baseY = py(yMin);
  const areaD = d + `L${px(sorted[sorted.length - 1].x)},${baseY}L${px(sorted[0].x)},${baseY}Z`;

  const yTicks = niceTicks(yMin, yMax, 4);
  const gid = "grad" + uid;
  const glow = "glow" + uid;

  function onMove(clientX: number) {
    const el = plotRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const svgX = ((clientX - rect.left) / rect.width) * W;
    // nearest point by screen-x
    let best = 0, bestD = Infinity;
    for (let i = 0; i < sorted.length; i++) {
      const dd = Math.abs(px(sorted[i].x) - svgX);
      if (dd < bestD) { bestD = dd; best = i; }
    }
    setHover(best);
    setTip({
      left: (px(sorted[best].x) / W) * rect.width,
      top: (py(sorted[best].y) / H) * rect.height,
    });
  }
  function clear() { setHover(null); setTip(null); }

  const hp = hover != null ? sorted[hover] : null;

  return (
    <div
      className="chart-plot"
      ref={plotRef}
      onMouseMove={(e) => onMove(e.clientX)}
      onMouseLeave={clear}
      onTouchStart={(e) => onMove(e.touches[0].clientX)}
      onTouchMove={(e) => { onMove(e.touches[0].clientX); }}
      onTouchEnd={clear}
    >
      <svg viewBox={`0 0 ${W} ${H}`}>
        <defs>
          <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.30" />
            <stop offset="70%" stopColor={color} stopOpacity="0.06" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </linearGradient>
          <filter id={glow} x="-20%" y="-40%" width="140%" height="180%">
            <feGaussianBlur stdDeviation="2.6" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {yTicks.map((t, i) => (
          <g key={i}>
            <line className="grid-line" x1={PAD.l} y1={py(t)} x2={W - PAD.r} y2={py(t)} />
            <text className="axis-label" x={PAD.l - 9} y={py(t) + 3} textAnchor="end">
              {yFormat(t)}
            </text>
          </g>
        ))}
        <line className="grid-base" x1={PAD.l} y1={baseY} x2={W - PAD.r} y2={baseY} />

        {area && <path className="fade-area" d={areaD} fill={`url(#${gid})`} />}
        <path
          className="draw-line"
          d={d}
          pathLength={1}
          fill="none"
          stroke={color}
          strokeWidth={2.2}
          strokeLinejoin="round"
          strokeLinecap="round"
          filter={`url(#${glow})`}
        />

        {hp && (
          <g>
            <line x1={px(hp.x)} y1={PAD.t} x2={px(hp.x)} y2={baseY} stroke={color} strokeWidth={1} strokeOpacity={0.5} strokeDasharray="3 3" />
            <circle cx={px(hp.x)} cy={py(hp.y)} r={5.5} fill={color} fillOpacity={0.18} />
            <circle cx={px(hp.x)} cy={py(hp.y)} r={3.2} fill={PRIMARY_HI} stroke="var(--bg)" strokeWidth={1.4} />
          </g>
        )}

        <text className="axis-label" x={PAD.l} y={H - 9} textAnchor="start">{xFormat(xMin)}</text>
        <text className="axis-label" x={W - PAD.r} y={H - 9} textAnchor="end">{xFormat(xMax)}</text>
      </svg>

      {hp && tip && (
        <div className="chart-tip" style={{ left: tip.left, top: tip.top }}>
          <div className="tip-x">{hp.label ? hp.label.split(":")[0] : xFormat(hp.x)}</div>
          <div className="tip-y">{yFormat(hp.y)}</div>
        </div>
      )}
    </div>
  );
}

export function BarChart({
  bars,
  color = PRIMARY,
  yFormat = (v) => String(Math.round(v)),
}: {
  bars: { label: string; value: number; color?: string }[];
  color?: string;
  yFormat?: (v: number) => string;
}) {
  const [hover, setHover] = useState<number | null>(null);
  if (!bars.length) return <EmptyPlot note="No samples in this window yet." />;
  const yMax = Math.max(...bars.map((b) => b.value), 1);
  const yTicks = niceTicks(0, yMax, 4);
  const innerW = W - PAD.l - PAD.r;
  const bw = innerW / bars.length;
  const py = (y: number) => H - PAD.b - (y / yMax) * (H - PAD.t - PAD.b);
  const baseY = H - PAD.b;

  return (
    <div className="chart-plot">
      <svg viewBox={`0 0 ${W} ${H}`} onMouseLeave={() => setHover(null)}>
        {yTicks.map((t, i) => (
          <g key={i}>
            <line className={i === 0 ? "grid-base" : "grid-line"} x1={PAD.l} y1={py(t)} x2={W - PAD.r} y2={py(t)} />
            <text className="axis-label" x={PAD.l - 9} y={py(t) + 3} textAnchor="end">{yFormat(t)}</text>
          </g>
        ))}
        {bars.map((b, i) => {
          const x = PAD.l + i * bw + bw * 0.16;
          const w = bw * 0.68;
          const y = py(b.value);
          const h = Math.max(baseY - y, 0);
          const c = b.color || color;
          return (
            <g key={i} onMouseEnter={() => setHover(i)}>
              <rect
                className="rise-bar"
                x={x} y={y} width={w} height={h} rx={4}
                fill={c}
                opacity={hover === null || hover === i ? 0.92 : 0.42}
                style={{ animationDelay: `${i * 45}ms` }}
              />
              {(bars.length <= 14 || i % 2 === 0) && (
                <text className="axis-label" x={x + w / 2} y={H - 10} textAnchor="middle">{b.label}</text>
              )}
              {hover === i && (
                <text className="axis-label" x={x + w / 2} y={y - 6} textAnchor="middle" fill={PRIMARY_HI} style={{ fontSize: 11 }}>
                  {yFormat(b.value)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// Horizontal proportion bars (supply distribution, pool share).
export function ProportionBars({
  rows,
}: {
  rows: { label: string; value: number; pct: number; color: string; sub?: string }[];
}) {
  if (!rows.length) return <EmptyPlot note="No distribution data yet." />;
  const max = Math.max(...rows.map((r) => r.pct), 0.0001);
  return (
    <div>
      {rows.map((r, i) => (
        <div className="bar-row" key={i}>
          <div className="bar-label" title={r.sub ? `${r.label} · ${r.sub}` : r.label}>
            {r.label}
          </div>
          <div className="bar-track">
            <div
              className="bar-fill"
              style={{
                width: `${Math.max((r.pct / max) * 100, 0.8)}%`,
                background: `linear-gradient(90deg, ${r.color}, color-mix(in srgb, ${r.color} 62%, transparent))`,
                animationDelay: `${i * 60}ms`,
              }}
            />
          </div>
          <div className="bar-pct">
            {r.pct >= 0.01 ? r.pct.toFixed(2) : r.pct.toExponential(1)}%
          </div>
        </div>
      ))}
    </div>
  );
}
