// SPDX-License-Identifier: AGPL-3.0-or-later
import { ReactNode, useState } from "react";
import { Link } from "../lib/router";

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="loading">
      <span className="spinner" /> {label}
    </div>
  );
}

export function ErrorBox({ error }: { error: string }) {
  return (
    <div className="err-box">
      <strong>RPC error:</strong> {error}
      <div className="faint" style={{ marginTop: 8, fontSize: 12.5 }}>
        Is a Bloch node reachable? Reads go directly to the node's public JSON-RPC endpoint.
      </div>
    </div>
  );
}

export function Stat({
  label,
  value,
  sub,
  unit,
  small,
  icon,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  unit?: string;
  small?: boolean;
  icon?: ReactNode;
}) {
  return (
    <div className="card stat">
      <div className="label">
        {icon}
        {label}
      </div>
      <div className={"value" + (small ? " sm" : "")}>
        {value}
        {unit && <span className="unit">{unit}</span>}
      </div>
      {sub != null && <div className="sub">{sub}</div>}
    </div>
  );
}

export function Copyable({ text, children }: { text: string; children?: ReactNode }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="row-actions" style={{ display: "inline-flex" }}>
      {children ?? <code>{text}</code>}
      <button
        className="copy-btn"
        title="Copy"
        onClick={() => {
          navigator.clipboard?.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        }}
      >
        {copied ? "✓" : "⧉"}
      </button>
    </span>
  );
}

export function HashLink({
  hash,
  to,
  display,
}: {
  hash: string;
  to: string;
  display?: string;
}) {
  return (
    <Link to={to} className="mono-link">
      {display ?? hash}
    </Link>
  );
}

export function KV({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <div className="kv">
      {rows.map(([k, v], i) => (
        <div key={i} style={{ display: "contents" }}>
          <div className="k">{k}</div>
          <div className="v">{v}</div>
        </div>
      ))}
    </div>
  );
}
