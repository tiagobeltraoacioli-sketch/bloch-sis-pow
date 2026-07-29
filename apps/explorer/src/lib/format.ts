// Formatting helpers. Integer satoshis are the source of truth (1 BLOCH = 1e8
// sat); "bloch" values are display-only.

const SATS_PER_BLOCH = 100_000_000n;

export function fmtBloch(sats: number | string | bigint, maxFrac = 4): string {
  let s: bigint;
  try {
    s = BigInt(typeof sats === "number" ? Math.round(sats) : sats);
  } catch {
    return "0";
  }
  const neg = s < 0n;
  if (neg) s = -s;
  const whole = s / SATS_PER_BLOCH;
  const frac = (s % SATS_PER_BLOCH).toString().padStart(8, "0").slice(0, maxFrac).replace(/0+$/, "");
  const wholeStr = whole.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return (neg ? "-" : "") + wholeStr + (frac ? "." + frac : "");
}

export function fmtInt(n: number | string): string {
  const v = typeof n === "string" ? Number(n) : n;
  if (!isFinite(v)) return "0";
  return Math.round(v).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

export function fmtNum(n: number, digits = 2): string {
  if (!isFinite(n)) return "0";
  return n.toLocaleString(undefined, { maximumFractionDigits: digits });
}

// Compact hashrate: H/s, KH/s, MH/s, ...
export function fmtHashrate(hs: number): string {
  if (!isFinite(hs) || hs <= 0) return "0 H/s";
  const units: [string, number][] = [
    ["EH/s", 1e18],
    ["PH/s", 1e15],
    ["TH/s", 1e12],
    ["GH/s", 1e9],
    ["MH/s", 1e6],
    ["KH/s", 1e3],
  ];
  for (const [label, t] of units) if (hs >= t) return `${(hs / t).toFixed(2)} ${label}`;
  return `${hs.toFixed(2)} H/s`;
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function fmtDuration(secs: number): string {
  if (!isFinite(secs) || secs < 0) return "—";
  if (secs < 90) return `${Math.round(secs)}s`;
  const m = secs / 60;
  if (m < 90) return `${m.toFixed(1)}m`;
  const h = m / 60;
  if (h < 48) return `${h.toFixed(1)}h`;
  return `${(h / 24).toFixed(1)}d`;
}

export function timeAgo(unixSecs: number): string {
  const now = Date.now() / 1000;
  const d = now - unixSecs;
  if (d < 0) return "just now";
  if (d < 60) return `${Math.floor(d)}s ago`;
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
  return `${Math.floor(d / 86400)}d ago`;
}

export function fmtTime(unixSecs: number): string {
  return new Date(unixSecs * 1000).toISOString().replace("T", " ").replace(".000Z", " UTC");
}

export function short(hash: string, head = 8, tail = 8): string {
  if (!hash) return "";
  if (hash.length <= head + tail + 1) return hash;
  return `${hash.slice(0, head)}…${hash.slice(-tail)}`;
}

// difficulty from a compact "bits" value (Bitcoin-style), relative to diff-1.
export function difficultyFromBits(bits: number): number {
  if (!bits) return 0;
  const exp = bits >>> 24;
  const mant = bits & 0x00ffffff;
  const target = mant * Math.pow(256, exp - 3);
  const diff1 = 0xffff * Math.pow(256, 0x1d - 3);
  return target > 0 ? diff1 / target : 0;
}
