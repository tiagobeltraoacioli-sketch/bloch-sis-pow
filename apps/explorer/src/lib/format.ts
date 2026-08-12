// SPDX-License-Identifier: AGPL-3.0-or-later
// Formatting helpers. Integer satoshis are the source of truth (1 BLOCH = 1e8
// sat); "bloch" values are display-only.
//
// AMOUNT ENCODING — canonical rule: docs/specs/BLOCH-SATOSHI-ENCODING.md
// (restated as BLOCH-RPC-V4 R3). Satoshi fields arrive as decimal STRINGS
// from a V4 node and as bare JSON numbers from a live Genesis-3 node, so every
// reader here accepts both. Measured reason: Genesis-4 supply is 1e19 sat,
// ~1110x Number.MAX_SAFE_INTEGER (9,007,199,254,740,991), so a satoshi value
// that passes through a JS number is silently rounded. Never call Number() on
// one — use toSats() to get an exact bigint, or fmtBloch()/fmtInt() to display.

const SATS_PER_BLOCH = 100_000_000n;

/**
 * Parse a wire satoshi value (string | number | bigint) into an exact bigint.
 * Returns 0n for null/undefined/garbage — this is a read-only explorer, so a
 * bad field renders as zero rather than throwing the whole page away.
 */
export function toSats(v: string | number | bigint | null | undefined): bigint {
  if (v === null || v === undefined) return 0n;
  if (typeof v === "bigint") return v;
  if (typeof v === "number") return Number.isFinite(v) ? BigInt(Math.round(v)) : 0n;
  const s = v.trim();
  return /^-?\d+$/.test(s) ? BigInt(s) : 0n;
}

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

/**
 * Group-separate an integer. Also the raw-satoshi renderer (`… sat` subtitles),
 * so it MUST have an exact path: routing a satoshi value through Number() is
 * the corruption site this function used to be. bigint and integer-strings are
 * formatted digit-for-digit; only genuinely fractional input falls back to
 * Number(), and that is never a satoshi amount.
 */
export function fmtInt(n: number | string | bigint): string {
  if (typeof n === "bigint") return group(n.toString());
  if (typeof n === "string") {
    const s = n.trim();
    if (/^-?\d+$/.test(s)) return group(BigInt(s).toString());
    const v = Number(s);
    return isFinite(v) ? group(Math.round(v).toString()) : "0";
  }
  if (!isFinite(n)) return "0";
  // Above 2^53 a number has already lost its low digits; show it exactly as the
  // double actually is rather than pretending, and let callers pass a string.
  if (Number.isSafeInteger(n)) return group(n.toString());
  return group(BigInt(Math.round(n)).toString());
}

function group(s: string): string {
  return s.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
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
