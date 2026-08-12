// JSON-RPC client with an explicit, ordered endpoint chain.
//
// Why a chain: this file used to hardcode `https://g2rpc.posternpool.com/` —
// the POOL's tunnel hostname — as a silent default. The pool is decommissioned
// together with the Genesis-3 halt at height 80,000
// (docs/specs/BLOCH-ECOSYSTEM-MIGRATION.md §6, item 3), so that default would
// have taken blochl1.com down with it. The chain below prefers endpoints that
// survive the decommission, and every failover step is logged (console.warn)
// instead of happening silently.
//
// Production order:
//   1. VITE_RPC_URL          — build-time override; if set, used EXCLUSIVELY
//                              (explicit config never silently falls back).
//   2. rpc.blochl1.com       — the neutral RPC hostname on the explorer's own
//                              domain. OPS ACTION REQUIRED before the halt:
//                              route it (tunnel ingress + DNS + edge cert) to
//                              the surviving archival node's RPC. Not yet
//                              provisioned as of 2026-08-11 (NXDOMAIN), which
//                              the failover tolerates — it just warns and moves
//                              on until ops wires it.
//   3. /rpc (same origin)    — the Cloudflare Pages Function
//                              (functions/rpc.js, read-only allowlist).
//                              Survives with the site by construction. Needs
//                              BLOCH_RPC_URL set on the Pages project to a
//                              NON-Cloudflare-proxied upstream — a proxied
//                              upstream reproduces the 403 "error code: 1003"
//                              worker loop that motivated the old direct-POST
//                              bypass. In dev, Vite proxies this path to a
//                              local node (vite.config.ts).
//   4. g2rpc.posternpool.com — DEPRECATED BRIDGE. The pool tunnel is the only
//                              endpoint actually live as of 2026-08-11, so it
//                              stays as the last resort to keep the explorer
//                              up until (2) or (3) is wired. DELETE this entry
//                              when the pool is decommissioned at the halt.
//
// Failover semantics: an endpoint is demoted only on TRANSPORT-level failure
// (fetch rejection — DNS/TLS/CORS/offline —, a non-JSON body such as an edge
// error page, or HTTP 5xx). JSON-RPC errors are application-level and are
// thrown, never failed over: a live node answering "unknown method" must not
// be mistaken for a dead one. The first endpoint that answers is pinned for
// the session; if the whole chain fails, the next call retries from the top.
//
// Handles Bloch's non-standard error convention: errors can arrive either as a
// top-level JSON-RPC `error` object OR embedded as `result.error` (a string).

export type RpcParams = (string | number | boolean | null)[];

const OVERRIDE = (import.meta as any).env?.VITE_RPC_URL as string | undefined;
const DEV = Boolean((import.meta as any).env?.DEV);

const ENDPOINT_CHAIN: readonly string[] = OVERRIDE
  ? [OVERRIDE]
  : DEV
    ? ["/rpc"] // vite dev proxy → local node tunnel (vite.config.ts)
    : [
        "https://rpc.blochl1.com/", // neutral host — survives the pool decommission
        "/rpc", // same-origin Pages Function (allowlist)
        "https://g2rpc.posternpool.com/", // DEPRECATED bridge — dies with the pool at h 80,000
      ];

export class RpcError extends Error {
  constructor(message: string, readonly method: string) {
    super(message);
    this.name = "RpcError";
  }
}

let _id = 0;

// Index of the endpoint currently pinned; calls start here and walk forward.
let activeIdx = 0;
// Endpoints already warned about, so the console isn't spammed per call.
const warnedDown = new Set<string>();

/** The endpoint the client is currently using (for status UI / debugging). */
export function activeRpcEndpoint(): string {
  return ENDPOINT_CHAIN[Math.min(activeIdx, ENDPOINT_CHAIN.length - 1)];
}

/** True when the client has failed over past the primary endpoint. */
export function rpcIsDegraded(): boolean {
  return activeIdx > 0;
}

export async function rpc<T = any>(method: string, params: RpcParams = []): Promise<T> {
  const payload = JSON.stringify({ jsonrpc: "2.0", id: ++_id, method, params });
  const failures: string[] = [];

  for (let i = activeIdx; i < ENDPOINT_CHAIN.length; i++) {
    const endpoint = ENDPOINT_CHAIN[i];
    let body: any;

    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
      });
      if (res.status >= 500) {
        throw new Error(`HTTP ${res.status}`);
      }
      try {
        body = await res.json();
      } catch {
        throw new Error(`HTTP ${res.status}: non-JSON response`);
      }
    } catch (e: any) {
      // Transport-level failure: this endpoint is down. Fail over EXPLICITLY.
      const reason = String(e?.message || e);
      failures.push(`${endpoint} (${reason})`);
      const next = ENDPOINT_CHAIN[i + 1];
      if (!warnedDown.has(endpoint)) {
        warnedDown.add(endpoint);
        console.warn(
          next
            ? `[rpc] endpoint down: ${endpoint} — ${reason}; failing over to ${next}`
            : `[rpc] endpoint down: ${endpoint} — ${reason}; no fallback left`
        );
      }
      continue;
    }

    // The endpoint answered: pin it, then surface application-level errors.
    activeIdx = i;
    if (body?.error) {
      const msg = body.error.message || JSON.stringify(body.error);
      throw new RpcError(msg, method);
    }
    const result = body?.result;
    if (result && typeof result === "object" && !Array.isArray(result) && "error" in result) {
      throw new RpcError(String(result.error), method);
    }
    return result as T;
  }

  // Every endpoint in the chain is down — reset so the next call retries the
  // primary (which may have come back or been newly provisioned).
  activeIdx = 0;
  throw new RpcError(`all RPC endpoints unreachable: ${failures.join("; ")}`, method);
}

// Fire several independent calls at once; individual failures resolve to null
// so a single stalled/absent method never blanks the whole dashboard.
export async function rpcAllSettled<T extends Record<string, Promise<any>>>(
  calls: T
): Promise<{ [K in keyof T]: Awaited<T[K]> | null }> {
  const keys = Object.keys(calls) as (keyof T)[];
  const settled = await Promise.allSettled(keys.map((k) => calls[k]));
  const out: any = {};
  keys.forEach((k, i) => {
    const s = settled[i];
    out[k] = s.status === "fulfilled" ? s.value : null;
  });
  return out;
}
