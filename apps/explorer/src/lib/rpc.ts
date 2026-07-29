// JSON-RPC client. POSTs directly to the Bloch RPC tunnel endpoint from the
// browser (client-side, OUTSIDE Cloudflare) — this avoids the Cloudflare
// Worker→proxied-hostname loop (HTTP 403 "error code: 1003") that broke the
// old same-origin `/rpc` Pages Function. The tunnel host already returns CORS
// headers (Access-Control-Allow-Origin: *) and handles OPTIONS preflight.
//
// Configure with VITE_RPC_URL at build time; defaults to the working
// posternpool tunnel. (g2rpc.blochl1.com is the same tunnel but its edge cert
// was not yet provisioned at deploy time — switch the default once it is.)
//
// Handles Bloch's non-standard error convention: errors can arrive either as a
// top-level JSON-RPC `error` object OR embedded as `result.error` (a string).

export type RpcParams = (string | number | boolean | null)[];

const RPC_ENDPOINT =
  ((import.meta as any).env?.VITE_RPC_URL as string | undefined) ||
  "https://g2rpc.posternpool.com/";

export class RpcError extends Error {
  constructor(message: string, readonly method: string) {
    super(message);
    this.name = "RpcError";
  }
}

let _id = 0;

export async function rpc<T = any>(method: string, params: RpcParams = []): Promise<T> {
  const res = await fetch(RPC_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++_id, method, params }),
  });

  let body: any;
  try {
    body = await res.json();
  } catch {
    throw new RpcError(`HTTP ${res.status}: non-JSON response`, method);
  }

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
