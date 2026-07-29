// Cloudflare Pages Function: /rpc
// ---------------------------------------------------------------------------
// Read-only JSON-RPC passthrough to a Bloch (Genesis-2) node. Mirrors the
// bloch-explorer functions/rpc.js pattern: an explicit read-only method
// allowlist, a CORS-tight surface, and no node URL ever exposed to the browser.
// The upstream node RPC is READ-PUBLIC (no auth for reads); this Function only
// adds the allowlist + shields the node URL.
//
// Config (Pages project env var, Settings -> Environment variables):
//   BLOCH_RPC_URL   e.g. https://g2-rpc.posternlabs.com/  (a reachable
//                   read-only Genesis-2 node RPC forwarder). If UNSET, the
//                   site's live-stats panel stays hidden ("stats coming soon"),
//                   so this Function returns a clean 503 rather than probing a
//                   bogus default.
// ---------------------------------------------------------------------------

const ALLOWED_METHODS = new Set([
  "getnetworkinfo",
  "getdaginfo",
  "getblockcount",
  "getchainstats",
  "gethashrate",
  "getdifficultyhistory",
  "getpools",
  "getpeerinfo",
  "getpeers",
  "getmempoolinfo",
]);

const UPSTREAM_TIMEOUT_MS = 10000;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const upstream = env.BLOCH_RPC_URL;

  // No RPC configured -> tell the client to stay in "stats coming soon" mode.
  if (!upstream) {
    return json(503, {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32001, message: "live stats not configured" },
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json(400, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
  }

  const method = typeof body?.method === "string" ? body.method : "";
  const id = body?.id ?? null;

  if (!ALLOWED_METHODS.has(method)) {
    return json(403, {
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `method not allowed via public proxy: ${method || "(none)"}` },
    });
  }

  const forward = {
    jsonrpc: "2.0",
    id,
    method,
    params: Array.isArray(body.params) ? body.params : [],
  };

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    const res = await fetch(upstream, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(forward),
      signal: ac.signal,
    });
    const text = await res.text();
    return new Response(text, {
      status: res.status,
      headers: { "Content-Type": "application/json", ...CORS },
    });
  } catch (e) {
    return json(502, {
      jsonrpc: "2.0",
      id,
      error: { code: -32000, message: `upstream unreachable: ${String((e && e.message) || e)}` },
    });
  } finally {
    clearTimeout(timer);
  }
}
