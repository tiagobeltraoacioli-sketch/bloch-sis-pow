// Cloudflare Pages Function: /rpc  (blochl1.com, Pages project bloch-explorer)
// ---------------------------------------------------------------------------
// Read-only JSON-RPC passthrough to a Bloch node: an explicit read-only method
// allowlist, a same-origin/CORS-tight surface, and no key ever exposed to the
// browser. The upstream node RPC is READ-PUBLIC (no auth for reads); the only
// thing this Function adds is the allowlist + shielding the node URL.
//
// This is the client's fallback endpoint (src/lib/rpc.ts tier 3) and the one
// that survives the pool decommission by construction — it lives and dies
// with the site itself.
//
// Config (Pages project env var, Settings → Environment variables):
//   BLOCH_RPC_URL   the upstream node RPC, e.g. http://<archival-node>:16210/.
//                   MUST NOT be a Cloudflare-proxied hostname — a Worker
//                   fetching a proxied host on the same account trips the 403
//                   "error code: 1003" loop. Use a DNS-only hostname or a
//                   direct origin.
//                   If unset, this Function answers 503 EXPLICITLY rather than
//                   silently trying a default that cannot work in production.
//
// NOTE (Genesis-4): the allowlist below is the Genesis-3 surface. At the V4
// relaunch it must be rebuilt against docs/specs/BLOCH-RPC-V4.md — several
// methods here die with PoW and the new staking/finality methods are absent.
// ---------------------------------------------------------------------------

const ALLOWED_METHODS = new Set([
  // network / chain
  "getnetworkinfo",
  "getdaginfo",
  "getblockcount",
  "getchainstats",
  "gethashrate",
  "getdifficultyhistory",
  "getblocktimepercentiles",
  "getsupplydistribution",
  "getaddresscount",
  // blocks
  "getblockhash",
  "getblock",
  "getblockbyheight",
  "getrecentblocks",
  "gettxsbyblock",
  // transactions
  "gettransaction",
  "gettxstatus",
  "getrawmempool",
  "getmempoolinfo",
  "getmempoolstats",
  "estimatefee",
  "estimatefeeadvanced",
  "decoderawtransaction",
  // addresses / utxo
  "getbalance",
  "getutxos",
  "getaddressinfo",
  "getaddressbalance_at_height",
  "listtransactions",
  "validateaddress",
  "validateaddressverbose",
  // pools / peers / misc
  "getpools",
  "getpeerinfo",
  "getpeers",
  "getattestation",
]);

const UPSTREAM_TIMEOUT_MS = 12000;

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
  if (!upstream) {
    // Explicit, diagnosable failure — never a silent default. The client
    // (src/lib/rpc.ts) treats 5xx as "endpoint down" and fails over.
    return json(503, {
      jsonrpc: "2.0",
      id: null,
      error: {
        code: -32000,
        message:
          "RPC proxy not configured: set BLOCH_RPC_URL on the Pages project (Settings → Environment variables)",
      },
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

  // Rebuild the envelope ourselves — never forward arbitrary extra fields.
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
      error: { code: -32000, message: `upstream unreachable: ${String(e && e.message || e)}` },
    });
  } finally {
    clearTimeout(timer);
  }
}
