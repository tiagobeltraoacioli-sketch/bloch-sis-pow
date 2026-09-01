// Cloudflare Pages Function: /rpc  (blochl1.com, Pages project bloch-explorer)
// ---------------------------------------------------------------------------
// Read-only JSON-RPC passthrough to the Genesis-4 ARCHIVAL nodes: an explicit
// read-only method allowlist, CORS, and failover between the two archivals.
//
// WHY THIS FUNCTION HAS TO EXIST AT ALL. The archivals answer JSON-RPC on
// :8080 with no `Access-Control-Allow-Origin` header of any kind (measured
// 2026-09-01), so a browser cannot call them directly however public they are.
// This Function is the CORS boundary.
//
// WHY ARCHIVALS AND NOT A VALIDATOR. A Genesis-4 node serves RPC from the
// consensus thread itself — `EngineBackend::call` posts every request to the
// engine's event loop and waits on it. The port has no auth and no rate limit.
// Pointing a public web page at a validator means every reader competes with
// block production, on a chain whose block cadence is already the thing
// everyone is watching. The archivals propose nothing, so they can absorb it.
//
// WRITES ARE NOT PROXIED. `sendrawtransaction` is deliberately absent from the
// allowlist below: it is a write, this endpoint is unauthenticated, and an
// explorer has no business carrying one.
//
// UPSTREAM HOSTNAMES, NOT IPs. A Pages Function is a Worker, and a Worker
// `fetch()` to a bare IP literal is answered by Cloudflare itself with 403
// "error code: 1003" — it never reaches the origin. Nor may the hostname be
// Cloudflare-PROXIED, which trips the same 1003 from the other side. So the
// upstreams are `sslip.io` names, which resolve by DNS to the IP encoded in
// them: `139-180-166-5.sslip.io` -> 139.180.166.5. Both were verified to
// answer `getblockcount` on 2026-09-01. That puts a third party in the
// resolution path; the durable fix is DNS-only A records in a zone we control,
// exactly as `wrangler.toml` says for the Genesis-3 upstream, and it needs a
// token with `zone:write`.
//
// Optional override: `BLOCH_G4_RPC_URLS`, comma-separated, replaces the list.
// ---------------------------------------------------------------------------

/**
 * The archivals, tried in order. Both are peers/archival only.
 * Plain http:// is deliberate: the hop is Function -> origin, server side, so
 * there is no browser mixed-content problem. It is unencrypted, which for a
 * read-only public chain RPC means an observer learns which entries were asked
 * about and an on-path attacker could lie to the explorer. Neither touches
 * keys or consensus.
 */
const DEFAULT_UPSTREAMS = [
  "http://139-180-166-5.sslip.io:8080/",
  "http://139-180-173-231.sslip.io:8080/",
];

// The Genesis-4 READ surface, taken from `route()` in
// `crates/bloch-pos-node/src/rpc.rs`. The list that used to be here was the
// Genesis-3 one — `getdaginfo`, `gethashrate`, `getblockbyheight`,
// `validateaddress` and the rest died with proof of work, and every method
// this explorer actually calls was missing from it.
//
// Two names are absent on purpose rather than by oversight:
//   `sendrawtransaction`  a write; see the header.
//   `gettransaction`      the node refuses it by design (there are no
//                         transaction ids at this layer). It is left OUT so
//                         the refusal comes from the node, in the node's own
//                         words, rather than from this proxy pretending the
//                         method does not exist — those are different
//                         diagnoses and an integrator acts differently on each.
const ALLOWED_METHODS = new Set([
  // chain / head
  "getcapabilities",
  "getchaininfo",
  "getblockcount",
  "getmempoolinfo",
  // blocks
  "getblockbyslot",
  "getblockbyid",
  // validators
  "getvalidator",
  "getvalidatorcount",
  // the eUTXO set
  "getbalance",
  "getutxos",
  "listunspent",
  "gettxout",
  "gettransaction",
]);

const UPSTREAM_TIMEOUT_MS = 12000;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Expose-Headers": "x-bloch-upstream",
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

function upstreams(env) {
  const raw = env.BLOCH_G4_RPC_URLS || env.BLOCH_RPC_URL || "";
  const list = raw
    .split(",")
    .map((u) => u.trim())
    .filter(Boolean);
  return list.length ? list : DEFAULT_UPSTREAMS;
}

export async function onRequestPost(context) {
  const { request, env } = context;

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
  const forward = JSON.stringify({
    jsonrpc: "2.0",
    id,
    method,
    params: Array.isArray(body.params) ? body.params : [],
  });

  const targets = upstreams(env);
  let lastError = "no upstream configured";

  for (const upstream of targets) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), UPSTREAM_TIMEOUT_MS);
    try {
      const res = await fetch(upstream, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: forward,
        signal: ac.signal,
      });
      // A 5xx from an archival is that box having a bad time, not an answer.
      // Move on. Any 2xx/4xx is the node speaking and is returned verbatim,
      // including a JSON-RPC `error` object: "gettransaction is refused by
      // design" is a real answer and asking a second node cannot improve it.
      if (res.status >= 500) {
        lastError = `${upstream} answered ${res.status}`;
        continue;
      }
      const text = await res.text();
      return new Response(text, {
        status: res.status,
        headers: {
          "Content-Type": "application/json",
          // Which archival answered. The explorer prints it, so a reader can
          // tell two nodes apart when they disagree instead of assuming one
          // anonymous "the chain".
          "x-bloch-upstream": new URL(upstream).host,
          ...CORS,
        },
      });
    } catch (e) {
      lastError = `${upstream}: ${String((e && e.message) || e)}`;
    } finally {
      clearTimeout(timer);
    }
  }

  return json(502, {
    jsonrpc: "2.0",
    id,
    error: { code: -32000, message: `no archival answered (${lastError})` },
  });
}
