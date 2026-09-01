// Cloudflare Pages Function: /g4 — the Genesis-4 read path.
// ---------------------------------------------------------------------------
// Separate from `functions/rpc.js`, which is the Genesis-3 surface and stays
// pointed at the proof-of-work archival. The two chains have different method
// sets and different upstreams, and one Function answering for both is how a
// reader ends up shown a Genesis-3 answer under a Genesis-4 heading.
//
// WHAT THIS EXISTS FOR
//
// Two hard constraints meet here and neither is negotiable:
//
//   1. **Never read from a validator.** The node RPC has no auth and no rate
//      limiting, and it is served by the same thread that runs consensus — a
//      browser tab refreshing a block list is then competing with block
//      production for the lock. Reads go to the archivals, which are peers
//      that validate nothing and can be hammered without consequence.
//
//   2. **A browser cannot reach an archival directly.** The site is HTTPS, the
//      archivals speak plain HTTP on :8080, and they send no CORS headers
//      (measured: an OPTIONS preflight returns nothing at all). Mixed content
//      blocks the request before CORS even gets a say. So the hop has to
//      happen server-side, which is what this file is.
//
// UPSTREAM ADDRESSING — the sslip.io hostnames are not decoration.
// A Pages Function is a Worker, and a Worker `fetch()` to a bare IP literal is
// answered by Cloudflare itself with 403 "error code: 1003" (direct IP access
// not allowed); it never leaves the edge. The upstream must therefore be a
// *hostname*. `139-180-166-5.sslip.io` is public wildcard DNS that resolves to
// the IP encoded in its own name, so it reaches the archival without anyone
// having to hold a DNS record. It works, and it also puts a third party in the
// resolution path of the explorer's only read tier — the durable fix is
// DNS-only A records in the blochl1.com zone, at which point only the strings
// in G4_ARCHIVALS change. See wrangler.toml for the same note on the G3 path.
//
// TWO UPSTREAMS, AND THE CLIENT CAN PICK
//   POST /g4          → failover: try the archivals in turn, first answer wins.
//                       For bulk scans, where the question is cheap and being
//                       wrong about one slot is recoverable.
//   POST /g4?node=0|1 → pinned to one archival, no failover.
//                       This is what makes two-node agreement *possible*:
//                       asking the same question twice through a failover pool
//                       can silently hit the same node twice and return an
//                       agreement that was never tested. See src/lib/source.ts.
//
// Config (Pages project env var, or [vars] in wrangler.toml):
//   G4_ARCHIVALS  comma-separated upstream URLs, in order. Must be hostnames,
//                 not IPs — see above. Falls back to the two known archivals.
// ---------------------------------------------------------------------------

// The Genesis-4 read surface, from crates/bloch-pos-node/src/rpc.rs `route()`.
//
// Reads only. `sendrawtransaction` is deliberately absent: this proxy is the
// explorer's, and an explorer has no business carrying a write. It is also the
// one method whose node-local `tx_hash` return value has misled integrators
// (see the /tx page), so refusing it here costs nothing and removes a trap.
//
// `gettransaction` and `getnewaddress` ARE allowed through, even though the
// node refuses both permanently. That is on purpose: the node's refusal text
// is the most useful answer either method has, and proxying it means a caller
// gets the real explanation (-32005 / -32006) instead of this proxy's
// "method not allowed", which would send them looking for a newer build.
const ALLOWED = new Set([
  "getchaininfo",
  "getblockcount",
  "getblockbyslot",
  "getblockbyid",
  "getvalidator",
  "getvalidatorcount",
  "getbalance",
  "gettxout",
  "getutxos",
  "listunspent",
  "getmempoolinfo",
  "getcapabilities",
  "gettransaction",
  "getnewaddress",
]);

const DEFAULT_ARCHIVALS = [
  "http://139-180-166-5.sslip.io:8080/",
  "http://139-180-173-231.sslip.io:8080/",
];

// Long enough to ride out a cold historical slot lookup — measured at 1–3 s on
// the live archivals, with occasional stragglers — and short enough that a
// wedged upstream fails over rather than holding the tab.
const UPSTREAM_TIMEOUT_MS = 10000;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Expose-Headers": "x-bloch-source, x-bloch-node-index",
};

function json(status, body, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...CORS, ...extra },
  });
}

function archivals(env) {
  const raw = (env && env.G4_ARCHIVALS) || "";
  const list = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return list.length ? list : DEFAULT_ARCHIVALS;
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS });
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

  if (!ALLOWED.has(method)) {
    return json(403, {
      jsonrpc: "2.0",
      id,
      error: {
        code: -32601,
        message: `not a Genesis-4 read method: ${method || "(none)"}`,
      },
    });
  }

  // Rebuild the envelope rather than forwarding what arrived — an upstream
  // should never see a field this proxy did not put there.
  const forward = JSON.stringify({
    jsonrpc: "2.0",
    id,
    method,
    params: Array.isArray(body.params) ? body.params : [],
  });

  const pool = archivals(env);
  const url = new URL(request.url);
  const pin = url.searchParams.get("node");

  // A pinned request gets exactly one upstream and no failover. Falling back
  // would defeat the only reason to pin.
  let order;
  if (pin !== null) {
    const i = Number(pin);
    if (!Number.isInteger(i) || i < 0 || i >= pool.length) {
      return json(400, {
        jsonrpc: "2.0",
        id,
        error: { code: -32602, message: `no archival with index ${pin}` },
      });
    }
    order = [i];
  } else {
    order = pool.map((_, i) => i);
  }

  const failures = [];
  for (const i of order) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), UPSTREAM_TIMEOUT_MS);
    try {
      const res = await fetch(pool[i], {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: forward,
        signal: ac.signal,
      });
      if (!res.ok) {
        failures.push(`${i}:http ${res.status}`);
        continue;
      }
      const text = await res.text();
      // A JSON-RPC `error` body is a real answer from a healthy node — most of
      // all -32007, which is a slot the proposer missed and is the single most
      // common answer this proxy returns. Never fail over on it: the next
      // archival would say the same thing, and treating it as an outage is how
      // a normal empty slot turns into a fake network alarm.
      return new Response(text, {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          ...CORS,
          "x-bloch-source": "archival",
          "x-bloch-node-index": String(i),
        },
      });
    } catch (e) {
      failures.push(`${i}:${String((e && e.message) || e)}`);
    } finally {
      clearTimeout(timer);
    }
  }

  // Every archival is gone. Distinct code from anything a node emits, so the
  // client can tell "we could not ask" apart from "the chain answered no" —
  // the distinction the whole slot surface is built on.
  return json(
    502,
    {
      jsonrpc: "2.0",
      id,
      error: {
        code: -32050,
        message: `no archival answered (${failures.join("; ")})`,
      },
    },
    { "x-bloch-source": "none" },
  );
}
