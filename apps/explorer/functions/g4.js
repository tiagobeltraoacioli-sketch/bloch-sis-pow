// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Cloudflare Pages Function: /g4 — CORROBORATED Genesis-4 JSON-RPC read.
// ---------------------------------------------------------------------------
// This exists because of one specific failure mode, and it is worth stating
// plainly before the code:
//
//   The public proxy (`https://posternlabs.com/g4rpc`) is SOFT on
//   `getchaininfo`. When it cannot get two nodes to agree it does not error —
//   it returns one node's answer. A single node's `getchaininfo` is that
//   node's *opinion* of the head, and this chain has already shipped a day on
//   which nodes at the same height reported different `block_id`s and
//   different balances. A number read from one node and rendered without
//   qualification is how a reader ends up believing a fork.
//
// So this Function asks BOTH keyless archival nodes, compares the answers
// field by field, and returns the comparison alongside the result. The page
// above it is required to render the difference between "two nodes agree" and
// "one node said so". It is never allowed to quietly pick a winner.
//
// WHY NOT READ THE ARCHIVALS FROM THE BROWSER
//   1. They serve plain http on :8080 — an https page cannot fetch them
//      (mixed content), and
//   2. they send no CORS headers (an OPTIONS gets 405), and
//   3. fanning out from every open tab multiplies the load by the number of
//      readers. Here it is one pair of requests per request, at the edge.
//
// WHY NOT A VALIDATOR
//   Validator RPC is served by the consensus loop itself and has no rate
//   limiting. Polling one to draw a chart about its health is how you cause
//   the thing you are drawing. These two are keyless archivals; they hold no
//   validator key and produce nothing. They are the only nodes this file is
//   permitted to name.
//
// WHY sslip.io HOSTNAMES AND NOT THE IPs
//   Measured on this project, 2026-08-12: a Pages Function is a Worker, and a
//   Worker `fetch()` to a bare IP literal is answered by Cloudflare itself
//   with 403 "error code: 1003" — it never reaches the origin. sslip.io is a
//   public wildcard-DNS service that resolves `1-2-3-4.sslip.io` to 1.2.3.4.
//   It is a third party in the resolution path, which is a real (small) cost:
//   an attacker who controlled it could point these names elsewhere and lie to
//   the explorer. It cannot touch keys or consensus, and the corroboration
//   check below is exactly what makes such a lie visible — it would have to
//   capture BOTH names and keep the two forged answers consistent.
//
//   The durable fix is two DNS-only A records in a zone we control. When they
//   exist, change ARCHIVALS and nothing else moves.
// ---------------------------------------------------------------------------

/**
 * The two keyless archival nodes. Not validators. Not the public proxy.
 * Order is not significance: neither is primary, and the code below must never
 * develop a preference for the first one.
 */
const ARCHIVALS = [
  { id: "archival-a", ip: "139.180.166.5", url: "http://139-180-166-5.sslip.io:8080/" },
  { id: "archival-b", ip: "139.180.173.231", url: "http://139-180-173-231.sslip.io:8080/" },
];

/**
 * Read-only method allowlist for Genesis-4.
 *
 * The Genesis-3 list in `rpc.js` does not apply here — different chain,
 * different surface. Anything not named is refused rather than forwarded,
 * because a passthrough that forwards unknown methods is a passthrough whose
 * blast radius is whatever the node grows next.
 */
const ALLOWED = new Set([
  "getchaininfo",
  "getblockcount",
  "getblockbyslot",
  "getblockbyid",
  "getvalidator",
  "getvalidatorcount",
  "getvalidators",
  "getstakedistribution",
  "getsupply",
  "getmempoolinfo",
  "getbalance",
  "getutxos",
  "listunspent",
  "gettxout",
  "getcapabilities",
  // Named on purpose although the node REFUSES both, permanently. Leaving them
  // out would make this proxy answer "method not allowed" where the node would
  // have answered NO_TRANSACTION_INDEX / NO_WALLET with its reason. The client
  // branches on those codes (see CODE in src/lib/source.ts); a proxy-level 403
  // would send an integrator hunting for a newer binary that does not exist.
  "gettransaction",
  "getnewaddress",
]);

/**
 * Fields of `getchaininfo` that must match for two nodes to be called agreed.
 *
 * `slot`, `height` and `block_id` are deliberately NOT in here. Two honest
 * nodes routinely differ by a slot simply because one answered a moment later
 * than the other, and calling that a disagreement would cry wolf on every
 * other request until the warning meant nothing. What must match is the
 * FINALITY CLAIM — the checkpoints and their roots. Two nodes differing on
 * those are not out of step; they are on different chains.
 */
const CONSENSUS_FIELDS = [
  "justified.epoch",
  "justified.root",
  "finalized.epoch",
  "finalized.root",
];

const UPSTREAM_TIMEOUT_MS = 9000;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  // `source.ts` reads the answering node out of this header to decide whether
  // a cross-check was possible at all. Without the expose header the browser
  // hides it and every pinned read looks unattributed.
  "Access-Control-Expose-Headers": "x-bloch-source, x-bloch-node-index",
};

function json(status, body, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...CORS, ...(extraHeaders || {}) },
  });
}

function dig(obj, path) {
  return path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
}

async function askOne(node, forward) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), UPSTREAM_TIMEOUT_MS);
  const started = Date.now();
  try {
    const res = await fetch(node.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(forward),
      signal: ac.signal,
    });
    const body = await res.json();
    if (body && body.error) {
      return { id: node.id, ip: node.ip, ok: false, ms: Date.now() - started, error: body.error.message };
    }
    return { id: node.id, ip: node.ip, ok: true, ms: Date.now() - started, result: body ? body.result : undefined };
  } catch (e) {
    return {
      id: node.id,
      ip: node.ip,
      ok: false,
      ms: Date.now() - started,
      error: String((e && e.message) || e),
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS });
}

/**
 * `POST /g4?node=N` — pinned to ONE archival, no failover, no corroboration.
 *
 * This is not a weaker version of the default path; it is what makes the
 * default path's promise checkable. `agree()` in `src/lib/source.ts` needs two
 * reads it KNOWS came from different boxes, and a failover pool cannot give
 * that — ask it twice and it may answer from the same node both times. So the
 * client pins each of the two reads itself and compares them. The answer is
 * returned as plain JSON-RPC, with the node it came from stamped in
 * `x-bloch-node-index`, because a corroboration envelope here would be this
 * Function asserting agreement it deliberately did not check.
 */
async function pinned(nodes, index, forward, id) {
  const node = nodes[index];
  if (!node) {
    return json(400, {
      jsonrpc: "2.0",
      id,
      error: { code: -32602, message: `no archival at index ${index}` },
    });
  }
  const a = await askOne(node, forward);
  if (!a.ok) {
    return json(
      502,
      { jsonrpc: "2.0", id, error: { code: -32050, message: a.error || "archival did not answer" } },
      { "x-bloch-source": "none", "x-bloch-node-index": String(index) },
    );
  }
  return json(
    200,
    { jsonrpc: "2.0", id, result: a.result },
    {
      "x-bloch-source": "archival",
      "x-bloch-node-index": String(index),
      "Cache-Control": "no-store",
    },
  );
}

export async function onRequestPost(context) {
  let body;
  try {
    body = await context.request.json();
  } catch {
    return json(400, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
  }

  const method = typeof body?.method === "string" ? body.method : "";
  const id = body?.id ?? null;
  if (!ALLOWED.has(method)) {
    return json(403, {
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `method not allowed: ${method || "(none)"}` },
    });
  }

  // Rebuild the envelope; never forward fields we did not inspect.
  const forward = {
    jsonrpc: "2.0",
    id: 1,
    method,
    params: Array.isArray(body.params) ? body.params : [],
  };

  // Pinned read? Answer from exactly that box and say so.
  const q = new URL(context.request.url).searchParams.get("node");
  if (q !== null && /^\d+$/.test(q)) return pinned(ARCHIVALS, Number(q), forward, id);

  const answers = await Promise.all(ARCHIVALS.map((n) => askOne(n, forward)));
  const live = answers.filter((a) => a.ok);

  if (live.length === 0) {
    return json(502, {
      jsonrpc: "2.0",
      id,
      error: { code: -32000, message: "no archival answered" },
      corroboration: { state: "none", sources: answers },
    });
  }

  // Which fields are compared depends on the method. For `getchaininfo` it is
  // the finality claim; for everything else it is the whole result, compared
  // as canonical JSON — a block or a balance either matches or it does not.
  let agree;
  let differing = [];
  if (live.length < ARCHIVALS.length) {
    agree = null; // not disagreement — absence of a second opinion.
  } else if (method === "getchaininfo") {
    differing = CONSENSUS_FIELDS.filter(
      (f) => String(dig(live[0].result, f)) !== String(dig(live[1].result, f)),
    );
    agree = differing.length === 0;
  } else {
    agree = JSON.stringify(live[0].result) === JSON.stringify(live[1].result);
    if (!agree) differing = ["result"];
  }

  // WHICH ANSWER IS RETURNED, AND WHY IT IS NOT A VOTE.
  //
  // When the nodes agree, either will do. When they do NOT agree we still
  // return one — a page that renders nothing during a fork is a page that
  // goes blank exactly when someone needs it — but `state: "conflict"` and
  // both raw answers travel with it, and the client is contractually required
  // to render the conflict rather than the number. Picking the more advanced
  // head here would be a silent fork choice performed by a web proxy, which
  // is precisely the authority this file must not have.
  const chosen = method === "getchaininfo"
    ? live.reduce((a, b) => (b.result?.slot > a.result?.slot ? b : a))
    : live[0];

  const state = live.length < ARCHIVALS.length ? "single" : agree ? "corroborated" : "conflict";

  return json(
    200,
    {
      jsonrpc: "2.0",
      id,
      result: chosen.result,
      corroboration: {
        state,
        agreed_on: method === "getchaininfo" ? CONSENSUS_FIELDS : ["result"],
        differing,
        answered_by: chosen.id,
        sources: answers.map((a) => ({
          id: a.id,
          ip: a.ip,
          ok: a.ok,
          ms: a.ms,
          error: a.error,
          // The finality claim from each node, verbatim, so the client can
          // show BOTH sides of a conflict instead of a warning about one.
          claim:
            a.ok && method === "getchaininfo"
              ? {
                  slot: a.result?.slot,
                  height: a.result?.height,
                  block_id: a.result?.block_id,
                  justified: a.result?.justified,
                  finalized: a.result?.finalized,
                }
              : undefined,
        })),
      },
    },
    // Never cached. A stale finality answer is worse than no answer: the whole
    // point of the page above is that it is showing the chain *now*.
    {
      "Cache-Control": "no-store",
      "x-bloch-source": "archival",
      "x-bloch-node-index": String(ARCHIVALS.findIndex((n) => n.id === chosen.id)),
    },
  );
}
