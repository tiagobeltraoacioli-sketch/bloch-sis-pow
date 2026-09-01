// Cloudflare Pages Function: /g4/validators
// ---------------------------------------------------------------------------
// The validator-set listing the node does not have.
//
// WHY THIS EXISTS AT THE EDGE, AND NOT IN THE BROWSER
//
// Genesis-4 serves `getvalidator` one index at a time. There is no bulk form.
// The obvious client-side answer — loop the browser over every index — is the
// one thing that must not happen, and the reason is not politeness:
//
//   * the node's JSON-RPC has no authentication and no rate limiting, and
//   * it is served from the same thread as consensus.
//
// So a fan-out of 64 is 64 chances to delay the block production the page is
// reporting on, MULTIPLIED BY EVERY READER. A single popular page becomes an
// unauthenticated amplifier pointed at the chain. Moving the fan-out here
// makes it once per cache period for the whole internet instead of once per
// visitor, and points it at an archival rather than at anything that proposes.
//
// WHERE IT READS
//
// The two keyless archival nodes, never a validator. An archival serving a
// stale read is a stale number on a web page; a validator missing its slot
// because it was answering a web page is a missed block. Those are not the
// same cost, so they do not get the same treatment.
//
// The upstreams are given as sslip.io hostnames rather than bare IPs on
// purpose: a Worker `fetch()` to an IP literal is answered by Cloudflare
// itself with 403 "error code: 1003" and never reaches the origin. This is
// the same measured constraint documented at length in wrangler.toml, and the
// same third-party-in-the-resolution-path caveat applies — override
// G4_ARCHIVAL_1 / G4_ARCHIVAL_2 with real DNS-only hostnames when they exist.
//
// PAGINATION IS A PLATFORM LIMIT, NOT A STYLE CHOICE
//
// A Pages Function may make 50 subrequests per invocation on the entry plan.
// 64 validators plus a head read exceeds that, so the set is served in pages
// of 32. The cap is enforced here rather than trusted from the query string:
// `limit` is clamped, not validated-and-rejected, because the failure mode of
// an unclamped limit is this endpoint becoming the amplifier it was written to
// prevent.
// ---------------------------------------------------------------------------

/** Hard ceiling on `limit`, chosen to stay under the subrequest budget. */
const MAX_LIMIT = 32;

/**
 * How long a page of the set stays fresh at the edge.
 *
 * An epoch is 32 slots of 30s — 16 minutes — and effective stake only moves on
 * an epoch boundary, so a minute of staleness cannot show a wrong number for
 * long. It is short enough that a state change (an exit, a slashing) surfaces
 * quickly, and long enough that a thousand readers cost the archival one
 * fan-out rather than a thousand.
 */
const CACHE_SECONDS = 60;

/** Per-upstream timeout. Shorter than the client's patience, deliberately. */
const UPSTREAM_TIMEOUT_MS = 9000;

/** Concurrent upstream calls per invocation. */
const CONCURRENCY = 6;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(status, body, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...CORS, ...(extraHeaders || {}) },
  });
}

function upstreams(env) {
  return [
    env.G4_ARCHIVAL_1 || "http://139-180-166-5.sslip.io:8080/",
    env.G4_ARCHIVAL_2 || "http://139-180-173-231.sslip.io:8080/",
  ];
}

async function rpc(url, method, params) {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params || [] }),
      signal: ac.signal,
    });
    const body = await res.json();
    if (body && body.error) throw new Error(body.error.message || "rpc error");
    return body.result;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Ask both archivals, in a stable order, and take the first that answers.
 *
 * Used for the per-validator fan-out, where a stale row is the honest failure
 * and doubling 32 reads to defend against it would cost the archivals twice
 * the traffic for a worse trade.
 */
async function rpcAny(urls, method, params) {
  let lastErr;
  for (const u of urls) {
    try {
      return { value: await rpc(u, method, params), source: u };
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error("no archival answered");
}

/**
 * The head, asked of BOTH archivals, with their answers compared.
 *
 * The fan-out below is a first-answer read, but the head is not, and the
 * difference is deliberate. Two facts make an uncorroborated head actively
 * misleading here:
 *
 *   1. The archivals run a DIFFERENT BINARY from the validator fleet
 *      (`bloch-pos-quatro` against the fleet's `bloch-pos-cinco`), and this
 *      chain has a documented history of nodes on different builds deriving
 *      different committees. Two archivals agreeing with each other is not
 *      evidence that they agree with the chain.
 *   2. Reading `:8080` reaches the node directly, past every protection the
 *      public proxy applies. A forked archival keeps answering, confidently.
 *
 * So the comparison is reported rather than resolved. Every stake figure this
 * endpoint returns is "as of" this head, and a reader who is shown the head
 * without being shown whether anything corroborates it has been told a number
 * and denied the one fact that says whether to believe it.
 *
 * Only the FINALITY claim is compared. Slot and height legitimately differ by
 * a slot or two between two healthy nodes, and flagging that as a conflict
 * would train everyone to ignore the flag.
 */
async function corroboratedHead(urls) {
  const results = await Promise.all(
    urls.map(async (u) => {
      const started = Date.now();
      try {
        const value = await rpc(u, "getchaininfo", []);
        return { url: u, ok: true, ms: Date.now() - started, value };
      } catch (e) {
        return { url: u, ok: false, ms: Date.now() - started, error: String((e && e.message) || e) };
      }
    }),
  );

  const answered = results.filter((r) => r.ok);
  if (answered.length === 0) {
    throw new Error(results.map((r) => `${r.url}: ${r.error}`).join("; "));
  }

  const claim = (v) => ({
    justified_epoch: v.justified && v.justified.epoch,
    justified_root: v.justified && v.justified.root,
    finalized_epoch: v.finalized && v.finalized.epoch,
    finalized_root: v.finalized && v.finalized.root,
  });

  let state = "single";
  let differing = [];
  if (answered.length > 1) {
    const a = claim(answered[0].value);
    const b = claim(answered[1].value);
    differing = Object.keys(a).filter((k) => a[k] !== b[k]);
    state = differing.length === 0 ? "corroborated" : "conflict";
  }

  return {
    head: answered[0].value,
    source: answered[0].url,
    corroboration: {
      state,
      differing,
      sources: results.map((r) => ({
        url: r.url,
        ok: r.ok,
        ms: r.ms,
        error: r.ok ? undefined : r.error,
        claim: r.ok ? { slot: r.value.slot, height: r.value.height, ...claim(r.value) } : undefined,
      })),
    },
  };
}

/** Bounded-concurrency map; per-item failures are captured, never thrown. */
async function mapLimit(items, limit, work) {
  const out = new Array(items.length);
  let next = 0;
  const runner = async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      try {
        out[i] = { ok: true, value: await work(items[i], i) };
      } catch (e) {
        out[i] = { ok: false, error: String((e && e.message) || e) };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, runner));
  return out;
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS });
}

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const offset = Math.max(0, Number(url.searchParams.get("offset") || 0) | 0);
  const wanted = Number(url.searchParams.get("limit") || MAX_LIMIT) | 0;
  const limit = Math.min(MAX_LIMIT, Math.max(1, wanted || MAX_LIMIT));

  // Normalise the cache key so `?limit=999` and `?limit=32` are one entry,
  // and so a missing parameter and its default are not two.
  const keyUrl = new URL(url.origin + url.pathname);
  keyUrl.searchParams.set("offset", String(offset));
  keyUrl.searchParams.set("limit", String(limit));
  const cacheKey = new Request(keyUrl.toString(), { method: "GET" });
  const cache = caches.default;

  const hit = await cache.match(cacheKey);
  if (hit) {
    const withMark = new Response(hit.body, hit);
    withMark.headers.set("X-Bloch-Cache", "hit");
    return withMark;
  }

  const urls = upstreams(env);

  let head;
  let headSource;
  let corroboration;
  try {
    const r = await corroboratedHead(urls);
    head = r.head;
    headSource = r.source;
    corroboration = r.corroboration;
  } catch (e) {
    return json(502, {
      error: `no archival answered getchaininfo: ${String((e && e.message) || e)}`,
    });
  }

  const total = (head && head.validators && head.validators.total) || 0;
  const end = Math.min(total, offset + limit);
  const indices = [];
  for (let i = offset; i < end; i++) indices.push(i);

  // Alternate archivals across the fan-out so neither carries the whole page.
  const settled = await mapLimit(indices, CONCURRENCY, (idx, n) =>
    rpc(urls[n % urls.length], "getvalidator", [idx]),
  );

  const validators = settled.map((r, n) =>
    r.ok ? r.value : { index: indices[n], unavailable: r.error },
  );

  const payload = {
    // The head the set was read against. Without it a reader cannot tell a
    // stale page from a live one, and every number below is only true as of
    // some epoch.
    head: {
      slot: head.slot,
      height: head.height,
      epoch: head.epoch,
      slot_in_epoch: head.slot_in_epoch,
      slots_per_epoch: head.slots_per_epoch,
      finalized_height: head.finalized_height,
      justified: head.justified,
      finalized: head.finalized,
      block_id: head.block_id,
      state_root: head.state_root,
    },
    counts: {
      total,
      active: (head.validators && head.validators.active) || 0,
      total_active_stake_sat: head.total_active_stake_sat,
    },
    offset,
    limit,
    returned: validators.length,
    validators,
    source: headSource,
    // The client is required to surface a `conflict` rather than the number
    // it accompanies. See the note on `corroboratedHead`.
    corroboration,
    generated_at: Math.floor(Date.now() / 1000),
  };

  const res = json(200, payload, {
    "Cache-Control": `public, max-age=${CACHE_SECONDS}`,
    "X-Bloch-Cache": "miss",
  });
  context.waitUntil(cache.put(cacheKey, res.clone()));
  return res;
}
