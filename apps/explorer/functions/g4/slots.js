// Cloudflare Pages Function: /g4/slots
// ---------------------------------------------------------------------------
// A window of consecutive slots, for the one participation signal Genesis-4
// actually publishes.
//
// WHAT THIS CAN AND CANNOT MEASURE — read before using it for a number.
//
// A block header carries `proposer_index`: who built it. It carries
// `attestation_count`: how many attestations were *included*. It does NOT
// carry which validators attested — there is no aggregation bitfield on this
// RPC, and no `getattestation`/`getcommittee` method to ask separately.
//
// Two consequences, both of which the pages reading this endpoint must state
// rather than paper over:
//
//   1. PROPOSALS are attributable. If a block exists at a slot, the validator
//      that made it is named.
//   2. MISSED slots are NOT attributable. The duty roster is not served, so an
//      empty slot cannot be charged to anyone. "Missed by v17" is not a
//      sentence this data can support, and inventing it would be the third
//      wrong figure of the week.
//
// So this endpoint yields an OBSERVED proposal record, not an attestation
// rate. An attestation rate per validator needs either the aggregation bits or
// the indexer; until one exists, that column stays empty on purpose.
//
// Caching: a finalized slot can never change, so a fully-finalized window is
// cached long. A window containing the head is cached briefly, because its
// tail is still being written.
// ---------------------------------------------------------------------------

import { gate, gateResponse } from "../../edge/gate.js";

const MAX_LIMIT = 32;

/**
 * JSON-RPC error code the node uses for "no canonical block at this slot".
 * Its own message calls it "a missed proposal, not an error", and this
 * endpoint honours that: absence is data, not a failure.
 */
const ABSENT_SLOT_CODE = -32007;
const CONCURRENCY = 6;
const UPSTREAM_TIMEOUT_MS = 9000;

/** A window whose every slot is finalized cannot change again. */
const CACHE_SECONDS_FINAL = 600;
/** A window touching the head is still moving. */
const CACHE_SECONDS_LIVE = 30;

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
    if (body && body.error) {
      const err = new Error(body.error.message || "rpc error");
      err.rpcCode = body.error.code;
      throw err;
    }
    return body.result;
  } finally {
    clearTimeout(timer);
  }
}

async function rpcAny(urls, method, params) {
  let lastErr;
  for (const u of urls) {
    try {
      return await rpc(u, method, params);
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error("no archival answered");
}

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
        out[i] = { ok: false, error: String((e && e.message) || e), code: e && e.rpcCode };
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
  const urls = upstreams(env);

  const wanted = Number(url.searchParams.get("limit") || MAX_LIMIT) | 0;
  const limit = Math.min(MAX_LIMIT, Math.max(1, wanted || MAX_LIMIT));

  // ── the governor, part 1: the head read ─────────────────────────────────
  //
  // This one is unavoidable even on a cache hit — the key is keyed on `to`,
  // which defaults to the head, so the head must be known before the cache can
  // be consulted. It is one cheap call; it is charged as one.
  {
    const refusal = gate(request, { clientCost: 1, upstreamCalls: 1, method: url.pathname });
    if (refusal) return gateResponse(refusal, CORS);
  }

  let head;
  try {
    head = await rpcAny(urls, "getchaininfo", []);
  } catch (e) {
    return json(502, { error: `no archival answered getchaininfo: ${String((e && e.message) || e)}` });
  }

  // `to` is the newest slot in the window, defaulting to the head. Clamped to
  // the head so a caller cannot make the edge walk slots that do not exist.
  const toParam = url.searchParams.get("to");
  const to = Math.min(head.slot, toParam === null ? head.slot : Math.max(0, Number(toParam) | 0));
  const from = Math.max(0, to - limit + 1);

  const keyUrl = new URL(url.origin + url.pathname);
  keyUrl.searchParams.set("to", String(to));
  keyUrl.searchParams.set("limit", String(limit));
  const cacheKey = new Request(keyUrl.toString(), { method: "GET" });
  const cache = caches.default;
  const hit = await cache.match(cacheKey);
  if (hit) {
    const marked = new Response(hit.body, hit);
    marked.headers.set("X-Bloch-Cache", "hit");
    return marked;
  }

  // ── the governor, part 2: the walk ──────────────────────────────────────
  //
  // Below the cache-hit return on purpose: a hit costs the chain nothing, so
  // it is neither charged nor refused. Serving from cache while the budget is
  // empty is what the cache is FOR.
  //
  // Charged `limit` — the calls this miss will really make — because pricing
  // per REQUEST would make the widest range cost the same as the narrowest,
  // i.e. make the expensive shape the cheapest to abuse. CONCURRENCY bounds
  // one request's fan-out; it does nothing about a thousand requests a second,
  // and this route serves the dashboard's slot strip.
  {
    const refusal = gate(request, {
      clientCost: 2,
      upstreamCalls: limit,
      method: url.pathname,
    });
    if (refusal) return gateResponse(refusal, CORS);
  }

  const slots = [];
  for (let s = to; s >= from; s--) slots.push(s);

  const settled = await mapLimit(slots, CONCURRENCY, (s, n) =>
    rpc(urls[n % urls.length], "getblockbyslot", [s]),
  );

  // An empty slot and an unreadable slot are different facts and are kept
  // apart. Collapsing them is how a network problem gets reported as a missed
  // proposal — a much more alarming thing than it is.
  const rows = settled.map((r, n) => {
    const slot = slots[n];
    if (r.ok && r.value) {
      const b = r.value;
      return {
        slot,
        present: true,
        block_id: b.block_id,
        height: b.height,
        epoch: b.epoch,
        proposer_index: b.proposer_index,
        timestamp: b.timestamp,
        tx_count: b.tx_count,
        attestation_count: b.attestation_count,
        finality: b.finality,
        finalized: b.finalized,
      };
    }
    // The node distinguishes these itself, and says so in the error CODE:
    // -32007 is "no canonical block at this slot", which its own message
    // spells out as "a missed proposal, not an error". Keying on the code
    // rather than on the wording means a reworded message cannot silently
    // turn every missed slot into a reported outage.
    if (r.code === ABSENT_SLOT_CODE) return { slot, present: false };
    return { slot, present: false, unreadable: r.ok ? "empty result" : r.error };
  });

  const allFinal = rows.every((r) => r.present === false || r.finalized === true);
  const maxAge = allFinal ? CACHE_SECONDS_FINAL : CACHE_SECONDS_LIVE;

  const payload = {
    head: { slot: head.slot, epoch: head.epoch, height: head.height, slots_per_epoch: head.slots_per_epoch },
    from,
    to,
    slots: rows,
    generated_at: Math.floor(Date.now() / 1000),
  };

  const res = json(200, payload, {
    "Cache-Control": `public, max-age=${maxAge}`,
    "X-Bloch-Cache": "miss",
  });
  context.waitUntil(cache.put(cacheKey, res.clone()));
  return res;
}
